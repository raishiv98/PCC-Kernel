/* Performance-oriented Congestion Control (PCC) — hardened HSNetwork build
 *
 * PCC is a rate-based congestion control algorithm that chooses its sending
 * rate based on an explicit utility function computed over RTT-length
 * monitor intervals.
 *
 * After slow start, on each call to cong_control, PCC:
 *	- Adds new acks to the current monitor interval.
 *	- If the monitor interval is finished, computes a new rate based on
 *	  the interval's rate and observed utility (Vivace utility: achieved
 *	  throughput penalised by latency inflation and loss).
 *
 * Reference:
 *	"PCC Vivace: Online-Learning Congestion Control"
 *	Dong, Meng, Zarchy, Arslan, Gilad, Godfrey, Schapira, NSDI '18.
 *
 * ---------------------------------------------------------------------------
 * v2.1 changelog:
 *  - COMPILE FIX (6.10+): the .cong_control hook signature changed in 6.10
 *    from (sk, rs) to (sk, ack, flag, rs). Assigning the old prototype is a
 *    hard error under -Werror=incompatible-pointer-types, so the module did
 *    not build on Ubuntu HWE 6.11+ / Debian 13 (6.12). Now version-shimmed.
 *  - COUNTER WRAPAROUND: tp->delivered and tp->lost are u32 and wrap in
 *    roughly 14 hours at 1 Gbit/s with a 1448-byte MSS — well inside the
 *    life of a long-lived tunnelled flow. The interval lifecycle compared
 *    these with plain > / <, which invert at the wrap and leave interval
 *    accounting incoherent until the flow resets. All counter comparisons
 *    now go through wraparound-safe pcc_after()/pcc_before().
 *  - CLAMP BYPASS: start_interval() wrote sk_pacing_rate via a raw
 *    min_t(u64, rate, sk->sk_max_pacing_rate) instead of pcc_clamp_rate(),
 *    so the absolute pcc_max_rate_mbit backstop never reached the pacing
 *    layer and the unset-sentinel check was skipped. Worse, probing rates
 *    (rate * 1.1) were never clamped at all, so a flow pinned at the
 *    ceiling paced at 110% of it indefinitely. start_interval() now clamps,
 *    and pcc_setup_intervals_probing() clamps both probe rates.
 *  - DECISION/RATE MISMATCH: pcc_decide_moving() computed the decision
 *    direction BEFORE applying the packet floor and the rate clamp, so a
 *    move that got clamped back to the current rate was still recorded as
 *    RATE_UP/RATE_DOWN. That is a milder form of the v2.0 last_decision
 *    bug: the direction-reversal test compared against a direction that
 *    never happened. Decision is now derived from the final rate.
 *  - Local variable 'before' in pcc_process() renamed (it shadowed the
 *    kernel's before() sequence-comparison helper from <net/tcp.h>).
 *  - Doc correction: v2.0 claimed "div_u64 throughout (32-bit safe)". Only
 *    pcc_set_cwnd() uses div_u64; the utility and gradient paths use plain
 *    s64/s64 division, which needs __divdi3 and will not link on 32-bit.
 *    This module is 64-bit only. Claim removed rather than papered over.
 *
 * v2.0 changelog (on top of the earlier divergence fixes):
 *  - ATOMIC ALLOCATION: .init runs in softirq context for passive opens
 *    (i.e. every inbound proxy connection). kzalloc(GFP_KERNEL) there can
 *    sleep in atomic context -> "scheduling while atomic" under memory
 *    pressure. Now GFP_ATOMIC | __GFP_NOWARN with graceful degradation.
 *  - INVALID-INTERVAL SEMANTICS: a no-signal interval (zero delivered, or
 *    shorter than the trust thresholds) previously scored utility = 0.
 *    Zero is MID-RANGE, not neutral: it outranks a legitimate interval
 *    with negative utility (heavy loss / latency inflation), flipping
 *    probing decisions exactly when the path is congested. No-signal
 *    intervals are now flagged invalid; the decision round holds the
 *    current rate and re-runs instead of acting on garbage.
 *  - LOG FLOOD: loss-state enter/exit used unconditional printk. On lossy
 *    last miles at thousands of flows that saturates journald. Now behind
 *    the pcc_debug switch like everything else.
 *  - pcc_exp(): bounded iteration count (previously could spin/overflow
 *    on large arguments; latent, allegro-only, fixed anyway).
 *  - Racy global flow-id counter -> atomic_t.
 *  - LATENT DECISION BUG: pcc_decide_moving() compared the new direction
 *    against pcc->last_decision but never wrote the new decision back, so
 *    the "direction reversed -> re-probe" test always compared against
 *    the init-time value (RATE_UP). Moving/probing transitions were
 *    effectively arbitrary. last_decision is now updated each move.
 *  - sk_max_pacing_rate "unset" sentinel is ~0UL on >= 4.20 (the field is
 *    unsigned long there); the old ~0U compare never matched, so the
 *    per-socket cap path mis-fired (harmlessly, but wrong). Fixed with a
 *    version-correct sentinel.
 *  - Cross-kernel compatibility (4.14 LTS onwards): tcp_snd_cwnd()
 *    accessors on >= 5.19, min_t/max_t/clamp_t throughout, no reliance
 *    on umin()/get_random_u8(). 64-bit architectures only (see v2.1).
 *  - Slow-start growth factor is now a module parameter, default 100%
 *    (true doubling per interval, as in the Vivace paper) instead of the
 *    hardcoded 1.5x, for competitive ramp-up against BBR on long fat
 *    proxy flows. Exit still reverts to the pre-overshoot rate.
 *  - Interval array sized to what is actually used (PCC_INTERVALS, not
 *    2x), halving per-socket heap at high concurrency.
 *  - Dead hooks removed, magic numbers named (TCP_CA_Loss,
 *    PCC_IGNORE_PACKETS), comment/typo cleanup.
 *
 * Retained earlier fixes:
 *  - Signed max() on latency inflation (umax() reinterpreted negative
 *    inflation as ~1.8e19 and wrecked the utility).
 *  - Utility based on ACHIEVED throughput, not target rate (target-rate
 *    utility grows without bound on signal-free flows -> rate runaway).
 *  - Division-before-guard fixes in the gradient calculation.
 *  - Short-interval / low-delivery throughput-explosion guards
 *    (pcc_min_recv_us, pcc_min_delivered).
 *  - Absolute internal rate ceiling (pcc_max_rate_mbit) because
 *    sk_max_pacing_rate is unset on xray/HAProxy-terminated sockets.
 *  - Slow-start exit when pinned at the rate cap.
 */
#include <linux/module.h>
#include <linux/version.h>
#include <linux/atomic.h>
#include <linux/random.h>
#include <linux/math64.h>
#include <net/tcp.h>

/* ------------------------------------------------------------------------- *
 * Kernel compatibility shims (target: 4.14 LTS ... 6.x)
 * ------------------------------------------------------------------------- */

/* 5.19 removed direct tp->snd_cwnd access in favour of accessors. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
#define pcc_snd_cwnd_set(tp, val)	tcp_snd_cwnd_set((tp), (val))
#else
#define pcc_snd_cwnd_set(tp, val)	do { (tp)->snd_cwnd = (val); } while (0)
#endif

/* 4.20 widened sk_pacing_rate / sk_max_pacing_rate from u32 to unsigned
 * long; the "unset" sentinel is all-ones of the FIELD's type. Comparing
 * against ~0U on a 64-bit unsigned long field never matches. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
#define PCC_PACING_UNSET	(~0UL)
#else
#define PCC_PACING_UNSET	(~0U)
#endif

/* 6.10 changed the .cong_control prototype from
 *     void (*)(struct sock *sk, const struct rate_sample *rs)
 * to
 *     void (*)(struct sock *sk, u32 ack, int flag, const struct rate_sample *)
 * to give the hook access to the ack and ack flags. Assigning the old
 * prototype is caught by -Werror=incompatible-pointer-types, which is on by
 * default in modern builds, so this is a build break rather than a warning. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
#define PCC_CONG_CONTROL_ACK_FLAG	1
#endif

/* Wraparound-safe comparisons for the packet counters.
 *
 * tp->delivered, tp->lost and tp->data_segs_out are u32. At 1 Gbit/s with a
 * 1448-byte MSS that is roughly 86k packets/sec, so the counters wrap in
 * about 14 hours — comfortably inside the lifetime of a long-lived proxied
 * connection. Plain > / < invert across the wrap and the interval lifecycle
 * (send_interval_ended / receive_interval_ended) then either stalls or fires
 * continuously until the flow is torn down.
 *
 * Same trick as the kernel's before()/after() from <net/tcp.h>; named
 * separately so a local variable can never shadow them. */
#define pcc_after(a, b)		((s32)((u32)(a) - (u32)(b)) > 0)
#define pcc_before(a, b)	((s32)((u32)(a) - (u32)(b)) < 0)

/* ------------------------------------------------------------------------- *
 * Module parameters
 * ------------------------------------------------------------------------- */

/* Per-interval debug logging is OFF by default. Enable at runtime with:
 *     echo 1 > /sys/module/tcp_pcc/parameters/pcc_debug
 * This prevents the kernel-log flood that saturates journald/rsyslog. */
static bool pcc_debug;
module_param(pcc_debug, bool, 0644);
MODULE_PARM_DESC(pcc_debug, "enable per-interval debug logging (default off)");

#define pcc_dbg(fmt, ...) \
	do { if (unlikely(pcc_debug)) printk(KERN_INFO "tcp_pcc: " fmt, ##__VA_ARGS__); } while (0)

/* Runtime-tunable guards (stop divergence under load):
 *
 * pcc_min_recv_us   : minimum interval receive-duration (microseconds) for
 *                     a throughput measurement to be trusted. Short ack
 *                     bursts (e.g. 2 delivered over a few us) otherwise
 *                     manufacture gigabit "throughput" out of a near-zero
 *                     denominator.
 * pcc_min_delivered : minimum delivered packets for a trustworthy interval.
 * pcc_max_rate_mbit : ABSOLUTE ceiling on the internal pcc->rate, Mbit/s.
 *                     sk_max_pacing_rate is unset on xray/HAProxy-
 *                     terminated TCP, so a socket-derived cap silently
 *                     never applies; this flat cap always does. Set it
 *                     GENEROUSLY ABOVE the real link rate — it is a
 *                     runaway backstop, not a shaper. If it sits at link
 *                     rate, the clamp becomes the controller and the
 *                     gradient logic is bypassed. 0 disables.
 * pcc_ss_growth_pct : slow-start growth per interval, percent of current
 *                     rate. 100 = doubling (Vivace paper, competitive
 *                     with BBR startup); 50 = the old conservative 1.5x
 *                     for very loss-fragile paths.
 */
static uint pcc_min_recv_us = 1000;	/* 1 ms */
static uint pcc_min_delivered = 3;
static uint pcc_max_rate_mbit = 1000;	/* 1 Gbit/s absolute ceiling */
static uint pcc_ss_growth_pct = 100;	/* double per interval */
module_param(pcc_min_recv_us, uint, 0644);
module_param(pcc_min_delivered, uint, 0644);
module_param(pcc_max_rate_mbit, uint, 0644);
module_param(pcc_ss_growth_pct, uint, 0644);
MODULE_PARM_DESC(pcc_min_recv_us, "min interval recv duration (us) to trust throughput");
MODULE_PARM_DESC(pcc_min_delivered, "min delivered packets to trust an interval");
MODULE_PARM_DESC(pcc_max_rate_mbit, "absolute internal rate ceiling in Mbit/s (0=off)");
MODULE_PARM_DESC(pcc_ss_growth_pct, "slow start growth per interval, % of rate (100=double)");

/* ------------------------------------------------------------------------- *
 * Constants
 * ------------------------------------------------------------------------- */

/* Number of monitor intervals in one randomised probing round (2 paired
 * up/down experiments). */
#define PCC_INTERVALS 4

/* Probing changes rate by 10% up and down of current rate. */
#define PCC_PROBING_EPS 10
#define PCC_PROBING_EPS_PART 100

#define PCC_SCALE 1000 /* fixed-point scale for fractions/utilities/gradients */

#define PCC_RATE_MIN 1024u			/* bytes/sec floor */
#define PCC_RATE_MIN_PACKETS_PER_RTT 2
#define PCC_IGNORE_PACKETS 10			/* acct slack between intervals */
#define PCC_INTERVAL_MIN_PACKETS 20
#define PCC_ALPHA 100

#define PCC_GRAD_STEP_SIZE 25	/* default step size for gradient ascent */
#define PCC_MAX_SWING_BUFFER 1	/* RTTs to dampen gradient ascent */

#define PCC_LAT_INFL_FILTER 30	/* latency inflation below 3% is ignored */

/* Rates must differ by at least 2% or gradients are very noisy. */
#define PCC_MIN_RATE_DIFF_RATIO_FOR_GRAD 20

#define PCC_MIN_CHANGE_BOUND 100 /* first rate change at most 10% of rate */
#define PCC_CHANGE_BOUND_STEP 70 /* consecutive changes may grow by 7% */
#define PCC_AMP_MIN 1		 /* starting amplifier for gradient step */

#define PCC_LOSS_MARGIN 5
#define PCC_MAX_LOSS 10

#define PCC_EXP_MAX_ITER 40	/* hard bound on Taylor terms in pcc_exp() */

#define USE_PROBING

enum PCC_DECISION {
	PCC_RATE_UP,
	PCC_RATE_DOWN,
	PCC_RATE_STAY,
};

/* ------------------------------------------------------------------------- *
 * Data structures
 * ------------------------------------------------------------------------- */

struct pcc_interval {
	u64 rate;		/* sending rate of this interval, bytes/sec */

	s64 recv_start;		/* timestamps while interval awaited acks */
	s64 recv_end;

	s64 send_start;		/* timestamps while interval data was sent */
	s64 send_end;

	s64 start_rtt;		/* smoothed RTT at start/end of interval */
	s64 end_rtt;

	u32 packets_sent_base;	/* packets sent before this interval started */
	u32 packets_ended;	/* data_segs_out snapshot when sending ended */

	s64 utility;		/* observed utility of this interval */
	u32 lost;		/* packets sent this interval that were lost */
	u32 delivered;		/* packets sent this interval, delivered */

	bool invalid;		/* interval carried no usable signal; do not
				 * act on its utility (see v2.0 changelog) */
};

static atomic_t pcc_flow_id = ATOMIC_INIT(0);

struct pcc_data {
	struct pcc_interval *intervals;	/* stats for one probing round */
	int send_index;		/* interval currently being sent */
	int receive_index;	/* interval currently receiving acks */

	s64 rate;		/* current sending rate, bytes/sec */
	s64 last_rate;		/* previous sending rate */

	/* utility function pointer (loss- or latency-based) */
	void (*util_func)(struct pcc_data *, struct pcc_interval *,
			  struct sock *);

	bool start_mode;	/* in slow start? */
	bool moving;		/* in gradient-ascent move to a new rate? */
	bool loss_state;	/* inside TCP_CA_Loss recovery: interval
				 * accounting is suspended */

	bool wait;		/* all scheduled intervals sent; holding rate
				 * while waiting for their acks */
	enum PCC_DECISION last_decision; /* last rate change direction */
	u32 lost_base;		/* tp->lost snapshot from previous call */
	u32 delivered_base;	/* tp->delivered snapshot from previous call */

	/* debug helpers */
	int id;
	int decisions_count;

	u32 packets_counted;	/* delivered+lost accounted so far, minus
				 * the loss-recovery adjustment below */
	u32 spare;		/* packets that raced the loss-recovery
				 * window and must be excluded from interval
				 * accounting (see pcc_set_state) */

	s32 amplifier;		/* multiplier on the current step size */
	s32 swing_buffer;	/* RTTs left before step size may grow */
	s32 change_bound;	/* max change as proportion of current rate */
};

/* ------------------------------------------------------------------------- *
 * Rate clamping
 * ------------------------------------------------------------------------- */

/* Clamp the module's internal target rate to something physically plausible.
 *
 * Primary cap is ABSOLUTE (pcc_max_rate_mbit), applied unconditionally —
 * sk_max_pacing_rate is unset on xray/HAProxy-terminated sockets, so a cap
 * derived from it silently never applies. If sk_max_pacing_rate IS set to a
 * real value, honour it as a (possibly tighter) additional cap. */
static s64 pcc_clamp_rate(struct sock *sk, s64 rate)
{
	s64 cap;

	if (rate < PCC_RATE_MIN)
		rate = PCC_RATE_MIN;

	/* absolute ceiling in bytes/sec: Mbit/s * 1e6 / 8 = Mbit/s * 125000 */
	if (pcc_max_rate_mbit) {
		cap = (s64)pcc_max_rate_mbit * 125000;
		if (rate > cap)
			rate = cap;
	}

	/* tighter per-socket cap, only when it holds a real value */
	if (sk->sk_max_pacing_rate &&
	    sk->sk_max_pacing_rate != PCC_PACING_UNSET) {
		cap = (s64)sk->sk_max_pacing_rate;
		if (rate > cap)
			rate = cap;
	}

	return rate;
}

/* ------------------------------------------------------------------------- *
 * Getters / setters
 * ------------------------------------------------------------------------- */

static u32 pcc_get_rtt(struct tcp_sock *tp)
{
	/* Smoothed RTT if we have one; else 1 ms as a "LAN RTT" (from BBR). */
	if (tp->srtt_us)
		return max(tp->srtt_us >> 3, 1U);
	return USEC_PER_MSEC;
}

/* Set cwnd to 2x the BDP implied by the current pacing rate so the window
 * never throttles pacing (same gain BBR uses); floor of 4 packets. */
static void pcc_set_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 mss = tp->mss_cache ? tp->mss_cache : TCP_MSS_DEFAULT;
	u64 cwnd;

	cwnd = (u64)READ_ONCE(sk->sk_pacing_rate) * pcc_get_rtt(tp);
	cwnd = div_u64(cwnd, USEC_PER_SEC);
	cwnd = div_u64(cwnd, mss);
	cwnd *= 2;
	cwnd = clamp_t(u64, cwnd, 4, tp->snd_cwnd_clamp);
	pcc_snd_cwnd_set(tp, (u32)cwnd);
}

/* Was the pcc struct fully initialised? (Allocation may have failed.) */
static bool pcc_valid(struct pcc_data *pcc)
{
	return (pcc && pcc->intervals && pcc->intervals[0].rate);
}

/* ------------------------------------------------------------------------- *
 * Interval setup
 * ------------------------------------------------------------------------- */

/* Set the target rates of all probing intervals and reset statistics.
 * Each pair tests +eps/-eps around the current rate in random order. */
static void pcc_setup_intervals_probing(struct pcc_data *pcc, struct sock *sk)
{
	u64 rate_low, rate_high;
	u8 rand;
	int i;

	get_random_bytes(&rand, 1);
	rate_high = pcc->rate * (PCC_PROBING_EPS_PART + PCC_PROBING_EPS);
	rate_low = pcc->rate * (PCC_PROBING_EPS_PART - PCC_PROBING_EPS);

	rate_high /= PCC_PROBING_EPS_PART;
	rate_low /= PCC_PROBING_EPS_PART;

	/* Clamp BOTH probe rates. Previously rate_high (rate * 1.1) was never
	 * clamped anywhere, so once pcc->rate reached pcc_max_rate_mbit the
	 * flow paced at 110% of the ceiling forever and the probe pair
	 * straddled a rate the controller could not actually adopt. If the
	 * clamp collapses rate_high onto pcc->rate the pair becomes
	 * asymmetric, which is fine: pcc_decide_rate() is a pairwise utility
	 * comparison, and a win for rate_low correctly walks the rate back
	 * down off the ceiling. */
	rate_high = (u64)pcc_clamp_rate(sk, (s64)rate_high);
	rate_low = (u64)pcc_clamp_rate(sk, (s64)rate_low);

	for (i = 0; i < PCC_INTERVALS; i += 2) {
		if ((rand >> (i / 2)) & 1) {
			pcc->intervals[i].rate = rate_low;
			pcc->intervals[i + 1].rate = rate_high;
		} else {
			pcc->intervals[i].rate = rate_high;
			pcc->intervals[i + 1].rate = rate_low;
		}

		pcc->intervals[i].packets_sent_base = 0;
		pcc->intervals[i + 1].packets_sent_base = 0;
	}

	pcc->send_index = 0;
	pcc->receive_index = 0;
	pcc->wait = false;
}

/* Reset statistics and set the target rate for a single monitor interval. */
static void pcc_setup_intervals_moving(struct pcc_data *pcc)
{
	pcc->intervals[0].packets_sent_base = 0;
	pcc->intervals[0].rate = pcc->rate;
	pcc->send_index = 0;
	pcc->receive_index = 0;
	pcc->wait = false;
}

/* Set the pacing rate and cwnd based on the currently-sending interval. */
static void start_interval(struct sock *sk, struct pcc_data *pcc)
{
	u64 rate = pcc->rate;
	struct pcc_interval *interval;

	if (!pcc->wait) {
		interval = &pcc->intervals[pcc->send_index];
		interval->packets_ended = 0;
		interval->lost = 0;
		interval->delivered = 0;
		interval->invalid = false;
		interval->packets_sent_base =
			max(tcp_sk(sk)->data_segs_out, 1U);
		interval->send_start = tcp_sk(sk)->tcp_mstamp;
		rate = interval->rate;
	}

	/* Must go through pcc_clamp_rate(): it applies the PCC_RATE_MIN floor,
	 * the absolute pcc_max_rate_mbit backstop, AND the sentinel-checked
	 * sk_max_pacing_rate cap. The old raw min_t() against
	 * sk->sk_max_pacing_rate skipped the absolute ceiling entirely, so the
	 * backstop never reached the value actually written to the socket. */
	rate = (u64)pcc_clamp_rate(sk, (s64)rate);
	WRITE_ONCE(sk->sk_pacing_rate, rate);
	pcc_set_cwnd(sk);
}

/* ------------------------------------------------------------------------- *
 * Utility and decisions
 * ------------------------------------------------------------------------- */

/* Bounded fixed-point e^x: x is number*PCC_SCALE, returns e^number*PCC_SCALE.
 * Iteration is hard-capped: the Taylor series terminates naturally for the
 * argument range the allegro utility feeds it, but a stray large argument
 * previously risked a very long loop / overflow. */
static u32 pcc_exp(s32 x)
{
	s64 temp = PCC_SCALE;
	s64 e = PCC_SCALE;
	int i;

	for (i = 1; temp != 0 && i < PCC_EXP_MAX_ITER; i++) {
		temp *= x;
		temp /= i;
		temp /= PCC_SCALE;
		e += temp;
	}
	return e;
}

/* Gradient of utility w.r.t. sending rate, but only if the rates differ
 * enough for the measurement to have low noise.
 *
 * Guards run BEFORE the divisions: rate_1 == 0 faults on the ratio,
 * rate_2 == rate_1 faults on the final division. Either way there is no
 * usable gradient, so return 0 (flat -> don't move rate). */
static s64 pcc_calc_util_grad(s64 rate_1, s64 util_1, s64 rate_2, s64 util_2)
{
	s64 rate_diff_ratio;

	if (rate_1 <= 0 || rate_2 <= 0 || rate_2 == rate_1)
		return 0;

	rate_diff_ratio = (PCC_SCALE * (rate_2 - rate_1)) / rate_1;
	if (rate_diff_ratio < PCC_MIN_RATE_DIFF_RATIO_FOR_GRAD &&
	    rate_diff_ratio > -1 * PCC_MIN_RATE_DIFF_RATIO_FOR_GRAD)
		return 0;

	return (PCC_SCALE * PCC_SCALE * (util_2 - util_1)) / (rate_2 - rate_1);
}

/* Vivace utility: achieved throughput, penalised by latency inflation and
 * loss. Latency-aware — the right choice for VPN/proxy traffic with
 * variable RTT and non-congestive loss. */
static void pcc_calc_utility_vivace(struct pcc_data *pcc,
				    struct pcc_interval *interval,
				    struct sock *sk)
{
	s64 loss_ratio, delivered, lost, mss, rate, throughput, util;
	s64 lat_infl = 0;
	s64 rtt_diff;
	s64 rtt_diff_thresh = 0;
	s64 send_dur = interval->send_end - interval->send_start;
	s64 recv_dur = interval->recv_end - interval->recv_start;

	interval->invalid = false;

	lost = interval->lost;
	delivered = interval->delivered;
	mss = tcp_sk(sk)->mss_cache;
	rate = interval->rate;
	throughput = 0;
	if (recv_dur > 0)
		throughput = (USEC_PER_SEC * delivered * mss) / recv_dur;

	if (delivered == 0) {
		pcc_dbg("%d ucalc: no packets delivered -> no signal\n",
			pcc->id);
		interval->utility = 0;
		interval->invalid = true;
		return;
	}

	/* Divergence guard: a too-short interval makes the throughput
	 * division explode. With recv_dur of a few us and delivered 2,
	 * (USEC_PER_SEC * delivered * mss) / recv_dur manufactures gigabit
	 * "throughput" from noise; utility then chases it and the rate runs
	 * away (the 56-182 Gbps flows seen at 1800 users). An interval this
	 * short carries no usable signal: mark it invalid so the decision
	 * logic repeats it instead of acting on it. (Scoring it 0 is NOT
	 * neutral — 0 outranks a legitimately negative interval and flips
	 * decisions under congestion.) */
	if (recv_dur < (s64)pcc_min_recv_us ||
	    delivered < (s64)pcc_min_delivered) {
		pcc_dbg("%d ucalc: short interval recv_dur %lld delv %lld -> no signal\n",
			pcc->id, recv_dur, delivered);
		interval->utility = 0;
		interval->invalid = true;
		return;
	}

	rtt_diff = interval->end_rtt - interval->start_rtt;
	if (throughput > 0)
		rtt_diff_thresh = (2 * USEC_PER_SEC * mss) / throughput;
	if (send_dur > 0)
		lat_infl = (PCC_SCALE * rtt_diff) / send_dur;

	pcc_dbg("%d ucalc: lat (%lld->%lld) lat_infl %lld\n",
		pcc->id, interval->start_rtt / USEC_PER_MSEC,
		interval->end_rtt / USEC_PER_MSEC, lat_infl);

	if (rtt_diff < rtt_diff_thresh && rtt_diff > -1 * rtt_diff_thresh)
		lat_infl = 0;

	if (lat_infl < PCC_LAT_INFL_FILTER && lat_infl > -1 * PCC_LAT_INFL_FILTER)
		lat_infl = 0;

	if (lat_infl < 0 && pcc->start_mode)
		lat_infl = 0;

	/* loss rate = lost packets / all packets counted */
	loss_ratio = (lost * PCC_SCALE) / (lost + delivered);

	if (pcc->start_mode && loss_ratio < 100)
		loss_ratio = 0;

	/* lat_infl is signed and can be negative (RTT dropped during the
	 * interval). An unsigned max() here reinterprets a small negative
	 * lat_infl as ~1.8e19 and makes util underflow to garbage, driving
	 * the rate controller into nonsense — must stay SIGNED max().
	 *
	 * Utility is based on ACHIEVED throughput, not the TARGET rate. On
	 * signal-free flows (no loss, sub-3% latency inflation) the penalty
	 * term is ~0, so util = rate would rise with target rate without
	 * bound -> every flow ramps to u32 wrap. Using throughput makes
	 * utility plateau once the link saturates: pushing target rate
	 * higher no longer raises delivered throughput, the gradient -> 0
	 * and the rate stops climbing. This is the intended Vivace
	 * behaviour. */
	util = throughput -
	       (throughput * (900 * max((s64)0, lat_infl) + 5 * loss_ratio)) /
	       PCC_SCALE;

	pcc_dbg("%d ucalc: rate %lld sent %u delv %lld lost %lld lat (%lld->%lld) util %lld thpt %lld\n",
		pcc->id, rate,
		interval->packets_ended - interval->packets_sent_base,
		delivered, lost, interval->start_rtt / USEC_PER_MSEC,
		interval->end_rtt / USEC_PER_MSEC, util, throughput);
	interval->utility = util;
}

/* Allegro (loss-based) utility. Not selected by default; kept selectable
 * for experiments. Same no-signal guards as vivace. */
static void pcc_calc_utility_allegro(struct pcc_data *pcc,
				     struct pcc_interval *interval,
				     struct sock *sk)
{
	s64 loss_ratio, delivered, lost, mss, rate, throughput, util;
	s64 recv_dur = interval->recv_end - interval->recv_start;

	interval->invalid = false;

	lost = interval->lost;
	delivered = interval->delivered;
	mss = tcp_sk(sk)->mss_cache;
	rate = interval->rate;
	throughput = 0;
	if (recv_dur > 0)
		throughput = (USEC_PER_SEC * delivered * mss) / recv_dur;

	if (!(lost + delivered) ||
	    recv_dur < (s64)pcc_min_recv_us ||
	    delivered < (s64)pcc_min_delivered) {
		interval->utility = 0;
		interval->invalid = true;
		return;
	}

	/* loss rate = lost / all counted * 100 * FACTOR_1 */
	loss_ratio = (lost * PCC_SCALE * PCC_ALPHA) / (lost + delivered);

	/* util = throughput / (1 + e^(100*loss_rate)) - loss_ratio * rate */
	util = loss_ratio - (PCC_LOSS_MARGIN * PCC_SCALE);
	if (util < PCC_MAX_LOSS * PCC_SCALE)
		util = (throughput * PCC_SCALE) / (pcc_exp(util) + PCC_SCALE);
	else
		util = 0;

	/* util *= goodput */
	util *= (PCC_SCALE * PCC_ALPHA) - loss_ratio;
	util /= PCC_SCALE * PCC_ALPHA;
	/* util -= "wasted rate" */
	util -= (rate * loss_ratio) / (PCC_ALPHA * PCC_SCALE);

	pcc_dbg("rate %lld sent %u delv %lld lost %lld util %lld\n",
		rate, interval->packets_ended - interval->packets_sent_base,
		delivered, lost, util);
	interval->utility = util;
}

static enum PCC_DECISION pcc_get_decision(struct pcc_data *pcc, s64 new_rate)
{
	if (pcc->rate == new_rate)
		return PCC_RATE_STAY;

	return pcc->rate < new_rate ? PCC_RATE_UP : PCC_RATE_DOWN;
}

static s64 pcc_decide_rate(struct pcc_data *pcc)
{
	bool run_1_res, run_2_res, did_agree;

	run_1_res = pcc->intervals[0].utility > pcc->intervals[1].utility;
	run_2_res = pcc->intervals[2].utility > pcc->intervals[3].utility;

	/* did_agree: did the two experiment pairs point the same way? */
	did_agree = !((run_1_res == run_2_res) ^
		      (pcc->intervals[0].rate == pcc->intervals[2].rate));

	if (did_agree) {
		if (run_2_res) {
			pcc->last_rate = pcc->intervals[2].rate;
			pcc->intervals[0].utility = pcc->intervals[2].utility;
		} else {
			pcc->last_rate = pcc->intervals[3].rate;
			pcc->intervals[0].utility = pcc->intervals[3].utility;
		}
		return run_2_res ? pcc->intervals[2].rate :
				   pcc->intervals[3].rate;
	} else {
		return pcc->rate;
	}
}

static void pcc_decide(struct pcc_data *pcc, struct sock *sk)
{
	struct pcc_interval *interval;
	s64 new_rate;
	bool no_signal = false;
	int i;

	for (i = 0; i < PCC_INTERVALS; i++) {
		interval = &pcc->intervals[i];
		(*pcc->util_func)(pcc, interval, sk);
		no_signal |= interval->invalid;
	}

	/* Any invalid interval poisons the pairwise comparison (a no-signal
	 * 0 outranks a legitimately negative utility). Hold the current
	 * rate and re-run the probing round instead of acting on it. */
	if (no_signal) {
		pcc_dbg("%d decide: invalid interval(s), re-probing at %lld (%d)\n",
			pcc->id, pcc->rate, pcc->decisions_count);
		pcc_setup_intervals_probing(pcc, sk);
		start_interval(sk, pcc);
		return;
	}

	new_rate = pcc_decide_rate(pcc);
	new_rate = pcc_clamp_rate(sk, new_rate);   /* hard runaway backstop */

	if (new_rate != pcc->rate) {
		pcc_dbg("%d decide: on new rate %d %lld (%d)\n",
			pcc->id, pcc->rate < new_rate, new_rate,
			pcc->decisions_count);
		pcc->moving = true;
		pcc_setup_intervals_moving(pcc);
	} else {
		pcc_dbg("%d decide: stay %lld (%d)\n", pcc->id,
			pcc->rate, pcc->decisions_count);
		pcc_setup_intervals_probing(pcc, sk);
	}

	pcc->rate = new_rate;
	start_interval(sk, pcc);
	pcc->decisions_count++;
}

/* Take larger steps if we keep changing rate in the same direction,
 * otherwise reset to take smaller steps again. */
static void pcc_update_step_params(struct pcc_data *pcc, s64 step)
{
	if ((step > 0) == (pcc->rate > pcc->last_rate)) {
		if (pcc->swing_buffer > 0)
			pcc->swing_buffer--;
		else
			pcc->amplifier++;
	} else {
		pcc->swing_buffer = min(pcc->swing_buffer + 1,
					PCC_MAX_SWING_BUFFER);
		pcc->amplifier = PCC_AMP_MIN;
		pcc->change_bound = PCC_MIN_CHANGE_BOUND;
	}
}

/* Bound any rate change as a proportion of the current rate, so large
 * gradients don't drastically change sending rate. */
static s64 pcc_apply_change_bound(struct pcc_data *pcc, s64 step)
{
	s32 step_sign;
	s64 change_ratio;

	if (pcc->rate == 0)
		return step;

	step_sign = step > 0 ? 1 : -1;
	step *= step_sign;
	change_ratio = (PCC_SCALE * step) / pcc->rate;

	if (change_ratio > pcc->change_bound) {
		step = (pcc->rate * pcc->change_bound) / PCC_SCALE;
		pcc_dbg("bound %d rate %lld step %lld\n",
			pcc->change_bound, pcc->rate, step);
		pcc->change_bound += PCC_CHANGE_BOUND_STEP;
	} else {
		pcc->change_bound = PCC_MIN_CHANGE_BOUND;
	}
	return step_sign * step;
}

/* Choose up/down rate changes based on the utility gradient. The caller has
 * already recomputed intervals[0].utility and verified it is valid. */
static s64 pcc_decide_rate_moving(struct sock *sk, struct pcc_data *pcc,
				  s64 prev_utility)
{
	struct pcc_interval *interval = &pcc->intervals[0];
	s64 utility = interval->utility;
	s64 grad, step, min_step;

	pcc_dbg("%d mv: pr %lld pu %lld nr %lld nu %lld\n",
		pcc->id, pcc->last_rate, prev_utility, pcc->rate, utility);

	grad = pcc_calc_util_grad(pcc->rate, utility,
				  pcc->last_rate, prev_utility);

	step = grad * PCC_GRAD_STEP_SIZE;	/* gradient ascent */
	pcc_update_step_params(pcc, step);	/* accelerate/decelerate */
	step *= pcc->amplifier;
	step /= PCC_SCALE;
	step = pcc_apply_change_bound(pcc, step);

	/* Step must be large enough to compute the next gradient with low
	 * noise. */
	min_step = (pcc->rate * PCC_MIN_RATE_DIFF_RATIO_FOR_GRAD) / PCC_SCALE;
	min_step *= 11;			/* slightly above the minimum */
	min_step /= 10;
	if (step >= 0 && step < min_step)
		step = min_step;
	else if (step < 0 && step > -1 * min_step)
		step = -1 * min_step;

	pcc_dbg("%d mv: grad %lld step %lld amp %d min_step %lld\n",
		pcc->id, grad, step, pcc->amplifier, min_step);

	return pcc->rate + step;
}

/* Choose a new direction and update state from the moving state. */
static void pcc_decide_moving(struct sock *sk, struct pcc_data *pcc)
{
	struct pcc_interval *interval = &pcc->intervals[0];
	enum PCC_DECISION decision, last_decision;
	s64 new_rate, packet_min_rate;
	s64 prev_utility = interval->utility;

	(*pcc->util_func)(pcc, interval, sk);

	/* No usable signal: restore the gradient memory and re-run this
	 * move interval at the same rate rather than stepping on noise. */
	if (interval->invalid) {
		interval->utility = prev_utility;
		pcc_dbg("%d moving: invalid interval, re-running at %lld\n",
			pcc->id, pcc->rate);
		pcc_setup_intervals_moving(pcc);
		start_interval(sk, pcc);
		return;
	}

	new_rate = pcc_decide_rate_moving(sk, pcc, prev_utility);
	packet_min_rate = (USEC_PER_SEC * PCC_RATE_MIN_PACKETS_PER_RTT *
			   tcp_sk(sk)->mss_cache) / pcc_get_rtt(tcp_sk(sk));
	new_rate = max(new_rate, packet_min_rate);
	new_rate = pcc_clamp_rate(sk, new_rate);   /* hard runaway backstop */

	/* Decide the direction from the FINAL rate. Deriving it before the
	 * packet floor and the clamp meant a move clamped back onto the
	 * current rate was still recorded as UP or DOWN, so the
	 * direction-reversal test below compared against a move that never
	 * happened. A clamped move now yields PCC_RATE_STAY, which differs
	 * from any previous direction and sends the flow back to probing —
	 * the right response when it is pinned at the ceiling. */
	decision = pcc_get_decision(pcc, new_rate);
	last_decision = pcc->last_decision;
	pcc->last_rate = pcc->rate;
	pcc_dbg("%d moving: new rate %lld (%d) old rate %lld\n",
		pcc->id, new_rate, pcc->decisions_count, pcc->last_rate);
	pcc->rate = new_rate;
	pcc->last_decision = decision;
	if (decision != last_decision) {
#ifdef USE_PROBING
		pcc->moving = false;
		pcc_setup_intervals_probing(pcc, sk);
#else
		pcc_setup_intervals_moving(pcc);
#endif
	} else {
		pcc_setup_intervals_moving(pcc);
	}

	start_interval(sk, pcc);
}

/* Grow the target rate each interval until link utility stops increasing
 * accordingly. Then revert to the pre-overshoot rate and switch to the
 * gradient-ascent moving stage. */
static void pcc_decide_slow_start(struct sock *sk, struct pcc_data *pcc)
{
	struct pcc_interval *interval = &pcc->intervals[0];
	s64 utility, prev_utility, tmp_rate, grow;

	grow = ((s64)pcc->rate * pcc_ss_growth_pct) / 100;
	if (grow < PCC_RATE_MIN)
		grow = PCC_RATE_MIN;

	/* If the rate has already reached the clamp ceiling, slow start's
	 * growth has nowhere to go. Without this, a flow whose (possibly
	 * noisy) utility keeps "increasing" would stay in slow start
	 * forever pinned at the cap. Exit to the moving/probing stage. */
	if (pcc->rate >= pcc_clamp_rate(sk, pcc->rate + grow)) {
		pcc->last_rate = pcc->rate;
		pcc->start_mode = false;
		pcc_dbg("%d: start mode ended (rate capped)\n", pcc->id);
#ifdef USE_PROBING
		pcc_setup_intervals_probing(pcc, sk);
#else
		pcc->moving = true;
		pcc_setup_intervals_moving(pcc);
#endif
		start_interval(sk, pcc);
		return;
	}

	prev_utility = interval->utility;
	(*pcc->util_func)(pcc, interval, sk);
	utility = interval->utility;

	/* No usable signal: repeat the interval at the same rate. Neither
	 * growing on noise nor exiting slow start on noise is acceptable. */
	if (interval->invalid) {
		interval->utility = prev_utility;
		pcc_dbg("%d: start mode: invalid interval, repeating\n",
			pcc->id);
		interval->rate = pcc->rate;
		pcc->send_index = 0;
		pcc->receive_index = 0;
		pcc->wait = false;
		start_interval(sk, pcc);
		return;
	}

	pcc_dbg("%d: start mode: r %lld u %lld pr %lld pu %lld\n",
		pcc->id, pcc->rate, utility, pcc->last_rate, prev_utility);

	if (utility > prev_utility) {
		pcc->last_rate = pcc->rate;
		pcc->rate += grow;
		pcc->rate = pcc_clamp_rate(sk, pcc->rate); /* no compounding
							      past the cap */
		interval->utility = utility;
		interval->rate = pcc->rate;
		pcc->send_index = 0;
		pcc->receive_index = 0;
		pcc->wait = false;
	} else {
		/* Utility fell: the last growth step overshot. Revert to
		 * the pre-overshoot rate and hand over to gradient ascent. */
		tmp_rate = pcc->last_rate;
		pcc->last_rate = pcc->rate;
		pcc->rate = tmp_rate;
		pcc->start_mode = false;
		pcc_dbg("%d: start mode ended\n", pcc->id);
#ifdef USE_PROBING
		pcc_setup_intervals_probing(pcc, sk);
#else
		pcc->moving = true;
		pcc_setup_intervals_moving(pcc);
#endif
	}
	start_interval(sk, pcc);
}

/* ------------------------------------------------------------------------- *
 * Interval lifecycle from ack/loss samples
 * ------------------------------------------------------------------------- */

/* Have we sent all the data we need for this interval? Must have at least
 * the minimum number of packets and have spanned roughly one RTT. */
static bool send_interval_ended(struct pcc_interval *interval,
				struct tcp_sock *tp, struct pcc_data *pcc)
{
	u32 packets_sent = tp->data_segs_out - interval->packets_sent_base;

	if (packets_sent < PCC_INTERVAL_MIN_PACKETS)
		return false;

	/* wraparound-safe: these are u32 counters, not bounded quantities */
	if (pcc_after(pcc->packets_counted, interval->packets_sent_base)) {
		interval->packets_ended = tp->data_segs_out;
		return true;
	}
	return false;
}

/* Have we accounted (acked or lost) enough of the packets we sent to
 * compute summary statistics? */
static bool receive_interval_ended(struct pcc_interval *interval,
				   struct tcp_sock *tp, struct pcc_data *pcc)
{
	return interval->packets_ended &&
	       pcc_before(interval->packets_ended - PCC_IGNORE_PACKETS,
			  pcc->packets_counted);
}

/* Start the next interval's sending stage. If no further interval is
 * scheduled (probing round complete, or in slow start / moving), hold the
 * current rate while waiting for acks. */
static void start_next_send_interval(struct sock *sk, struct pcc_data *pcc)
{
	pcc->send_index++;
	if (pcc->send_index == PCC_INTERVALS || pcc->start_mode || pcc->moving)
		pcc->wait = true;

	start_interval(sk, pcc);
}

/* Update the receiving time window and the packets lost/delivered counters
 * from socket statistics. */
static void pcc_update_interval(struct pcc_interval *interval,
				struct pcc_data *pcc, struct sock *sk)
{
	interval->recv_end = tcp_sk(sk)->tcp_mstamp;
	interval->end_rtt = tcp_sk(sk)->srtt_us >> 3;
	if (interval->lost + interval->delivered == 0) {
		interval->recv_start = tcp_sk(sk)->tcp_mstamp;
		interval->start_rtt = tcp_sk(sk)->srtt_us >> 3;
	}

	interval->lost += tcp_sk(sk)->lost - pcc->lost_base;
	interval->delivered += tcp_sk(sk)->delivered - pcc->delivered_base;
}

/* Update the PCC model: advance send/receive intervals, and when a full
 * measurement completes, run the appropriate decision stage. */
static void pcc_process(struct sock *sk)
{
	struct pcc_data *pcc = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct pcc_interval *interval;
	int index;
	u32 prev_counted;	/* was 'before', which shadowed the kernel's
				 * before() helper from <net/tcp.h> */

	if (!pcc_valid(pcc))
		return;

	pcc_set_cwnd(sk);
	if (pcc->loss_state)
		goto end;
	if (!pcc->wait) {
		interval = &pcc->intervals[pcc->send_index];
		if (send_interval_ended(interval, tp, pcc)) {
			interval->send_end = tp->tcp_mstamp;
			start_next_send_interval(sk, pcc);
		}
	}

	index = pcc->receive_index;
	interval = &pcc->intervals[index];
	prev_counted = pcc->packets_counted;
	pcc->packets_counted = tp->delivered + tp->lost - pcc->spare;

	if (!interval->packets_sent_base)
		goto end;

	if (pcc_after(prev_counted,
		      interval->packets_sent_base + PCC_IGNORE_PACKETS))
		pcc_update_interval(interval, pcc, sk);

	if (receive_interval_ended(interval, tp, pcc)) {
		pcc->receive_index++;
		if (pcc->start_mode)
			pcc_decide_slow_start(sk, pcc);
		else if (pcc->moving)
			pcc_decide_moving(sk, pcc);
		else if (pcc->receive_index == PCC_INTERVALS)
			pcc_decide(pcc, sk);
	}

end:
	pcc->lost_base = tp->lost;
	pcc->delivered_base = tp->delivered;
}

#ifdef PCC_CONG_CONTROL_ACK_FLAG
static void pcc_process_sample(struct sock *sk, u32 ack, int flag,
			       const struct rate_sample *rs)
#else
static void pcc_process_sample(struct sock *sk, const struct rate_sample *rs)
#endif
{
	pcc_process(sk);
}

/* ------------------------------------------------------------------------- *
 * Congestion-ops hooks
 * ------------------------------------------------------------------------- */

static void pcc_init(struct sock *sk)
{
	struct pcc_data *pcc = inet_csk_ca(sk);

	/* MUST be atomic: for passive opens (every inbound proxy
	 * connection) this runs in softirq context, where GFP_KERNEL can
	 * sleep -> "scheduling while atomic". On the rare allocation
	 * failure the flow degrades gracefully: pcc_valid() fails, no
	 * pacing/cwnd updates are made, and the connection limps along at
	 * its initial window rather than crashing the box. */
	pcc->intervals = kcalloc(PCC_INTERVALS, sizeof(*pcc->intervals),
				 GFP_ATOMIC | __GFP_NOWARN);
	if (!pcc->intervals) {
		printk_ratelimited(KERN_WARNING
				   "tcp_pcc: interval alloc failed, flow degraded\n");
		return;
	}

	pcc->id = atomic_inc_return(&pcc_flow_id);
	pcc->amplifier = PCC_AMP_MIN;
	pcc->swing_buffer = 0;
	pcc->change_bound = PCC_MIN_CHANGE_BOUND;
	pcc->rate = PCC_RATE_MIN * 512;		/* ~4 Mbit/s initial */
	pcc->last_rate = PCC_RATE_MIN * 512;
	tcp_sk(sk)->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	pcc->start_mode = true;
	pcc->moving = false;
	pcc->intervals[0].utility = S64_MIN;

	pcc->util_func = &pcc_calc_utility_vivace;
	/* pcc->util_func = &pcc_calc_utility_allegro; */

	pcc_setup_intervals_probing(pcc, sk);
	start_interval(sk, pcc);
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
}

static void pcc_release(struct sock *sk)
{
	struct pcc_data *pcc = inet_csk_ca(sk);

	kfree(pcc->intervals);
	pcc->intervals = NULL;
}

/* PCC does not always reduce cwnd on losses, so there is nothing to undo. */
static u32 pcc_undo_cwnd(struct sock *sk)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
	return tcp_snd_cwnd(tcp_sk(sk));
#else
	return tcp_sk(sk)->snd_cwnd;
#endif
}

static u32 pcc_ssthresh(struct sock *sk)
{
	return TCP_INFINITE_SSTHRESH; /* PCC does not use ssthresh */
}

/* Suspend interval accounting while the stack is in loss recovery
 * (TCP_CA_Loss): retransmissions make delivered/lost counters unusable for
 * interval attribution. On exit, fold the packets that raced the recovery
 * window into the 'spare' adjustment and restart probing cleanly. */
static void pcc_set_state(struct sock *sk, u8 new_state)
{
	struct pcc_data *pcc = inet_csk_ca(sk);
	s32 spare;

	if (!pcc_valid(pcc))
		return;

	if (pcc->loss_state && new_state != TCP_CA_Loss) {
		spare = tcp_sk(sk)->delivered + tcp_sk(sk)->lost +
			tcp_packets_in_flight(tcp_sk(sk));
		spare -= tcp_sk(sk)->data_segs_out;
		spare -= pcc->spare;
		pcc->spare += spare;
		pcc_dbg("%d loss ended: spare %d\n", pcc->id, spare);

		pcc->loss_state = false;
		pcc_setup_intervals_probing(pcc, sk);
		start_interval(sk, pcc);
	} else if (!pcc->loss_state && new_state == TCP_CA_Loss) {
		pcc_dbg("%d loss: started\n", pcc->id);
		pcc->loss_state = true;
		pcc->wait = true;
		start_interval(sk, pcc);
	}
}

static struct tcp_congestion_ops tcp_pcc_cong_ops __read_mostly = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "pcc",
	.owner		= THIS_MODULE,
	.init		= pcc_init,
	.release	= pcc_release,
	.cong_control	= pcc_process_sample,
	.undo_cwnd	= pcc_undo_cwnd,
	.ssthresh	= pcc_ssthresh,
	.set_state	= pcc_set_state,
};

/* ------------------------------------------------------------------------- *
 * Module registration
 * ------------------------------------------------------------------------- */

static int __init pcc_register(void)
{
	BUILD_BUG_ON(sizeof(struct pcc_data) > ICSK_CA_PRIV_SIZE);
	pr_info("tcp_pcc: registering PCC Vivace v2.1 (hardened)\n");
	return tcp_register_congestion_control(&tcp_pcc_cong_ops);
}

static void __exit pcc_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_pcc_cong_ops);
}

module_init(pcc_register);
module_exit(pcc_unregister);

MODULE_AUTHOR("Tomer Gilad <tomer.gilad1@mail.huji.ac.il>");
MODULE_AUTHOR("Nathan Jay <njay2@illinois.edu>");
MODULE_AUTHOR("Nogah Frankel <nogah.frankel@gmail.com>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP PCC (Performance-oriented Congestion Control), hardened");
MODULE_VERSION("2.1");
