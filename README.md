# PCC Vivace (hardened) for Linux — build, load and run guide

A hardened build of the **PCC Vivace** TCP congestion-control kernel module (`tcp_pcc.c`), plus **`pcc-deploy.sh`**, a menu/CLI script that builds, loads, persists and tunes it on a live server. It is derived from [PCCproject/PCC-Kernel](https://github.com/PCCproject/PCC-Kernel) (the `vivace` branch) and aimed at proxy / VPN nodes (Xray, HAProxy, WireGuard) that carry many long-lived and short-lived TCP flows.

Everything you need is in [`src/`](src/):

| File | What it is |
|---|---|
| [`src/tcp_pcc.c`](src/tcp_pcc.c) | The kernel module (registers a congestion-control algorithm named `pcc`) |
| [`src/Makefile`](src/Makefile) | Standard out-of-tree kbuild Makefile |
| [`src/pcc-deploy.sh`](src/pcc-deploy.sh) | Build / load / persist / tune / unload helper |

> **Status:** v2.1. Use on a test node first. Loading a congestion-control module and changing the system default affects every new TCP connection on the machine.

## What is different from upstream (v2.1)

- Builds on Linux **6.10+** (the `.cong_control` prototype changed; handled with a version shim).
- Packet-counter comparisons are **wraparound-safe** (the 32-bit counters wrap after roughly 14 hours at 1 Gbit/s).
- An **absolute rate ceiling** (`pcc_max_rate_mbit`) is applied to every pacing-rate write, including the probing rates.
- Intervals with no usable signal are flagged invalid and re-run, instead of being scored as utility 0.
- Memory for each flow is allocated with `GFP_ATOMIC` (safe in softirq context for inbound connections).
- Debug logging is behind a switch (`pcc_debug`, off by default) so it cannot flood the journal.
- The full changelog is in the header comment of [`src/tcp_pcc.c`](src/tcp_pcc.c).

**Limits:** 64-bit kernels only. The module targets kernels 4.14 through 6.x.

## Requirements

- Linux, **64-bit**, with the headers for the **running** kernel (the script installs them on Debian/Ubuntu via `apt` and on Fedora/RHEL via `dnf`).
- `root` (use `sudo`).
- Recommended: `dkms` (so the module is rebuilt automatically after kernel upgrades) and `iproute2` (`tc`, `ip`, `ss`).
- Recommended: the `bbr` algorithm available on the host. The script uses it as the fallback congestion control. Check with `sysctl net.ipv4.tcp_available_congestion_control`.

## Quick start

```bash
git clone -b hardened-v2.1 https://github.com/raishiv98/PCC-Kernel.git
cd PCC-Kernel/src
chmod +x pcc-deploy.sh

sudo ./pcc-deploy.sh build     # install prerequisites and compile tcp_pcc.ko
sudo ./pcc-deploy.sh load      # insert the module (restores your previous default CC)
sudo ./pcc-deploy.sh status    # confirm it is loaded and see the overall state
```

Run `./pcc-deploy.sh` with no arguments to get a numbered menu instead. Every action works by number or by name. Set `SKIP_PREREQS=1` to skip the `apt`/`dnf` step when you already have the toolchain and headers.

After `load` you should see this in the kernel log and `pcc` in the list of available algorithms:

```bash
sudo dmesg | tail -n 5          # tcp_pcc: registering PCC Vivace v2.1 (hardened)
cat /proc/sys/net/ipv4/tcp_available_congestion_control
```

## Using PCC

### Per application (safest)

Loading the module does **not** change the system default. A program opts in per socket:

```python
import socket
s = socket.socket()
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, b"pcc")
```

Check that connections really use it:

```bash
ss -tin | grep -w pcc
```

### As the system default

```bash
sudo ./pcc-deploy.sh default     # asks you to type "yes", applies until reboot
```

To make it survive a reboot:

```bash
sudo ./pcc-deploy.sh persist                  # module auto-loads at boot, default unchanged
sudo ./pcc-deploy.sh persist --with-default   # ...and pcc becomes the default CC at boot
```

`persist` also writes a **fallback** sysctl file that sets `bbr` first. If the module is ever missing at boot (for example after a kernel upgrade without DKMS), the `pcc` line fails and the system stays on `bbr` instead of silently dropping to `cubic`. With `dkms` installed, `persist` registers the module as `tcp_pcc/2.1` so it is rebuilt for new kernels. Without it the script falls back to a plain copy that does **not** survive a kernel upgrade, and warns you.

## Tuning (optional)

```bash
sudo ./pcc-deploy.sh tune          # sysctl profile for pcc + proxies, with rp_filter=2
sudo ./pcc-deploy.sh tune-norp     # same profile, rp_filter left untouched
sudo ./pcc-deploy.sh revert-tune   # put the pre-tune values back
```

`tune` writes `/etc/sysctl.d/99-zz-tcp_pcc-tune.conf` scaled to the machine's RAM and CPU count (socket buffers, backlog queues, connection-churn settings, keepalives, file-descriptor and conntrack limits) and sets `fq` as the root qdisc on the default-route interface(s), because PCC relies on pacing. The first run snapshots the old values so `revert-tune` can restore them. **Read the generated file before using it on a production server**; it changes many sysctls. If your service runs behind systemd, also raise `LimitNOFILE` in its unit so the higher file limits take effect.

Use `tune-norp` if you do not need loose reverse-path filtering (`rp_filter=2` is meant for asymmetric multi-interface setups such as WireGuard egress).

## Module parameters

Set at runtime (takes effect immediately for new decisions):

```bash
echo 2000 | sudo tee /sys/module/tcp_pcc/parameters/pcc_max_rate_mbit
```

| Parameter | Default | Meaning |
|---|---|---|
| `pcc_max_rate_mbit` | 1000 | Absolute runaway ceiling on the internal rate, in Mbit/s. Set it **well above your real link speed**; if it sits at link rate the clamp becomes the controller. `0` disables it. |
| `pcc_min_recv_us` | 1000 | Minimum interval receive time (µs) for a throughput measurement to be trusted |
| `pcc_min_delivered` | 3 | Minimum delivered packets for an interval to count |
| `pcc_ss_growth_pct` | 100 | Slow-start growth per interval as a percent of the current rate (100 = doubling, 50 = gentler) |
| `pcc_debug` | 0 | Set to 1 for per-interval debug logging in the kernel log |

`./pcc-deploy.sh params` shows the current values and can write them to `/etc/modprobe.d/tcp_pcc.conf`. That file applies when the module is loaded with `modprobe` at boot, not to the script's own `load` (which uses `insmod`), so after a manual reload set the values again at runtime.

## Reloading after you change the code

```bash
cd PCC-Kernel/src
sudo ./pcc-deploy.sh build
sudo ./pcc-deploy.sh load      # drains, unloads the old module, inserts the new one
```

`load` switches the default to `bbr` while it drains, waits for the module's reference count to reach zero, then restores the default you had before. If connections are still holding the module it **refuses to force** the unload; restart the service that owns those sockets (for example Xray or HAProxy) and run `load` again.

## Removing it

```bash
sudo ./pcc-deploy.sh unload       # drain, then rmmod
sudo ./pcc-deploy.sh uninstall    # remove the module and all persisted PCC config (asks first)
sudo ./pcc-deploy.sh revert-tune  # separately, undo the sysctl tuning
```

`uninstall` leaves your source folder alone and leaves the system default on `bbr`. It does not undo `tune`; use `revert-tune` for that. A live `fq` qdisc is not reverted either; reset it yourself if you want, for example `tc qdisc replace dev <if> root fq_codel`.

## Troubleshooting

| Symptom | What to check |
|---|---|
| "headers for … still missing" | Install headers for the **running** kernel, or reboot into the newest installed kernel, then run `build` again |
| Build error about `cong_control` on a new kernel | Make sure you are on the `hardened-v2.1` branch; 6.10+ is handled there, upstream is not |
| `insmod failed` / `pcc` not listed | Read `sudo dmesg \| tail`; an existing module of the same name may be loaded |
| `status` shows a live qdisc that is **not fq** | Run `tune` (or `tc qdisc replace dev <if> root fq`). Without `fq`, pacing falls back to a per-socket hrtimer, which costs CPU at high concurrency |
| Rate looks capped | Raise `pcc_max_rate_mbit` above your link speed |
| Module gone after a kernel update | You are not using DKMS. Install `dkms` and run `persist` again |

## License and credits

Dual BSD/GPL, as declared in [`src/tcp_pcc.c`](src/tcp_pcc.c) (`MODULE_LICENSE`); the upstream [LICENSE](LICENSE) is included. Based on PCC-Kernel by Tomer Gilad, Nathan Jay and Nogah Frankel. Algorithm: Dong et al., *PCC Vivace: Online-Learning Congestion Control*, NSDI '18.
