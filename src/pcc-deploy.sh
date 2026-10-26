#!/usr/bin/env bash
#
# pcc-deploy.sh v2.1 — build, load and manage the (patched) PCC congestion-
# control module safely on a live node.
#
# Unlike the upstream auto_load installer, this script:
#   * never forces pcc as the system default without an explicit, confirmed step
#   * drains on the MODULE REFCOUNT, which is authoritative, not on ss output
#   * restores the previous default CC after a reload (v2.1)
#   * prefers DKMS so a kernel upgrade does not silently drop you to cubic (v2.1)
#   * writes an explicit fallback CC so a missing module lands on bbr, not cubic
#   * applies fq to live interfaces, not just net.core.default_qdisc (v2.1)
#   * never deletes your source tree
#   * keeps every destructive action behind its own subcommand
#
# Usage (interactive):
#   ./pcc-deploy.sh                    # numbered menu
#
# Usage (direct — number or name both work):
#   ./pcc-deploy.sh 1  | build         # ensure prereqs + compile ./tcp_pcc.ko
#   ./pcc-deploy.sh 2  | load          # (re)load the locally-built module
#   ./pcc-deploy.sh 3  | status        # show module/socket/qdisc/default state
#   ./pcc-deploy.sh 4  | default       # set pcc as system default (asks first)
#   ./pcc-deploy.sh 5  | persist       # survive reboot (DKMS if available)
#   ./pcc-deploy.sh 6  | tune          # sysctl tuning for pcc + xray (rp_filter=2)
#   ./pcc-deploy.sh 7  | tune-norp     # same tuning but rp_filter left untouched
#   ./pcc-deploy.sh 8  | revert-tune   # restore pre-tune sysctl values
#   ./pcc-deploy.sh 9  | unload        # drain then rmmod
#   ./pcc-deploy.sh 10 | uninstall     # remove module + all persisted config
#   ./pcc-deploy.sh 11 | params        # show / persist module parameters
#
# Most subcommands need root. Set SKIP_PREREQS=1 to skip the apt step.

set -uo pipefail

# ---- configuration ---------------------------------------------------------
MODULE_NAME="tcp_pcc"        # module file name (tcp_pcc.ko)
MODULE_VERSION="2.1"         # must match MODULE_VERSION() in tcp_pcc.c (DKMS)
CC_NAME="pcc"                # congestion-control name as seen by sysctl
FALLBACK_CC="bbr"            # what to fall back to when draining/unloading
SRC_DIR="${SRC_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
KO="${SRC_DIR}/${MODULE_NAME}.ko"
KVER="$(uname -r)"
TREE_KO="/lib/modules/${KVER}/kernel/drivers/net/${MODULE_NAME}.ko"
AUTOLOAD_CONF="/etc/modules-load.d/${MODULE_NAME}.conf"
MODPROBE_CONF="/etc/modprobe.d/${MODULE_NAME}.conf"

# sysctl file ordering matters. systemd-sysctl applies /etc/sysctl.d/* in
# lexical order, last write wins:
#   10-...-fallback  -> bbr   (applies first, always succeeds)
#   99-...           -> pcc   (overrides it, but only if the module loaded)
#   99-zz-...-tune   -> everything else
# If the module is missing after a kernel upgrade, the pcc line fails and the
# fallback value survives. Without the fallback file the system lands on
# cubic, silently, on every socket.
FALLBACK_CONF="/etc/sysctl.d/10-${MODULE_NAME}-fallback.conf"
SYSCTL_CONF="/etc/sysctl.d/99-${MODULE_NAME}.conf"
TUNE_CONF="/etc/sysctl.d/99-zz-${MODULE_NAME}-tune.conf"
# Debian/Ubuntu ship /etc/sysctl.d/99-sysctl.conf (a symlink to
# /etc/sysctl.conf), which loads AFTER anything numbered 98. The tune profile
# used to live there, so a distro rp_filter=1 would silently override ours at
# boot — which breaks asymmetric WireGuard egress in a way that looks like a
# routing bug. Hence 99-zz-. The old path is kept only for cleanup.
TUNE_CONF_LEGACY="/etc/sysctl.d/98-${MODULE_NAME}-tune.conf"

STATE_DIR="/var/lib/pcc-deploy"
TUNE_BACKUP="${STATE_DIR}/sysctl-pre-tune.conf"
PREV_CC_FILE="${STATE_DIR}/previous-default-cc"
DRAIN_TIMEOUT="${DRAIN_TIMEOUT:-60}"   # seconds to wait for sockets to close
SKIP_PREREQS="${SKIP_PREREQS:-0}"      # 1 = skip apt update/install step

# ---- helpers ---------------------------------------------------------------
log()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        err "this action needs root — re-run with sudo"
        exit 1
    fi
}

# Install prerequisites before proceeding. Runs at most once per invocation.
# Only build/load call this — 'default', 'persist' and 'status' have no
# business running apt-get update on a production node.
PREREQS_DONE=0
ensure_prereqs() {
    [ "${SKIP_PREREQS}" = "1" ] && return 0
    [ "${PREREQS_DONE}" -eq 1 ] && return 0
    need_root

    if command -v apt-get >/dev/null 2>&1; then
        log "prerequisites: apt update + build-essential + linux-headers-${KVER}"
        apt-get update || { err "apt update failed"; exit 1; }
        apt-get install -y build-essential "linux-headers-${KVER}" \
            || { err "prerequisite install failed"; exit 1; }
    elif command -v dnf >/dev/null 2>&1; then
        log "prerequisites: dnf gcc/make + kernel-devel-${KVER}"
        dnf install -y gcc make "kernel-devel-${KVER}" "kernel-headers-${KVER}" \
            || { err "prerequisite install failed"; exit 1; }
    else
        warn "no apt/dnf found — ensure gcc, make and headers for ${KVER} exist"
    fi

    PREREQS_DONE=1
    ok "prerequisites ready"
}

module_loaded() { lsmod | awk '{print $1}' | grep -qx "${MODULE_NAME}"; }

# Third column of lsmod = "used by" count. This is the authoritative answer to
# "is anything still holding this module", and it is exactly what rmmod
# checks. Prints 0 when not loaded so callers can compare numerically.
module_refcount() {
    local rc
    rc="$(lsmod | awk -v m="${MODULE_NAME}" '$1==m {print $3}')"
    echo "${rc:-0}"
}

# Display only. ss output is line-wrapped and state-filtered, so it
# undercounts — sockets in fin-wait etc. still pin the module. Never gate an
# rmmod on this number; that is what module_refcount is for.
pcc_socket_count() {
    ss -tin state established 2>/dev/null | grep -cw "${CC_NAME}" || true
}

cc_available() {
    grep -qw "${CC_NAME}" /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null
}

current_default_cc() { cat /proc/sys/net/ipv4/tcp_congestion_control; }

default_route_ifaces() {
    ip -4 route show default 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | sort -u
}

have_dkms() { command -v dkms >/dev/null 2>&1; }

# ---- subcommands -----------------------------------------------------------
cmd_build() {
    need_root
    ensure_prereqs

    if [ ! -d "/lib/modules/${KVER}/build" ]; then
        err "headers for ${KVER} still missing after prereq install"
        err "installed headers may target a newer kernel — reboot into it first"
        exit 1
    fi
    ok "kernel headers present"

    if [ ! -f "${SRC_DIR}/Makefile" ]; then
        err "no Makefile in ${SRC_DIR} — point SRC_DIR at your PCC source dir"
        exit 1
    fi

    log "compiling in ${SRC_DIR}"
    make -C "${SRC_DIR}" || { err "build failed"; exit 1; }
    [ -f "${KO}" ] || { err "build produced no ${MODULE_NAME}.ko"; exit 1; }
    ok "built ${KO}"
}

# Move new sockets off pcc and wait for the module refcount to reach zero.
drain() {
    local elapsed=0 rc n
    log "setting default CC to ${FALLBACK_CC} so no new sockets pick ${CC_NAME}"
    sysctl -w "net.ipv4.tcp_congestion_control=${FALLBACK_CC}" >/dev/null

    rc="$(module_refcount)"
    if [ "${rc}" -eq 0 ]; then ok "nothing holds ${MODULE_NAME}"; return 0; fi

    n="$(pcc_socket_count)"
    warn "${rc} reference(s) still on ${MODULE_NAME} (~${n} established sockets)"
    warn "these connections must close (or be restarted) before unload:"
    ss -tinp state established 2>/dev/null | grep -w "${CC_NAME}" | head || true

    while [ "${elapsed}" -lt "${DRAIN_TIMEOUT}" ]; do
        rc="$(module_refcount)"
        if [ "${rc}" -eq 0 ]; then
            printf '\n'; ok "all ${CC_NAME} references released"; return 0
        fi
        sleep 2; elapsed=$((elapsed + 2))
        printf '\r    %ss elapsed, refcount %s ' "${elapsed}" "${rc}"
    done
    printf '\n'
    warn "timeout: refcount still ${rc}."
    warn "restart the owning service (e.g. xray/haproxy) to release it,"
    warn "then re-run. Refusing to force rmmod on a busy module."
    return 1
}

cmd_load() {
    need_root
    ensure_prereqs
    [ -f "${KO}" ] || { err "no ${KO}; run build (1) first"; exit 1; }

    # Remember the default CC BEFORE drain() rewrites it. Without this, every
    # reload silently leaves the node on ${FALLBACK_CC} while the script
    # reports success, and new connections quietly stop using pcc.
    local prev_cc; prev_cc="$(current_default_cc)"
    mkdir -p "${STATE_DIR}"
    echo "${prev_cc}" > "${PREV_CC_FILE}"
    log "current default CC is '${prev_cc}' — will restore it after reload"

    if module_loaded; then
        local rc; rc="$(module_refcount)"
        log "${MODULE_NAME} already loaded (used by ${rc})"
        if [ "${rc}" -ne 0 ]; then
            drain || exit 1
        fi
        log "removing old in-memory module"
        rmmod "${MODULE_NAME}" || { err "rmmod failed"; exit 1; }
    fi

    log "inserting ${KO}"
    insmod "${KO}" || { err "insmod failed"; exit 1; }

    if cc_available; then
        ok "${CC_NAME} loaded and available"
    else
        err "${CC_NAME} not in tcp_available_congestion_control — check dmesg"
        exit 1
    fi

    # Restore whatever the default was before we touched it.
    if [ "${prev_cc}" != "$(current_default_cc)" ]; then
        if grep -qw "${prev_cc}" /proc/sys/net/ipv4/tcp_available_congestion_control; then
            sysctl -w "net.ipv4.tcp_congestion_control=${prev_cc}" >/dev/null
            ok "restored previous default CC: ${prev_cc}"
        else
            warn "previous default '${prev_cc}' is no longer available;"
            warn "default left at $(current_default_cc)"
        fi
    fi
    rm -f "${PREV_CC_FILE}"
}

cmd_status() {
    local ifaces i qd p
    echo "module file   : ${KO} $( [ -f "${KO}" ] && echo '(present)' || echo '(MISSING)')"
    if module_loaded; then
        echo "loaded        : yes (used by $(module_refcount))"
    else
        echo "loaded        : no"
    fi
    echo "available CCs : $(cat /proc/sys/net/ipv4/tcp_available_congestion_control)"
    echo "system default: $(current_default_cc)"
    echo "${CC_NAME} sockets   : $(pcc_socket_count) established (display only)"

    # net.core.default_qdisc applies to qdiscs created AFTER it is set. A
    # running interface keeps whatever it had, and pcc then falls back to
    # TCP's internal per-socket hrtimer pacing — which works, but costs one
    # high-resolution timer per socket. At high concurrency that is real
    # softirq time you would never see in the sysctl output alone.
    echo "default qdisc : $(cat /proc/sys/net/core/default_qdisc 2>/dev/null) (sysctl setting)"
    ifaces="$(default_route_ifaces)"
    if [ -n "${ifaces}" ] && command -v tc >/dev/null 2>&1; then
        for i in ${ifaces}; do
            qd="$(tc qdisc show dev "${i}" 2>/dev/null | head -1 | awk '{print $2}')"
            if [ "${qd}" = "fq" ]; then
                echo "    ${i} live  : ${qd}"
            else
                echo "    ${i} live  : ${qd:-unknown}  <-- NOT fq; pcc is pacing via hrtimer"
            fi
        done
    else
        echo "    live qdisc: (tc unavailable — install iproute2)"
    fi

    echo "rp_filter     : all=$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null) default=$(cat /proc/sys/net/ipv4/conf/default/rp_filter 2>/dev/null)"

    if [ -d "/sys/module/${MODULE_NAME}/parameters" ]; then
        echo "module params :"
        for p in /sys/module/"${MODULE_NAME}"/parameters/*; do
            [ -e "${p}" ] || continue
            printf '    %-18s = %s\n' "$(basename "${p}")" "$(cat "${p}" 2>/dev/null)"
        done
    fi

    echo "persisted     :"
    if have_dkms && dkms status 2>/dev/null | grep -q "^${MODULE_NAME}"; then
        echo "    dkms      : $(dkms status 2>/dev/null | grep "^${MODULE_NAME}" | tr '\n' ' ')"
    else
        echo "    dkms      : not registered (kernel upgrade will drop the module)"
    fi
    echo "    tree .ko  : $( [ -f "${TREE_KO}" ] && echo present || echo absent )"
    echo "    autoload  : $( [ -f "${AUTOLOAD_CONF}" ] && echo present || echo absent )"
    echo "    modprobe  : $( [ -f "${MODPROBE_CONF}" ] && echo present || echo absent )"
    echo "    fallback  : $( [ -f "${FALLBACK_CONF}" ] && echo "present (${FALLBACK_CC})" || echo 'ABSENT — a missing module would fall back to cubic' )"
    echo "    cc sysctl : $( [ -f "${SYSCTL_CONF}" ] && echo present || echo absent )"
    if [ -f "${TUNE_CONF}" ]; then
        if grep -q 'rp_filter' "${TUNE_CONF}"; then
            echo "    tune conf : present (with rp_filter)"
        else
            echo "    tune conf : present (no rp_filter)"
        fi
    else
        echo "    tune conf : absent"
    fi
    [ -f "${TUNE_CONF_LEGACY}" ] && \
        warn "legacy ${TUNE_CONF_LEGACY} present — re-run tune to migrate it"
    echo "    tune bkup : $( [ -f "${TUNE_BACKUP}" ] && echo present || echo absent )"
}

cmd_default() {
    need_root
    cc_available || { err "${CC_NAME} not loaded; run load (2) first"; exit 1; }

    warn "Setting ${CC_NAME} as the SYSTEM DEFAULT."
    warn "New connections will use it. Existing ones keep their current CC."
    warn "On a busy production node this is a real change — proceed carefully."
    read -r -p "Type 'yes' to set ${CC_NAME} as default: " ans
    [ "${ans}" = "yes" ] || { log "aborted"; return 0; }

    sysctl -w "net.ipv4.tcp_congestion_control=${CC_NAME}" >/dev/null
    ok "runtime default is now $(current_default_cc)"
    log "to make it persist across reboot, run persist (5) with the default option"
}

# Write the low-numbered fallback so a missing module never lands on cubic.
write_fallback_conf() {
    cat > "${FALLBACK_CONF}" <<EOF
# Written by pcc-deploy.sh. Loads BEFORE $(basename "${SYSCTL_CONF}").
# If ${MODULE_NAME} is absent (e.g. after a kernel upgrade) the pcc line in
# that file fails to apply and this value stands. Without it the kernel would
# silently fall back to cubic on every socket.
net.ipv4.tcp_congestion_control = ${FALLBACK_CC}
EOF
    ok "fallback CC persisted: ${FALLBACK_CC} (${FALLBACK_CONF})"
}

persist_via_dkms() {
    local src="/usr/src/${MODULE_NAME}-${MODULE_VERSION}"

    log "registering with DKMS as ${MODULE_NAME}/${MODULE_VERSION}"
    if dkms status 2>/dev/null | grep -q "^${MODULE_NAME}/${MODULE_VERSION}"; then
        log "removing previous DKMS registration for this version"
        dkms remove -m "${MODULE_NAME}" -v "${MODULE_VERSION}" --all >/dev/null 2>&1 || true
    fi

    rm -rf "${src}"
    install -d -m 0755 "${src}"
    install -m 0644 "${SRC_DIR}/${MODULE_NAME}.c" "${src}/" || return 1
    install -m 0644 "${SRC_DIR}/Makefile" "${src}/" || return 1

    cat > "${src}/dkms.conf" <<EOF
PACKAGE_NAME="${MODULE_NAME}"
PACKAGE_VERSION="${MODULE_VERSION}"
BUILT_MODULE_NAME[0]="${MODULE_NAME}"
DEST_MODULE_LOCATION[0]="/updates"
AUTOINSTALL="yes"
EOF

    dkms add -m "${MODULE_NAME}" -v "${MODULE_VERSION}" >/dev/null 2>&1 || true
    if dkms install -m "${MODULE_NAME}" -v "${MODULE_VERSION}" --force; then
        ok "DKMS install complete — the module rebuilds on kernel upgrades"
        return 0
    fi
    err "DKMS install failed"
    return 1
}

persist_via_tree() {
    warn "Using a plain in-tree install."
    warn "This module will NOT survive a kernel upgrade. After the next"
    warn "unattended-upgrade + reboot, ${MODULE_NAME} will be missing and the"
    warn "node will run ${FALLBACK_CC} (via ${FALLBACK_CONF})."
    warn "Install dkms and re-run persist to avoid that."
    install -D -m 0644 "${KO}" "${TREE_KO}"
    depmod -a
    ok "installed ${TREE_KO}"
}

cmd_persist() {
    need_root
    [ -f "${KO}" ] || { err "no ${KO}; build first"; exit 1; }

    # Always write the fallback first, so it exists even if a later step fails.
    write_fallback_conf

    if have_dkms && [ -f "${SRC_DIR}/${MODULE_NAME}.c" ]; then
        persist_via_dkms || persist_via_tree
    else
        have_dkms || warn "dkms not installed"
        persist_via_tree
    fi

    echo "${MODULE_NAME}" > "${AUTOLOAD_CONF}"
    ok "module will auto-load at boot (${AUTOLOAD_CONF})"

    if [ "${1:-}" = "--with-default" ]; then
        cat > "${SYSCTL_CONF}" <<EOF
# Written by pcc-deploy.sh. Loads AFTER $(basename "${FALLBACK_CONF}").
# If ${MODULE_NAME} is missing this line fails and ${FALLBACK_CC} stands.
net.ipv4.tcp_congestion_control = ${CC_NAME}
EOF
        ok "${CC_NAME} set as persistent default (${SYSCTL_CONF})"
    else
        log "default NOT persisted; pass --with-default to also do that"
    fi
}

cmd_params() {
    local pdir="/sys/module/${MODULE_NAME}/parameters" p line ans
    if [ ! -d "${pdir}" ]; then
        err "${MODULE_NAME} not loaded — no parameters to show"
        exit 1
    fi

    echo "current runtime parameters:"
    for p in "${pdir}"/*; do
        [ -e "${p}" ] || continue
        printf '    %-18s = %s\n' "$(basename "${p}")" "$(cat "${p}" 2>/dev/null)"
    done
    echo
    log "change one at runtime, e.g.:  echo 1 > ${pdir}/pcc_debug"
    echo
    read -r -p "persist current values to ${MODPROBE_CONF}? [y/N]: " ans
    case "${ans}" in
        y|Y) ;;
        *) log "not persisted"; return 0 ;;
    esac
    need_root

    line=""
    for p in "${pdir}"/*; do
        [ -e "${p}" ] || continue
        line="${line} $(basename "${p}")=$(cat "${p}" 2>/dev/null)"
    done
    echo "options ${MODULE_NAME}${line}" > "${MODPROBE_CONF}"
    ok "wrote ${MODPROBE_CONF}"
    # modprobe.d only applies when the module is loaded via modprobe, i.e. at
    # boot through modules-load.d. It has no effect on the insmod path in
    # cmd_load, so a reload here keeps whatever is already set at runtime.
    log "note: applies at boot via modprobe, not to 'load' (which uses insmod)"
}

# Generate the tuning profile scaled to this machine.
# $1 = "norp" to omit the rp_filter keys entirely.
# Deliberately does NOT set tcp_congestion_control — that stays with
# default/persist (options 4/5) so tune/revert never flips your CC.
generate_tune_conf() {
    local variant="${1:-}"
    local mem_kb mem_gb cores rmax wmax backlog synbacklog ct_max

    mem_kb="$(awk '/MemTotal/{print $2}' /proc/meminfo)"
    mem_gb=$(( mem_kb / 1048576 ))
    cores="$(nproc)"

    # socket buffer ceilings by RAM
    if   [ "${mem_gb}" -ge 8 ]; then rmax=67108864
    elif [ "${mem_gb}" -ge 4 ]; then rmax=33554432
    else                             rmax=16777216
    fi
    wmax="${rmax}"

    # queue depths by cores
    if [ "${cores}" -ge 8 ]; then backlog=32768; synbacklog=65536
    else                          backlog=16384; synbacklog=32768
    fi

    # conntrack sizing (~300B/entry): 128k per GiB, clamp [262144, 2097152]
    ct_max=$(( mem_gb * 131072 ))
    [ "${ct_max}" -lt 262144 ]  && ct_max=262144
    [ "${ct_max}" -gt 2097152 ] && ct_max=2097152

    cat <<EOF
# Generated by pcc-deploy.sh tune$( [ "${variant}" = "norp" ] && echo "-norp" ) on $(date -Is)
# Machine: ${mem_gb} GiB RAM, ${cores} cores, kernel ${KVER}
# Profile: PCC congestion control + Xray/HAProxy high-concurrency proxy
# NOTE: tcp_congestion_control intentionally NOT set here (see ${SYSCTL_CONF})
# NOTE: numbered 99-zz- so it wins against the distro's 99-sysctl.conf

# --- qdisc: fq honors sk_pacing_rate, which pcc's rate control relies on ---
# This only affects qdiscs created after it is applied; 'tune' also pushes fq
# onto the live default-route interface(s).
net.core.default_qdisc = fq

# --- socket buffers (pcc probes rates; don't let buffers be the ceiling) ---
net.core.rmem_max = ${rmax}
net.core.wmem_max = ${wmax}
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 262144 ${rmax}
net.ipv4.tcp_wmem = 4096 262144 ${wmax}
net.ipv4.tcp_moderate_rcvbuf = 1
net.core.optmem_max = 81920
# UDP floors (WireGuard egress under load)
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# --- accept/ingress queues (HAProxy on 443, connection bursts) ---
net.core.somaxconn = 65535
net.core.netdev_max_backlog = ${backlog}
net.ipv4.tcp_max_syn_backlog = ${synbacklog}
net.ipv4.tcp_syncookies = 1
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000

# --- connection churn (thousands of short-lived proxy flows) ---
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 1048576
net.ipv4.tcp_max_orphans = 262144
net.ipv4.tcp_abort_on_overflow = 0

# --- per-connection behavior for proxied long/short flows ---
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_mtu_probing = 1

# tcp_fastopen is deliberately NOT set here. The TFO cookie exchange is a
# distinctive handshake feature on a port where it is rare, it is a known
# middlebox-breakage source on exactly the paths these clients use, and it
# buys close to nothing on long-lived proxied flows. Set it yourself if you
# have measured a reason to.

# --- keepalive: reap dead client connections faster ---
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
EOF

    if [ "${variant}" != "norp" ]; then
        cat <<EOF

# --- routing: loose rp_filter for asymmetric multi-interface (wg) egress ---
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
EOF
    fi

    cat <<EOF

# --- file descriptors (xray + haproxy under high concurrency) ---
fs.file-max = 2097152
fs.nr_open = 2097152

# --- memory pressure ---
vm.swappiness = 10
EOF

    # conntrack keys only if the netfilter conntrack subsystem is present
    if [ -d /proc/sys/net/netfilter ]; then
        cat <<EOF

# --- conntrack (present on this node; sized to ${ct_max}) ---
net.netfilter.nf_conntrack_max = ${ct_max}
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
EOF
    fi
}

# Restore specific keys (by grep pattern) from the backup at runtime.
restore_keys_from_backup() {
    local pattern="$1" key val
    [ -f "${TUNE_BACKUP}" ] || return 0
    grep -E "${pattern}" "${TUNE_BACKUP}" | while IFS='=' read -r key val; do
        key="$(echo "${key}" | tr -d ' ')"
        val="$(echo "${val}" | sed 's/^ *//')"
        sysctl -w "${key}=${val}" >/dev/null 2>&1 \
            && log "restored ${key} = ${val}"
    done
}

# net.core.default_qdisc does nothing to an interface that already has a
# qdisc. Push fq onto the live default-route interface(s) so pcc's pacing is
# enforced by fq rather than by a per-socket hrtimer.
apply_fq_live() {
    local ifaces i cur
    command -v tc >/dev/null 2>&1 || {
        warn "tc not found (install iproute2) — live qdisc left unchanged"
        return 0
    }
    ifaces="$(default_route_ifaces)"
    [ -n "${ifaces}" ] || { warn "no default route found — skipping live qdisc"; return 0; }

    for i in ${ifaces}; do
        cur="$(tc qdisc show dev "${i}" 2>/dev/null | head -1 | awk '{print $2}')"
        if [ "${cur}" = "fq" ]; then
            ok "${i}: already fq"
            continue
        fi
        log "${i}: replacing root qdisc ${cur:-unknown} -> fq"
        if tc qdisc replace dev "${i}" root fq 2>/dev/null; then
            ok "${i}: now fq"
        else
            warn "${i}: could not set fq (multiqueue? try 'tc qdisc replace dev ${i} root mq' first)"
        fi
    done
    log "note: only default-route interface(s) touched. WireGuard and other"
    log "      virtual devices are left alone on purpose."
}

# $1 = "" (full profile) or "norp" (skip rp_filter)
cmd_tune() {
    need_root
    local variant="${1:-}" tmp

    if [ -f "${TUNE_CONF_LEGACY}" ]; then
        log "removing legacy ${TUNE_CONF_LEGACY} (superseded by ${TUNE_CONF})"
        rm -f "${TUNE_CONF_LEGACY}"
    fi

    if [ "${variant}" = "norp" ]; then
        log "generating tuning profile (rp_filter untouched) for this machine"
    else
        log "generating tuning profile (with rp_filter=2) for this machine"
    fi
    tmp="$(mktemp)"
    generate_tune_conf "${variant}" > "${tmp}"

    # Snapshot current values of every key we're about to change — but only
    # on the FIRST tune, so the backup always reflects the true pre-tune state
    # even if tune is re-run after a hardware change or variant switch.
    if [ ! -f "${TUNE_BACKUP}" ]; then
        log "snapshotting current values to ${TUNE_BACKUP}"
        mkdir -p "${STATE_DIR}"
        {
            echo "# pre-tune sysctl snapshot taken $(date -Is) by pcc-deploy.sh"
            grep -E '^[a-z]' "${tmp}" | cut -d'=' -f1 | sed 's/ *$//' | \
            while read -r key; do
                val="$(sysctl -n "${key}" 2>/dev/null)" || continue
                # normalize whitespace in multi-value keys (tcp_rmem etc.)
                echo "${key} = $(echo "${val}" | tr '\t' ' ' | tr -s ' ')"
            done
            # snapshot rp_filter even in norp mode so a later full tune,
            # or a variant switch, can still be fully reverted
            if [ "${variant}" = "norp" ]; then
                for k in net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter; do
                    v="$(sysctl -n "${k}" 2>/dev/null)" || continue
                    echo "${k} = ${v}"
                done
            fi
        } > "${TUNE_BACKUP}"
        ok "backup written ($(grep -c '^[a-z]' "${TUNE_BACKUP}") keys)"
    else
        warn "backup already exists (${TUNE_BACKUP}) — keeping original pre-tune state"
    fi

    # If switching full -> norp, put runtime rp_filter back to its pre-tune
    # value; otherwise the old rp_filter=2 lingers with nothing owning it.
    if [ "${variant}" = "norp" ] && [ -f "${TUNE_CONF}" ] \
        && grep -q 'rp_filter' "${TUNE_CONF}"; then
        log "previous tune set rp_filter — restoring pre-tune values"
        restore_keys_from_backup 'rp_filter'
    fi

    install -m 0644 "${tmp}" "${TUNE_CONF}"
    rm -f "${tmp}"
    ok "wrote ${TUNE_CONF}"

    log "applying now"
    if sysctl -p "${TUNE_CONF}" >/dev/null 2>&1; then
        ok "all keys applied"
    else
        # apply what we can, report what failed
        warn "some keys failed to apply:"
        sysctl -p "${TUNE_CONF}" 2>&1 >/dev/null | sed 's/^/    /' || true
    fi

    apply_fq_live

    log "note: raise LimitNOFILE in xray/haproxy systemd units to benefit"
    log "      from fs.nr_open (sysctl alone doesn't lift per-process limits)"
    ok "tune complete — revert anytime with revert-tune"
}

cmd_revert_tune() {
    need_root

    rm -f "${TUNE_CONF_LEGACY}"

    if [ ! -f "${TUNE_CONF}" ] && [ ! -f "${TUNE_BACKUP}" ]; then
        ok "nothing to revert — no tune conf or backup found"
        return 0
    fi

    if [ -f "${TUNE_CONF}" ]; then
        rm -f "${TUNE_CONF}"
        ok "removed ${TUNE_CONF} (no longer applied at boot)"
    fi

    if [ -f "${TUNE_BACKUP}" ]; then
        log "restoring pre-tune runtime values from ${TUNE_BACKUP}"
        if sysctl -p "${TUNE_BACKUP}" >/dev/null 2>&1; then
            ok "runtime values restored"
        else
            warn "some keys failed to restore:"
            sysctl -p "${TUNE_BACKUP}" 2>&1 >/dev/null | sed 's/^/    /' || true
        fi
        rm -f "${TUNE_BACKUP}"
        ok "backup consumed and removed"
    else
        warn "no backup found — conf removed but runtime values remain until reboot"
    fi

    warn "the LIVE root qdisc is not reverted (tune may have set it to fq)."
    warn "reset it yourself if needed: tc qdisc replace dev <if> root fq_codel"
}

cmd_unload() {
    need_root
    module_loaded || { ok "${MODULE_NAME} not loaded"; return 0; }
    if [ "$(module_refcount)" -ne 0 ]; then drain || exit 1; fi
    rmmod "${MODULE_NAME}" && ok "unloaded ${MODULE_NAME}"
}

cmd_uninstall() {
    need_root
    warn "This removes the module and ALL persisted PCC config."
    warn "(sysctl tuning from tune/tune-norp is NOT touched — use revert-tune)"
    read -r -p "Type 'yes' to continue: " ans
    [ "${ans}" = "yes" ] || { log "aborted"; return 0; }

    sysctl -w "net.ipv4.tcp_congestion_control=${FALLBACK_CC}" >/dev/null
    if module_loaded; then
        [ "$(module_refcount)" -ne 0 ] && drain
        rmmod "${MODULE_NAME}" 2>/dev/null || warn "could not rmmod (still busy?)"
    fi

    if have_dkms && dkms status 2>/dev/null | grep -q "^${MODULE_NAME}"; then
        log "removing DKMS registration"
        dkms remove -m "${MODULE_NAME}" -v "${MODULE_VERSION}" --all >/dev/null 2>&1 || true
        rm -rf "/usr/src/${MODULE_NAME}-${MODULE_VERSION}"
    fi

    rm -f "${TREE_KO}" "${AUTOLOAD_CONF}" "${SYSCTL_CONF}" \
          "${FALLBACK_CONF}" "${MODPROBE_CONF}"
    depmod -a
    ok "removed module + persisted config; default is now ${FALLBACK_CC}"
    log "(your source tree in ${SRC_DIR} was left untouched)"
}

usage() {
    sed -n '3,35p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# ---- menu / dispatch --------------------------------------------------------
run_action() {
    case "$1" in
        1|build)         cmd_build ;;
        2|load)          cmd_load ;;
        3|status)        cmd_status ;;
        4|default)       cmd_default ;;
        5|persist)       cmd_persist "${2:-}" ;;
        6|tune)          cmd_tune "" ;;
        7|tune-norp)     cmd_tune "norp" ;;
        8|revert-tune)   cmd_revert_tune ;;
        9|unload)        cmd_unload ;;
        10|uninstall)    cmd_uninstall ;;
        11|params)       cmd_params ;;
        0|q|quit|exit)   exit 0 ;;
        *) return 1 ;;
    esac
    return 0
}

menu() {
    while true; do
        echo
        echo "======= PCC deploy v${MODULE_VERSION} — ${MODULE_NAME} (${KVER}) ======="
        echo "  1) build        — install prereqs + compile ${MODULE_NAME}.ko"
        echo "  2) load         — (re)load the module, restoring the default CC"
        echo "  3) status       — module/socket/qdisc/default/tune state"
        echo "  4) default      — set ${CC_NAME} as system default (confirms first)"
        echo "  5) persist      — survive reboot (DKMS if available)"
        echo "  6) tune         — sysctl profile for ${CC_NAME} + xray (rp_filter=2)"
        echo "  7) tune-norp    — same profile, rp_filter left untouched"
        echo "  8) revert-tune  — restore pre-tune sysctl values"
        echo "  9) unload       — drain on refcount then rmmod"
        echo " 10) uninstall    — remove module + all persisted config"
        echo " 11) params       — show / persist module parameters"
        echo "  0) quit"
        echo "======================================================================"
        read -r -p "select [0-11]: " choice
        echo

        extra=""
        if [ "${choice}" = "5" ] || [ "${choice}" = "persist" ]; then
            read -r -p "also persist ${CC_NAME} as default CC? [y/N]: " p
            case "${p}" in y|Y) extra="--with-default" ;; esac
        fi

        run_action "${choice}" "${extra}" || warn "invalid choice: '${choice}'"
    done
}

if [ $# -eq 0 ]; then
    menu
else
    run_action "$1" "${2:-}" || { usage; exit 1; }
fi
