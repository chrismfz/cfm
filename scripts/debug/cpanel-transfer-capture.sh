#!/usr/bin/env bash
# scripts/debug/cpanel-transfer-capture.sh
#
# Synchronised packet / socket / log capture for debugging cPanel WHM
# live-transfer ("Account Restore") hangs through the CFM Lua panel tunnel
# at /acctxferrsync — the failure mode documented in
# docs/dnat-bypass.md ("cPanel transfer still stuck at ~20% even with
# tunnel changes").
#
# Run it on BOTH peers simultaneously, kick off the same transfer in both
# the failing-mode (tunnel) and known-good-mode (bypass) configurations,
# then ship the two tarballs back for analysis.
#
# Layers captured:
#
#   wire      tcpdump on the external NIC (both peers) and on lo (source
#             only) so we see openresty <-> cpsrvd loopback alongside
#             rigel <-> earth wire traffic.
#
#   sockets   `ss -tnpieO` snapshots every $SNAP_INTERVAL seconds and
#             (when available) `conntrack -L -p tcp` snapshots, so we
#             can correlate Recv-Q / Send-Q growth and ESTAB->CLOSE_WAIT
#             transitions with the pcap timeline.
#
#   process   source side tails the openresty / angie / nginx error log
#             so the cfm_panel_tunnel pump WARN lines land alongside
#             everything else. Destination side runs `strace -tt` on
#             whm_xfer_download-ssl when it appears so we can see exactly
#             which syscall it is blocked on at hang time.
#
# Usage on the SOURCE server (the cpsrvd whose account is being moved):
#
#   sudo scripts/debug/cpanel-transfer-capture.sh start source <peer_ip> [out_dir]
#
# Usage on the DESTINATION server (running whm_xfer_download-ssl):
#
#   sudo scripts/debug/cpanel-transfer-capture.sh start dest   <peer_ip> [out_dir]
#
# Stop and bundle (either side):
#
#   sudo scripts/debug/cpanel-transfer-capture.sh stop  [out_dir]
#   sudo scripts/debug/cpanel-transfer-capture.sh bundle [out_dir]
#
# Suggested protocol for one debugging round:
#
#   1. RUN A (known-good baseline):
#        on source:  cfm dnat cpanel bypass add <dest_ip>
#                    (this restores direct-to-cpsrvd for that peer)
#        on both:    sudo .../cpanel-transfer-capture.sh start <role> <peer>
#        in WHM:     start the transfer of one small account, let it finish
#        on both:    sudo .../cpanel-transfer-capture.sh stop && bundle
#
#   2. RUN B (failing case):
#        on source:  cfm dnat cpanel bypass del <dest_ip>
#                    (forces the transfer back through the lua tunnel)
#        on both:    sudo .../cpanel-transfer-capture.sh start <role> <peer>
#        in WHM:     start the same transfer, wait for it to hang at ~20%
#        on both:    sudo .../cpanel-transfer-capture.sh stop && bundle
#
# Then diff the pcaps in wireshark at the boundary where cpsrvd sends its
# final segment and FIN: in run A that FIN reaches rigel within a few ms;
# in run B it does not (or arrives much later) — that is the bug.

set -euo pipefail

CMD=${1:-}
ROLE=${2:-}
PEER=${3:-}
OUT=${4:-/var/lib/cfm/debug-cpxfer}
SNAP_INTERVAL=${SNAP_INTERVAL:-2}

usage() {
  cat >&2 <<EOF
usage:
  $0 start source <peer_ip> [out_dir]
  $0 start dest   <peer_ip> [out_dir]
  $0 stop  [out_dir]
  $0 bundle [out_dir]

environment overrides:
  SNAP_INTERVAL  seconds between ss/conntrack snapshots (default 2)
  PANEL_PORTS    space-separated panel ports for wire capture
                 (default: "2087 12087" on source, "2087" on dest)
  ERROR_LOGS     space-separated nginx/openresty error logs to follow
                 (default: auto-detect openresty / angie / nginx)
EOF
  exit 64
}

need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "must run as root (tcpdump + strace + conntrack require it)" >&2
    exit 1
  fi
}

ts() { date +%Y%m%d-%H%M%S; }

start_capture() {
  need_root
  [[ -z "$ROLE" || -z "$PEER" ]] && usage
  case "$ROLE" in source|dest) ;; *) usage;; esac

  if [[ -f "$OUT/.active" ]]; then
    echo "a capture is already active: $(cat "$OUT/.active")" >&2
    echo "run '$0 stop' first" >&2
    exit 1
  fi

  local session_dir="$OUT/$(ts)-$ROLE"
  mkdir -p "$session_dir"

  {
    echo "role=$ROLE"
    echo "peer=$PEER"
    echo "host=$(hostname)"
    echo "host_ips=$(hostname -I 2>/dev/null || true)"
    echo "started_at=$(date -Is)"
    echo "kernel=$(uname -a)"
    echo "interval_sec=$SNAP_INTERVAL"
  } > "$session_dir/meta.txt"

  # One-shot environment snapshot at session start
  {
    echo "=== ip addr ==="
    ip -o addr show 2>/dev/null || true
    echo
    echo "=== ip route ==="
    ip route show 2>/dev/null || true
    echo
    echo "=== nft list ruleset (cfm tables only) ==="
    nft list table inet cfm_panel_redirect 2>/dev/null || true
    nft list table inet cfm_web_redirect 2>/dev/null || true
    echo
    echo "=== sysctl net.ipv4.tcp_fin_timeout ==="
    sysctl net.ipv4.tcp_fin_timeout 2>/dev/null || true
    echo "=== sysctl net.ipv4.tcp_keepalive_time ==="
    sysctl net.ipv4.tcp_keepalive_time 2>/dev/null || true
  } > "$session_dir/env-snapshot.txt" 2>&1

  : "${PANEL_PORTS:=$( [[ $ROLE == source ]] && echo '2087 12087' || echo '2087' )}"

  # Build BPF and ss filter expressions from PANEL_PORTS
  local bpf_ports=""
  local ss_filter=""
  for p in $PANEL_PORTS; do
    if [[ -n "$bpf_ports" ]]; then
      bpf_ports+=" or "
      ss_filter+=" or "
    fi
    bpf_ports+="tcp port $p"
    ss_filter+="sport = :$p or dport = :$p"
  done

  # ---- Layer 1: wire ----
  # External-NIC pcap. -i any catches packets on every interface; we filter
  # to peer + panel ports to keep noise out. -U flushes per-packet so a
  # `stop` mid-flight still gets a clean trailing block.
  tcpdump -ni any -s0 -U -w "$session_dir/${ROLE}-ext.pcap" \
    "host $PEER and ($bpf_ports)" \
    > "$session_dir/${ROLE}-ext.tcpdump.log" 2>&1 &
  echo $! > "$session_dir/pid.ext"

  if [[ $ROLE == source ]]; then
    # Loopback pcap for openresty <-> cpsrvd. No peer filter — both legs
    # are 127.0.0.1 conversations on panel ports.
    tcpdump -ni lo -s0 -U -w "$session_dir/source-lo.pcap" "$bpf_ports" \
      > "$session_dir/source-lo.tcpdump.log" 2>&1 &
    echo $! > "$session_dir/pid.lo"
  fi

  # ---- Layer 2: sockets ----
  (
    while :; do
      printf '\n===== %s =====\n' "$(date -Is)"
      ss -tnpieO "( $ss_filter )" 2>&1 || true
      sleep "$SNAP_INTERVAL"
    done
  ) > "$session_dir/${ROLE}-ss.log" 2>&1 &
  echo $! > "$session_dir/pid.ss"

  if command -v conntrack >/dev/null 2>&1; then
    (
      while :; do
        printf '\n===== %s =====\n' "$(date -Is)"
        conntrack -L -p tcp 2>/dev/null \
          | grep -E "(${PEER//./\\.}|=2087|=12087)" || true
        sleep "$SNAP_INTERVAL"
      done
    ) > "$session_dir/${ROLE}-conntrack.log" 2>&1 &
    echo $! > "$session_dir/pid.ct"
  fi

  # ---- Layer 3: process / log ----
  if [[ $ROLE == source ]]; then
    # The CFM panel listener (where cfm_panel_tunnel.lua runs) writes to
    # openresty's or angie's error log — NOT cpanel's bundled ea-nginx
    # at /var/log/nginx/error.log. Check the openresty/angie locations
    # first; only fall back to /var/log/nginx if neither exists. This
    # ordering matters: if we pick the wrong file we get pages of WP
    # cron noise and zero [cfm_panel_tunnel] pump lines.
    : "${ERROR_LOGS:=}"
    if [[ -z "$ERROR_LOGS" ]]; then
      local detected=()
      for c in \
        /usr/local/openresty/nginx/logs/error.log \
        /var/log/openresty/error.log \
        /var/log/angie/error.log \
        /usr/local/angie/logs/error.log \
        /var/log/nginx/error.log; do
        [[ -f $c ]] && detected+=("$c")
      done
      ERROR_LOGS="${detected[*]:-}"
    fi
    if [[ -n "$ERROR_LOGS" ]]; then
      # shellcheck disable=SC2086
      tail -F $ERROR_LOGS > "$session_dir/source-nginx-error.log" 2>&1 &
      echo $! > "$session_dir/pid.errlog"
      echo "$ERROR_LOGS" > "$session_dir/error_log_paths.txt"
    fi
  fi

  if [[ $ROLE == dest ]]; then
    # Background attach loop: poll for whm_xfer_download-ssl, attach
    # strace when it appears, re-attach on the next run if the transfer
    # is re-started during this session.
    (
      while :; do
        local pid
        pid=$(pgrep -fn whm_xfer_download-ssl 2>/dev/null || true)
        if [[ -n "$pid" ]]; then
          printf '\n##### attached at %s pid=%s #####\n' "$(date -Is)" "$pid"
          strace -ttT -f -s 256 \
            -e trace=network,read,write,close,poll,select,ppoll,epoll_wait,epoll_pwait \
            -p "$pid" 2>&1 || true
        else
          sleep 1
        fi
      done
    ) > "$session_dir/dest-xfer-strace.log" 2>&1 &
    echo $! > "$session_dir/pid.strace"
  fi

  echo "$session_dir" > "$OUT/.active"
  echo "started: $session_dir"
  echo "pids:"
  for f in "$session_dir"/pid.*; do
    [[ -f $f ]] || continue
    printf '  %s = %s\n' "$(basename "$f")" "$(cat "$f")"
  done
  echo
  echo "kick off your cPanel transfer now. when it finishes (run A) or"
  echo "when it hangs at ~20%% (run B), come back and:"
  echo
  echo "  sudo $0 stop"
  echo "  sudo $0 bundle"
}

stop_capture() {
  need_root
  if [[ ! -f "$OUT/.active" ]]; then
    echo "no active capture in $OUT" >&2
    exit 1
  fi
  local session_dir
  session_dir=$(cat "$OUT/.active")
  if [[ ! -d "$session_dir" ]]; then
    echo "stale .active pointer at $OUT/.active (dir gone)" >&2
    rm -f "$OUT/.active"
    exit 1
  fi
  echo "stopping $session_dir"

  # Polite SIGTERM first so tcpdump flushes its capture buffer cleanly.
  for f in "$session_dir"/pid.*; do
    [[ -f $f ]] || continue
    local pid
    pid=$(cat "$f")
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done

  sleep 1

  # SIGKILL anything still alive.
  for f in "$session_dir"/pid.*; do
    [[ -f $f ]] || continue
    local pid
    pid=$(cat "$f")
    [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
  done

  echo "stopped_at=$(date -Is)" >> "$session_dir/meta.txt"
  rm -f "$OUT/.active"
  echo "session: $session_dir"
}

bundle_capture() {
  local session_dir
  session_dir=$(ls -1dt "$OUT"/*/ 2>/dev/null | head -n1)
  session_dir=${session_dir%/}
  if [[ -z "$session_dir" || ! -d "$session_dir" ]]; then
    echo "no sessions in $OUT" >&2
    exit 1
  fi
  local tar_path="$session_dir.tar.gz"
  tar -czf "$tar_path" -C "$(dirname "$session_dir")" "$(basename "$session_dir")"
  echo "$tar_path"
  ls -lh "$tar_path"
}

case "$CMD" in
  start)  start_capture ;;
  stop)   stop_capture  ;;
  bundle) bundle_capture ;;
  *)      usage ;;
esac
