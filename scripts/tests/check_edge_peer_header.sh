#!/usr/bin/env bash
# check_edge_peer_header.sh — every block of the edge confs that proxies
# (proxy_pass) sends the edge's own TCP peer as X-CFM-Peer.
#
# WHY: an origin that keys security on the TCP peer (NGM's panel login
# limiter, mail guard and auth-log bans) reads X-CFM-Peer from a loopback
# peer, because CF-Connecting-IP / X-Real-IP carry the visitor the edge
# resolved, which a Cloudflare Worker writes itself. A block that proxies
# without `proxy_set_header X-CFM-Peer $realip_remote_addr;` would pass a
# CLIENT's own X-CFM-Peer through to the origin, letting it choose that
# address. So: each proxy_pass block (or, for one inside an `if`, the
# location around it) sets it, exactly with that value.
#
# Usage: scripts/tests/check_edge_peer_header.sh [conf...]
#   default: configs/openresty.conf configs/angie.conf configs/cfm-edge.conf
set -euo pipefail
cd "$(dirname "$0")/../.."
confs=("$@")
[ ${#confs[@]} -gt 0 ] || confs=(configs/openresty.conf configs/angie.conf configs/cfm-edge.conf)
command -v awk >/dev/null || { echo "check_edge_peer_header: awk missing" >&2; exit 1; }

fail=0
for f in "${confs[@]}"; do
    [ -r "$f" ] || { echo "❌ $f: not readable" >&2; fail=1; continue; }
    out=$(awk '
    # A frame per { ... }; iff[] marks an `if (...) {` frame. nginx gives a
    # location the server-level proxy_set_header list only when the location
    # sets none itself, and every proxying block here sets some, so the header
    # must be in the proxy_pass block itself or, for a proxy_pass inside an
    # if, in the enclosing location the if inherits from.
    {
        line = $0; sub(/#.*/, "", line)
        if (line ~ /proxy_set_header[[:space:]]+X-CFM-Peer([[:space:]]|;)/) {
            if (line ~ /proxy_set_header[[:space:]]+X-CFM-Peer[[:space:]]+\$realip_remote_addr;/) has[fid[depth]] = 1
            else bad[NR] = "X-CFM-Peer set to something other than $realip_remote_addr"
        }
        if (line ~ /^[[:space:]]*proxy_pass[[:space:]]/) {
            np++; pp[np] = NR; d = depth; k = 0
            while (d >= 1) { chain[np, k++] = fid[d]; if (!iff[fid[d]]) break; d-- }
            nch[np] = k
        }
        n = split(line, ch, "")
        for (i = 1; i <= n; i++) {
            if (ch[i] == "{") { depth++; fid[depth] = ++frames; iff[frames] = (line ~ /^[[:space:]]*if[[:space:]]*\(/) }
            else if (ch[i] == "}") depth--
        }
    }
    END {
        for (k in bad) { print k ": " bad[k]; e = 1 }
        for (i = 1; i <= np; i++) {
            ok = 0
            for (k = 0; k < nch[i]; k++) if (has[chain[i, k]]) ok = 1
            if (!ok) { print pp[i] ": proxy_pass without proxy_set_header X-CFM-Peer $realip_remote_addr in its own block"; e = 1 }
        }
        printf "#count %d\n", np
        exit e
    }' "$f") && rc=0 || rc=$?
    count=$(printf '%s\n' "$out" | sed -n 's/^#count //p')
    if [ "$rc" != 0 ]; then
        printf '%s\n' "$out" | grep -v '^#count' | sed "s|^|❌ $f:|" >&2
        fail=1
    elif [ "${count:-0}" -eq 0 ]; then
        echo "❌ $f: no proxy_pass found — the check read nothing" >&2
        fail=1
    else
        echo "✅ $f: all ${count} proxy_pass blocks send X-CFM-Peer \$realip_remote_addr"
    fi
done
exit "$fail"
