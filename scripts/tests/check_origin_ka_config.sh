#!/usr/bin/env bash
# check_origin_ka_config.sh — static regression gate for the origin-keepalive
# 443 SNI-safety invariant (see docs/proxy-performance.md and
# configs/lua/cfm_origin_ka.lua).
#
# WHY THIS EXISTS
# The Lua unit tests (scripts/tests/cfm_origin_ka_test.lua) prove the balancer
# state machine but never read the edge config, so they cannot catch a config
# refactor that silently re-enables 443 connection/TLS reuse — exactly the class
# of bug behind the 2026-08 cross-SNI 421 incident (nginx-core's native upstream
# keepalive is ON by default since nginx 1.29.7 and is SNI-blind). This gate
# asserts, purely by static inspection of the reference confs:
#
#   openresty.conf
#     * both cfm_origin_http and cfm_origin_https upstreams carry `keepalive 0;`
#       (disables the default-on, SNI-blind native pool; Lua owns the 80 pool).
#   angie.conf
#     * neither cfm_origin_* upstream carries a `keepalive` directive — Angie
#       keeps native upstream keepalive OFF by default AND rejects `keepalive 0`
#       (confirmed Angie 1.12.1: `angie -t` -> invalid value "0"), so `keepalive
#       0` there is both unneeded and a hard config-load failure.
#   both confs
#     * every HTTPS-origin location — a location INSIDE an `ssl` server block
#       that proxies to the origin via `proxy_pass $cfm_pass` or
#       `proxy_pass https://$server_addr` — carries the full trio
#       `proxy_ssl_server_name on; proxy_ssl_name $host;
#       proxy_ssl_session_reuse off;` (SNI + no cross-SNI TLS session reuse; the
#       upstream SSL-session cache is peer-keyed, not SNI-keyed). Checked
#       per-location, so deleting the whole trio from one location is caught
#       (a plain count/adjacency check would not). The plain-HTTP server's
#       $cfm_pass locations correctly need none of these and are not flagged.
#
# It does NOT replace the live two-vhost integration test (which needs the
# deployed engine) — it just stops the trivial "someone deleted a line" regress.

set -euo pipefail
cd "$(dirname "$0")/../.."

ORT=configs/openresty.conf
ANG=configs/angie.conf
fail=0
err() { echo "❌ [origin-ka-config] $*" >&2; fail=1; }

# upstream_state FILE NAME → prints "yes" / "no" / "absent":
#   whether the brace-delimited `upstream <name> { ... }` block in FILE contains
#   a `keepalive <n>;` directive line (matches keepalive with any value).
upstream_keepalive_state() {
  awk -v name="$2" '
    !inb && $0 ~ ("^[[:space:]]*upstream[[:space:]]+" name "[[:space:]]*\\{") { inb=1; found_any=1 }
    inb {
      if ($0 ~ /^[[:space:]]*keepalive[[:space:]]+[0-9]+[[:space:]]*;/) hit=1
      a=$0; o=gsub(/\{/,"",a); b=$0; c=gsub(/\}/,"",b); depth += o - c
      if (depth <= 0) { print (hit?"yes":"no"); done=1; exit }
    }
    END { if (!found_any) print "absent"; else if (!done) print (hit?"yes":"no") }
  ' "$1"
}

# ── OpenResty: both origin upstreams MUST disable the native pool ────────────
for up in cfm_origin_http cfm_origin_https; do
  st=$(upstream_keepalive_state "$ORT" "$up")
  case "$st" in
    yes)     ;;  # has a keepalive directive — expected (keepalive 0)
    no)      err "$ORT: upstream '$up' has NO 'keepalive 0;' — nginx>=1.29.7 native pool (SNI-blind) stays ON; 443 reuse can return." ;;
    absent)  err "$ORT: upstream '$up' block not found — did the origin upstreams get renamed/removed?" ;;
  esac
done
# Confirm the value is specifically 0, not some N (which would re-enable pooling).
if ! grep -Eq '^[[:space:]]*keepalive[[:space:]]+0[[:space:]]*;' "$ORT"; then
  err "$ORT: no 'keepalive 0;' directive found at all (expected one per origin upstream)."
fi
if grep -Eq '^[[:space:]]*keepalive[[:space:]]+[1-9][0-9]*[[:space:]]*;' "$ORT"; then
  # A non-zero keepalive anywhere in the origin upstreams would re-enable native pooling.
  for up in cfm_origin_http cfm_origin_https; do
    blk=$(awk -v name="$up" '
      !inb && $0 ~ ("^[[:space:]]*upstream[[:space:]]+" name "[[:space:]]*\\{"){inb=1}
      inb{print; a=$0;o=gsub(/\{/,"",a);b=$0;c=gsub(/\}/,"",b);depth+=o-c; if(depth<=0)exit}
    ' "$ORT")
    if printf '%s\n' "$blk" | grep -Eq '^[[:space:]]*keepalive[[:space:]]+[1-9]'; then
      err "$ORT: upstream '$up' sets a NON-zero keepalive — that re-enables the SNI-blind native pool."
    fi
  done
fi

# ── Angie: origin upstreams MUST NOT carry a keepalive directive ─────────────
for up in cfm_origin_http cfm_origin_https; do
  st=$(upstream_keepalive_state "$ANG" "$up")
  case "$st" in
    no)      ;;  # no keepalive directive — expected on Angie
    yes)     err "$ANG: upstream '$up' has a 'keepalive' directive — remove it: Angie defaults native keepalive off AND its parser rejects 'keepalive 0' (confirmed Angie 1.12.1: 'angie -t' -> invalid value \"0\"), so any keepalive directive here risks breaking the reload." ;;
    absent)  err "$ANG: upstream '$up' block not found — did the origin upstreams get renamed/removed?" ;;
  esac
done

# ── Both confs: every HTTPS-origin location carries the full SNI-safe trio ────
# A pure count/adjacency check has a blind spot: deleting BOTH the
# proxy_ssl_name and proxy_ssl_session_reuse lines from one HTTPS-origin
# location still "passes" (fewer proxy_ssl_name, remaining ones still paired).
# So we identify each origin-proxy location INSIDE the ssl server block
# (`listen ... ssl`) — one that proxies to the HTTPS origin via
# `proxy_pass $cfm_pass` or `proxy_pass https://$server_addr` — and require ALL
# THREE of: proxy_ssl_server_name on; proxy_ssl_name $host;
# proxy_ssl_session_reuse off;. The plain-HTTP (non-ssl) server's $cfm_pass
# locations correctly need none of these and are not flagged.
#
# Assumes CFM config style: `location ... {` opens on one line and location
# match patterns contain no literal '{'. True for the whole current config.
for f in "$ORT" "$ANG"; do
  # (a) location-aware completeness (the real regression guard).
  missing=$(awk '
    /^[[:space:]]*server[[:space:]]*\{/          { in_ssl=0 }                 # new server: reset
    /^[[:space:]]*listen[[:space:]].*[[:space:]]ssl([[:space:];]|$)/ { in_ssl=1 }  # ssl listener => HTTPS server
    !loc && /^[[:space:]]*location[[:space:]].*\{/ {
      loc=1; body=$0 "\n"; isorigin=0; locline=NR
      t=$0; o=gsub(/\{/,"",t); u=$0; c=gsub(/\}/,"",u); d=o-c
      if ($0 ~ /proxy_pass[[:space:]]+\$cfm_pass/ || $0 ~ /proxy_pass[[:space:]]+https:\/\/\$server_addr/) isorigin=1
      next
    }
    loc {
      body=body $0 "\n"
      if ($0 ~ /proxy_pass[[:space:]]+\$cfm_pass/ || $0 ~ /proxy_pass[[:space:]]+https:\/\/\$server_addr/) isorigin=1
      t=$0; o=gsub(/\{/,"",t); u=$0; c=gsub(/\}/,"",u); d+=o-c
      if (d<=0) {
        if (in_ssl && isorigin) {
          m=""
          if (body !~ /proxy_ssl_server_name[[:space:]]+on[[:space:]]*;/)  m=m " proxy_ssl_server_name-on"
          if (body !~ /proxy_ssl_name[[:space:]]+\$host[[:space:]]*;/)     m=m " proxy_ssl_name-$host"
          if (body !~ /proxy_ssl_session_reuse[[:space:]]+off[[:space:]]*;/) m=m " proxy_ssl_session_reuse-off"
          if (m!="") print "location@line" locline ":" m
        }
        loc=0; body=""; isorigin=0
      }
    }
  ' "$f")
  if [ -n "$missing" ]; then
    while IFS= read -r linfo; do
      err "$f: HTTPS-origin $linfo — missing required 443 SNI-safety directive(s)."
    done <<< "$missing"
  fi

  # (b) presence: the conf must actually carry each directive at least once
  #     (guards a wholesale deletion, or a conf with no ssl origin locations).
  for d in 'proxy_ssl_server_name[[:space:]]+on' 'proxy_ssl_name[[:space:]]+\$host' 'proxy_ssl_session_reuse[[:space:]]+off'; do
    if ! grep -Eq "^[[:space:]]*$d[[:space:]]*;" "$f"; then
      err "$f: no '$(echo "$d" | sed 's/\[\[:space:\]\]+/ /g');' directive anywhere — 443 origin SNI-safety config missing?"
    fi
  done

  # (c) ordering nicety: each proxy_ssl_name $host is immediately followed by
  #     proxy_ssl_session_reuse off (keeps the pair visibly together).
  unpaired=$(awk '
    prev { if ($0 !~ /^[[:space:]]*proxy_ssl_session_reuse[[:space:]]+off[[:space:]]*;/) print pn; prev=0 }
    /^[[:space:]]*proxy_ssl_name[[:space:]]+\$host[[:space:]]*;/ { prev=1; pn=NR }
    END { if (prev) print pn }
  ' "$f")
  if [ -n "$unpaired" ]; then
    err "$f: proxy_ssl_name \$host at line(s) [$(echo "$unpaired" | tr '\n' ' ')] NOT immediately followed by 'proxy_ssl_session_reuse off;'."
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "[origin-ka-config] FAILED — see errors above (invariant: 443 origin reuse blocked at every layer)." >&2
  exit 1
fi
echo "[origin-ka-config] OK: OpenResty origin upstreams set keepalive 0; Angie carries none; every 443 origin location disables TLS session reuse."
