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
#     * every 443 origin SNI line (`proxy_ssl_name $host;`) is immediately
#       followed by `proxy_ssl_session_reuse off;` (no cross-SNI TLS session
#       reuse; the upstream SSL-session cache is peer-keyed, not SNI-keyed).
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

# ── Both confs: every proxy_ssl_name $host is paired with session-reuse off ───
for f in "$ORT" "$ANG"; do
  # (a) adjacency: each `proxy_ssl_name $host;` directive line is immediately
  #     followed by `proxy_ssl_session_reuse off;`.
  unpaired=$(awk '
    prev { if ($0 !~ /^[[:space:]]*proxy_ssl_session_reuse[[:space:]]+off[[:space:]]*;/) print pn; prev=0 }
    /^[[:space:]]*proxy_ssl_name[[:space:]]+\$host[[:space:]]*;/ { prev=1; pn=NR }
    END { if (prev) print pn }   # trailing proxy_ssl_name with no following line
  ' "$f")
  if [ -n "$unpaired" ]; then
    err "$f: proxy_ssl_name \$host at line(s) [$(echo "$unpaired" | tr '\n' ' ')] NOT immediately followed by 'proxy_ssl_session_reuse off;' — 443 could reuse a cross-SNI TLS session."
  fi
  # (b) count parity: as many session-reuse-off as proxy_ssl_name directives.
  n_name=$(grep -Ec '^[[:space:]]*proxy_ssl_name[[:space:]]+\$host[[:space:]]*;' "$f" || true)
  n_reuse=$(grep -Ec '^[[:space:]]*proxy_ssl_session_reuse[[:space:]]+off[[:space:]]*;' "$f" || true)
  if [ "$n_name" -eq 0 ]; then
    err "$f: no 'proxy_ssl_name \$host;' directives found — 443 origin SNI config missing?"
  elif [ "$n_reuse" -lt "$n_name" ]; then
    err "$f: $n_name proxy_ssl_name directive(s) but only $n_reuse proxy_ssl_session_reuse off — every 443 origin location needs session reuse off."
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "[origin-ka-config] FAILED — see errors above (invariant: 443 origin reuse blocked at every layer)." >&2
  exit 1
fi
echo "[origin-ka-config] OK: OpenResty origin upstreams set keepalive 0; Angie carries none; every 443 origin location disables TLS session reuse."
