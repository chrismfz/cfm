#!/usr/bin/env bash
# check_site_cache_config.sh — static regression gate for the Site Cache edge
# config invariant (Phase 3b, Tier A static caching; see docs/site-cache-design.md).
#
# WHY THIS EXISTS
# CFM ripped out a GLOBAL, unconditional cache once because it broke redirects,
# SSO, webmail and cPanel. The whole design turns that around: caching is
# BYPASS-BY-DEFAULT, flipped on per-request only by cfm_cache.static_gate(). A
# conf refactor that activates proxy_cache WITHOUT the bypass gate would silently
# reintroduce exactly the failure that burned us. The Lua unit tests never read
# the edge config, so this gate asserts, purely by static inspection of the
# reference confs:
#
#   both confs (openresty.conf, angie.conf)
#     * the cfm_static cache zone is declared (proxy_cache_path .../cfm_static).
#     * $cfm_cache_skip is declared and DEFAULTS TO "1" (bypass); it is never
#       set to "0" anywhere in the conf (that flip only ever comes from Lua).
#     * EVERY location that activates `proxy_cache cfm_static;` ALSO carries
#       `proxy_cache_bypass $cfm_cache_skip;` AND `proxy_no_cache
#       $cfm_cache_skip;` — bypass-by-default, both serve-side and store-side.
#     * Set-Cookie is never added to proxy_ignore_headers (nginx must keep NOT
#       caching a response that carries Set-Cookie).
#   parity
#     * both confs activate proxy_cache on the same number of locations (a cache
#       location added to one edge but not the other is a drift bug).
#
# Like check_origin_ka_config.sh, this does NOT replace live validation (the
# release checklist + a two-vhost box test) — it just stops the trivial
# "someone activated proxy_cache without the bypass gate" regression.
#
# A guardrail that cannot run its matcher must FAIL, never report OK (CLAUDE.md
# §5): awk/grep are POSIX-base (not ripgrep), and every expected anchor has a
# presence check that fails when absent.

set -euo pipefail
cd "$(dirname "$0")/../.."

ORT=configs/openresty.conf
ANG=configs/angie.conf
fail=0
err() { echo "❌ [site-cache-config] $*" >&2; fail=1; }

for f in "$ORT" "$ANG"; do
  [ -f "$f" ] || { err "$f: missing — cannot verify Site Cache config."; continue; }

  # ── (a) location-aware bypass-by-default (the real regression guard) ─────────
  # For each location whose body activates `proxy_cache cfm_static;`, require
  # BOTH bypass directives keyed on $cfm_cache_skip. Brace depth counting
  # tolerates the nested access_by_lua_block { ... } inside the location.
  missing=$(awk '
    !loc && /^[[:space:]]*location[[:space:]].*\{/ {
      loc=1; body=$0 "\n"; locline=NR
      t=$0; o=gsub(/\{/,"",t); u=$0; c=gsub(/\}/,"",u); d=o-c
      next
    }
    loc {
      body=body $0 "\n"
      t=$0; o=gsub(/\{/,"",t); u=$0; c=gsub(/\}/,"",u); d+=o-c
      if (d<=0) {
        if (body ~ /proxy_cache[[:space:]]+cfm_static[[:space:]]*;/) {
          m=""
          if (body !~ /proxy_cache_bypass[[:space:]]+\$cfm_cache_skip[[:space:]]*;/) m=m " proxy_cache_bypass-$cfm_cache_skip"
          if (body !~ /proxy_no_cache[[:space:]]+\$cfm_cache_skip[[:space:]]*;/)     m=m " proxy_no_cache-$cfm_cache_skip"
          if (m!="") print "location@line" locline ":" m
        }
        loc=0; body=""
      }
    }
  ' "$f")
  if [ -n "$missing" ]; then
    while IFS= read -r linfo; do
      err "$f: cache $linfo — a proxy_cache location without the bypass-by-default gate reintroduces unconditional caching."
    done <<< "$missing"
  fi

  # ── (b) presence: the conf must actually carry each anchor at least once ─────
  if ! grep -Eq '^[[:space:]]*proxy_cache_path[[:space:]]+/var/cache/nginx/cfm_static[[:space:]]' "$f"; then
    err "$f: no 'proxy_cache_path .../cfm_static' zone declared — Tier A config missing?"
  fi
  if ! grep -Eq '^[[:space:]]*set[[:space:]]+\$cfm_cache_skip[[:space:]]+"1";' "$f"; then
    err "$f: \$cfm_cache_skip is not declared with its bypass-by-default value \"1\"."
  fi
  if ! grep -Eq '^[[:space:]]*proxy_cache[[:space:]]+cfm_static[[:space:]]*;' "$f"; then
    err "$f: no 'proxy_cache cfm_static;' anywhere — did Tier A activation get removed? (this gate must verify something)"
  fi
  for d in 'proxy_cache_bypass[[:space:]]+\$cfm_cache_skip' 'proxy_no_cache[[:space:]]+\$cfm_cache_skip'; do
    if ! grep -Eq "^[[:space:]]*$d[[:space:]]*;" "$f"; then
      err "$f: no '$(echo "$d" | sed 's/\[\[:space:\]\]+/ /g');' directive anywhere — bypass-by-default gate missing."
    fi
  done

  # ── (c) negatives: never cache-by-default, never ignore Set-Cookie ───────────
  if grep -Eq '^[[:space:]]*set[[:space:]]+\$cfm_cache_skip[[:space:]]+"0";' "$f"; then
    err "$f: \$cfm_cache_skip is set to \"0\" in the conf — the cache-on flip must come ONLY from cfm_cache.static_gate(), never a static default."
  fi
  if grep -Eiq '^[[:space:]]*proxy_ignore_headers[[:space:]].*Set-Cookie' "$f"; then
    err "$f: proxy_ignore_headers lists Set-Cookie — nginx would then CACHE responses that set a cookie (session leak). Never do this in a cache path."
  fi
done

# ── (d) parity: both edges activate proxy_cache on the same # of locations ─────
ort_n=$(grep -Ec '^[[:space:]]*proxy_cache[[:space:]]+cfm_static[[:space:]]*;' "$ORT" || true)
ang_n=$(grep -Ec '^[[:space:]]*proxy_cache[[:space:]]+cfm_static[[:space:]]*;' "$ANG" || true)
if [ "$ort_n" != "$ang_n" ]; then
  err "openresty.conf has $ort_n 'proxy_cache cfm_static;' location(s) but angie.conf has $ang_n — the two edges must cache the same places."
fi

if [ "$fail" -ne 0 ]; then
  echo "[site-cache-config] FAILED — see errors above (invariant: caching is bypass-by-default; the gate must come from Lua)." >&2
  exit 1
fi
echo "[site-cache-config] OK: cfm_static zone declared, \$cfm_cache_skip bypass-by-default, every proxy_cache location gated, Set-Cookie never ignored, openresty↔angie parity ($ort_n locations)."
