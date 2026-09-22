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
#       $cfm_cache_skip $cfm_cache_non200;` — bypass-by-default (serve + store)
#       plus the only-200 rail, and buffering ON (nginx stores nothing off it).
#     * the only-200 rail: a `map $upstream_status $cfm_cache_non200` block is
#       defined AND fed into proxy_no_cache, so a 3xx/4xx/5xx is NEVER stored
#       whatever the origin sends (a cached 30x once broke webmail/cPanel/SSO).
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
          if (body !~ /proxy_no_cache[[:space:]]+\$cfm_cache_skip[[:space:];]/)      m=m " proxy_no_cache-$cfm_cache_skip"
          # Only a 200 may ever be STORED: $cfm_cache_non200 (a map on
          # $upstream_status) must ride proxy_no_cache, so a 3xx/4xx/5xx can never
          # be cached whatever the origin sends — a cached 30x once broke
          # webmail/cPanel/SSO, the reason CFM ripped out its global cache.
          if (body !~ /proxy_no_cache[[:space:]]+\$cfm_cache_skip[[:space:]]+\$cfm_cache_non200/) m=m " proxy_no_cache-$cfm_cache_non200(non-200-could-cache)"
          # A cache location MUST buffer: nginx writes to proxy_cache only on the
          # buffered upstream path, so `proxy_buffering off` here makes caching a
          # silent no-op (stores nothing, never a HIT). Require an explicit ON
          # and forbid an OFF in the same location.
          if (body ~ /proxy_buffering[[:space:]]+off[[:space:]]*;/)                 m=m " proxy_buffering-off(cache-would-store-nothing)"
          if (body !~ /proxy_buffering[[:space:]]+on[[:space:]]*;/)                 m=m " missing-proxy_buffering-on"
          if (m!="") print "location@line" locline ":" m
        }
        loc=0; body=""
      }
    }
  ' "$f")
  if [ -n "$missing" ]; then
    while IFS= read -r linfo; do
      err "$f: cache $linfo — a proxy_cache location is missing a required directive (no bypass gate → unconditional caching; buffering off → nginx silently caches NOTHING)."
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
  if ! grep -Eq '^[[:space:]]*proxy_cache_bypass[[:space:]]+\$cfm_cache_skip[[:space:]]*;' "$f"; then
    err "$f: no 'proxy_cache_bypass \$cfm_cache_skip;' directive anywhere — bypass-by-default gate missing."
  fi
  if ! grep -Eq '^[[:space:]]*proxy_no_cache[[:space:]]+\$cfm_cache_skip[[:space:];]' "$f"; then
    err "$f: no 'proxy_no_cache \$cfm_cache_skip …;' directive anywhere — bypass-by-default gate missing."
  fi
  # 200-only rail: the map must be defined AND referenced by proxy_no_cache.
  if ! grep -Eq '^[[:space:]]*map[[:space:]]+\$upstream_status[[:space:]]+\$cfm_cache_non200[[:space:]]*\{' "$f"; then
    err "$f: no 'map \$upstream_status \$cfm_cache_non200 { … }' block — the 200-only rail is undefined (a 3xx/4xx/5xx could be cached)."
  fi
  if ! grep -Eq '^[[:space:]]*proxy_no_cache[[:space:]]+\$cfm_cache_skip[[:space:]]+\$cfm_cache_non200' "$f"; then
    err "$f: \$cfm_cache_non200 is never fed into a proxy_no_cache directive — non-200 responses could be stored."
  fi

  # ── (c) negatives: never cache-by-default, never ignore Set-Cookie ───────────
  if grep -Eq '^[[:space:]]*set[[:space:]]+\$cfm_cache_skip[[:space:]]+"0";' "$f"; then
    err "$f: \$cfm_cache_skip is set to \"0\" in the conf — the cache-on flip must come ONLY from cfm_cache.static_gate(), never a static default."
  fi
  if grep -Eiq '^[[:space:]]*proxy_ignore_headers[[:space:]].*Set-Cookie' "$f"; then
    err "$f: proxy_ignore_headers lists Set-Cookie — nginx would then CACHE responses that set a cookie (session leak). Never do this in a cache path."
  fi
done

# ── (d) parity: both edges cache the SAME locations (not just the same count) ──
# Emit each cache location's own `location …{` header line (whitespace-normalised,
# sorted) per conf and diff them. Comparing counts alone would pass a refactor
# that added a cache to one path in openresty and a DIFFERENT path in angie —
# the exact drift this guard exists to stop.
cache_locs() {
  awk '
    !loc && /^[[:space:]]*location[[:space:]].*\{/ {
      loc=1; body=$0 "\n"; first=$0
      t=$0; o=gsub(/\{/,"",t); u=$0; c=gsub(/\}/,"",u); d=o-c
      next
    }
    loc {
      body=body $0 "\n"
      t=$0; o=gsub(/\{/,"",t); u=$0; c=gsub(/\}/,"",u); d+=o-c
      if (d<=0) {
        if (body ~ /proxy_cache[[:space:]]+cfm_static[[:space:]]*;/) {
          gsub(/^[[:space:]]+/,"",first); print first
        }
        loc=0; body=""
      }
    }
  ' "$1" | sort
}
ort_n=$(grep -Ec '^[[:space:]]*proxy_cache[[:space:]]+cfm_static[[:space:]]*;' "$ORT" || true)
ang_n=$(grep -Ec '^[[:space:]]*proxy_cache[[:space:]]+cfm_static[[:space:]]*;' "$ANG" || true)
if ! diff <(cache_locs "$ORT") <(cache_locs "$ANG") >/dev/null 2>&1; then
  err "openresty.conf and angie.conf cache DIFFERENT locations (not merely a count mismatch); the two edges must cache the same paths. Divergence:"
  diff <(cache_locs "$ORT") <(cache_locs "$ANG") 2>/dev/null | sed 's/^/       /' >&2 || true
fi

if [ "$fail" -ne 0 ]; then
  echo "[site-cache-config] FAILED — see errors above (invariant: caching is bypass-by-default; the gate must come from Lua)." >&2
  exit 1
fi
echo "[site-cache-config] OK: cfm_static zone declared, \$cfm_cache_skip bypass-by-default, every proxy_cache location gated + buffered, only-200 rail (\$cfm_cache_non200) enforced, Set-Cookie never ignored, openresty↔angie parity ($ort_n locations)."
