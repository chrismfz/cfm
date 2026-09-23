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
#     * EVERY location that activates `proxy_cache cfm_static;` (or a
#       cfm_micro_<n>s bucket) ALSO carries `proxy_cache_bypass $cfm_cache_skip
#       $cfm_req_auth;` AND `proxy_no_cache $cfm_cache_skip $cfm_cache_non200
#       $cfm_req_auth;` — bypass-by-default (serve + store), the only-200 rail
#       and the credentialed-request rail — plus buffering ON (nginx stores
#       nothing off it), the whole key
#       `g$cfm_cache_gen|$server_addr|$cf_xfp://$host$request_uri`, the per-tier
#       proxy_cache_lock_timeout (1s static, 5s micro), and the forwarded-header
#       pins (X-Forwarded-Host = $host, the rest dropped). Full-line and
#       after-`;` comments are stripped before matching, so a commented-out
#       directive never satisfies a check, and the parser must open every
#       location in the file (a header it cannot read fails, not skips).
#     * `map $http_authorization $cfm_req_auth` exists with default "1" (so
#       `Authorization: 0`, which a raw predicate reads as false, still counts).
#     * the only-200 rail: a `map $upstream_status $cfm_cache_non200` block is
#       defined AND fed into proxy_no_cache, so a 3xx/4xx/5xx is NEVER stored
#       whatever the origin sends (a cached 30x once broke webmail/cPanel/SSO).
#     * Set-Cookie, Vary and Cache-Control are never added to
#       proxy_ignore_headers (nginx must keep NOT caching a response that sets a
#       cookie or says private/no-store, and must keep one copy per Vary
#       variant), and proxy_cache_methods never lists a non-GET/HEAD method.
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
  # Comments are STRIPPED before matching (and before brace counting): the rail
  # comments quote the very directives this checks, so matching raw text let a
  # commented-out gate pass (verified by mutation). Only two comment forms are
  # stripped — a full-line comment, and a trailing one after a `;` — because a
  # # can legitimately sit INSIDE a value (a regex location, inline Lua, a
  # quoted string) and cutting there would hide the rest of the line. The
  # confs use no other comment form. As a backstop, the number of locations
  # this parser opens must equal the number of location lines in the file, so
  # a header it fails to recognise fails the guard instead of going unchecked.
  parsed=$(awk '
    { ln=$0; if (ln ~ /^[[:space:]]*#/) ln=""; else sub(/;[[:space:]]*#.*$/,";",ln) }
    !loc && ln ~ /^[[:space:]]*location[[:space:]].*\{/ {
      loc=1; body=ln "\n"; locline=NR; nloc++
      t=ln; o=gsub(/\{/,"",t); u=ln; c=gsub(/\}/,"",u); d=o-c
      next
    }
    loc {
      body=body ln "\n"
      t=ln; o=gsub(/\{/,"",t); u=ln; c=gsub(/\}/,"",u); d+=o-c
      if (d<=0) {
        # Tier A (cfm_static) and Tier B (cfm_micro_<n>s) cache locations share
        # the same bypass-by-default + only-200 + buffering rails.
        if (body ~ /proxy_cache[[:space:]]+(cfm_static|cfm_micro_[0-9]+s)[[:space:]]*;/) {
          m=""
          if (body !~ /proxy_cache_bypass[[:space:]]+\$cfm_cache_skip[[:space:];]/) m=m " proxy_cache_bypass-$cfm_cache_skip"
          if (body !~ /proxy_no_cache[[:space:]]+\$cfm_cache_skip[[:space:];]/)      m=m " proxy_no_cache-$cfm_cache_skip"
          # Request-identity rails (see the http-level note in the confs). nginx
          # does NOT bypass on Authorization by itself, so a credentialed 200
          # (basic auth / Directory Privacy) would be replayed to anonymous
          # visitors: $cfm_req_auth (a map on $http_authorization, so the value
          # "0" still counts) must ride BOTH predicates.
          if (body !~ /proxy_cache_bypass[[:space:]][^;]*\$cfm_req_auth[[:space:];]/) m=m " proxy_cache_bypass-$cfm_req_auth(credentialed-response-could-be-served)"
          if (body !~ /proxy_no_cache[[:space:]][^;]*\$cfm_req_auth[[:space:];]/)     m=m " proxy_no_cache-$cfm_req_auth(credentialed-response-could-be-stored)"
          # The WHOLE key is pinned: purge generation first (else purge is a
          # silent no-op), the destination IP (the origin is chosen by it, so a
          # request to another IP with a spoofed Host would poison this vhost),
          # the scheme the origin is told ($cf_xfp), then host and full URI
          # (dropping either shares one copy across vhosts or URLs).
          if (body !~ /proxy_cache_key[[:space:]]+"g[$]cfm_cache_gen[|][$]server_addr[|][$]cf_xfp:\/\/[$]host[$]request_uri"[[:space:]]*;/) m=m " proxy_cache_key-must-be-g$cfm_cache_gen|$server_addr|$cf_xfp://$host$request_uri"
          # Lock wait, per tier: it must outlast the fill (else a cold-key burst
          # all reaches the origin) yet bounds the queue on an uncacheable key.
          # Static files fill fast: 1s. HTML renders slowly: 5s.
          if (body ~ /proxy_cache[[:space:]]+cfm_static[[:space:]]*;/ && body !~ /proxy_cache_lock_timeout[[:space:]]+1s[[:space:]]*;/)            m=m " static-proxy_cache_lock_timeout-must-be-1s"
          if (body ~ /proxy_cache[[:space:]]+cfm_micro_[0-9]+s[[:space:]]*;/ && body !~ /proxy_cache_lock_timeout[[:space:]]+5s[[:space:]]*;/)   m=m " micro-proxy_cache_lock_timeout-must-be-5s(cold-fill-stampede)"
          # Forwarded headers an app may build URLs or routes from are not in the
          # key: X-Forwarded-Host is pinned to $host and the rest are dropped.
          if (body !~ /proxy_set_header[[:space:]]+X-Forwarded-Host[[:space:]]+\$host[[:space:]]*;/) m=m " X-Forwarded-Host-not-pinned-to-$host"
          nh=split("X-Forwarded-Server X-Forwarded-Port X-Forwarded-Scheme X-Forwarded-Protocol X-Forwarded-Prefix X-Forwarded-Ssl X-Forwarded-Uri X-Forwarded-Path X-Host X-Original-Host X-Original-URL X-Original-Uri X-Rewrite-URL Forwarded Front-End-Https X-Url-Scheme X-Scheme X-HTTP-Method-Override X-HTTP-Method X-Method-Override", H, " ")
          for (i=1; i<=nh; i++) {
            if (body !~ ("proxy_set_header[[:space:]]+" H[i] "[[:space:]]+\"\"[[:space:]]*;")) m=m " " H[i] "-not-dropped"
          }
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
          # A Tier B micro location is reached ONLY via ngx.exec from the cfm.lua
          # allow-path (Phase B3b); it must be `internal;` so a direct request can
          # never hit an un-enforced cache-serving location.
          if (body ~ /proxy_cache[[:space:]]+cfm_micro_[0-9]+s[[:space:]]*;/ && body !~ /[[:space:]]internal[[:space:]]*;/) m=m " missing-internal(micro-location-directly-reachable)"
          # …and it MUST override the server-level access_by_lua_file cfm.lua with
          # its own access handler. Without it the location inherits cfm.lua, which
          # re-runs on the ngx.exec internal redirect, reaches Step 4, execs here
          # again, and loops until nginx 500s (internal redirection cycle) —
          # site-breaking the moment MICRO_CACHE_ENFORCE is armed, and the pcall
          # around the gate cannot catch it (nginx redirect machinery, not a Lua
          # error). Every cfm.lua-bypass location carries this override.
          # Match the DIRECTIVE shape (access_by_lua_block {), not the bare
          # substring: the per-location comment itself contains the words
          # "access_by_lua_file cfm.lua", which would satisfy a substring !~ test
          # and let a deletion of just the directive (comment kept) pass — the
          # exact regression this must catch. The directive shape never appears
          # in the comment.
          if (body ~ /proxy_cache[[:space:]]+cfm_micro_[0-9]+s[[:space:]]*;/ && body !~ /access_by_lua_block[[:space:]]*\{/) m=m " missing-access-override(cfm.lua-re-entry-redirect-loop-500)"
          if (m!="") print "location@line" locline ":" m
        }
        loc=0; body=""
      }
    }
    END { print "__NLOC__ " nloc+0 }
  ' "$f")
  nloc_parsed=$(sed -n 's/^__NLOC__ //p' <<< "$parsed")
  missing=$(grep -v '^__NLOC__ ' <<< "$parsed" || true)
  nloc_file=$(grep -Ec '^[[:space:]]*location[[:space:]]' "$f" || true)
  if [ -z "$nloc_parsed" ] || [ "$nloc_parsed" != "$nloc_file" ]; then
    err "$f: the location parser opened ${nloc_parsed:-?} locations but the file has $nloc_file location lines — a header it cannot recognise (e.g. { on the next line, or a comment form it does not strip) would go UNCHECKED; fix the conf or the parser."
  fi
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
  if ! grep -Eq '^[[:space:]]*proxy_cache_bypass[[:space:]]+\$cfm_cache_skip[[:space:];]' "$f"; then
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

  # Credentialed-request rail: the map the cache predicates key on. A predicate
  # treats "0" as false, so the map (any non-empty Authorization → "1") is what
  # makes "Authorization: 0" bypass too; it must exist and default to "1".
  auth_map=$(awk '
    /^[[:space:]]*map[[:space:]]+\$http_authorization[[:space:]]+\$cfm_req_auth[[:space:]]*\{/ { inm=1; next }
    inm && /^[[:space:]]*\}/ { inm=0 }
    inm { sub(/#.*$/,""); gsub(/[[:space:]]+/," "); print }
  ' "$f")
  if ! grep -Eq '^[[:space:]]*map[[:space:]]+\$http_authorization[[:space:]]+\$cfm_req_auth[[:space:]]*\{' "$f"; then
    err "$f: no 'map \$http_authorization \$cfm_req_auth { … }' — the credentialed-request rail the cache predicates key on is undefined."
  elif ! grep -Eq '^ ?default "1"; ?$' <<< "$auth_map" || ! grep -Eq '^ ?"" ""; ?$' <<< "$auth_map"; then
    err "$f: \$cfm_req_auth map must be exactly: default \"1\" (any Authorization → bypass) and \"\" \"\" (none) — got: $(tr '\n' '|' <<< "$auth_map")"
  fi

  # ── (b2) Tier B micro-cache zones (Phase B1): all six TTL buckets declared ───
  # Each zone's dir must exist before `-t` (the daemon + installers provision all
  # six), and a partial set would [emerg] at reload the moment a location names a
  # missing zone. Assert every bucket zone AND its internal location is present in
  # BOTH confs (the loop runs per conf, so a bucket added to one edge but not the
  # other fails here — the parity guard). The per-location rails (bypass gate,
  # only-200, buffering, internal) are checked in section (a) above.
  for ttl in 1s 2s 5s 10s 30s 60s; do
    if ! grep -Eq "^[[:space:]]*proxy_cache_path[[:space:]]+/var/cache/nginx/cfm_micro_${ttl}[[:space:]]" "$f"; then
      err "$f: no 'proxy_cache_path .../cfm_micro_${ttl}' zone declared — Tier B micro bucket missing (all of {1,2,5,10,30,60}s are required)."
    fi
    # (b3, Phase B3a) each bucket has its internal @cfm_micro_<n>s location.
    if ! grep -Eq "^[[:space:]]*location[[:space:]]+@cfm_micro_${ttl}[[:space:]]*\{" "$f"; then
      err "$f: no 'location @cfm_micro_${ttl} { … }' — Tier B micro bucket has a zone but no internal serving location (B3b's ngx.exec would 500)."
    fi
  done

  # ── (c) negatives: never cache-by-default, never ignore Set-Cookie ───────────
  if grep -Eq '^[[:space:]]*set[[:space:]]+\$cfm_cache_skip[[:space:]]+"0";' "$f"; then
    err "$f: \$cfm_cache_skip is set to \"0\" in the conf — the cache-on flip must come ONLY from cfm_cache.static_gate(), never a static default."
  fi
  if grep -Eiq '^[[:space:]]*proxy_ignore_headers[[:space:]].*Set-Cookie' "$f"; then
    err "$f: proxy_ignore_headers lists Set-Cookie — nginx would then CACHE responses that set a cookie (session leak). Never do this in a cache path."
  fi
  # Vary: ignoring it stores ONE variant (one language, one encoding, one
  # mobile/desktop page) and serves it to every client.
  if grep -Eiq '^[[:space:]]*proxy_ignore_headers[[:space:]].*[[:space:]]Vary([[:space:];]|$)' "$f"; then
    err "$f: proxy_ignore_headers lists Vary — nginx would store one variant and serve it to every client. Never do this in a cache path."
  fi
  # Cache-Control: the origin's private / no-store / no-cache is the §4 rail
  # that keeps per-user pages out. Ignoring it needs a REPLACEMENT rail (a map
  # on the origin Cache-Control fed into proxy_no_cache) in the same change.
  if grep -Eiq '^[[:space:]]*proxy_ignore_headers[[:space:]].*Cache-Control' "$f"; then
    err "$f: proxy_ignore_headers lists Cache-Control — the origin's private/no-store would no longer keep per-user pages out. Add a replacement rail and update this guard in the same change."
  fi
  # GET/HEAD only (the nginx default): a cached POST replays one form submission
  # result to everyone.
  if grep -Eiq '^[[:space:]]*proxy_cache_methods[[:space:]].*(POST|PUT|PATCH|DELETE)' "$f"; then
    err "$f: proxy_cache_methods lists a non-GET/HEAD method — a cached POST/PUT result would be served to every client."
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

# ── (e) micro-zone parity: the six cfm_micro_<n>s declarations must be BYTE-for-
# byte identical between the two edges (not just present). Presence in both (b2)
# already catches a missing bucket; this also catches a per-bucket param drift
# (keys_zone size, max_size, inactive) between angie and openresty — a bucket B2
# routes to must behave the same on either edge.
micro_zones() {
  grep -E '^[[:space:]]*proxy_cache_path[[:space:]]+/var/cache/nginx/cfm_micro_' "$1" \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+/ /g' | sort
}
if ! diff <(micro_zones "$ORT") <(micro_zones "$ANG") >/dev/null 2>&1; then
  err "openresty.conf and angie.conf declare the micro-cache zones DIFFERENTLY (a per-bucket keys_zone/max_size/inactive drift); the six cfm_micro_<n>s zones must be identical on both edges. Divergence:"
  diff <(micro_zones "$ORT") <(micro_zones "$ANG") 2>/dev/null | sed 's/^/       /' >&2 || true
fi

# ── (f) micro-LOCATION body parity: the full @cfm_micro_<n>s serving blocks must
# be byte-identical between the two edges. (b3) only checks the header is present
# in both; this diffs the BODIES so a per-bucket drift in proxy_cache_valid, the
# cache key ($cfm_cache_gen prefix), or any rail between angie and openresty is
# caught — both edges are ngx.exec targets B3b routes to and must cache the same
# way. Brace-depth capture tolerates any (future) nested block in a location.
micro_blocks() {
  awk '
    !loc && /^[[:space:]]*location[[:space:]]+@cfm_micro_[0-9]+s[[:space:]]*\{/ {
      loc=1; buf=$0 "\n"
      t=$0; o=gsub(/\{/,"",t); u=$0; c=gsub(/\}/,"",u); d=o-c; next
    }
    loc {
      buf=buf $0 "\n"
      t=$0; o=gsub(/\{/,"",t); u=$0; c=gsub(/\}/,"",u); d+=o-c
      if (d<=0) { printf "%s", buf; loc=0; buf="" }
    }
  ' "$1"
}
if ! diff <(micro_blocks "$ORT") <(micro_blocks "$ANG") >/dev/null 2>&1; then
  err "openresty.conf and angie.conf define the @cfm_micro_<n>s LOCATIONS differently (a per-bucket TTL / cache-key / rail drift); the micro serving blocks must be byte-identical on both edges. Divergence:"
  diff <(micro_blocks "$ORT") <(micro_blocks "$ANG") 2>/dev/null | sed 's/^/       /' >&2 || true
fi

if [ "$fail" -ne 0 ]; then
  echo "[site-cache-config] FAILED — see errors above (invariant: caching is bypass-by-default; the gate must come from Lua)." >&2
  exit 1
fi
echo "[site-cache-config] OK: cfm_static zone declared, Tier B micro buckets {1,2,5,10,30,60}s (zone + internal @cfm_micro_<n>s location) declared in both confs, \$cfm_cache_skip bypass-by-default, every proxy_cache location gated + buffered + (micro) internal, only-200 rail (\$cfm_cache_non200) enforced, request-identity rails (\$cfm_req_auth bypass + map, full g\$cfm_cache_gen|\$server_addr|\$cf_xfp:// key, per-tier lock_timeout, forwarded headers pinned) on every cache location, every location parsed, Set-Cookie/Vary/Cache-Control never ignored, GET/HEAD-only cache methods, openresty↔angie parity ($ort_n static locations)."
