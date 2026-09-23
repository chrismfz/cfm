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
#     * $cfm_cache_skip is declared and DEFAULTS TO "1" (bypass); the conf never
#       sets it to anything else, nor assigns it from inline Lua (the flip only
#       ever comes from cfm_cache.lua).
#     * EVERY location that activates `proxy_cache cfm_static;` (or a
#       cfm_micro_<n>s bucket) ALSO carries `proxy_cache_bypass $cfm_cache_skip
#       $cfm_req_auth;` AND `proxy_no_cache $cfm_cache_skip $cfm_cache_non200
#       $cfm_req_auth;` — bypass-by-default (serve + store), the only-200 rail
#       and the credentialed-request rail — plus buffering ON (nginx stores
#       nothing off it), the whole key
#       `g$cfm_cache_gen|$server_addr|$scheme|$cf_xfp://$host$request_uri`, the
#       per-tier proxy_cache_lock_timeout (1s static, 5s micro), and the
#       forwarded-header pins (X-Forwarded-Host = $host, the rest dropped; each
#       set exactly once), with the lock itself on. Any other cache zone is
#       rejected. The conf is lexed like nginx (quotes, escapes, # comments) and
#       split into statements, and every rail must match a DIRECTIVE at a
#       statement start — comment text, a Lua -- comment or a quoted value never
#       satisfies one, and a one-line location or { on the next line is parsed
#       like any other. Every location statement must be parsed and every
#       proxy_cache directive must sit in a checked cache location (a
#       mis-parse fails, never skips).
#     * `map $http_authorization $cfm_req_auth` is the only writer of
#       $cfm_req_auth (no other map, set, set_by_lua or inline-Lua assignment,
#       in any letter case) and holds exactly `default "1"` and `"" ""` (so
#       `Authorization: 0`, which a raw predicate reads as false, still counts,
#       and no extra key can exempt a credential).
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

  # ── (a) statement-aware checks (the real regression guard) ──────────────────
  # The conf is parsed the way nginx lexes it, then split into STATEMENTS:
  #   * per line, a quote opens only at a token start (line start or after
  #     whitespace ; { } ( , = [); inside quotes a backslash escapes the next
  #     character and ; { } are MASKED, so they never act as a statement or
  #     block boundary (a regex location such as "^/a{2}$" is one token);
  #   * outside quotes a # at a token start begins a comment to end of line;
  #   * every ; ends a statement and every { / } is its own boundary, so each
  #     directive starts a statement no matter how lines are laid out (a
  #     one-line location, two directives on a line, { on the next line).
  # Every rail below must match a DIRECTIVE at a statement start, so comment
  # text, a Lua -- comment or a quoted value can never satisfy one (all three
  # used to pass by mutation). Brace depth then delimits each top-level
  # location; any location holding a proxy_cache (other than off) is checked.
  # Backstops, counted as statement-start tokens over the WHOLE file:
  #   * location tokens == locations parsed (a nested or swallowed location);
  #   * proxy_cache tokens == those inside checked cache locations (one at
  #     server/http level is inherited ungated by location /).
  # Also enforced here, token-based and case-insensitive where nginx is
  # (variable names and header names): $cfm_req_auth has exactly one writer,
  # its map, holding exactly default "1" and "" ""; $cfm_cache_skip is only
  # ever set to "1" in the conf; proxy_ignore_headers never lists Set-Cookie,
  # Vary or Cache-Control; proxy_cache_methods never lists a non-GET/HEAD one.
  # Inline Lua is lexed by the same rules; a Lua quirk (a # length operator at
  # a token start, a brace in a -- comment) can only remove text or unbalance
  # braces, which surfaces as a missing rail or a count mismatch, never a pass.
  parsed=$(awk '
    function mask(c) { if (c == ";") return "\001"; if (c == "{") return "\002"; if (c == "}") return "\003"; return c }
    function strip(s,   i, n, ch, q, prev, out) {
      q = ""; prev = " "; out = ""; n = length(s)
      for (i = 1; i <= n; i++) {
        ch = substr(s, i, 1)
        if (ch == "\\" && i < n) { out = out ch mask(substr(s, i + 1, 1)); i++; prev = "x"; continue }
        if (q != "") {
          if (ch == q) { q = ""; out = out ch; prev = ch; continue }
          out = out mask(ch); continue
        }
        if ((ch == "\"" || ch == "\047") && prev ~ /[[:space:];{}(,=[]/) { q = ch; out = out ch; prev = ch; continue }
        if (ch == "#" && prev ~ /[[:space:];{}]/) break
        out = out ch; prev = ch
      }
      return out
    }
    function cnt(str, re,   n) { n = 0; while (match(str, re)) { n++; str = substr(str, RSTART + RLENGTH) } return n }
    function check_loc(   m, nz, lb, i, nh, H, st, mi) {
      nz = cnt(body, A "proxy_cache[[:space:]]+[^[:space:];]+[[:space:]]*;") - cnt(body, A "proxy_cache[[:space:]]+off[[:space:]]*;")
      if (nz <= 0) return
      ncache++; cache_toks += nz; m = ""
      if (nz != 1) m = m " more-than-one-proxy_cache"
      st = (body ~ (A "proxy_cache[[:space:]]+cfm_static[[:space:]]*;"))
      mi = (body ~ (A "proxy_cache[[:space:]]+cfm_micro_[0-9]+s[[:space:]]*;"))
      if (!st && !mi) m = m " unknown-cache-zone(only-cfm_static-or-cfm_micro_Ns)"
      # Bypass-by-default: serve AND store gated on $cfm_cache_skip.
      if (body !~ (A "proxy_cache_bypass[[:space:]]+[$]cfm_cache_skip[[:space:];]")) m = m " proxy_cache_bypass-$cfm_cache_skip"
      if (body !~ (A "proxy_no_cache[[:space:]]+[$]cfm_cache_skip[[:space:];]"))     m = m " proxy_no_cache-$cfm_cache_skip"
      # nginx does NOT bypass on Authorization by itself, so a credentialed 200
      # (basic auth / Directory Privacy) would be replayed to anonymous
      # visitors: $cfm_req_auth (a map, so the value "0" still counts) must
      # ride BOTH predicates.
      if (body !~ (A "proxy_cache_bypass[[:space:]][^;]*[$]cfm_req_auth[[:space:];]")) m = m " proxy_cache_bypass-$cfm_req_auth(credentialed-response-could-be-served)"
      if (body !~ (A "proxy_no_cache[[:space:]][^;]*[$]cfm_req_auth[[:space:];]"))     m = m " proxy_no_cache-$cfm_req_auth(credentialed-response-could-be-stored)"
      # Only a 200 is ever STORED (a cached 30x once broke webmail/cPanel/SSO).
      if (body !~ (A "proxy_no_cache[[:space:]]+[$]cfm_cache_skip[[:space:]]+[$]cfm_cache_non200")) m = m " proxy_no_cache-$cfm_cache_non200(non-200-could-cache)"
      # The WHOLE key: purge generation first (else purge is a silent no-op),
      # the destination IP (the origin is chosen by it), the listener scheme
      # ($scheme: :9080 and :9043 reach different origin ports) AND the scheme
      # the origin is told ($cf_xfp: differs behind a trusted peer) — either
      # alone merges two origin answers — then host and full URI.
      if (body !~ (A "proxy_cache_key[[:space:]]+\"g[$]cfm_cache_gen[|][$]server_addr[|][$]scheme[|][$]cf_xfp://[$]host[$]request_uri\"[[:space:]]*;")) m = m " proxy_cache_key-must-be-g$cfm_cache_gen|$server_addr|$scheme|$cf_xfp://$host$request_uri"
      # Anti-stampede: the lock ON, and its wait per tier (it must outlast the
      # fill, else a cold-key burst all reaches the origin, yet it bounds the
      # queue on an uncacheable key). Static files fill fast: 1s. HTML: 5s.
      if (body !~ (A "proxy_cache_lock[[:space:]]+on[[:space:]]*;")) m = m " proxy_cache_lock-must-be-on"
      if (st && body !~ (A "proxy_cache_lock_timeout[[:space:]]+1s[[:space:]]*;")) m = m " static-proxy_cache_lock_timeout-must-be-1s"
      if (mi && body !~ (A "proxy_cache_lock_timeout[[:space:]]+5s[[:space:]]*;")) m = m " micro-proxy_cache_lock_timeout-must-be-5s(cold-fill-stampede)"
      # Forwarded headers an app may build URLs or routes from are not in the
      # key: X-Forwarded-Host is pinned to $host and the rest are dropped, each
      # set exactly once (a second proxy_set_header for the same name, in any
      # case, is sent as a second header and undoes the pin).
      lb = tolower(body)
      if (body !~ (A "proxy_set_header[[:space:]]+X-Forwarded-Host[[:space:]]+[$]host[[:space:]]*;")) m = m " X-Forwarded-Host-not-pinned-to-$host"
      else if (cnt(lb, A "proxy_set_header[[:space:]]+x-forwarded-host[[:space:]]") != 1) m = m " X-Forwarded-Host-set-more-than-once"
      nh = split("X-Forwarded-Server X-Forwarded-Port X-Forwarded-Scheme X-Forwarded-Protocol X-Forwarded-Prefix X-Forwarded-Ssl X-Forwarded-Uri X-Forwarded-Path X-Host X-Original-Host X-Original-URL X-Original-Uri X-Rewrite-URL Forwarded Front-End-Https X-Url-Scheme X-Scheme X-HTTP-Method-Override X-HTTP-Method X-Method-Override", H, " ")
      for (i = 1; i <= nh; i++) {
        if (body !~ (A "proxy_set_header[[:space:]]+" H[i] "[[:space:]]+\"\"[[:space:]]*;")) m = m " " H[i] "-not-dropped"
        else if (cnt(lb, A "proxy_set_header[[:space:]]+" tolower(H[i]) "[[:space:]]") != 1) m = m " " H[i] "-set-more-than-once"
      }
      # A cache location MUST buffer: nginx writes to proxy_cache only on the
      # buffered upstream path (buffering off = silently caches NOTHING).
      if (body ~ (A "proxy_buffering[[:space:]]+off[[:space:]]*;")) m = m " proxy_buffering-off(cache-would-store-nothing)"
      if (body !~ (A "proxy_buffering[[:space:]]+on[[:space:]]*;")) m = m " missing-proxy_buffering-on"
      # A Tier B micro location is reached ONLY via ngx.exec from the cfm.lua
      # allow-path: it must be internal (never directly reachable) and must
      # override the inherited server-level access_by_lua_file cfm.lua, which
      # would otherwise re-run on the redirect, exec here again and loop until
      # nginx 500s (the pcall around the gate cannot catch that).
      if (mi && body !~ (A "internal[[:space:]]*;")) m = m " missing-internal(micro-location-directly-reachable)"
      if (mi && body !~ (A "access_by_lua_block[[:space:]]*[{]")) m = m " missing-access-override(cfm.lua-re-entry-redirect-loop-500)"
      if (m != "") print "ERR cache location@line" locline ":" m " — a proxy_cache location is missing a required rail (no bypass gate → unconditional caching; buffering off → nginx silently caches NOTHING)."
    }
    BEGIN { A = "\n[[:space:]]*" }
    {
      ln = strip($0)
      gsub(/;/, ";\n", ln); gsub(/[{]/, "{\n", ln); gsub(/[}]/, "\n}\n", ln)
      np = split(ln, P, "\n")
      for (j = 1; j <= np; j++) if (P[j] !~ /^[[:space:]]*$/) { K++; ST[K] = P[j]; SL[K] = NR }
    }
    END {
      all = "\n"
      for (k = 1; k <= K; k++) all = all ST[k] "\n"
      for (k = 1; k <= K; k++) {
        s = ST[k]
        if (!loc && s ~ /^[[:space:]]*location[[:space:]]/) { loc = 1; body = "\n"; locline = SL[k]; nloc++; d = 0; seen = 0 }
        if (loc) {
          body = body s "\n"
          if (s ~ /[{][[:space:]]*$/) { d++; seen = 1 }
          if (s ~ /^[[:space:]]*[}][[:space:]]*$/) d--
          if (seen && d <= 0) { check_loc(); loc = 0; body = "" }
        }
      }
      if (loc) print "ERR a location opened at line " locline " never closes — the parser lost track of braces, so nothing after it was checked."
      lt = cnt(all, A "location[[:space:]]")
      if (lt != nloc) print "ERR " nloc " top-level locations were parsed but the file has " lt " location statements — a nested or swallowed location would go UNCHECKED."
      ct = cnt(all, A "proxy_cache[[:space:]]+[^[:space:];]+[[:space:]]*;") - cnt(all, A "proxy_cache[[:space:]]+off[[:space:]]*;")
      if (ct != cache_toks) print "ERR " cache_toks " proxy_cache directives sit in checked cache locations but the file has " ct " — one outside any location (server/http level) is inherited UNGATED by location /."
      if (ncache == 0) print "ERR no cache location found at all — this gate must verify something."

      # Credentialed-request rail. nginx variable names are case-insensitive,
      # so every writer check runs on the lower-cased text.
      la = tolower(all)
      nmaps = cnt(la, A "map[[:space:]]+[^[:space:]]+[[:space:]]+[$]cfm_req_auth[[:space:]]*[{]")
      # a directive whose FIRST argument is $cfm_req_auth writes it (set,
      # set_by_lua*, perl_set, js_set, auth_request_set …); a map reading it is not.
      nwr = cnt(la, A "[a-z_]+[[:space:]]+[$]cfm_req_auth([[:space:];{]|$)") - cnt(la, A "map[[:space:]]+[$]cfm_req_auth[[:space:]]")
      nlua = cnt(la, "ngx[.]var[.]cfm_req_auth[[:space:]]*=[^=]") + cnt(la, "ngx[.]var[[][\"\047]cfm_req_auth[\"\047][]][[:space:]]*=[^=]")
      mk = 0
      for (k = 1; k <= K; k++) if (tolower(ST[k]) ~ /^[[:space:]]*map[[:space:]]+[$]http_authorization[[:space:]]+[$]cfm_req_auth([[:space:]{]|$)/) { mk = k; break }
      if (!mk) print "ERR no map $http_authorization $cfm_req_auth { … } — the credentialed-request rail the cache predicates key on is undefined."
      else {
        k = mk; if (ST[k] !~ /[{][[:space:]]*$/) k++
        ne = 0; okd = 0; oke = 0; got = ""
        for (k = k + 1; k <= K; k++) {
          e = ST[k]; if (e ~ /^[[:space:]]*[}][[:space:]]*$/) break
          gsub(/[[:space:]]+/, " ", e); sub(/^ /, "", e); sub(/ $/, "", e)
          ne++; got = got "|" e
          if (e == "default \"1\";") okd = 1; else if (e == "\"\" \"\";") oke = 1
        }
        if (ne != 2 || !okd || !oke) print "ERR $cfm_req_auth map must hold EXACTLY: default \"1\" (any Authorization → bypass) and \"\" \"\" (none) — got:" got
      }
      if (nmaps != 1) print "ERR $cfm_req_auth is written by " nmaps " maps — it must have exactly one (map $http_authorization $cfm_req_auth)."
      if (nwr > 0) print "ERR $cfm_req_auth is written by " nwr " other directive(s) (set / set_by_lua / …) — the credentialed-request rail must come only from its map."
      if (nlua > 0) print "ERR inline Lua assigns ngx.var.cfm_req_auth — the credentialed-request rail must come only from its map."

      # $cfm_cache_skip: the conf only ever declares the bypass default "1"; the
      # flip to "0" comes ONLY from cfm_cache.lua (static_gate / micro_gate).
      for (k = 1; k <= K; k++) {
        e = tolower(ST[k])
        if (e ~ /^[[:space:]]*set[[:space:]]+[$]cfm_cache_skip[[:space:]]/ && e !~ /^[[:space:]]*set[[:space:]]+[$]cfm_cache_skip[[:space:]]+"1"[[:space:]]*;/) print "ERR line " SL[k] ": $cfm_cache_skip is set to something other than \"1\" — the cache-on flip must come ONLY from cfm_cache.lua, never the conf."
        if (e ~ /^[[:space:]]*proxy_ignore_headers[[:space:]]/ && e ~ /[[:space:]](set-cookie|vary|cache-control)([[:space:];]|$)/) print "ERR line " SL[k] ": proxy_ignore_headers lists Set-Cookie, Vary or Cache-Control — nginx would then store a response that sets a cookie or says private/no-store, or one Vary variant for everyone. Ignoring Cache-Control needs a replacement rail and a guard update in the same change."
        if (e ~ /^[[:space:]]*proxy_cache_methods[[:space:]]/ && e ~ /[[:space:]](post|put|patch|delete)([[:space:];]|$)/) print "ERR line " SL[k] ": proxy_cache_methods lists a non-GET/HEAD method — a cached POST/PUT result would be served to every client."
      }
      if (cnt(la, "ngx[.]var[.]cfm_cache_skip[[:space:]]*=[^=]") > 0) print "ERR inline Lua assigns ngx.var.cfm_cache_skip — the flip must come ONLY from cfm_cache.lua."
    }
  ' "$f")
  if [ -n "$parsed" ]; then
    while IFS= read -r line; do
      err "$f: ${line#ERR }"
    done <<< "$parsed"
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

  # ── (c) negatives (cache-on flip, proxy_ignore_headers, proxy_cache_methods,
  # writers of $cfm_req_auth) are enforced statement-aware in section (a).
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
echo "[site-cache-config] OK: cfm_static zone declared, Tier B micro buckets {1,2,5,10,30,60}s (zone + internal @cfm_micro_<n>s location) declared in both confs, \$cfm_cache_skip bypass-by-default, every proxy_cache location gated + buffered + (micro) internal, only-200 rail (\$cfm_cache_non200) enforced, request-identity rails (\$cfm_req_auth bypass + map, full g\$cfm_cache_gen|\$server_addr|\$scheme|\$cf_xfp:// key, per-tier lock_timeout, forwarded headers pinned) on every cache location, every location + every proxy_cache directive accounted for, Set-Cookie/Vary/Cache-Control never ignored, GET/HEAD-only cache methods, openresty↔angie parity ($ort_n static locations)."
