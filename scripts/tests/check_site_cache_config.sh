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
#     * $cfm_cache_skip DEFAULTS TO "1" (bypass) in EVERY server that holds a
#       cache location, and nothing else in the conf may write it (the flip
#       only ever comes from cfm_cache.lua).
#     * EVERY location that activates `proxy_cache cfm_static;` (or a
#       cfm_micro_<n>s bucket) ALSO carries `proxy_cache_bypass $cfm_cache_skip
#       $cfm_req_auth;` AND `proxy_no_cache $cfm_cache_skip $cfm_cache_non200
#       $cfm_req_auth;` — bypass-by-default (serve + store), the only-200 rail
#       and the credentialed-request rail — plus buffering ON (nginx stores
#       nothing off it), the whole key
#       `g$cfm_cache_gen|$server_addr|$scheme|$cf_xfp://$host$request_uri`, the
#       lock on with its per-tier timeout (1s static, 5s micro), and the
#       forwarded-header pins (X-Forwarded-Host = $host, the rest dropped; each
#       set exactly once). Any other cache zone is rejected.
#     * `map $http_authorization $cfm_req_auth` and `map $upstream_status
#       $cfm_cache_non200` each hold EXACTLY their two entries, and nothing else
#       writes either variable (so `Authorization: 0`, which a raw predicate
#       reads as false, still counts; no extra key can exempt a credential or
#       store a 404/301).
#     * Set-Cookie and Vary are never added to proxy_ignore_headers (nginx must
#       keep NOT caching a response that sets a cookie, and must keep one copy
#       per Vary variant), and proxy_cache_methods never lists a non-GET/HEAD
#       method. Cache-Control / Expires / X-Accel-Expires may be ignored ONLY
#       in a @cfm_micro_<n>s location, which must then carry exactly
#       `proxy_ignore_headers Cache-Control Expires X-Accel-Expires;` plus the
#       replacement rails $cfm_cc_nostore (private/no-store/no-cache/
#       s-maxage=0) and $cfm_xae_nocache (X-Accel-Expires 0 / @…) on
#       proxy_no_cache — their maps exact (volatile included), nothing else
#       writing them — proxy_cache_background_update off (on keeps serving a
#       stale page whose refresh can no longer be stored), exactly
#       `proxy_cache_use_stale updating error timeout http_500 http_502
#       http_503 http_504`, and exactly one `proxy_cache_valid 200 <N>s` with
#       N the bucket its name and zone say (with the origin headers ignored it
#       is the only TTL). A proxy_ignore_headers anywhere else (Tier A, server
#       or http level, which a location would inherit) may not list them.
#     * the Tier B sentinel `set $cfm_micro_conf "1";` sits in `location /` of
#       every server that has micro locations, and nowhere else (cfm_cache.lua
#       routes to micro only when it reads "1": a sentinel in a server without
#       the named locations would 500, one in a passthrough would buffer it);
#       that server also sets the default `set $cfm_micro_conf "";` at server
#       level; its `location /` has no rewrite / try_files / error_page and
#       neither it nor its server has a rewrite_by_lua* (a `rewrite … last` or
#       ngx.req.set_uri(…, true) would carry the sentinel into another location
#       without making the request internal), and buffering is never turned
#       off in it nor at server/http level (which it would inherit).
#     * every @cfm_micro_<n>s location caches into a cfm_micro_<n>s zone and
#       sets $cfm_upstream "cfm_apache_micro"; the only log_by_lua is the
#       http-level one and it still calls cfm_cache.micro_note (remember-
#       uncacheable; a server- or location-level log_by_lua would override it).
#     * lua_shared_dict cfm_cache_uncacheable (remember-uncacheable) exists,
#       and every micro zone's inactive is at least 30s below cfm_cache.lua's
#       MICRO_UNCACHEABLE_STALE_TTL (so a stale copy is evicted before the
#       next probe of a page that stopped being cacheable).
#     * proxy_cache_convert_head is never turned off, anywhere (the key has no
#       method: a body-less HEAD entry would be served to GETs).
#     * the conf includes exactly its known files, by full path (a new include
#       could carry a second copy of a rail map, which this scan would not see).
#   How: the conf is lexed like nginx (quotes, escapes, ${var}, # comments),
#   inline *_by_lua_block bodies are lexed as Lua and kept out of the checks,
#   and the text is assembled into real statements — so every rail must match
#   a DIRECTIVE at a statement start, and a one-line location, { on the next
#   line or a directive wrapped over lines is parsed like any other. Every
#   location and every proxy_cache statement must be accounted for, so a
#   mis-parse fails, never skips. Section (a) documents the details.
#   parity
#     * both confs cache the same locations (every zone), declare the same
#       micro zones, and carry byte-identical @cfm_micro_<n>s blocks.
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
declare -A ncache_of=() nstatic_of=() clocs_of=() mzones_of=()
err() { echo "❌ [site-cache-config] $*" >&2; fail=1; }

for f in "$ORT" "$ANG"; do
  [ -f "$f" ] || { err "$f: missing — cannot verify Site Cache config."; continue; }

  # ── (a) statement-aware checks (the real regression guard) ──────────────────
  # The conf is lexed the way nginx reads it and assembled into real
  # STATEMENTS (one directive or block boundary each, however it is laid out
  # over lines):
  #   * nginx text: a quote opens only at a token start (line start, or after
  #     whitespace ; { }) and may span lines; inside quotes and after a
  #     backslash the characters ; { } are MASKED so they never act as a
  #     boundary (a regex location such as "^/a{2}$" is one token); ${var} is a
  #     variable, not a block; a # at a token start outside quotes is a comment.
  #   * a *_by_lua_block body is lexed with LUA rules (-- and --[[ ]] comments,
  #     short and [[long]] strings, # is the length operator) and is kept OUT of
  #     the statement stream: only its closing } takes part in brace depth. So
  #     Lua code, Lua comments and Lua strings can neither satisfy a rail nor
  #     unbalance a location. Inline Lua must not reference the guarded
  #     variables at all ($cfm_cache_skip / $cfm_req_auth / $cfm_cache_non200 /
  #     $cfm_cc_nostore / $cfm_xae_nocache / $cfm_micro_conf: the cache-on flip
  #     and the micro routing live in cfm_cache.lua, never inline).
  # Every rail must then match a DIRECTIVE at a statement start, so comment
  # text or a quoted value never satisfies one; a one-line location, { on the
  # next line and a directive wrapped over several lines parse like anything
  # else. Brace depth delimits each top-level location; any location holding a
  # proxy_cache (other than off) is checked. Backstops, counted as statement-
  # start tokens over the whole file:
  #   * location statements == locations parsed (a nested or swallowed one);
  #   * proxy_cache statements == those inside checked cache locations (one at
  #     server/http level is inherited ungated by location /);
  #   * every server block holding a cache location sets $cfm_cache_skip "1"
  #     at server level (bypass-by-default is per server).
  # Writers are whitelisted, token-based and case-insensitive (nginx variable
  # and header names are): a statement that mentions $cfm_req_auth may only be
  # its map (map $http_authorization $cfm_req_auth) or a cache predicate; the
  # same for $cfm_cache_non200 (its map $upstream_status), $cfm_cc_nostore
  # (map $upstream_http_cache_control) and $cfm_xae_nocache (map
  # $upstream_http_x_accel_expires) with proxy_no_cache; $cfm_cache_skip may
  # only be `set … "1"` or a cache predicate; $cfm_micro_conf only its
  # sentinel `set … "1"` in a `location /`. Known, adversarial-only gaps
  # (tracked for the guard-hardening follow-up): a regex named capture of a
  # guarded name, a Lua long-string index, a *_by_lua string-form directive,
  # and an identically mis-indented closing brace in both micro blocks (the
  # section (f) extractor works by indentation). All four maps hold EXACTLY their
  # entries (two; the two micro maps also `volatile;`). proxy_ignore_headers
  # never lists Set-Cookie / Vary, lists
  # Cache-Control / Expires / X-Accel-Expires only in a micro location, and
  # proxy_cache_methods never lists a non-GET/HEAD method (quoted or not).
  # Scope: the two reference confs. Files they include are not scanned (today
  # only data files and configs/cfm-panel-listeners.conf.in, which carries no
  # cache directive and none of the guarded variables).
  parsed=$(awk '
    function rep(c, n,   r) { r = ""; while (n-- > 0) r = r c; return r }
    function mask(c) { if (c == ";") return "\001"; if (c == "{") return "\002"; if (c == "}") return "\003"; return c }
    function lexline(s,   i, n, ch, out, prev) {
      out = ""; prev = " "; n = length(s); i = 1; LQ = ""
      while (i <= n) {
        ch = substr(s, i, 1)
        if (LUA) {
          if (LC != "") { j = index(substr(s, i), LC); if (j == 0) { i = n + 1; continue } i += j - 1 + length(LC); LC = ""; continue }
          if (LQ != "") { LT = LT ch; if (ch == "\\") { LT = LT substr(s, i + 1, 1); i += 2; continue } if (ch == LQ) LQ = ""; i++; continue }
          if (substr(s, i, 2) == "--") {
            if (match(substr(s, i + 2), /^\[=*\[/)) { LC = "]" rep("=", RLENGTH - 2) "]"; i += 2 + RLENGTH; continue }
            i = n + 1; continue
          }
          if (ch == "[" && match(substr(s, i), /^\[=*\[/)) { LC = "]" rep("=", RLENGTH - 2) "]"; i += RLENGTH; continue }
          if (ch == "\"" || ch == "\047") { LQ = ch; LT = LT ch; i++; continue }
          if (ch == "{") { LD++; LT = LT ch; i++; continue }
          if (ch == "}") { LD--; if (LD == 0) { LUA = 0; out = out " }"; prev = "}"; i++; continue } LT = LT ch; i++; continue }
          LT = LT ch; i++; continue
        }
        if (Q != "") { if (ch == "\\" && i < n) { out = out ch mask(substr(s, i + 1, 1)); CUR = CUR "x"; i += 2; continue } if (ch == Q) { Q = ""; out = out ch; prev = ch } else { out = out mask(ch); CUR = CUR ch } i++; continue }
        if (VB) { out = out mask(ch); if (ch == "}") VB = 0; i++; continue }
        if (ch == "\\" && i < n) { out = out ch mask(substr(s, i + 1, 1)); CUR = CUR "x"; i += 2; prev = "x"; continue }
        if ((ch == "\"" || ch == "\047") && prev ~ /[[:space:];{}]/) { Q = ch; out = out ch; prev = ch; i++; continue }
        if (ch == "#" && prev ~ /[[:space:];{}]/) break
        if (ch == "{" && prev == "$") { VB = 1; out = out mask(ch); prev = "x"; i++; continue }
        if (ch == "{") { if (CUR ~ /^[[:space:]]*[a-z_]+_by_lua_block([[:space:]]+[$][^[:space:]]*)?[[:space:]]*$/) { LUA = 1; LD = 1 } CUR = ""; out = out ch; prev = ch; i++; continue }
        if (ch == ";" || ch == "}") { CUR = ""; out = out ch; prev = ch; i++; continue }
        CUR = CUR ch; out = out ch; prev = ch; i++
      }
      CUR = CUR " "; LT = LT "\n"
      return out
    }
    function emit(s, l) { K++; ST[K] = s; SL[K] = l }
    function cnt(str, re,   n) { n = 0; while (match(str, re)) { n++; str = substr(str, RSTART + RLENGTH) } return n }
    function mapcheck(hdr_re, want1, want2, name, want3,   k, mk, e, ne, ok1, ok2, ok3, got, nw) {
      mk = 0
      for (k = 1; k <= K; k++) if (tolower(ST[k]) ~ hdr_re) { mk = k; break }
      if (!mk) { print "ERR no " name " map — the rail the cache predicates key on is undefined."; return }
      ne = 0; ok1 = 0; ok2 = 0; ok3 = (want3 == ""); got = ""; nw = (want3 == "") ? 2 : 3
      for (k = mk + 1; k <= K; k++) {
        e = ST[k]; if (e ~ /^[[:space:]]*[}][[:space:]]*$/) break
        gsub(/[[:space:]]+/, " ", e); sub(/^ /, "", e); sub(/ $/, "", e)
        ne++; got = got "|" e
        if (e == want1) ok1 = 1; else if (e == want2) ok2 = 1; else if (want3 != "" && e == want3) ok3 = 1
      }
      if (ne != nw || !ok1 || !ok2 || !ok3) print "ERR the " name " map must hold EXACTLY: " want1 " and " want2 (want3 != "" ? " and " want3 : "") " — got:" got
    }
    function check_loc(   m, nz, lb, i, nh, H, st, mi, ns, lh, zn, hn) {
      # The Tier B sentinel: only `location /` may carry it (see the header).
      lh = body; sub(/^\n/, "", lh); sub(/\n.*$/, "", lh); gsub(/[[:space:]]+/, " ", lh); sub(/^ /, "", lh); sub(/ $/, "", lh)
      ns = cnt(body, A "set[[:space:]]+[$]cfm_micro_conf[[:space:]]+\"1\"[[:space:]]*;")
      if (ns > 0) {
        sentinels += ns
        if (lh != "location / {" || ns != 1) print "ERR location@line" locline " (" lh "): set $cfm_micro_conf \"1\" belongs once in `location /` only — anywhere else micro-cache would take over a location it must not buffer."
        if (lh == "location / {" && insrv) srv_sentinel = 1
        if (body ~ (A "(rewrite|try_files|error_page)[[:space:]]")) print "ERR location@line" locline " (" lh "): the location carrying the $cfm_micro_conf sentinel has a rewrite / try_files / error_page — it would carry the sentinel into the location it redirects to."
        if (body ~ (A "proxy_buffering[[:space:]]+[\"\047]?off[\"\047]?[[:space:]]*;")) print "ERR location@line" locline " (" lh "): the location carrying the $cfm_micro_conf sentinel turns buffering off — it streams, and micro would buffer it."
        if (body ~ (A "rewrite_by_lua[a-z_]*[[:space:]]")) print "ERR location@line" locline " (" lh "): the location carrying the $cfm_micro_conf sentinel has a rewrite_by_lua* — ngx.req.set_uri(…, true) would carry the sentinel into another location."
      }
      if (lh ~ /^location @cfm_micro_/ && body !~ (A "proxy_cache[[:space:]]+cfm_micro_[0-9]+s[[:space:]]*;")) print "ERR location@line" locline " (" lh "): a Tier B bucket location must cache into its cfm_micro_<n>s zone — cfm_cache.lua routes HTML here."
      nz = cnt(body, A "proxy_cache[[:space:]]+[^[:space:];]+[[:space:]]*;") - cnt(body, A "proxy_cache[[:space:]]+off[[:space:]]*;")
      if (nz <= 0) return
      ncache++; cache_toks += nz; m = ""; if (insrv) srv_cache = 1
      if (nz != 1) m = m " more-than-one-proxy_cache"
      st = (body ~ (A "proxy_cache[[:space:]]+cfm_static[[:space:]]*;"))
      mi = (body ~ (A "proxy_cache[[:space:]]+cfm_micro_[0-9]+s[[:space:]]*;"))
      if (!st && !mi) m = m " unknown-cache-zone(only-cfm_static-or-cfm_micro_Ns)"
      if (st) nstatic++
      if (mi) micro_seen = 1
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
      # case or quoted, is sent as a second header and undoes the pin).
      lb = tolower(body)
      if (body !~ (A "proxy_set_header[[:space:]]+X-Forwarded-Host[[:space:]]+[$]host[[:space:]]*;")) m = m " X-Forwarded-Host-not-pinned-to-$host"
      else if (cnt(lb, A "proxy_set_header[[:space:]]+[\"\047]?x-forwarded-host[\"\047]?[[:space:]]") != 1) m = m " X-Forwarded-Host-set-more-than-once"
      nh = split("X-Forwarded-Server X-Forwarded-Port X-Forwarded-Scheme X-Forwarded-Protocol X-Forwarded-Prefix X-Forwarded-Ssl X-Forwarded-Uri X-Forwarded-Path X-Host X-Original-Host X-Original-URL X-Original-Uri X-Rewrite-URL Forwarded Front-End-Https X-Url-Scheme X-Scheme X-HTTP-Method-Override X-HTTP-Method X-Method-Override", H, " ")
      for (i = 1; i <= nh; i++) {
        if (body !~ (A "proxy_set_header[[:space:]]+" H[i] "[[:space:]]+\"\"[[:space:]]*;")) m = m " " H[i] "-not-dropped"
        else if (cnt(lb, A "proxy_set_header[[:space:]]+[\"\047]?" tolower(H[i]) "[\"\047]?[[:space:]]") != 1) m = m " " H[i] "-set-more-than-once"
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
      # Tier B: the TTL is the bucket TTL (origin Cache-Control / Expires /
      # X-Accel-Expires ignored), so the "do not store" half of those headers
      # must come back as proxy_no_cache rails, and a background refresh that
      # cannot be stored must not keep a stale page alive (background_update off).
      if (mi) {
        if (insrv) srv_micro = 1
        if (cnt(body, A "proxy_ignore_headers[[:space:]]") != 1 || body !~ (A "proxy_ignore_headers[[:space:]]+Cache-Control[[:space:]]+Expires[[:space:]]+X-Accel-Expires[[:space:]]*;")) m = m " micro-proxy_ignore_headers-must-be-exactly-Cache-Control-Expires-X-Accel-Expires"
        else micro_ign++
        if (body !~ (A "proxy_no_cache[[:space:]][^;]*[$]cfm_cc_nostore[[:space:];]")) m = m " proxy_no_cache-$cfm_cc_nostore(private/no-store/no-cache-could-be-stored)"
        if (body !~ (A "proxy_no_cache[[:space:]][^;]*[$]cfm_xae_nocache[[:space:];]")) m = m " proxy_no_cache-$cfm_xae_nocache(X-Accel-Expires:0-could-be-stored)"
        if (body !~ (A "proxy_cache_background_update[[:space:]]+off[[:space:]]*;")) m = m " micro-proxy_cache_background_update-must-be-off(stale-page-served-while-refresh-cannot-store)"
        if (cnt(body, A "proxy_cache_use_stale[[:space:]]") != 1 || body !~ (A "proxy_cache_use_stale[[:space:]]+updating[[:space:]]+error[[:space:]]+timeout[[:space:]]+http_500[[:space:]]+http_502[[:space:]]+http_503[[:space:]]+http_504[[:space:]]*;")) m = m " micro-proxy_cache_use_stale-must-be-exactly-updating-error-timeout-http_500-http_502-http_503-http_504"
        # The bucket TTL is the only TTL now: the location name, its zone and
        # its one proxy_cache_valid must all say the same N.
        zn = ""; if (match(body, A "proxy_cache[[:space:]]+cfm_micro_[0-9]+s[[:space:]]*;")) { zn = substr(body, RSTART, RLENGTH); sub(/^.*cfm_micro_/, "", zn); sub(/s.*$/, "", zn) }
        hn = lh; sub(/^location @cfm_micro_/, "", hn); sub(/s \{$/, "", hn)
        if (zn == "" || hn != zn) m = m " micro-location-name-and-zone-disagree(@cfm_micro_" hn "s-vs-cfm_micro_" zn "s)"
        else if (cnt(body, A "proxy_cache_valid[[:space:]]") != 1 || body !~ (A "proxy_cache_valid[[:space:]]+200[[:space:]]+" zn "s[[:space:]]*;")) m = m " micro-proxy_cache_valid-must-be-exactly-200-" zn "s(the-bucket-TTL)"
      }
      if (mi && body !~ (A "set[[:space:]]+[$]cfm_upstream[[:space:]]+\"cfm_apache_micro\"[[:space:]]*;")) m = m " micro-must-set-$cfm_upstream-cfm_apache_micro(the-remember-uncacheable-hook-and-the-stats-key-on-it)"
      hdr = body; sub(/^\n/, "", hdr); sub(/\n.*$/, "", hdr); gsub(/[[:space:]]+/, " ", hdr); sub(/^ /, "", hdr); print "CLOC " hdr
      if (m != "") print "ERR cache location@line" locline ":" m " — a proxy_cache location is missing a required rail (no bypass gate → unconditional caching; buffering off → nginx silently caches NOTHING)."
    }
    BEGIN { A = "\n[[:space:]]*" }
    {
      ln = lexline($0)
      gsub(/;/, ";\n", ln); gsub(/[{]/, "{\n", ln); gsub(/[}]/, "\n}\n", ln)
      np = split(ln, P, "\n")
      for (jj = 1; jj <= np; jj++) {
        p = P[jj]; if (p ~ /^[[:space:]]*$/) continue
        if (p ~ /^[[:space:]]*[}][[:space:]]*$/) { if (pend != "") emit(pend, pl); emit(p, NR); pend = ""; continue }
        if (pend == "") { pend = p; pl = NR } else pend = pend " " p
        if (pend ~ /[;{][[:space:]]*$/) { emit(pend, pl); pend = "" }
      }
    }
    END {
      if (pend != "") emit(pend, pl)
      if (LUA) print "ERR a *_by_lua_block never closes — the Lua lexer lost track, so nothing after it was checked."
      all = "\n"
      for (k = 1; k <= K; k++) all = all ST[k] "\n"
      D = 0
      for (k = 1; k <= K; k++) {
        s = ST[k]; ls = tolower(s)
        isopen = (s ~ /[{][[:space:]]*$/); isclose = (s ~ /^[[:space:]]*[}][[:space:]]*$/)
        if (!insrv && !loc && isopen && ls ~ /^[[:space:]]*server[[:space:]]*[{][[:space:]]*$/) { insrv = 1; srvD = D; srv_set = 0; srv_cache = 0; srv_micro = 0; srv_sentinel = 0; srv_mdef = 0; srv_rwlua = 0; srvline = SL[k] }
        if (insrv && D == srvD + 1 && ls ~ /^[[:space:]]*set[[:space:]]+[$]cfm_cache_skip[[:space:]]+"1"[[:space:]]*;/) srv_set = 1
        if (insrv && !loc && D == srvD + 1 && ls ~ /^[[:space:]]*set[[:space:]]+[$]cfm_micro_conf[[:space:]]+""[[:space:]]*;[[:space:]]*$/) { srv_mdef++; mdefs++ }
        if (insrv && !loc && ls ~ /^[[:space:]]*rewrite_by_lua[a-z_]*[[:space:]]/) srv_rwlua++
        if (ls ~ /^[[:space:]]*log_by_lua[a-z_]*[[:space:]]/ && (D != 1 || insrv || loc)) print "ERR line " SL[k] ": a log_by_lua* below http level overrides the http-level one — the Tier B remember-uncacheable hook (cfm_cache.micro_note) and the cache stats would stop for it."
        if (!loc && ls ~ /^[[:space:]]*proxy_buffering[[:space:]]+["\047]?off["\047]?[[:space:]]*;/) print "ERR line " SL[k] ": proxy_buffering off at " (insrv ? "server" : "http") " level — `location /` (the Tier B entry) inherits it and would stream; turn buffering off per location."
        if (!loc && s ~ /^[[:space:]]*location[[:space:]]/) { loc = 1; body = "\n"; locline = SL[k]; nloc++; d = 0; seen = 0 }
        if (loc) {
          body = body s "\n"
          if (isopen) { d++; seen = 1 }
          if (isclose) d--
          if (seen && d <= 0) { check_loc(); loc = 0; body = "" }
        }
        if (isopen) D++
        if (isclose) { D--; if (insrv && D == srvD) {
          if (srv_cache && !srv_set) print "ERR the server block opened at line " srvline " has a cache location but no server-level set $cfm_cache_skip \"1\" — bypass-by-default is lost for every vhost on it."
          if (srv_micro && !srv_sentinel) print "ERR the server block opened at line " srvline " has @cfm_micro_<n>s locations but its `location /` lacks set $cfm_micro_conf \"1\" — cfm_cache.lua would never route to them."
          if (srv_sentinel && !srv_micro) print "ERR the server block opened at line " srvline " sets $cfm_micro_conf \"1\" but has no @cfm_micro_<n>s location — an ngx.exec to a missing named location 500s."
          if (srv_micro && srv_mdef != 1) print "ERR the server block opened at line " srvline " has @cfm_micro_<n>s locations but " srv_mdef " server-level set $cfm_micro_conf \"\" defaults (want exactly 1) — without it every read outside `location /` logs an uninitialized-variable warning."
          if (!srv_micro && srv_mdef) print "ERR the server block opened at line " srvline " sets a $cfm_micro_conf default but has no @cfm_micro_<n>s location."
          if (srv_micro && srv_rwlua) print "ERR the server block opened at line " srvline " has @cfm_micro_<n>s locations and a server-level rewrite_by_lua* — inherited by `location /`, its ngx.req.set_uri(…, true) would carry the sentinel into another location."
          insrv = 0 } }
      }
      if (loc) print "ERR a location opened at line " locline " never closes — the parser lost track of braces, so nothing after it was checked."
      lt = cnt(all, A "location[[:space:]]")
      if (lt != nloc) print "ERR " nloc " top-level locations were parsed but the file has " lt " location statements — a nested or swallowed location would go UNCHECKED."
      ct = cnt(all, A "proxy_cache[[:space:]]+[^[:space:];]+[[:space:]]*;") - cnt(all, A "proxy_cache[[:space:]]+off[[:space:]]*;")
      if (ct != cache_toks) print "ERR " cache_toks " proxy_cache directives sit in checked cache locations but the file has " ct " — one outside any location (server/http level) is inherited UNGATED by location /."
      if (ncache == 0) print "ERR no cache location found at all — this gate must verify something."
      if (nstatic == 0) print "ERR no proxy_cache cfm_static location — did Tier A activation get removed? (this gate must verify something)"
      print "NCACHE " ncache + 0
      print "NSTATIC " nstatic + 0

      # Rail maps: exactly their two entries (one extra key re-opens the leak).
      mapcheck("^[[:space:]]*map[[:space:]]+[$]http_authorization[[:space:]]+[$]cfm_req_auth[[:space:]]*[{][[:space:]]*$", "default \"1\";", "\"\" \"\";", "$http_authorization → $cfm_req_auth", "")
      mapcheck("^[[:space:]]*map[[:space:]]+[$]upstream_status[[:space:]]+[$]cfm_cache_non200[[:space:]]*[{][[:space:]]*$", "default \"1\";", "\"200\" \"\";", "$upstream_status → $cfm_cache_non200 (only-200)", "")
      mapcheck("^[[:space:]]*map[[:space:]]+[$]upstream_http_cache_control[[:space:]]+[$]cfm_cc_nostore[[:space:]]*[{][[:space:]]*$", "default \"\";", "\"~*(private|no-store|no-cache|s-maxage=0*(?:[^0-9]|$))\" \"1\";", "$upstream_http_cache_control → $cfm_cc_nostore (micro: private/no-store/no-cache/s-maxage=0 never stored)", "volatile;")
      mapcheck("^[[:space:]]*map[[:space:]]+[$]upstream_http_x_accel_expires[[:space:]]+[$]cfm_xae_nocache[[:space:]]*[{][[:space:]]*$", "default \"\";", "\"~^(?:0+|@.*)$\" \"1\";", "$upstream_http_x_accel_expires → $cfm_xae_nocache (micro: X-Accel-Expires 0 / @… never stored)", "volatile;")
      if (!micro_seen) print "ERR no @cfm_micro_<n>s cache location found — the Tier B checks must verify something."
      if (!sentinels) print "ERR no set $cfm_micro_conf \"1\" sentinel found — Tier B would never route."
      nm1 = 0; nm2 = 0; nm3 = 0; nm4 = 0; nmc = 0; nme = 0; nign = 0
      for (k = 1; k <= K; k++) {
        u = tolower(ST[k]); gsub(/\002/, "{", u); gsub(/\003/, "}", u); gsub(/\001/, ";", u)
        fw = u; sub(/^[[:space:]]*/, "", fw); sub(/[^a-z0-9_].*$/, "", fw)
        pred = (fw == "proxy_cache_bypass" || fw == "proxy_no_cache")
        # Writers whitelist: nginx variable names are case-insensitive, ${x} and
        # a quoted "$x" are the same variable.
        if (u ~ /[$][{]?cfm_req_auth([^a-z0-9_]|$)/) {
          if (u ~ /^[[:space:]]*map[[:space:]]+[$]http_authorization[[:space:]]+[$]cfm_req_auth[[:space:]]*[{][[:space:]]*$/) nm1++
          else if (!pred) print "ERR line " SL[k] ": $cfm_req_auth appears in a " fw " statement — only its map and the cache predicates may reference it (another writer can override the credentialed-request rail)."
        }
        if (u ~ /[$][{]?cfm_cache_non200([^a-z0-9_]|$)/) {
          if (u ~ /^[[:space:]]*map[[:space:]]+[$]upstream_status[[:space:]]+[$]cfm_cache_non200[[:space:]]*[{][[:space:]]*$/) nm2++
          else if (fw != "proxy_no_cache") print "ERR line " SL[k] ": $cfm_cache_non200 appears in a " fw " statement — only its map and proxy_no_cache may reference it (another writer can re-open non-200 storage)."
        }
        if (u ~ /[$][{]?cfm_cc_nostore([^a-z0-9_]|$)/) {
          if (u ~ /^[[:space:]]*map[[:space:]]+[$]upstream_http_cache_control[[:space:]]+[$]cfm_cc_nostore[[:space:]]*[{][[:space:]]*$/) nm3++
          else if (fw != "proxy_no_cache") print "ERR line " SL[k] ": $cfm_cc_nostore appears in a " fw " statement — only its map and proxy_no_cache may reference it (another writer can let a private/no-store page be stored)."
        }
        if (u ~ /[$][{]?cfm_xae_nocache([^a-z0-9_]|$)/) {
          if (u ~ /^[[:space:]]*map[[:space:]]+[$]upstream_http_x_accel_expires[[:space:]]+[$]cfm_xae_nocache[[:space:]]*[{][[:space:]]*$/) nm4++
          else if (fw != "proxy_no_cache") print "ERR line " SL[k] ": $cfm_xae_nocache appears in a " fw " statement — only its map and proxy_no_cache may reference it."
        }
        if (u ~ /[$][{]?cfm_micro_conf([^a-z0-9_]|$)/) {
          if (u ~ /^[[:space:]]*set[[:space:]]+[$]cfm_micro_conf[[:space:]]+"1"[[:space:]]*;[[:space:]]*$/) nmc++
          else if (u ~ /^[[:space:]]*set[[:space:]]+[$]cfm_micro_conf[[:space:]]+""[[:space:]]*;[[:space:]]*$/) nme++
          else print "ERR line " SL[k] ": $cfm_micro_conf appears in a " fw " statement — only its sentinel set $cfm_micro_conf \"1\" in `location /` may."
        }
        if (fw == "proxy_ignore_headers" && u ~ /[[:space:]]["\047]?(cache-control|expires|x-accel-expires)["\047]?([[:space:];]|$)/) nign++
        if (u ~ /[$][{]?cfm_cache_skip([^a-z0-9_]|$)/ && !pred && u !~ /^[[:space:]]*set[[:space:]]+[$]cfm_cache_skip[[:space:]]+"1"[[:space:]]*;[[:space:]]*$/) print "ERR line " SL[k] ": $cfm_cache_skip appears in a " fw " statement — the conf may only set it to \"1\" (the cache-on flip comes ONLY from cfm_cache.lua)."
        if (fw == "proxy_ignore_headers" && u ~ /[[:space:]]["\047]?(set-cookie|vary)["\047]?([[:space:];]|$)/) print "ERR line " SL[k] ": proxy_ignore_headers lists Set-Cookie or Vary — nginx would then store a response that sets a cookie, or one Vary variant for everyone."
        if (fw == "proxy_cache_convert_head" && u ~ /[[:space:]]["\047]?off["\047]?([[:space:];]|$)/) print "ERR line " SL[k] ": proxy_cache_convert_head off — the cache key has no method, so a body-less HEAD entry would be served to GET clients."
        if (fw == "proxy_cache_path" && u ~ /cfm_micro_/) { z = ST[k]; gsub(/[[:space:]]+/, " ", z); print "MZONE " z }
        if (fw == "proxy_cache_methods" && u ~ /[[:space:]]["\047]?(post|put|patch|delete)["\047]?([[:space:];]|$)/) print "ERR line " SL[k] ": proxy_cache_methods lists a non-GET/HEAD method — a cached POST/PUT result would be served to every client."
      }
      if (nm1 != 1) print "ERR $cfm_req_auth is written by " nm1 " copies of its map — it must have exactly one."
      if (nm2 != 1) print "ERR $cfm_cache_non200 is written by " nm2 " copies of its map — it must have exactly one."
      if (nm3 != 1) print "ERR $cfm_cc_nostore is written by " nm3 " copies of its map — it must have exactly one."
      if (nm4 != 1) print "ERR $cfm_xae_nocache is written by " nm4 " copies of its map — it must have exactly one."
      if (nmc != sentinels) print "ERR " nmc " set $cfm_micro_conf \"1\" statements but " sentinels " sit in a `location /` — one is outside any location."
      if (nme != mdefs) print "ERR " nme " set $cfm_micro_conf \"\" statements but only " mdefs + 0 " are a server-level default of a micro server — one inside a location (or at http level) can clear the sentinel of `location /`."
      for (k = 1; k <= K; k++) { u = ST[k]; if (u ~ /^[[:space:]]*include[[:space:]]/) { sub(/^[[:space:]]*include[[:space:]]+/, "", u); sub(/[[:space:]]*;.*$/, "", u); print "INC " u } }
      if (nign != micro_ign) print "ERR " nign " proxy_ignore_headers statements list Cache-Control / Expires / X-Accel-Expires but only " micro_ign " sit in the micro locations — Tier A (or a server/http-level one a location inherits) would let the origin set the TTL and drop the nginx private/no-store rail."
      if (all !~ (A "lua_shared_dict[[:space:]]+cfm_cache_uncacheable[[:space:]]+[0-9]+[kKmM]?[[:space:]]*;")) print "ERR no lua_shared_dict cfm_cache_uncacheable — Tier B cannot remember an uncacheable key, so its requests queue on the cache lock."
      lt2 = tolower(LT)
      if (lt2 !~ /pcall\(cm\.micro_note\)/ || lt2 !~ /"cfm_apache_micro"/) print "ERR the http-level log_by_lua no longer calls cfm_cache.micro_note for cfm_apache_micro requests — Tier B would stop remembering uncacheable keys and their requests would queue on the cache lock."
      if (lt2 ~ /cfm_req_auth|cfm_cache_skip|cfm_cache_non200|cfm_cc_nostore|cfm_xae_nocache|cfm_micro_conf/) print "ERR inline Lua references $cfm_req_auth / $cfm_cache_skip / $cfm_cache_non200 / $cfm_cc_nostore / $cfm_xae_nocache / $cfm_micro_conf — the cache rails must come only from the conf maps, the sentinel and cfm_cache.lua."
    }
  ' "$f")
  ncache_of["$f"]=$(sed -n 's/^NCACHE //p' <<< "$parsed")
  nstatic_of["$f"]=$(sed -n 's/^NSTATIC //p' <<< "$parsed")
  clocs_of["$f"]=$(sed -n 's/^CLOC //p' <<< "$parsed" | sort)
  # The includes are pinned: this scan does not read them, so a new one could
  # carry a second copy of a rail map (a later map for the same variable wins)
  # or a cache directive. Add one here only after checking it carries neither.
  incs=$(sed -n 's/^INC //p' <<< "$parsed" | sort | tr '\n' ' ')
  case "$f" in
    "$ORT") idir=/usr/local/openresty/nginx/conf ;;
    *)      idir=/etc/angie ;;
  esac
  want_incs="$idir/cfm-panel-listeners.conf $idir/challenge_waf_bypass.conf $idir/mime.types $idir/trusted_proxies.conf "
  [ "$incs" = "$want_incs" ] \
    || err "$f: the conf includes [$incs] — expected exactly [$want_incs]; an included file is not scanned by this guard."
  mzones_of["$f"]=$(sed -n 's/^MZONE //p' <<< "$parsed")
  parsed=$(grep -Ev '^(NCACHE|NSTATIC|CLOC|INC|MZONE) ' <<< "$parsed" || true)
  if [ -n "$parsed" ]; then
    while IFS= read -r line; do
      err "$f: ${line#ERR }"
    done <<< "$parsed"
  fi

  # ── (b) presence: the conf must actually carry each anchor at least once ─────
  if ! grep -Eq '^[[:space:]]*proxy_cache_path[[:space:]]+/var/cache/nginx/cfm_static[[:space:]]' "$f"; then
    err "$f: no 'proxy_cache_path .../cfm_static' zone declared — Tier A config missing?"
  fi
  # The other anchors (at least one cfm_static cache location, the bypass /
  # no_cache / only-200 predicates, the four rail maps, the per-server
  # $cfm_cache_skip "1") are enforced statement-aware in section (a), counted
  # by the parser, so a commented-out directive never satisfies them.

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
# Section (a)'s statement parser emits the header of every checked cache
# location (any zone; whitespace-normalised, sorted) per conf; diff them. Comparing counts alone would pass a refactor
# that added a cache to one path in openresty and a DIFFERENT path in angie —
# the exact drift this guard exists to stop.
ort_n=${nstatic_of[$ORT]:-?}
if [ "${clocs_of[$ORT]:-x}" != "${clocs_of[$ANG]:-y}" ]; then
  err "openresty.conf and angie.conf cache DIFFERENT locations (${ncache_of[$ORT]:-?} vs ${ncache_of[$ANG]:-?}; every zone compared, not merely a count); the two edges must cache the same paths. Divergence:"
  diff <(printf '%s\n' "${clocs_of[$ORT]}") <(printf '%s\n' "${clocs_of[$ANG]}") 2>/dev/null | sed 's/^/       /' >&2 || true
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

# ── (e2) a stale copy must age out while its key is marked uncacheable: after an
# EXPIRED refresh that cannot be stored, cfm_cache.lua skips micro for the key
# for MICRO_UNCACHEABLE_STALE_TTL, and nothing reads the entry meanwhile — so
# every micro zone's inactive must end well inside that window (30s margin for
# the fetch itself), or the next probe finds the old copy and serves it again
# to the requests that arrive during its fetch.
LUA_CACHE=configs/lua/cfm_cache.lua
stale_ttl=$(sed -n 's/^local MICRO_UNCACHEABLE_STALE_TTL[[:space:]]*=[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' "$LUA_CACHE" 2>/dev/null || true)
if [ -z "$stale_ttl" ]; then
  err "$LUA_CACHE: no 'local MICRO_UNCACHEABLE_STALE_TTL = <seconds>' — cannot check the micro zones' inactive against it."
else
  for f in "$ORT" "$ANG"; do
    # the parsed statements: comments stripped, a directive wrapped over lines
    # joined, and the LAST inactive= wins (as in nginx)
    inact=$(sed -nE 's/.*[[:space:]]inactive=([0-9]+)(s|m)?([[:space:]].*|;.*)$/\1 \2/p' <<< "${mzones_of[$f]:-}")
    [ "$(wc -l <<< "$inact")" = "6" ] && [ -n "$inact" ] || { err "$f: could not read the inactive= of all six micro zones (want <n>s or <n>m)."; continue; }
    while read -r n u; do
      secs=$n; [ "$u" = "m" ] && secs=$((n * 60))
      [ $((secs + 30)) -le "$stale_ttl" ] || err "$f: a micro zone has inactive=${n}${u:-s}, not at least 30s below cfm_cache.lua MICRO_UNCACHEABLE_STALE_TTL=${stale_ttl}s — a stale copy would survive its key's uncacheable mark and be served again at the next probe."
    done <<< "$inact"
  done
fi

# ── (f) micro-LOCATION body parity: the full @cfm_micro_<n>s serving blocks must
# be byte-identical between the two edges. (b3) only checks the header is present
# in both; this diffs the BODIES so a per-bucket drift in proxy_cache_valid, the
# cache key ($cfm_cache_gen prefix), or any rail between angie and openresty is
# caught — both edges are ngx.exec targets B3b routes to and must cache the same
# way. A block is captured by INDENTATION (it ends at the first line that is its
# header's own indent + "}"), not by raw brace counting, which a brace inside a
# Lua comment or string in the block would throw off. Section (a) separately
# checks the rails of each block; this is the byte-for-byte parity layer.
micro_blocks() {
  awk '
    !loc && /^[[:space:]]*location[[:space:]]+@cfm_micro_[0-9]+s[[:space:]]*\{/ {
      loc=1; buf=$0 "\n"; ind=$0; sub(/[^[:space:]].*$/, "", ind); next
    }
    loc {
      buf=buf $0 "\n"
      if ($0 == ind "}") { printf "%s", buf; loc=0; buf="" }
    }
    END { if (loc) print "UNTERMINATED micro block" }
  ' "$1"
}
if ! diff <(micro_blocks "$ORT") <(micro_blocks "$ANG") >/dev/null 2>&1; then
  err "openresty.conf and angie.conf define the @cfm_micro_<n>s LOCATIONS differently (a per-bucket TTL / cache-key / rail drift); the micro serving blocks must be byte-identical on both edges. Divergence:"
  diff <(micro_blocks "$ORT") <(micro_blocks "$ANG") 2>/dev/null | sed 's/^/       /' >&2 || true
fi

# ── (g) cache-dir provisioning parity: the dirs the confs cache into must be
# exactly the dirs that get provisioned. They are created in two places — the
# daemon (cmd/cfm/site_cache_dirs.go, every start) and the packaging/installer
# helper (scripts/cfm-cache-dirs.sh, before any `-t`) — and a zone whose dir is
# missing fails `-t` with [emerg] (the packaged conf is then not deployed), so
# the three lists must never drift. Each extraction must also find something:
# an empty list means the anchor moved, which fails rather than compares empty.
conf_dirs() {
  grep -E '^[[:space:]]*proxy_cache_path[[:space:]]+/var/cache/nginx/' "$1" \
    | sed -E 's#^[[:space:]]*proxy_cache_path[[:space:]]+/var/cache/nginx/([^[:space:]/]+).*#\1#' | sort -u
}
HELPER=scripts/cfm-cache-dirs.sh
GODIRS=cmd/cfm/site_cache_dirs.go
helper_dirs=$( { sed -n 's/^CFM_CACHE_DIRS="\(.*\)"$/\1/p' "$HELPER" 2>/dev/null || true; } | tr ' ' '\n' | sed '/^$/d' | sort -u)
go_dirs=$(awk '/^var siteCacheDirNames = \[\]string\{/ { in_=1; next } in_ && /^\}/ { in_=0 } in_' "$GODIRS" 2>/dev/null | sed -n 's/^[[:space:]]*"\([^"]*\)",[[:space:]]*$/\1/p' | sort -u)
ort_dirs=$(conf_dirs "$ORT"); ang_dirs=$(conf_dirs "$ANG")
[ -n "$helper_dirs" ] || err "$HELPER: no CFM_CACHE_DIRS=\"…\" list found — cannot verify the provisioned cache dirs."
# Pin what the lists are relative to, and that they are the ONLY source: every
# proxy_cache_path (any path) must be an unquoted /var/cache/nginx/<name>, both
# provisioners must use /var/cache/nginx as their root, the helper must assign
# its list exactly once and loop over it.
for f in "$ORT" "$ANG"; do
  bad_paths=$(grep -nE '^[[:space:]]*proxy_cache_path[[:space:]]' "$f" | grep -vE '^[0-9]+:[[:space:]]*proxy_cache_path[[:space:]]+/var/cache/nginx/[A-Za-z0-9_]+[[:space:]]' || true)
  [ -z "$bad_paths" ] || err "$f: a proxy_cache_path is not an unquoted /var/cache/nginx/<name> — nothing provisions its dir, so -t fails with [emerg]: $(tr '\n' ' ' <<< "$bad_paths")"
done
[ "$(grep -v '^[[:space:]]*#' "$HELPER" 2>/dev/null | grep -c 'CFM_CACHE_DIRS=' || true)" = "1" ] || err "$HELPER: CFM_CACHE_DIRS must be assigned exactly once (the parity check reads that one line)."
grep -Eq '^ROOT=\$\{1:-/var/cache/nginx\}$' "$HELPER" || err "$HELPER: ROOT must default to /var/cache/nginx (ROOT=\${1:-/var/cache/nginx})."
grep -Eq '^for n in \$CFM_CACHE_DIRS; do$' "$HELPER" || err "$HELPER: the provisioning loop must iterate \$CFM_CACHE_DIRS (for n in \$CFM_CACHE_DIRS; do)."
grep -Eq '^const siteCacheRoot = "/var/cache/nginx"$' "$GODIRS" || err "$GODIRS: siteCacheRoot must be \"/var/cache/nginx\"."
[ -n "$go_dirs" ] || err "$GODIRS: no siteCacheDirNames list found — cannot verify the daemon's cache dirs."
[ -n "$ort_dirs" ] || err "$ORT: no proxy_cache_path under /var/cache/nginx found."
if [ "$helper_dirs" != "$ort_dirs" ]; then
  err "$HELPER provisions a different set of cache dirs than $ORT caches into (a missing one fails -t with [emerg]). Divergence:"
  diff <(printf '%s\n' "$ort_dirs") <(printf '%s\n' "$helper_dirs") 2>/dev/null | sed 's/^/       /' >&2 || true
fi
if [ "$go_dirs" != "$ort_dirs" ]; then
  err "$GODIRS (daemon) provisions a different set of cache dirs than $ORT caches into. Divergence:"
  diff <(printf '%s\n' "$ort_dirs") <(printf '%s\n' "$go_dirs") 2>/dev/null | sed 's/^/       /' >&2 || true
fi
if [ "$ang_dirs" != "$ort_dirs" ]; then
  err "$ANG and $ORT cache into different dirs. Divergence:"
  diff <(printf '%s\n' "$ort_dirs") <(printf '%s\n' "$ang_dirs") 2>/dev/null | sed 's/^/       /' >&2 || true
fi

if [ "$fail" -ne 0 ]; then
  echo "[site-cache-config] FAILED — see errors above (invariant: caching is bypass-by-default; the gate must come from Lua)." >&2
  exit 1
fi
echo "[site-cache-config] OK: cfm_static zone declared, Tier B micro buckets {1,2,5,10,30,60}s (zone + internal @cfm_micro_<n>s location) declared in both confs, \$cfm_cache_skip bypass-by-default, every proxy_cache location gated + buffered + (micro) internal, only-200 rail (\$cfm_cache_non200) enforced, request-identity rails (\$cfm_req_auth bypass + map, full g\$cfm_cache_gen|\$server_addr|\$scheme|\$cf_xfp:// key, per-tier lock_timeout, forwarded headers pinned) on every cache location, every location + every proxy_cache directive accounted for, cache dirs provisioned by the daemon and cfm-cache-dirs.sh == the proxy_cache_path dirs, Set-Cookie/Vary never ignored, Cache-Control/Expires/X-Accel-Expires ignored only in micro with the \$cfm_cc_nostore/\$cfm_xae_nocache rails (volatile maps) + background_update off + use_stale incl. http_5xx + proxy_cache_valid == the bucket, the \$cfm_micro_conf sentinel only in a redirect-free location / of the micro server (server default \"\"), the cfm_cache_uncacheable dict with micro inactive < MICRO_UNCACHEABLE_STALE_TTL, convert_head never off, the include set pinned, GET/HEAD-only cache methods, openresty↔angie parity ($ort_n static locations)."
