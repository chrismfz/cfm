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
#     * Set-Cookie, Vary and Cache-Control are never added to
#       proxy_ignore_headers (nginx must keep NOT caching a response that sets a
#       cookie or says private/no-store, and must keep one copy per Vary
#       variant), and proxy_cache_methods never lists a non-GET/HEAD method.
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
declare -A ncache_of=() nstatic_of=() clocs_of=()
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
  #     variables at all ($cfm_cache_skip / $cfm_req_auth / $cfm_cache_non200:
  #     the cache-on flip lives in cfm_cache.lua, never inline).
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
  # same for $cfm_cache_non200 (its map $upstream_status); $cfm_cache_skip may
  # only be `set … "1"` or a cache predicate. Known, adversarial-only gaps
  # (tracked for the guard-hardening follow-up): a regex named capture of a
  # guarded name, a Lua long-string index, a *_by_lua string-form directive,
  # and an identically mis-indented closing brace in both micro blocks (the
  # section (f) extractor works by indentation). Both maps hold EXACTLY their two
  # entries. proxy_ignore_headers never lists Set-Cookie / Vary / Cache-Control
  # and proxy_cache_methods never lists a non-GET/HEAD method (quoted or not).
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
    function mapcheck(hdr_re, want1, want2, name,   k, mk, e, ne, ok1, ok2, got) {
      mk = 0
      for (k = 1; k <= K; k++) if (tolower(ST[k]) ~ hdr_re) { mk = k; break }
      if (!mk) { print "ERR no " name " map — the rail the cache predicates key on is undefined."; return }
      ne = 0; ok1 = 0; ok2 = 0; got = ""
      for (k = mk + 1; k <= K; k++) {
        e = ST[k]; if (e ~ /^[[:space:]]*[}][[:space:]]*$/) break
        gsub(/[[:space:]]+/, " ", e); sub(/^ /, "", e); sub(/ $/, "", e)
        ne++; got = got "|" e
        if (e == want1) ok1 = 1; else if (e == want2) ok2 = 1
      }
      if (ne != 2 || !ok1 || !ok2) print "ERR the " name " map must hold EXACTLY: " want1 " and " want2 " — got:" got
    }
    function check_loc(   m, nz, lb, i, nh, H, st, mi) {
      nz = cnt(body, A "proxy_cache[[:space:]]+[^[:space:];]+[[:space:]]*;") - cnt(body, A "proxy_cache[[:space:]]+off[[:space:]]*;")
      if (nz <= 0) return
      ncache++; cache_toks += nz; m = ""; if (insrv) srv_cache = 1
      if (nz != 1) m = m " more-than-one-proxy_cache"
      st = (body ~ (A "proxy_cache[[:space:]]+cfm_static[[:space:]]*;"))
      mi = (body ~ (A "proxy_cache[[:space:]]+cfm_micro_[0-9]+s[[:space:]]*;"))
      if (!st && !mi) m = m " unknown-cache-zone(only-cfm_static-or-cfm_micro_Ns)"
      if (st) nstatic++
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
        if (!insrv && !loc && isopen && ls ~ /^[[:space:]]*server[[:space:]]*[{][[:space:]]*$/) { insrv = 1; srvD = D; srv_set = 0; srv_cache = 0; srvline = SL[k] }
        if (insrv && D == srvD + 1 && ls ~ /^[[:space:]]*set[[:space:]]+[$]cfm_cache_skip[[:space:]]+"1"[[:space:]]*;/) srv_set = 1
        if (!loc && s ~ /^[[:space:]]*location[[:space:]]/) { loc = 1; body = "\n"; locline = SL[k]; nloc++; d = 0; seen = 0 }
        if (loc) {
          body = body s "\n"
          if (isopen) { d++; seen = 1 }
          if (isclose) d--
          if (seen && d <= 0) { check_loc(); loc = 0; body = "" }
        }
        if (isopen) D++
        if (isclose) { D--; if (insrv && D == srvD) { if (srv_cache && !srv_set) print "ERR the server block opened at line " srvline " has a cache location but no server-level set $cfm_cache_skip \"1\" — bypass-by-default is lost for every vhost on it."; insrv = 0 } }
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
      mapcheck("^[[:space:]]*map[[:space:]]+[$]http_authorization[[:space:]]+[$]cfm_req_auth[[:space:]]*[{][[:space:]]*$", "default \"1\";", "\"\" \"\";", "$http_authorization → $cfm_req_auth")
      mapcheck("^[[:space:]]*map[[:space:]]+[$]upstream_status[[:space:]]+[$]cfm_cache_non200[[:space:]]*[{][[:space:]]*$", "default \"1\";", "\"200\" \"\";", "$upstream_status → $cfm_cache_non200 (only-200)")
      nm1 = 0; nm2 = 0
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
        if (u ~ /[$][{]?cfm_cache_skip([^a-z0-9_]|$)/ && !pred && u !~ /^[[:space:]]*set[[:space:]]+[$]cfm_cache_skip[[:space:]]+"1"[[:space:]]*;[[:space:]]*$/) print "ERR line " SL[k] ": $cfm_cache_skip appears in a " fw " statement — the conf may only set it to \"1\" (the cache-on flip comes ONLY from cfm_cache.lua)."
        if (fw == "proxy_ignore_headers" && u ~ /[[:space:]]["\047]?(set-cookie|vary|cache-control)["\047]?([[:space:];]|$)/) print "ERR line " SL[k] ": proxy_ignore_headers lists Set-Cookie, Vary or Cache-Control — nginx would then store a response that sets a cookie or says private/no-store, or one Vary variant for everyone. Ignoring Cache-Control needs a replacement rail and a guard update in the same change."
        if (fw == "proxy_cache_methods" && u ~ /[[:space:]]["\047]?(post|put|patch|delete)["\047]?([[:space:];]|$)/) print "ERR line " SL[k] ": proxy_cache_methods lists a non-GET/HEAD method — a cached POST/PUT result would be served to every client."
      }
      if (nm1 != 1) print "ERR $cfm_req_auth is written by " nm1 " copies of its map — it must have exactly one."
      if (nm2 != 1) print "ERR $cfm_cache_non200 is written by " nm2 " copies of its map — it must have exactly one."
      lt2 = tolower(LT)
      if (lt2 ~ /cfm_req_auth|cfm_cache_skip|cfm_cache_non200/) print "ERR inline Lua references $cfm_req_auth / $cfm_cache_skip / $cfm_cache_non200 — the cache rails must come only from the conf maps and cfm_cache.lua."
    }
  ' "$f")
  ncache_of["$f"]=$(sed -n 's/^NCACHE //p' <<< "$parsed")
  nstatic_of["$f"]=$(sed -n 's/^NSTATIC //p' <<< "$parsed")
  clocs_of["$f"]=$(sed -n 's/^CLOC //p' <<< "$parsed" | sort)
  parsed=$(grep -Ev '^(NCACHE|NSTATIC|CLOC) ' <<< "$parsed" || true)
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
  # no_cache / only-200 predicates, both rail maps, the per-server
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
echo "[site-cache-config] OK: cfm_static zone declared, Tier B micro buckets {1,2,5,10,30,60}s (zone + internal @cfm_micro_<n>s location) declared in both confs, \$cfm_cache_skip bypass-by-default, every proxy_cache location gated + buffered + (micro) internal, only-200 rail (\$cfm_cache_non200) enforced, request-identity rails (\$cfm_req_auth bypass + map, full g\$cfm_cache_gen|\$server_addr|\$scheme|\$cf_xfp:// key, per-tier lock_timeout, forwarded headers pinned) on every cache location, every location + every proxy_cache directive accounted for, cache dirs provisioned by the daemon and cfm-cache-dirs.sh == the proxy_cache_path dirs, Set-Cookie/Vary/Cache-Control never ignored, GET/HEAD-only cache methods, openresty↔angie parity ($ort_n static locations)."
