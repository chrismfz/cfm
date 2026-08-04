-- /var/lib/cfm/lua/cfm_waf_detectors.lua (CFM-managed canonical location)
--
-- The 32 detect_* functions and a handful of detector-scoped helpers.
-- Split out of cfm_waf.lua to keep the engine module readable; behaviour
-- is identical to the inlined form.
--
-- Initialisation: cfm_waf.lua calls _M.init(CFG, util) once at module
-- load. CFG and the named util helpers are then available as upvalues
-- to every detector. Late-binding upvalues mean detector function bodies
-- can be defined before init() runs (Lua reads upvalues at call time).
--
-- Public surface: each detector is exported as _M.detect_<name>. Internal
-- helpers (auth_endpoint_tag, is_known_legit_xmlrpc, etc.) stay local to
-- this module — only other detectors in this file call them.

local _M = {}

-- Late-bound upvalues populated by _M.init().
local CFG, util
local has, header_string, lower, cap, count_occurs, has_long_b64_blob,
      is_known_legit_php_upload_endpoint, score_obfuscation_blob, begins,
      url_decode_once, normalize, strip_sql_comments, scan_str,
      strip_host_port, is_ipv4_literal, is_ipv6_literal

function _M.init(cfg, u)
  CFG  = cfg
  util = u
  has                                = u.has
  header_string                      = u.header_string
  lower                              = u.lower
  cap                                = u.cap
  count_occurs                       = u.count_occurs
  has_long_b64_blob                  = u.has_long_b64_blob
  is_known_legit_php_upload_endpoint = u.is_known_legit_php_upload_endpoint
  score_obfuscation_blob             = u.score_obfuscation_blob
  begins                             = u.begins
  url_decode_once                    = u.url_decode_once
  normalize                          = u.normalize
  strip_sql_comments                 = u.strip_sql_comments
  scan_str                           = u.scan_str
  strip_host_port                    = u.strip_host_port
  is_ipv4_literal                    = u.is_ipv4_literal
  is_ipv6_literal                    = u.is_ipv6_literal
end

-- ─────────────────────────────────────────────────────────────────────────────
-- BLOCK-CLASS DETECTORS
-- ─────────────────────────────────────────────────────────────────────────────

-- Sensitive-sink keywords used by the single-`../` confirmation branch
-- below. Substring match against the scan buffer (already lowercased and
-- double-decoded by scan_str). Every real-attack traversal hit observed
-- across mars/virgo/orion (2026-05-05 → 2026-05-11, 23,352-event sample)
-- contains at least one of these tokens; legitimate `../` use in CMS-
-- generated URLs (e.g. phpThumb `?src=../images/...`) does not.
local TRAVERSAL_SENSITIVE_SINKS = {
  "/etc/passwd", "/etc/shadow", "/proc/self", "/boot.ini",
  "wp-config", "configuration.php", "config.inc.php", "settings.php",
  "pearcmd", "xmlrpc.php",
  "/.ssh/", "/.aws/", "/.git/config", "/.env",
  "win.ini", "system32",
}

function _M.detect_traversal(uri, args, _s)
  local s = _s or scan_str(uri, args)

  -- Strong, unconditional signals — never legitimate in any request.
  if has(s, "%00") or has(s, "\x00") then return true end

  -- Triple-URL-encoded path-separator variants survive scan_str's
  -- double-decode and are sometimes used to bypass single-decode WAFs.
  if has(s, "..%2f")   or has(s, "..%5c")   then return true end
  if has(s, "%2e%2e/") or has(s, "%2e%2e\\") then return true end

  -- Plain `../` or `..\` — must be exactly two dots. A run of three or
  -- more dots (FB share-debug bot URIs like `/.../<x>`, ellipsis-style
  -- CMS slugs like `/pro.../blouzaki-t-shirt-craft/`) is not traversal
  -- and must not match.  Lua patterns: a non-dot byte followed by two
  -- dots and a separator, OR `../` / `..\` at the start of scan.
  local has_dotdot =
       string.find(s, "[^.]%.%./",  1, false)
    or string.find(s, "^%.%./",     1, false)
    or string.find(s, "[^.]%.%.\\", 1, false)
    or string.find(s, "^%.%.\\",    1, false)
  if not has_dotdot then return false end

  -- Multi-hop traversal — `../../` or `..\..\` is always an attack.
  if string.find(s, "%.%./%.%./",   1, false) then return true end
  if string.find(s, "%.%.\\%.%.\\", 1, false) then return true end

  -- Single `../` only fires when paired with a sensitive sink. This
  -- preserves every real-attack hit (wp-config, /etc/passwd, pearcmd,
  -- xmlrpc.php LFI, RevSlider, etc.) while suppressing benign single
  -- `../` use such as phpThumb `?src=../images/products/foo.jpg`.
  for i = 1, #TRAVERSAL_SENSITIVE_SINKS do
    if has(s, TRAVERSAL_SENSITIVE_SINKS[i]) then return true end
  end

  return false
end

-- A data: URI in the request PATH is a client-side artifact, not an attack: a
-- browser or link-preview crawler (e.g. facebookexternalhit) resolved an inline
-- `data:...` URI as a RELATIVE url, so the whole data: payload — a base64 image/
-- font, or inline JavaScript — arrives as the request path and 404s. Its content
-- is never reflected or executed by the origin, so the reflected-XSS / code-exec
-- URI heuristics must not scan it. Matches the `data:<type>/<subtype>` scheme
-- shape on the raw (still %-encoded) path; the mime prefix is literal there
-- (only the payload after the comma is %-encoded). Legit request paths do not
-- carry it. Scoped to the PATH only, so a real `?x=data:text/html,<script>`
-- attack in the QUERY STRING is unaffected.
local function uri_is_data_uri_path(uri)
  -- `%f[%a]` anchors `data:` at a scheme boundary (prev char not a letter), so a
  -- path segment like `/metadata:image/…` or `/userdata:foo` is NOT mistaken for
  -- a data: URI; `%a+/%a` requires the `<type>/<subtype>` mime shape.
  return lower(uri or ""):find("%f[%a]data:%a+/%a", 1, false) ~= nil
end
_M.uri_is_data_uri_path = uri_is_data_uri_path

function _M.detect_rce(uri, args, _s)
  local s = _s or scan_str(uri, args)

  if has(s, "${jndi:")   then return true end
  if has(s, "${j{n{d{i") then return true end
  if has(s, "$%7bjndi")  then return true end

  if has(s, ";wget ") then return true end
  if has(s, ";curl ") then return true end
  if has(s, "|bash")  then return true end
  if has(s, "|sh ")   then return true end
  if has(s, "`wget")  then return true end
  if has(s, "`curl")  then return true end

  -- Encoded-payload data URI paired with a code-exec CALL. Two FP guards, both
  -- targeting the same incident class (legit `data:*;base64,…` / inline-JS data
  -- URIs that a browser/crawler requested as a relative path — Facebook's
  -- link-preview crawler, a real Greek customer on epiplosou.gr — which
  -- false-positived this BLOCK-tier rule):
  --   1. The call markers are PAREN-ANCHORED (`eval(`/`exec(`/`system(`): `(` is
  --      not in the base64 alphabet, so it can never appear INSIDE a base64 blob,
  --      whereas the bare words "eval"/"exec"/"system" occur there by chance.
  --   2. Skipped entirely when the request PATH is a data: URI artifact — covers
  --      a legit inline script that both embeds a base64 asset AND calls `eval(`.
  -- The jndi/wget/curl/bash markers above stay FULL-surface (unguarded), so a
  -- real `/data:x,${jndi:…}` can't use the data: prefix to evade them.
  if not uri_is_data_uri_path(uri)
     and has(s, "base64,") and (has(s, "eval(") or has(s, "exec(") or has(s, "system(")) then
    return true
  end

  return false
end

-- Returns (action, tag) so the wire-up emits a sub-tag in the reason
-- string for log triage. Backwards-compatible at the rule-id level (607
-- is still the rule that fires) and at the family level (`WAF_EXPLOIT_METHOD`
-- is still the prefix); only the suffix is new (B2 extension).
function _M.detect_exploit_method(method)
  method = lower(method or "")

  if method == "trace"   then return "block",     "TRACE"   end
  if method == "track"   then return "block",     "TRACK"   end
  -- CFM angie/openresty isn't a forward proxy, so any CONNECT we see is
  -- by definition out-of-place. Sub-tag captures that intent for log
  -- triage even though the action is unchanged.
  if method == "connect" then return "block",     "CONNECT_NOT_PROXY" end

  -- DAV methods (PROPFIND/SEARCH) are intentionally NOT flagged: ownCloud,
  -- Nextcloud, Outlook and other legit WebDAV clients depend on them and
  -- flagging them globally breaks login/sync for those vhosts.

  return nil, nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- LOGONLY-CLASS SAFER ROLLOUT DETECTORS (existing)
-- ─────────────────────────────────────────────────────────────────────────────

function _M.detect_php_wrappers(args, body, _ns)
  local s = _ns or normalize(cap(args or "", CFG.max_scan_len) .. "&" .. cap(body or "", CFG.max_scan_len))
  if s == "" then return nil end

  if has(s, "php://")    then return "WRAP_PHP" end
  if has(s, "phar://")   then return "WRAP_PHAR" end
  if has(s, "data://")   then return "WRAP_DATA" end
  if has(s, "zip://")    then return "WRAP_ZIP" end
  if has(s, "expect://") then return "WRAP_EXPECT" end
  if has(s, "glob://")   then return "WRAP_GLOB" end

  return nil
end

function _M.detect_ip_host(host)
  local h = strip_host_port(host)
  if h == "" then return false end
  if is_ipv4_literal(h) then return true end
  if is_ipv6_literal(h) then return true end
  return false
end

-- Detect suspicious ASCII control characters.
-- Excludes TAB/LF/CR by only matching:
--   0x01-0x08, 0x0B, 0x0C, 0x0E-0x1F
--
-- Safer rollout:
--   * always inspect args
--   * inspect body only for textual payloads
--   * skip multipart/form-data bodies (binary uploads are noisy by design)
-- Known legitimate endpoints whose body/args routinely carry binary or packed
-- bytes that are not UTF-8 text and are not an encoding-bypass attempt. The
-- ctrl-chars (601) and bad-UTF8 (611) detectors skip these to avoid logonly FP
-- noise — observed heavily fleet-wide on Greek e-commerce admins + mobile
-- visitors (2026-06-25 five-server log review):
--   * WP Optimization Detective web-vitals store (packed metric payloads)
--   * WP media upload async-upload.php (raw image/file bytes)
local function is_known_binaryish_uri(uri)
  local u = lower(uri or "")
  if u == "" then return false end

  if u:match("^/wp%-json/optimization%-detective/")
     and has(u, "/url-metrics:store") then
    return true
  end

  local path = u:match("^[^?]*") or u
  if path:match("/wp%-admin/async%-upload%.php$") then
    return true
  end

  return false
end

function _M.detect_ctrl_chars(args, body, headers, uri)
  if is_known_binaryish_uri(uri) then
    return false
  end

  local a = args or ""
  if a ~= "" and a:find("[\x01-\x08\x0b\x0c\x0e-\x1f]") then
    return true
  end

  if not body or body == "" then
    return false
  end

  headers = headers or {}
  local ct = lower(headers["content-type"] or headers["Content-Type"] or "")

  if has(ct, "multipart/form-data") then
    return false
  end

  if ct ~= ""
     and not has(ct, "application/x-www-form-urlencoded")
     and not has(ct, "application/json")
     and not has(ct, "application/xml")
     and not has(ct, "text/") then
    return false
  end

  if body:find("[\x01-\x08\x0b\x0c\x0e-\x1f]") then
    return true
  end

  return false
end

local function is_textual_body_content_type(content_type)
  local ct = lower(content_type or "")
  if ct == "" then return true end

  if has(ct, "multipart/form-data")              then return false end
  if has(ct, "application/x-www-form-urlencoded") then return true end
  if has(ct, "application/json")                  then return true end
  if has(ct, "application/xml")                   then return true end
  if has(ct, "text/")                             then return true end

  return false
end

function _M.detect_php_webshell_body(body, headers)
  if not body or body == "" then return nil end

  headers = headers or {}
  local ct = header_string(headers["content-type"] or headers["Content-Type"])
  if not is_textual_body_content_type(ct) then
    return nil
  end

  local s = normalize(cap(body, tonumber(CFG.php_webshell_max_scan_len) or CFG.max_scan_len))
  if s == "" then return nil end

  if has(ct, "application/x-www-form-urlencoded") then
    s = s:gsub("%+", " ")
  end

  -- Webshell self-identifying strings (W2 extension). These are constants
  -- and page-title markers found inside the source of well-known shells:
  -- they're specific enough that a bare prose mention almost never matches
  -- (no legitimate page contains "0byt3m1n1" or "indoxploit"), but the body
  -- is still gated by the early-out below so we don't pay scoring cost on
  -- requests that lack any PHP marker at all.
  local function ws_name_match()
    if has(s, "b374k")      then return "B374K"      end
    if has(s, "c99shell")   then return "C99SHELL"   end
    if has(s, "r57shell")   then return "R57SHELL"   end
    if has(s, "indoxploit") then return "INDOXPLOIT" end
    if has(s, "0byt3m1n1")  then return "0BYT3M1N1"  end
    if has(s, "weevelyshell") then return "WEEVELY"  end
    if has(s, "<title>c99")   then return "C99_TITLE"  end
    if has(s, "<title>r57")   then return "R57_TITLE"  end
    -- WSO ships under several version banners; the prefix is the stable bit.
    if has(s, "wso 2.") or has(s, "wso 4.") or has(s, "wso 5.") then return "WSO" end
    return nil
  end

  if not (has(s, "<?") or has(s, "$_") or has(s, "eval") or has(s, "system")
          or has(s, "passthru") or has(s, "shell_exec") or has(s, "exec")
          or has(s, "b374k") or has(s, "c99shell") or has(s, "r57shell")
          or has(s, "indoxploit") or has(s, "0byt3m1n1")
          or has(s, "weevelyshell") or has(s, "wso 2.")
          or has(s, "wso 4.") or has(s, "wso 5.")) then
    return nil
  end

  local score = 0

  if has(s, "<?php") or has(s, "<?=") then
    score = score + 2
  end

  if has(s, "$_get") or has(s, "$_post") or has(s, "$_request")
     or has(s, "$_cookie") or has(s, "$_server") then
    score = score + 2
  end

  local function has_php_callable(name)
    if s:find("%f[%a_]" .. name .. "%s*%(") then return true end
    if s:find("@%s*" .. name .. "%s*%(") then return true end
    return false
  end

  -- Dynamic include / require — matches only when the include's argument
  -- starts with `$` (a variable). This is the malicious-loader shape:
  --   include $tmpfile;          ← matched
  --   include_once $_POST['k'];  ← matched
  --   include(@$cfg);            ← matched
  --   require_once $plugin_path; ← matched
  -- The literal-string forms used by all legitimate code do NOT match:
  --   include 'file.php';        ← skipped
  --   include "/abs/path.php";   ← skipped
  --   include __DIR__."/x.php";  ← skipped (next char is `_`, not `$`)
  --   require_once 'app.php';    ← skipped
  -- This is the FP-mitigation: tightened from a generic
  -- has_include_construct (which matched any argument shape) after the
  -- 2026-05-09 sample-replay audit showed the broader pattern would FP
  -- on common code-snippet plugin saves.
  local function has_dynamic_include(name)
    if s:find("%f[%a_]" .. name .. "%s+@?%$") then return true end
    if s:find("%f[%a_]" .. name .. "%s*%(%s*@?%$") then return true end
    if s:find("@%s*"     .. name .. "%s+@?%$") then return true end
    if s:find("@%s*"     .. name .. "%s*%(%s*@?%$") then return true end
    return false
  end

  if has_php_callable("eval") then score = score + 3 end
  if has_php_callable("assert") then score = score + 3 end
  if has_php_callable("system") then score = score + 3 end
  if has_php_callable("exec") then score = score + 3 end
  if has_php_callable("passthru") then score = score + 3 end
  if has_php_callable("shell_exec") then score = score + 3 end
  if has_php_callable("popen") then score = score + 3 end
  if has_php_callable("proc_open") then score = score + 3 end

  -- Dynamic include / require at +1. Combined with the existing <?php (+2)
  -- and superglobal (+2) signals, the loader-style malware fingerprint
  -- (forms.php / user.php samples from the 2026-05-09 audit, both of which
  -- include a variable that came from $_POST) reaches score 5 — exactly
  -- min_score. Literal-form includes (the WP-bootstrap case and any legit
  -- code-snippet plugin save with `require 'app.php'`) don't match
  -- has_dynamic_include and never contribute to the score, so they
  -- can't push a body over threshold.
  if has_dynamic_include("include")      then score = score + 1 end
  if has_dynamic_include("include_once") then score = score + 1 end
  if has_dynamic_include("require")      then score = score + 1 end
  if has_dynamic_include("require_once") then score = score + 1 end

  -- NOTE: removed in the 2026-05-09 audit follow-up — a bare +1 for
  -- `;` + `<?php` was firing on any multi-statement legit PHP body that
  -- mentioned a superglobal (`<?php $x=$_POST['msg']; echo $x;` scored
  -- 2+2+1=5 → fired with tag RAW_SUPERGLOBAL, an FP on every code-paste
  -- and form-helper plugin save). Score now needs an actual exec-class
  -- callable, a webshell-name marker, OR a dynamic include to cross
  -- threshold — which is the rule's stated intent.

  -- Webshell-name signature: +3 weight, comparable to a single PHP callable.
  -- Combined with the standard <?php (+2) opener it crosses the default
  -- min_score (5); alone (no <?php, no superglobal, no callable) it stays
  -- below threshold so a forum post mentioning "b374k" can't trigger.
  local ws_tag = ws_name_match()
  if ws_tag then score = score + 3 end

  local min_score = tonumber(CFG.php_webshell_min_score) or 5
  if score < min_score then
    return nil
  end

  -- Webshell-name match outranks the generic RAW_* tags because operators
  -- want to know *which* shell hit, not just that something did.
  if ws_tag then return "RAW_WS_" .. ws_tag end

  if s:find("<?php.-@?eval%s*%(") and s:find("%$_post") then return "RAW_EVAL_POST" end
  if s:find("<?php.-@?system%s*%(") and s:find("%$_get") then return "RAW_SYSTEM_GET" end
  if s:find("<?php.-@?passthru%s*%(") and s:find("%$_request") then return "RAW_PASSTHRU_REQUEST" end

  if has_php_callable("eval")       then return "RAW_EVAL" end
  if has_php_callable("assert")     then return "RAW_ASSERT" end
  if has_php_callable("system")     then return "RAW_SYSTEM" end
  if has_php_callable("exec")       then return "RAW_EXEC" end
  if has_php_callable("passthru")   then return "RAW_PASSTHRU" end
  if has_php_callable("shell_exec") then return "RAW_SHELL_EXEC" end
  if has_php_callable("popen")      then return "RAW_POPEN" end
  if has_php_callable("proc_open")  then return "RAW_PROC_OPEN" end

  -- Include/require tags rank below the exec-family ones (an attacker who
  -- has both eval and include in the body is already tagged RAW_EVAL —
  -- which is the more actionable label). The `_once` variants are checked
  -- first so the more-specific tag wins when both forms are present.
  if has_dynamic_include("include_once") then return "RAW_DYN_INCLUDE_ONCE" end
  if has_dynamic_include("require_once") then return "RAW_DYN_REQUIRE_ONCE" end
  if has_dynamic_include("include")      then return "RAW_DYN_INCLUDE" end
  if has_dynamic_include("require")      then return "RAW_DYN_REQUIRE" end

  if has(s, "$_get") or has(s, "$_post") or has(s, "$_request") then
    return "RAW_SUPERGLOBAL"
  end

  return "RAW_SCORING_HIT"
end

function _M.detect_b64_injection(body)
  if not body or body == "" then return nil end
  -- A base64 candidate must be at least 24 chars long; the body must be at least
  -- 25 bytes (the '=' plus 24 chars).  Skip the gmatch loop entirely for short bodies
  -- and bodies that contain no '=' assignment-style separator.
  if #body < 25 then return nil end
  if not body:find("=", 1, true) then return nil end

  -- B64_OBJ_INJECT (PHP object injection) is a LOW-PRIORITY FALLBACK: unlike every
  -- other marker here it fires at a capped `logonly` tier (cfm_waf.lua §33 burn-in),
  -- so it must never SHADOW a higher-tier hostile sibling. This detector returns on
  -- the first match, so returning the object tag eagerly would let an attacker
  -- prepend a serialized-object marker — in this candidate OR an earlier one — to
  -- downgrade a base64'd eval/system/union-select from challenge/block to logonly.
  -- Instead we REMEMBER an object hit and keep scanning; any hostile marker in this
  -- or a later candidate returns immediately and wins. The deferred object tag is
  -- returned only if no hostile marker is found anywhere. Audit F13.
  local deferred_obj = nil

  for candidate in body:gmatch("=([A-Za-z0-9+/]+=*)") do
    if #candidate >= 24 then
      local decoded = ngx.decode_base64(candidate)
      if decoded and #decoded >= 12 then
        local d = string.lower(decoded)

        if has(d, "$_get") or has(d, "$_post") or has(d, "$_cookie")
          or has(d, "$_server") or has(d, "$_session")
          or has(d, "$globals") or has(d, "http_raw_post_data") then
          return "B64_SUPERGLOBAL"
        end

        if has(d, "eval(")               then return "B64_EVAL" end
        if has(d, "assert(")             then return "B64_ASSERT" end
        if has(d, "exec(")               then return "B64_EXEC" end
        if has(d, "system(")             then return "B64_SYSTEM" end
        if has(d, "passthru(")           then return "B64_PASSTHRU" end
        if has(d, "shell_exec(")         then return "B64_SHELL_EXEC" end
        if has(d, "base64_decode(")      then return "B64_B64_DECODE" end
        if has(d, "gzinflate(")          then return "B64_GZINFLATE" end
        if has(d, "move_uploaded_file(") then return "B64_MOVEUPLOAD" end
        if has(d, "fsockopen(")          then return "B64_FSOCKOPEN" end
        if has(d, "curl_exec(")          then return "B64_CURL_EXEC" end
        if has(d, "file_get_contents(")  then return "B64_FILEGET" end

        if has(d, "<?php") or has(d, "<?=") then return "B64_PHP_TAG" end
        if has(d, "<script") then return "B64_XSS_SCRIPT" end
        if has(d, "<iframe") then return "B64_XSS_IFRAME" end
        if has(d, "<object") then return "B64_XSS_OBJECT" end

        if has(d, "union select")       then return "B64_SQLI_UNION" end
        if has(d, "insert into")        then return "B64_SQLI_INSERT" end
        if has(d, "information_schema") then return "B64_SQLI_SCHEMA" end

        -- Lowest priority (deferred — see the fallback note above the loop). PHP
        -- object-injection markers: a serialized object header O:<len>:"Class" or a
        -- custom-serialized C:<len>:"Class" (the unserialize() POP-chain gadget
        -- entry). `d` is lower()ed above, so match o:/c:. The %f[%a] frontier
        -- requires the marker to START a token — a real serialized object sits at
        -- string-start or after a structural delimiter (`;`, `{`) — so a word ending
        -- in o/c like foo:12:"bar" can't false-match. Objects only (not a:<len>:{
        -- arrays): only object unserialize triggers POP chains. (The old %bo%: used
        -- Lua's %b balanced-match by mistake — it asked for a literal '%' delimiter
        -- serialized data never contains, so this sub-rule matched nothing and was
        -- dead. Audit F13.)
        if not deferred_obj and (d:match('%f[%a]o:%d+:"') or d:match('%f[%a]c:%d+:"')) then
          deferred_obj = "B64_OBJ_INJECT"
        end
      end
    end
  end

  return deferred_obj
end

-- ─────────────────────────────────────────────────────────────────────────────
-- CHALLENGE-CLASS DETECTORS
-- ─────────────────────────────────────────────────────────────────────────────

-- Inline event-handler attribute names that carry reflected XSS. Kept as an
-- explicit set (not a generic `on%a+=` match) so benign query params that just
-- happen to start with "on" — onboarding, online, once, onsale, ontime — never
-- match. Curated toward the AUTO-FIRING handlers (fire with no user
-- interaction: load/error/focus+autofocus, CSS animation/transition, SVG SMIL
-- begin/end, <details ontoggle>, popover onbeforetoggle, media autoplay) plus
-- the classic interaction handlers, since those are what reflected-XSS payloads
-- actually use. Add handlers here; the matcher and its cost are unchanged.
local XSS_EVENT_HANDLERS = {
  -- auto-firing (no interaction required)
  onload = true, onerror = true, onfocus = true,
  onanimationstart = true, onanimationend = true, onanimationiteration = true,
  ontransitionstart = true, ontransitionrun = true, ontransitionend = true,
  ontransitioncancel = true,
  ontoggle = true, onbeforetoggle = true,
  onbegin = true, onend = true, onrepeat = true,          -- SVG SMIL animate/set
  onstart = true, onbounce = true, onfinish = true,       -- <marquee> auto-fire
  onpointerrawupdate = true, onpointerenter = true, onpointerover = true,
  onpointerdown = true, onpointerup = true, onpointermove = true,
  onpointerleave = true,
  onscroll = true, onscrollend = true,
  onplay = true, onplaying = true, oncanplay = true, oncanplaythrough = true,
  onended = true, onloadstart = true, onloadeddata = true, onloadedmetadata = true,
  ondurationchange = true, onpageshow = true,
  -- interaction handlers (classic reflected-XSS vectors)
  onmouseover = true, onmouseenter = true, onmouseleave = true,
  onmousemove = true, onmousedown = true, onmouseup = true, onmouseout = true,
  onclick = true, ondblclick = true, onauxclick = true, oncontextmenu = true,
  onwheel = true, onkeydown = true, onkeyup = true, onkeypress = true,
  oninput = true, onchange = true, onblur = true, onsubmit = true,
}

function _M.detect_xss(uri, args, _s)
  -- A data: URI in the request PATH is a client artifact (an inline data: URI a
  -- browser/crawler resolved as a relative url): it 404s and is never reflected,
  -- so its inline JavaScript (e.g. `el.onload = fn`, `.prototype`, a base64 font)
  -- must not read as reflected XSS. This false-positived rule 302 on
  -- facebookexternalhit crawling a `data:text/javascript,…` counter script on
  -- mobian.eu (breaking that site's Facebook link previews). Scoped to the PATH,
  -- so a real `?x=data:text/html,<script>` in the QUERY STRING still fires below.
  if uri_is_data_uri_path(uri) then return false end
  local s = _s or scan_str(uri, args)

  if has(s, "<script")      or has(s, "%3cscript") then return true end
  -- javascript: in attribute-value position only. Bots that follow
  -- <a href="javascript:void(0)"> anchor hrefs hit URIs that literally
  -- start with /javascript: — those are not XSS injections, skip them.
  if has(s, "=javascript:")   then return true end
  if has(s, "=\"javascript:") then return true end
  if has(s, "='javascript:")  then return true end

  -- Event-handler attributes, e.g. `<svg onload=alert(1)>`. One frontier
  -- gmatch pass captures each `on<word>` that is followed by optional
  -- whitespace and `=`, then checks it against XSS_EVENT_HANDLERS:
  --   * `%f[%w]` anchors on a non-word boundary, so an `on…=` embedded in a
  --     longer identifier is not flagged. WPML's `?ateJobCreationError=101`
  --     carries "onerror=" inside "creationError=" — mid-word, no frontier,
  --     so it never matches. Real reflected XSS always has a delimiter
  --     (space, quote, `<`, `=`, `&`, `;`, `/`) before the handler name.
  --   * `%s*=` tolerates whitespace before the `=` — HTML attribute parsers
  --     accept `onload =` / `onload\t=`, which the old `onload=` literal
  --     missed entirely (audit F33).
  --   * the set membership means only real handler names fire, so benign
  --     `on…=` params (onboarding=, online=) are captured but rejected.
  for handler in s:gmatch("%f[%w](on%a+)%s*=") do
    if XSS_EVENT_HANDLERS[handler] then return true end
  end

  return false
end

-- sqlmap-class blind-SQLi primitives, split into two confidence tiers.
--
-- SQLI_BLIND_TOKENS: DBMS-unique time-based primitives that do NOT collide
-- with any ordinary word or method name, so they are safe at `challenge`
-- (rule 301, WAF_SQLI). "waitfor delay" never matches the English "wait
-- for" (no space in the token); pg_sleep / dbms_* / now()=sysdate() /
-- rlike / the select(sleep( structural forms are SQL-only.
local SQLI_BLIND_TOKENS = {
  -- MSSQL (time-based)
  "waitfor delay", "waitfor time",
  -- PostgreSQL (time-based)
  "pg_sleep",
  -- Oracle (time-based / heavy query)
  "dbms_pipe.receive_message", "dbms_lock.sleep",
  -- MySQL (time-based, SQL-anchored)
  "now()=sysdate()", "rlike sleep(", "select sleep(", "select(sleep(",
  -- MySQL error-based (exp + bitwise NOT; rare in normal code)
  "exp(~",
}

-- SQLI_LEXICAL_TOKENS: real SQLi primitives that ALSO collide
-- case-insensitively with legitimate code/content, so they ride a SEPARATE
-- rule (309, WAF_SQLI_LEXICAL) kept at `logonly` — observed, never
-- challenged — until the WAF FP review (docs/waf.md) clears them:
--   benchmark(      — the word "benchmark(" in perf/dev content
--   extractvalue(   — camelCase extractValue( in XML parsers / JS / Java
--   updatexml(      — camelCase updateXml( / updateXML(
--   floor(rand(     — valid PHP floor(rand(...))
--   randomblob(     — JS randomBlob(
--   or sleep( / and sleep( / ,sleep( / (sleep(  — shell/code prose and
--                     minified/nested calls ("x or sleep(3)")
local SQLI_LEXICAL_TOKENS = {
  "benchmark(", "extractvalue(", "updatexml(", "floor(rand(", "randomblob(",
  "or sleep(", "and sleep(", ",sleep(", "(sleep(",
}

-- sqli_scan_strings(s) returns (sc, scw): the comment-stripped scan string and
-- a copy with runs of '+'/whitespace collapsed to a single space (so a
-- form-urlencoded space arriving as '+' or '%20' still matches the spaced
-- tokens). The three SQLi detectors below take this (sc, scw) pair directly so
-- the engine can compute it ONCE per scan surface (get_sqli_ua/get_sqli_ab,
-- memoized) instead of each rule recomputing strip_sql_comments + the collapse
-- on the same string — audit F30b. Exported for the engine's memoized getters.
local function sqli_scan_strings(s)
  local sc = strip_sql_comments(s or "")
  return sc, (sc:gsub("[+%s]+", " "))
end
_M.sqli_scan_strings = sqli_scan_strings

function _M.detect_sqli(sc, scw)
  -- sc = comment-stripped scan string (catches UN/**/ION SE/**/LECT bypass);
  -- scw = its '+'/whitespace-collapsed copy. Both are precomputed by the engine
  -- (double URL-decode already applied upstream by normalize()/scan_str()).

  -- Space-bearing tautology tokens are matched against `scw` (runs of
  -- '+'/whitespace collapsed to one space), NOT `sc`. A form/query space
  -- arrives as '+', and PHP (parse_str/$_GET/$_POST) et al. decode '+'
  -- ->space before the SQL runs, so the backend sees `union select` while
  -- `sc` (which preserves '+') still reads `union+select`. Checking these
  -- against `sc` let `1+union+select+…`, `1+or+1=1`, `'+or+'1'='1` evade
  -- rule 301 (block) even though the `%20`/space forms were caught — a
  -- first-try bypass. `scw` also folds double separators
  -- (`union%20%20select`, `union++select`) that a single-space substring
  -- test on `sc` misses. The `%`-encoded fallbacks stay on `sc` for the
  -- rare partial-decode case; `information_schema` has no separator so the
  -- two strings are equivalent for it.
  -- UNION SELECT: matched on scw (so `union+select` / `union%20%20select`
  -- collapse to `union select`) BUT gated on a value-terminator right before
  -- `union` — a digit, quote, or close-paren — or string start. Real UNION
  -- injection breaks out of an existing value first, and the common form
  -- `?id=1+union+select+…` lands the terminator as the trailing DIGIT of the
  -- value (`1 union`), not the `=`. Legit English keeps "union" as a NOUN
  -- after a word (`credit union select account`, `trade union selection`,
  -- `reunion selected`), which must NOT hit this BLOCK rule — a bare
  -- `has(scw,"union select")` would 403 them, because the '+'→space collapse
  -- turns the signature into a plain two-word substring (the '+' form the
  -- block-tier FP burn-in never saw, since pre-fix '+' wasn't collapsed).
  --
  -- Deliberately EXCLUDED from the terminator class, all to avoid real FPs
  -- where the collapse would otherwise create `<sep> union select<word>`:
  --   `=` — `?q=union+select+board` ("Union Select Board" municipal search,
  --         `?q=union+selectmen`) begins the value with the noun "union";
  --         the bare-value `?id=union+select` injection (no leading digit) is
  --         the rare form and is given up here rather than block those.
  --   `/` `,` — legit paths (`/union+selected+news`) and CSV values
  --         (`a,union+select,b`); negligible UNION-injection signal.
  -- Known residual GAPS (pre-existing, NOT closed here — they need the
  -- keyword/separator-tolerant rewrite tracked in docs/roadmaps, with its own
  -- FP burn-in per CLAUDE.md §6): `union all select`, `union distinct select`,
  -- `union(select`, and `union/**/select` (strip_sql_comments collapses the
  -- last to `unionselect`). This fix closes only the '+'-encoding bypass of
  -- the existing adjacent-`union select` signature.
  -- A SQL literal/keyword operand also breaks out of an unquoted value with
  -- NO digit/quote/paren before `union`: `?id=null union select`,
  -- `?enabled=true union select`, `1 is null union select`. `null`/`true`/
  -- `false` are complete valid operands, so the UNION executes; they end in a
  -- letter, so the char-class gate above misses them — match them explicitly.
  -- (The pre-fix plain-substring check caught these; dropping them would
  -- REGRESS vs the shipped rule. `true union select` / `null union select` as
  -- legit prose is SQL-speak, not natural language — negligible FP.)
  if scw:find("[%d'\"%)] ?union select")
     or scw:find("null ?union select")
     or scw:find("true ?union select")
     or scw:find("false ?union select")
     or scw:sub(1, 12) == "union select" then
    return true
  end
  if has(sc,  "union%20select")     then return true end
  if has(sc,  "information_schema") then return true end
  -- `' or '1'='1` needs quotes and ` or 1=1` keeps its leading space (so
  -- "operator 1=1" / "for 1=1" don't hit) — both stay FP-safe on scw, where
  -- the '+' form (`1+or+1=1`) now collapses to the space form we match.
  if has(scw, " or 1=1")            then return true end
  if has(sc,  " or%201=1")          then return true end
  if has(scw, "' or '1'='1")       then return true end
  if has(sc,  "%27%20or%20%271%27%3d%271") then return true end

  -- DBMS-unique time-based blind family (sqlmap).
  for i = 1, #SQLI_BLIND_TOKENS do
    if has(scw, SQLI_BLIND_TOKENS[i]) then return true end
  end

  -- sqlmap boolean-blind arithmetic inference tail, e.g.
  -- "-1 OR 2+481-481-1=0+0+0+1". The "=0+0+0+1" constant is stable across
  -- the randomised operands; keep '+' literal so it matches `sc`.
  if has(sc, "=0+0+0+1") then return true end

  return false
end

-- detect_sqli_blind_lexical matches the word/method-colliding blind tokens
-- (SQLI_LEXICAL_TOKENS). Wired to rule 309 at `logonly` so it cannot break
-- a legitimate app (XML parser / updater / custom script) during the trial.
function _M.detect_sqli_blind_lexical(sc, scw)
  for i = 1, #SQLI_LEXICAL_TOKENS do
    if has(scw, SQLI_LEXICAL_TOKENS[i]) then return true end
  end
  return false
end

-- union_mid_hit: is there `union<mid>select` in a VALUE-BREAK context on scw?
-- `mid` is a Lua-pattern fragment for what sits between union and select — the
-- SAME value-terminator guard as detect_sqli's `union select` (a digit / quote /
-- close-paren, or a null/true/false operand, right before `union`) so a legit
-- noun phrase ("credit union all selected") is not matched. No string-start
-- branch here: like rule 301's final form, a bare value-leading `union` (only a
-- `=` before it) is deliberately given up to avoid FPs, and the scan string is
-- uri.."?"..args so `union` never sits at position 1 in practice.
local function union_mid_hit(scw, mid)
  local body = "union" .. mid .. "select"
  return scw:find("[%d'\"%)] ?" .. body) ~= nil
      or scw:find("null ?" .. body) ~= nil
      or scw:find("true ?" .. body) ~= nil
      or scw:find("false ?" .. body) ~= nil
end

-- detect_sqli_union_variant matches UNION-based injection whose UNION and SELECT
-- are separated by an obfuscation that the adjacent-`union select` signature
-- (detect_sqli, rule 301) misses:
--   * a keyword — `union all select` / `union distinct select`;
--   * a parenthesis — `union(select`;
--   * an inline comment — `union/**/select`, which strip_sql_comments collapses
--     to `unionselect` (the comment removes the very space the 301 signature
--     needs); the same collapse applied to the keyword form yields
--     `unionallselect` / `uniondistinctselect` (`union/**/all/**/select`).
-- `UNION ALL SELECT` in particular is at least as common as plain UNION SELECT.
-- Gated on the same value-terminator guard as rule 301 (see union_mid_hit), and
-- ridden on a SEPARATE rule at `logonly` for a real-traffic burn-in before any
-- promotion to challenge/block (CLAUDE.md §6; docs/waf.md). Returns true/false.
function _M.detect_sqli_union_variant(sc, scw)
  if union_mid_hit(scw, " all ")      then return true end
  if union_mid_hit(scw, " distinct ") then return true end
  if union_mid_hit(scw, "%(")         then return true end -- union(select
  if union_mid_hit(scw, "")           then return true end -- unionselect (union/**/select collapsed)
  if union_mid_hit(scw, "all")        then return true end -- unionallselect (union/**/all/**/select)
  if union_mid_hit(scw, "distinct")   then return true end -- uniondistinctselect (comment-collapsed)
  return false
end

-- Superglobal / variable-override probe. A request parameter whose KEY is a
-- PHP superglobal / reserved name (e.g. `?_SERVER[x]=`, `&GLOBALS[x]=`, or
-- `_GET[x]=` in the body) is a PHP variable-poisoning attempt against code
-- using extract() / import_request_variables() / register_globals-style
-- patterns — the value gets injected as the named PHP variable.
--
-- Anchored to a parameter boundary so it matches the param NAME, not the
-- value: each pattern requires a `?`/`&`/`;` delimiter immediately before the
-- name and a `=` or `[` immediately after. Ordinary fields whose name merely
-- ENDS in one of these (`db_server=`, `mail_server=`, `name_server=`) are
-- preceded by a non-delimiter byte and do NOT match; a superglobal appearing
-- as a value (`?x=_server`) is preceded by `=` and does NOT match either.
-- An edge proxy can only flag this (it can't unset the key the way an
-- in-process PHP WAF does), so this ships at `logonly` (rule 318).
local SUPERGLOBAL_PATTERNS = {}
do
  local names = {
    "_get", "_post", "_request", "_cookie", "_server",
    "_env", "_files", "_session", "globals",
  }
  for i = 1, #names do
    SUPERGLOBAL_PATTERNS[i] = { name = names[i], pat = "[?&;]" .. names[i] .. "[=%[]" }
  end
end

function _M.detect_superglobal_override(uri, args, _s)
  -- Prefix a delimiter so a name at the very start of the scan string is
  -- still preceded by a boundary; normalize() has already lowercased and
  -- url-decoded, so an uppercase `_SERVER` / encoded `%5B` is covered.
  local s = "&" .. (_s or scan_str(uri, args))
  for i = 1, #SUPERGLOBAL_PATTERNS do
    if string.find(s, SUPERGLOBAL_PATTERNS[i].pat) then
      return SUPERGLOBAL_PATTERNS[i].name
    end
  end
  return nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- AUTH / BRUTE / XML-RPC HELPERS
-- ─────────────────────────────────────────────────────────────────────────────

local function auth_endpoint_tag(uri, method)
  uri = lower(uri or "")
  method = lower(method or "get")

  if has(uri, "/wp-login.php") then return "AUTH_WP_LOGIN" end
  if has(uri, "/xmlrpc.php")   then return "AUTH_WP_XMLRPC" end
  if has(uri, "/user/login") then return "AUTH_DRUPAL_LOGIN" end


if has(uri, "/administrator/index.php") then
  -- Treat Joomla admin as auth only for real login-ish flows,
  -- not every authenticated backend/template/ajax request.
  if method == "post" then
    return "AUTH_JOOMLA_ADMIN"
  end

  if has(uri, "option=com_login") then
    return "AUTH_JOOMLA_ADMIN"
  end

  if has(uri, "view=login") then
    return "AUTH_JOOMLA_ADMIN"
  end
end



  if has(uri, "/admin") and (has(uri, "login") or has(uri, "auth")) then
    return "AUTH_MAGENTO_ADMIN"
  end
  if has(uri, "/admin/") and (has(uri, "index.php") or has(uri, "login")) then
    return "AUTH_OPENCART_ADMIN"
  end

  if has(uri, "/admin/login") then return "AUTH_ADMIN_LOGIN" end
  if has(uri, "/login") and method == "post" then return "AUTH_LOGIN_POST" end

  return nil
end

function _M.detect_auth_burst(ip, host, uri, method, shdict)
  if not shdict or not ip or ip == "" then return nil end

  local tag = auth_endpoint_tag(uri, method)
  if not tag then return nil end

  local now = ngx.now()
  local win = tonumber(CFG.auth_window_sec or 20) or 20
  local thr = tonumber(CFG.auth_burst_threshold or 8) or 8

  local host_key = lower(host or "-")
  if host_key == "" then host_key = "-" end

  local kts  = "auth|ts|"  .. ip .. "|" .. host_key .. "|" .. tag
  local kcnt = "auth|cnt|" .. ip .. "|" .. host_key .. "|" .. tag

  local ts  = shdict:get(kts)
  local cnt = shdict:get(kcnt) or 0

  if not ts or (now - ts) >= win then
    shdict:set(kts, now, win + 1)
    shdict:set(kcnt, 1, win + 1)
    return nil
  end

  cnt = cnt + 1
  shdict:set(kcnt, cnt, win + 1)

  if cnt >= thr then
    return tag
  end
  return nil
end

function _M.detect_wp_login_probe(uri, method, headers, ip, host, shdict)
  uri = lower(uri or "")
  method = lower(method or "get")
  headers = headers or {}

  if not has(uri, "/wp-login.php") then return nil end

  local ua  = lower(headers["user-agent"] or headers["User-Agent"] or "")
  local ref = lower(headers["referer"]   or headers["Referer"]   or "")
  local accept = lower(headers["accept"] or headers["Accept"] or "")

  if method == "head" then
    local empty_ua = (ua == "")
    local missing_accept = (accept == "")
    local suspicious_ua_family =
      has(ua, "sqlmap") or has(ua, "nikto") or has(ua, "nmap") or has(ua, "masscan")
      or has(ua, "curl/") or has(ua, "python-requests") or has(ua, "wget/")

    local repeated_head = false
    if shdict and ip and ip ~= "" then
      local now = ngx.now()
      local win = tonumber(CFG.auth_wp_login_head_window_sec or 20) or 20
      local thr = tonumber(CFG.auth_wp_login_head_threshold or 3) or 3
      local host_key = lower(host or "-")
      if host_key == "" then host_key = "-" end

      local kts  = "authwph|ts|"  .. ip .. "|" .. host_key .. "|AUTH_WP_LOGIN_HEAD"
      local kcnt = "authwph|cnt|" .. ip .. "|" .. host_key .. "|AUTH_WP_LOGIN_HEAD"
      local ts = shdict:get(kts)
      local cnt = shdict:get(kcnt) or 0

      if not ts or (now - ts) >= win then
        shdict:set(kts, now, win + 1)
        shdict:set(kcnt, 1, win + 1)
      else
        cnt = cnt + 1
        shdict:set(kcnt, cnt, win + 1)
        if cnt >= thr then
          repeated_head = true
        end
      end
    end

    if empty_ua or missing_accept or suspicious_ua_family or repeated_head then
      return "AUTH_WP_LOGIN_HEAD"
    end
    return nil
  end

  if method == "post" and ua == "" and ref == "" then
    return "AUTH_WP_LOGIN_NO_UA_REF"
  end

  return nil
end

-- Narrow carve-out for known-legit WordPress XML-RPC traffic.
-- Goal: avoid challenging Jetpack while keeping generic XML-RPC protection.
local function is_known_legit_xmlrpc(uri, args, headers, body)
  uri = lower(uri or "")

  -- F24: gate on the URI FIRST. This predicate runs on the WAF hot path for every
  -- request (cfm_waf.lua sections 26 & 28), but only /xmlrpc.php traffic can ever
  -- be "legit xmlrpc" — so short-circuit before the args/body normalize
  -- (double-url-decode + lowercase + cap) below, which was pure waste on the
  -- ~99% of requests that aren't xmlrpc.
  if not has(uri, "/xmlrpc.php") then
    return false
  end

  args = normalize(cap(args or "", CFG.max_scan_len))
  body = normalize(cap(body or "", CFG.max_scan_len))
  headers = headers or {}

  local ua = lower(headers["user-agent"] or headers["User-Agent"] or "")

  -- Jetpack commonly identifies itself via query/body markers.
  if has(args, "for=jetpack") then
    return true
  end
  if has(body, "jetpack") then
    return true
  end
  if has(ua, "jetpack") or has(ua, "wordpress.com") then
    return true
  end

  return false
end
_M.is_known_legit_xmlrpc = is_known_legit_xmlrpc

-- API-style endpoints should not be judged by browser-only heuristics
-- like Referer/Accept quality. Keep UA quality scoring, but suppress
-- browser-behavior penalties on narrow machine endpoints only.
local function is_machine_style_endpoint(uri)
  local u = lower(uri or "")
  if u == "" then return false end

  -- Magento token endpoints
  if has(u, "/rest/v1/integration/admin/token") then return true end
  if has(u, "/rest/v1/integration/customer/token") then return true end

  -- WooCommerce / WP API
  if has(u, "/wp-json/wc/") then return true end
  if has(u, "/wp-json/wc-") then return true end
  if has(u, "/wp-json/wc_") then return true end

  -- Known app-to-app/payment style routes seen in logs
  if has(u, "/shop-api/") then return true end
  if has(u, "/transaction-payment-created") then return true end
  if has(u, "/payments_methods_endpoint") then return true end

  -- Generic machine endpoints
  if has(u, "/webhook")    then return true end
  if has(u, "/callback")   then return true end
  if has(u, "/oauth")      then return true end
  if has(u, "/auth/token") then return true end
  if has(u, "/api")    then return true end

  if has(u, "/auth/realms/") 			then return true end
  if has(u, "/realms/") 			then return true end
  if has(u, "/protocol/openid-connect/") 	then return true end
  if has(u, "/.well-known/openid-configuration") then return true end
  if has(u, "/.well-known/jwks.json")		then return true end
  if has(u, "/sso/") 				then return true end
  if has(u, "/stripe/webhook") 			then return true end
  if has(u, "/paypal/ipn") 			then return true end
  if has(u, "/adyen/") 				then return true end
  if has(u, "/checkout/webhook") 		then return true end
  if has(u, "/payment/callback")		then return true end
  if has(u, "/github/webhook") 			then return true end
  if has(u, "/gitlab/webhook") 			then return true end
  if has(u, "/bitbucket-hook") 			then return true end
  if has(u, "/slack/webhook") 			then return true end
  if has(u, "/telegram/webhook") 		then return true end
  if has(u, "/rest/") 				then return true end
  if has(u, "/graphql") 			then return true end
  if has(u, "/wp-json/") 			then return true end
  if has(u, "/wc-api/") 			then return true end
  if has(u, "/?wc-api=") 			then return true end
  if has(u, "/mobile-api/")			then return true end
  if has(u, "/client-api/")			then return true end
  if has(u, "/public-api/")			then return true end
  if has(u, "/upload")				then return true end
  if has(u, "/queue")				then return true end
  if has(u, "/jobs")				then return true end

  return false
end


function _M.detect_xmlrpc_probe(uri, method, body)
  uri = lower(uri or "")
  method = lower(method or "get")
  body = normalize(cap(body or "", CFG.max_scan_len))

  if not has(uri, "/xmlrpc.php") then return nil end
  if method ~= "post" then return nil end

  if is_known_legit_xmlrpc(uri, "", nil, body) then
    return nil
  end

  if has(body, "system.multicall") then
    return "AUTH_WP_XMLRPC_MULTICALL"
  end

  if has(body, "pingback.ping") then
    return "AUTH_WP_XMLRPC_PINGBACK"
  end

  return nil
end

function _M.detect_xmlrpc_post_burst(ip, host, uri, method, shdict, args, headers, body)
  if not shdict or not ip or ip == "" then return nil end

  uri = lower(uri or "")
  method = lower(method or "get")

  if method ~= "post" then return nil end
  if is_known_legit_xmlrpc(uri, args, headers, body) then
    return nil
  end

  if not has(uri, "/xmlrpc.php") then return nil end

  local now = ngx.now()
  local win = tonumber(CFG.xmlrpc_post_window_sec or 60) or 60
  local thr = tonumber(CFG.xmlrpc_post_threshold or 6) or 6

  local host_key = lower(host or "-")
  if host_key == "" then host_key = "-" end

  local kts  = "xmlrpc|ts|"  .. ip .. "|" .. host_key
  local kcnt = "xmlrpc|cnt|" .. ip .. "|" .. host_key

  local ts  = shdict:get(kts)
  local cnt = shdict:get(kcnt) or 0

  if not ts or (now - ts) >= win then
    shdict:set(kts, now, win + 1)
    shdict:set(kcnt, 1, win + 1)
    return nil
  end

  cnt = cnt + 1
  shdict:set(kcnt, cnt, win + 1)

  if cnt >= thr then
    return "AUTH_WP_XMLRPC_POST_BURST"
  end

  return nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- AUDIT-CLASS DETECTORS
-- ─────────────────────────────────────────────────────────────────────────────

-- Shell-command word list for value-aware cmd_param checks.
-- These tokens, when they appear as a stand-alone word in a parameter value,
-- mark the value as "shelly" — i.e. a real RCE attempt — versus benign uses
-- of generic dispatcher keys like cmd=open / system=rewards / command=viewres
-- found in WP plugins (elFinder, LWS WooRewards) and themes (WooCommerce
-- mini-cart, auto-parts visualizers).
-- Shell-command / tool names whose appearance as a generic dispatcher VALUE
-- (system= / command= / cmd=) indicates an RCE probe. Kept deliberately NARROW
-- after audit F14: only names that are essentially never a legitimate
-- dispatcher verb or identifier fragment. The ubiquitous words that used to
-- live here — id, w, ps, pwd, ls, env, cat, head, tail, less, more, host,
-- fetch, route, ping, dig, arp — were REMOVED: they collide with real values
-- (record `id`, `host` fields, `env=prod`, JS `fetch`, OpenCart `route`,
-- pagination `more`, hostnames like `host-01`), and system=/command= have no
-- elFinder carve-out, so a bare legit value FP-challenged comment/XHR/JSON
-- traffic ("Data is not JSON"). Their *weaponized* forms still fire via the
-- metachar / path checks in value_looks_shelly (`cat /etc/passwd`, `id;`,
-- `env|nc …`); the accepted trade is that the bare, un-metachar'd recon probe
-- (`command=id`, `system=ls`, `cmd=ping evil.com`) is no longer flagged.
local CMD_PARAM_SHELL_WORDS = {
  -- recon (unambiguous only; id/pwd/ls/ps/w/env/cat/head/tail/less/more/host
  -- removed by F14 as legit-value collisions)
  whoami = true, uname = true, hostname = true,
  -- file system / privilege (mutation verbs — rarely a legit dispatcher value)
  rm = true, mv = true, cp = true, mkdir = true, touch = true, ln = true,
  chmod = true, chown = true,
  -- network (ambiguous fetch/dig/ping/host/arp/route removed by F14)
  wget = true, curl = true, nc = true, netcat = true,
  socat = true, telnet = true, ssh = true, scp = true,
  nslookup = true, ifconfig = true, netstat = true, iptables = true,
  -- shells / interpreters
  bash = true, sh = true, dash = true, zsh = true, ksh = true, csh = true,
  python = true, python2 = true, python3 = true, perl = true, ruby = true,
  php = true, lua = true, node = true,
  -- exec primitives (PHP function names used as command verbs)
  exec = true, system = true, passthru = true, eval = true,
  ["shell_exec"] = true,
}

-- Does the value of a generic dispatcher param (cmd=, system=, command=)
-- look like a real shell command? Two ways for it to count:
--   1) contains a shell metacharacter (;  |  `  &&  $(  ${  >  <),
--   2) contains a known shell-command token as a whole word.
-- The args string has already been normalize()d — fully URL-decoded twice
-- and lowercased — so we only check raw chars.
local function value_looks_shelly(v)
  if not v or v == "" then return false end

  -- Shell metacharacters that have no business in a benign verb value.
  if v:find(";", 1, true)  then return true end
  if v:find("|", 1, true)  then return true end
  if v:find("`", 1, true)  then return true end
  if v:find("&&", 1, true) then return true end
  if v:find("$(", 1, true) then return true end
  if v:find("${", 1, true) then return true end
  if v:find(">",  1, true) then return true end
  if v:find("<",  1, true) then return true end

  -- Path indicators that wouldn't appear in a benign dispatcher verb.
  if has(v, "/bin/") or has(v, "/tmp/") or has(v, "/dev/")
     or has(v, "/etc/") or has(v, "/usr/") or has(v, "/var/") then
    return true
  end

  -- Word-tokenise on whitespace / + (form-encoded space) — the separators a
  -- real command invocation uses between the verb and its args (`uname -a`,
  -- `wget http://…`). Hyphen is DELIBERATELY part of a token, NOT a separator
  -- (audit F14): legit compound identifiers use `-` (`host-01`, `item-id`,
  -- `us-east-1`), so splitting on it shattered them into bare tokens (`host`,
  -- `id`) that hit the word list and FP-challenged. A genuine `cmd - arg`
  -- separates with whitespace, so keeping `-` inside the token loses no real
  -- probe. If the whole value or any token matches a shell-command name, fire.
  if CMD_PARAM_SHELL_WORDS[v] then return true end
  for word in v:gmatch("[%w_%-]+") do
    if CMD_PARAM_SHELL_WORDS[word] then return true end
  end

  return false
end

-- Extract the value of a top-level query parameter named k from a
-- normalize()'d args string. Returns the substring from the byte after
-- "k=" up to the next "&" (or end-of-string). Returns nil if the key
-- is not present at position 1 or after an "&".
local function arg_value(a, k)
  local p
  local prefix = k .. "="
  if string.sub(a, 1, #prefix) == prefix then
    p = #prefix + 1
  else
    local s, e = a:find("&" .. prefix, 1, true)
    if s then p = e + 1 end
  end
  if not p then return nil end
  local rest = string.sub(a, p)
  local amp = rest:find("&", 1, true)
  if amp then rest = string.sub(rest, 1, amp - 1) end
  return rest
end

-- elFinder (the file-manager library behind Joomla's K2 media manager,
-- com_media, and similar `task=connector` endpoints) drives every operation
-- through `cmd=<verb>`. A few of its verbs — ls / rm / mkdir / chmod — are
-- also shell-command names, so a *bare* elFinder verb trips
-- value_looks_shelly's word match and gets the admin challenged mid-upload
-- ("Invalid backend response. Data is not JSON." because the elFinder XHR
-- receives the challenge redirect instead of JSON). Suppress that single
-- collision: only when the request is a Joomla elFinder connector call
-- (task=connector) AND the cmd value is a pristine, single elFinder verb.
-- A real injection through cmd= still carries a metacharacter, a path, or a
-- non-verb shell word, none of which match here, so it is still flagged.
local ELFINDER_VERBS = {
  open = true, file = true, tree = true, parents = true, ls = true,
  tmb = true, size = true, dim = true, mkdir = true, mkfile = true,
  rm = true, rename = true, duplicate = true, paste = true, upload = true,
  get = true, put = true, archive = true, extract = true, search = true,
  info = true, resize = true, netmount = true, url = true, callback = true,
  chmod = true, zipdl = true, abort = true, editor = true,
}
local function is_elfinder_verb(a, v)
  -- Require the verb to be exact AND `task` to be a real query parameter
  -- equal to "connector" (not the substring "task=connector" buried inside
  -- another param's value — a key-precise check, per review).
  if not v or ELFINDER_VERBS[v] ~= true then return false end
  return arg_value(a, "task") == "connector"
end

function _M.detect_cmd_param_key(args, _na)
  local a = _na or normalize(cap(args or "", CFG.max_scan_len))
  if a == "" then return nil end

  local function key(k)
    if string.sub(a, 1, #k + 1) == (k .. "=") then return true end
    if has(a, "&" .. k .. "=") then return true end
    return false
  end

  -- PHP-dangerous function names: presence of the key alone is suspicious
  -- because no legitimate app names a query param after exec / passthru /
  -- shell_exec / eval / assert.
  if key("exec")       then return "CMD_EXEC" end
  if key("passthru")   then return "CMD_PASSTHRU" end
  if key("shell_exec") then return "CMD_SHELL_EXEC" end
  if key("eval")       then return "CMD_EVAL" end
  if key("assert")     then return "CMD_ASSERT" end

  -- Generic dispatcher keys (cmd=, system=, command=) are routinely used
  -- by legitimate WP plugins and themes as a verb selector, so a bare
  -- key match produces false positives (elFinder cmd=open, LWS WooRewards
  -- system=rewards, theme command=viewres). Require the value to look
  -- shelly — metachars or a known shell-command word — before firing.
  if key("system") then
    local v = arg_value(a, "system")
    if value_looks_shelly(v) then return "CMD_SYSTEM" end
  end
  if key("cmd") then
    local v = arg_value(a, "cmd")
    if value_looks_shelly(v) and not is_elfinder_verb(a, v) then return "CMD_CMD" end
  end
  if key("command") then
    local v = arg_value(a, "command")
    if value_looks_shelly(v) then return "CMD_COMMAND" end
  end

  return nil
end

-- Shell commands that, as the FIRST token inside a `backtick` command
-- substitution, indicate RCE. Module-scope so it isn't rebuilt per request.
-- (Lua patterns have no `(a|b|c)` alternation — see has_backtick_cmd. [F05])
local BACKTICK_CMDS = {
  wget = true, curl = true, bash = true, sh = true, nc = true, ncat = true,
  perl = true, python = true, php = true, ruby = true, lua = true, id = true,
  uname = true, whoami = true, cat = true, ls = true, ping = true,
}

function _M.detect_cmd_payload(args, _na)
  local a = _na or normalize(cap(args or "", CFG.max_scan_len))
  if a == "" then return nil end

  local ignore_backtick_only = false

  if has(a, "data:") and has(a, ";base64,") then
    return nil
  end

  do
    local p = string.find(a, "base64,", 1, true)
    if p then
      local rest = string.sub(a, p + 7)
      if #rest >= 256 then return nil end
    end
  end

  do
    for val in string.gmatch(a, "=([^&]+)") do
      if #val >= 512 then return nil end
    end
  end

  do
    if begins(a, "filters=") then
      local v = string.sub(a, 9)
      if v ~= "" and string.match(v, "^[a-z0-9_%-%[%]%|]+$")
         and not has(v, "||") and not has(v, "%7c%7c")
         and not has(v, "`")  and not has(v, "%60")
         and not has(v, ";wget") and not has(v, ";curl")
         and not has(v, ";bash") and not has(v, ";sh ") then
        return nil
      end
    end
  end

  if string.match(a, "[%?&][^=]+=[^&]*&&[a-z0-9_%-]+=") then
    return nil
  end

  if string.match(a, "[%?&][a-z0-9_%-]+=([a-z0-9_%-]+%|%|[a-z0-9_%-]+)") then
    return nil
  end

  if has(a, "/xmlrpc.php?for=jetpack&token=") then
    return nil
  end

  if has(a, "fbclid=") or has(a, "ttclid=") or has(a, "gclid=")
     or has(a, "msclkid=") or has(a, "__bpgid=") then
    return nil
  end

  -- Search/autocomplete suppression:
  -- do not return nil for the whole request, only suppress final PAY_BACKTICK
  -- if the suspicious bit is limited to a search-like free-text field.
  -- Only enter this path when backtick characters are actually present —
  -- the gmatch loop is otherwise dead work on every non-backtick request.
  if a:find("`", 1, true) or a:find("%%60", 1, true) then
    for key, val in a:gmatch("([a-z0-9_%-]+)=([^&]+)") do
      if key == "q" or key == "s" or key == "term" or key == "search" or key == "query" then
        local cleaned = val:gsub("%%60", ""):gsub("`", "")
        if cleaned ~= val then
          if not has(cleaned, ";wget")
             and not has(cleaned, ";curl")
             and not has(cleaned, ";bash")
             and not has(cleaned, ";sh ")
             and not has(cleaned, "%3bwget")
             and not has(cleaned, "%3bcurl")
             and not has(cleaned, "%3bbash")
             and not has(cleaned, "%3bsh%20")
             and not has(cleaned, "|wget")
             and not has(cleaned, "|curl")
             and not has(cleaned, "|bash")
             and not has(cleaned, "|sh ")
             and not has(cleaned, "%7cwget")
             and not has(cleaned, "%7ccurl")
             and not has(cleaned, "%7cbash")
             and not has(cleaned, "%7csh%20")
             and not has(cleaned, "%7csh+") then
            ignore_backtick_only = true
          end
        end
      end
    end
  end

  local function has_semi_cmd(s)
    if has(s, ";wget") or has(s, ";curl") or has(s, ";bash") or has(s, ";sh ") then return true end
    if has(s, "%3bwget") or has(s, "%3bcurl") or has(s, "%3bbash") or has(s, "%3bsh%20") then return true end
    return false
  end

  if has_semi_cmd(a) then return "PAY_SEMI_CMD" end

  if has(a, "|wget") or has(a, "%7cwget") then return "PAY_PIPE_WGET" end
  if has(a, "|curl") or has(a, "%7ccurl") then return "PAY_PIPE_CURL" end
  if has(a, "|bash") or has(a, "%7cbash") then return "PAY_PIPE_BASH" end
  if has(a, "|sh ")  or has(a, "%7csh%20") or has(a, "%7csh+") then return "PAY_PIPE_SH" end

  local function has_backtick_cmd(s)
    -- Require an actual backtick command-substitution shape to avoid
    -- flagging accidental trailing backticks in business app query params.
    -- Scan all backtick pairs so one benign pair cannot hide a later malicious one.
    for inner in s:gmatch("`([^`]+)`") do
      -- Leading token inside the backticks is a known shell command. Lua
      -- patterns have NO `(a|b|c)` alternation, so the old `(wget|curl|...)`
      -- was a dead literal match — capture the first word and test set
      -- membership instead. `a` is already lowercased by normalize(), and
      -- `%a+` stops at the first non-alpha, so the word must match a command
      -- exactly (e.g. `category` -> "category", never "cat"). [audit F05]
      local word = inner:match("^%s*(%a+)")
      if word and BACKTICK_CMDS[word] then
        return true
      end

      if inner:find(";", 1, true) or inner:find("|", 1, true) or inner:find("&&", 1, true) then
        return true
      end
    end

    return false
  end

  if has_backtick_cmd(a) then
    if not ignore_backtick_only then
      return "PAY_BACKTICK"
    end
    -- ignore_backtick_only was set because a SEARCH field (q/s/term/search/
    -- query) carried a benign backtick snippet. Honour that suppression ONLY
    -- if no backtick command survives once the search-field VALUES are
    -- stripped — otherwise a throwaway benign `q=\`x\`` would mask a real
    -- backtick command in another param (the flag used to be request-global).
    -- The leading "&" lets the fixed `(&key=)[^&]*` patterns also blank a
    -- search value that is the first arg. [review of audit F05]
    local ns = ("&" .. a)
      :gsub("(&q=)[^&]*", "%1"):gsub("(&s=)[^&]*", "%1")
      :gsub("(&term=)[^&]*", "%1"):gsub("(&search=)[^&]*", "%1")
      :gsub("(&query=)[^&]*", "%1")
    if has_backtick_cmd(ns) then
      return "PAY_BACKTICK"
    end
  end

  return nil
end

function _M.detect_debug_toggles(args, _na)
  local a = _na or normalize(cap(args or "", CFG.max_scan_len))
  if a == "" then return nil end

  local function arg_has_key(keys, values)
    for key, val in a:gmatch("([^&=?]+)=([^&]*)") do
      for _, wantk in ipairs(keys) do
        if key == wantk then
          if not values then
            return true
          end
          for _, wantv in ipairs(values) do
            if val == wantv then
              return true
            end
          end
        end
      end
    end
    return false
  end

  if arg_has_key({"xdebug_session_start"}) then
    return "DBG_XDEBUG"
  end

  if arg_has_key({"xdebug"}) then
    return "DBG_XDEBUG_KEY"
  end

  if arg_has_key({"debug"}, {"1", "true"}) then
    return "DBG_DEBUG"
  end

  if arg_has_key({"trace"}, {"1", "true"}) then
    return "DBG_TRACE"
  end

  if arg_has_key({"stacktrace"}, {"1", "true"}) then
    return "DBG_STACKTRACE"
  end

  return nil
end

function _M.detect_php_serialize(args, _na)
  local a = _na or normalize(cap(args or "", CFG.max_scan_len))
  if a == "" then return nil end

  -- PHP's serialize() emits objects as `O:<N>:"<ClassName>":<M>:{...}` where
  -- N is the decimal class-name length. The previous form (`o:` anywhere AND
  -- `:"` anywhere) produced FPs on any URL containing both substrings in
  -- unrelated positions — e.g. `<o:p class="">` (Microsoft Office HTML
  -- namespace pasted from Word) and Koha OPAC CCL search (`q=ccl=an:"167"
  -- and au: Haese`). Anchor on the digit-length marker between the colons
  -- so only real serialized payloads match. The URL-encoded branch catches
  -- triple-or-higher-encoded payloads that survive normalize()'s two
  -- url_decode_once passes.
  if string.find(a, "o:%d+:\"",                1, false) then return "SER_O_PLAIN" end
  if string.find(a, "c:%d+:\"",                1, false) then return "SER_C_PLAIN" end
  if string.find(a, "o%%3a%d+%%3a%%22",        1, false) then return "SER_O_URL"   end
  if string.find(a, "c%%3a%d+%%3a%%22",        1, false) then return "SER_C_URL"   end

  return nil
end

-- A PHP serialized OBJECT marker: O:<N>:"…" (object) or C:<N>:"…" (custom
-- object). Deliberately NOT a:<N>:{ (arrays) — those are common and benign.
-- Same digit-length anchoring as detect_php_serialize (avoids the `<o:p>` /
-- CCL-search FPs). `s` is expected already lowercased.
local function _has_php_object_marker(s)
  return string.find(s, "o:%d+:\"", 1, false) or string.find(s, "c:%d+:\"", 1, false)
      or string.find(s, "o%%3a%d+%%3a%%22", 1, false) or string.find(s, "c%%3a%d+%%3a%%22", 1, false)
end

-- Akeeba Restore endpoints round-trip the engine's own state as a base64-encoded
-- PHP-serialized object in the `factory` POST field on EVERY extraction step. That
-- blob IS a genuine O:N:"…" object, so the object-injection detector (rule 329)
-- cannot tell it from an attack by shape — it must exclude these endpoints by
-- context. Akeeba Restore drives Joomla core updates (com_joomlaupdate/extract.php,
-- restore.php, finalisation.php) AND Akeeba Backup restores (com_akeeba* /
-- restore.php, finalisation.php). FP seen 2026-07-17: a legit Joomla admin doing
-- `option=com_joomlaupdate&task=update.install` was blocked+ban-listed on every
-- extract.php step (the WordPress-cookie unauth gate does not recognise a Joomla
-- admin session, so the request looked "unauth"). `has`/`lower` are plain-substring
-- + lowercase; the check is uri-only and runs before any body normalisation.
local function _is_akeeba_restore_endpoint(uri)
  local u = lower(uri or "")
  if has(u, "com_joomlaupdate/") and
     (has(u, "extract.php") or has(u, "restore.php") or has(u, "finalisation.php")) then
    return true
  end
  if has(u, "com_akeeba") and
     (has(u, "restore.php") or has(u, "finalisation.php")) then
    return true
  end
  return false
end
_M.is_akeeba_restore_endpoint = _is_akeeba_restore_endpoint

-- [R2] Unauthenticated PHP object injection (deserialization -> RCE). Closes the
-- 153-site object-injection exposure (kirki/jet-engine/woodmart/
-- better-search-replace/fusion …) WITHOUT a per-plugin endpoint list: a PHP
-- serialized OBJECT marker in an UNAUTHENTICATED request is near-zero FP, because
-- legit serialized blobs (WooCommerce/Elementor/WPML) ride AUTHENTICATED
-- admin-ajax and carry the WP logged-in cookie. Stronger than rule 306
-- (WAF_SERIALIZE, challenge, ARGS-ONLY): scans args AND body, and decodes base64
-- object blobs (closing rule 304's logonly B64_OBJ_INJECT gap). Emits WAF_RCE
-- (already armed) at block.
--
-- The AUTHENTICATED case is deliberately left to rule 306 at `challenge` — an
-- exploit tool can't solve the JS challenge, and a real admin passing a legit
-- serialized blob is only challenged, never blocked/banned.
--
-- The Akeeba Restore endpoints (see _is_akeeba_restore_endpoint) are excluded at
-- the call site: they legitimately transport a base64 serialized object every step.
--
-- `nab` is the shared, memoized normalized+lowercased args+body (get_norm_ab()),
-- so this rule adds NO extra normalization pass. The UNAUTH gate lives at the
-- call site (so an authenticated request skips even nab materialisation). `args`
-- and `body` are the RAW surfaces, used only for the case-sensitive base64 scan.
function _M.detect_php_object_injection(nab, args, body)
  if nab and nab ~= "" and _has_php_object_marker(nab) then return "PLAIN" end
  -- base64'd object: a base64 PHP object starts "O:"->Tzo / "C:"->Qzo (base64 is
  -- case-sensitive). Cheap prefix prefilter on the raw surfaces before building
  -- the scan string; only decode candidates with that exact prefix, then confirm
  -- the decoded bytes carry the object marker.
  local ra, rb = args or "", body or ""
  if has(ra, "Tzo") or has(rb, "Tzo") or has(ra, "Qzo") or has(rb, "Qzo") then
    for cand in (ra .. "&" .. rb):gmatch("[TQ]zo[A-Za-z0-9+/]+=*") do
      if #cand >= 12 then
        local dec = ngx.decode_base64(cand)
        if dec and _has_php_object_marker(lower(dec)) then return "BASE64" end
      end
    end
  end
  return nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- RESEARCH ADDITIONS – HEADER / PROTOCOL CHECKS
-- ─────────────────────────────────────────────────────────────────────────────

-- [top-6a] Bad UA scorer.
-- Sources: uusec scanner-detection (plugin), anti_ddos_challenge.lua UA list.
--
-- Returns: score (int), composite_tag (string) or 0, nil if nothing fires.
--
-- Two tiers:
--   INSTANT  - known scanner tool UAs fire regardless of score.
--              These have zero legitimate use on shared hosting.
--   SCORED   - weak signals that are innocent alone but suspicious in combination.
--              Each signal adds points; caller checks against CFG.bad_ua_min_score.
--
-- Scored signals and weights:
--   UA presence:  empty/whitespace=+2, generic HTTP lib=+2
--   Method:       HEAD=+1   (scanners probe existence cheaply)
--   Headers:      no Accept=+1, no Referer on non-root URI=+1
--   URI target:   sensitive file (.env/.git/wp-config)=+4,
--                 credential/backup artifact (*.sql, passwords.txt)=+3
function _M.detect_bad_ua_scored(headers, uri, method)
  headers = headers or {}
  local ua  = header_string(headers["user-agent"] or headers["User-Agent"])
  local ual = lower(ua)

  -- INSTANT: named scanner / exploit tools - bypass scoring
  -- Slowloris self-identifies via Referer
  local ref = lower(headers["referer"] or headers["Referer"] or "")
  if has(ref, "code.google.com/p/slowhttptest") then return 99, "REF_SLOWLORIS" end

  if has(ual, "sqlmap")    then return 99, "UA_SQLMAP" end
  if has(ual, "nikto")     then return 99, "UA_NIKTO" end
  if has(ual, "nessus")    then return 99, "UA_NESSUS" end
  if has(ual, "masscan")   then return 99, "UA_MASSCAN" end
  if has(ual, "zgrab")     then return 99, "UA_ZGRAB" end
  if has(ual, "nuclei")    then return 99, "UA_NUCLEI" end
  if has(ual, "dirbuster") then return 99, "UA_DIRBUSTER" end
  if has(ual, "gobuster")  then return 99, "UA_GOBUSTER" end
  if has(ual, "wfuzz")     then return 99, "UA_WFUZZ" end
  if has(ual, "awvs")      then return 99, "UA_AWVS" end
  if has(ual, "appscan")   then return 99, "UA_APPSCAN" end

  -- Fake / impossible legacy browser families seen in bot traffic.
  -- Start as challenge via rule_bad_ua = "challenge".
  if ual:match("msie%s+[1-8]%.") and not ual:match("trident/[5-9]%.") then
    return 99, "UA_FAKE_LEGACY_MSIE"
  end

  if has(ual, "windows 95")
     or has(ual, "windows 98")
     or has(ual, "win 9x 4.90")
     or has(ual, "windows ce") then
    return 99, "UA_FAKE_LEGACY_WINDOWS"
  end

  if ual:match("trident/[1-4]%.") then
    return 99, "UA_FAKE_LEGACY_TRIDENT"
  end

  -- SCORED: accumulate weak signals
  local score = 0
  local tags  = {}
  local ul = lower(uri or "")
  local m = lower(method or "")

  -- Signal 1: UA quality (+2 for empty or known generic lib)
  if ua == "" or ual:match("^%s*$") then
    score = score + 2; tags[#tags+1] = "UA_EMPTY"
  elseif has(ual, "python-requests") then
    score = score + 2; tags[#tags+1] = "UA_PY_REQUESTS"
  elseif has(ual, "libwww-perl") then
    score = score + 2; tags[#tags+1] = "UA_LIBWWW"
  elseif has(ual, "winhttp") then
    score = score + 2; tags[#tags+1] = "UA_WINHTTP"
  elseif has(ual, "httrack") then
    score = score + 2; tags[#tags+1] = "UA_HTTRACK"
  end

  -- If UA is perfectly fine, no further scoring needed.
  -- machine_style (40+ has() calls) and ref are only needed when UA is suspicious,
  -- so defer them to after this early-exit to avoid wasting CPU on normal requests.
  if score == 0 then return 0, nil end

  local machine_style = is_machine_style_endpoint(ul)
  local ref = lower(headers["referer"] or headers["Referer"] or "")

  -- Signal 2: HEAD method (+1) - cheap existence probe used by scanners
  if m == "head" then
    score = score + 1; tags[#tags+1] = "HEAD"
  end

  -- Pre-compute URI risk class used by header-quality scoring.
  local uri_sensitive = false
  local uri_backup = false

  if has(ul, "/.git/")             then uri_sensitive = true end
  if has(ul, "/.env")              then uri_sensitive = true end
  if has(ul, "/wp-config.php")     then uri_sensitive = true end
  if has(ul, "/.htaccess")         then uri_sensitive = true end
  if has(ul, "/.htpasswd")         then uri_sensitive = true end
  if has(ul, "/config.php")        then uri_sensitive = true end
  if has(ul, "/configuration.php") then uri_sensitive = true end
  if has(ul, "/settings.php")      then uri_sensitive = true end

  -- Exclude ordinary password/account/reset routes from credential-artifact scoring.
  local is_normal_password_route = false
  if has(ul, "/my-account/lost-password") then is_normal_password_route = true end
  if has(ul, "/lost-password")            then is_normal_password_route = true end
  if has(ul, "/reset-password")           then is_normal_password_route = true end
  if has(ul, "/wp-login.php?action=lostpassword") then is_normal_password_route = true end

  local cred_artifact = false

  if ul:match("%.sql$") or ul:match("%.sql%.gz$") or ul:match("%.sql%.zip$") then
    uri_backup = true
  end

  -- Match filename/artifact style targets, not every app route containing "password".
  if not is_normal_password_route then
    if ul == "passwd" or has(ul, "/passwd") then
      cred_artifact = true
    end
    if ul:match("passwords?%.txt$") or has(ul, "/passwords.txt") or has(ul, "/password.txt") then
      cred_artifact = true
    end
    if ul:match("credentials?%.txt$") or has(ul, "/credential.txt") or has(ul, "/credentials.txt") then
      cred_artifact = true
    end
    if ul:match("credentials?%.json$") or has(ul, "/credential.json") or has(ul, "/credentials.json") then
      cred_artifact = true
    end
    if ul:match("secrets?%.env$") or has(ul, "/secret.env") or has(ul, "/secrets.env") then
      cred_artifact = true
    end
  end


  if cred_artifact then
    uri_backup = true
  end
  local in_backup_path = has(ul, "/backup") or has(ul, "/bak/") or has(ul, "/old/")
                      or has(ul, "/restore") or has(ul, "/archive")
  if in_backup_path and (ul:match("%.zip$") or ul:match("%.tar$") or ul:match("%.gz$")
                      or ul:match("%.rar$") or ul:match("%.tgz$")) then
    uri_backup = true
  end

  local strict_header_scoring = (m ~= "get" and m ~= "head") or uri_sensitive or uri_backup

  -- Signal 3: no Accept header (+1)
  -- Applied only on higher-risk request context to avoid FP on benign crawlers.
  -- Suppress for machine-style endpoints where browser header expectations do not apply.
  local accept = header_string(headers["accept"] or headers["Accept"])
  if accept == "" and strict_header_scoring and not machine_style then
    score = score + 1; tags[#tags+1] = "NO_ACCEPT"
  end

  -- Signal 4: no Referer on a non-trivial URI (+1)
  -- Skip scoring on root, common entry points, and static assets
  -- Suppress for machine-style endpoints where Referer is often absent by design.
  local is_entry = (ul == "/" or ul == ""
    or ul:match("%.map$")
    or ul:match("%.json$")
    or ul:match("%.xml$")
    or ul:match("%.css$") or ul:match("%.js$")  or ul:match("%.ico$")
    or ul:match("%.png$") or ul:match("%.jpg$") or ul:match("%.gif$")
    or ul:match("%.svg$") or ul:match("%.woff"))
  if strict_header_scoring and not machine_style and not is_entry and ref == "" then
    score = score + 1; tags[#tags+1] = "NO_REFERER"
  end

  -- Signal 5: URI targets a high-value sensitive file (+4)
  if uri_sensitive then
    if has(ul, "/.git/")             then tags[#tags+1] = "URI_GIT" end
    if has(ul, "/.env")              then tags[#tags+1] = "URI_ENV" end
    if has(ul, "/wp-config.php")     then tags[#tags+1] = "URI_WPCONFIG" end
    if has(ul, "/.htaccess")         then tags[#tags+1] = "URI_HTACCESS" end
    if has(ul, "/.htpasswd")         then tags[#tags+1] = "URI_HTPASSWD" end
    if has(ul, "/config.php")        then tags[#tags+1] = "URI_CONFIG_PHP" end
    if has(ul, "/configuration.php") then tags[#tags+1] = "URI_JOOMLA_CFG" end
    if has(ul, "/settings.php")      then tags[#tags+1] = "URI_SETTINGS_PHP" end
    score = score + 4
  end

  -- Signal 6: URI targets a credential / backup artifact (+3)
  -- Archives only scored when inside a backup-like path to avoid
  -- flagging legitimate CDN or media ZIP downloads.
  if uri_backup then
    if ul:match("%.sql$") or ul:match("%.sql%.gz$") or ul:match("%.sql%.zip$") then
      tags[#tags+1] = "URI_SQL_DUMP"
    end
    if cred_artifact then
      tags[#tags+1] = "URI_CRED_FILE"
    end
    if in_backup_path and (ul:match("%.zip$") or ul:match("%.tar$") or ul:match("%.gz$")
                        or ul:match("%.rar$") or ul:match("%.tgz$")) then
      tags[#tags+1] = "URI_BACKUP_ARCHIVE"
    end
    score = score + 3
  end

  return score, table.concat(tags, "+")
end

-- [top-6b] Shellshock CVE-2014-6271 / CVE-2014-7169.
-- Source: uusec shellshock-vulnerability.lua.
-- Pattern: () { in any header value (CGI exposes headers as env vars).
-- The URI/path branch was removed after a 2026-05-08 production analysis
-- found the only URI hit was a JS code fragment "/function(t){...}" — JS
-- minifiers commonly produce "() {" in URL paths and that is not Shellshock.
-- Real Shellshock exploits arrive via CGI headers (User-Agent, Cookie,
-- Referer); the URI surface produced FPs without catching real attacks.
function _M.detect_shellshock(headers, _uri)
  local pat = "%(%)%s*{"

  headers = headers or {}
  for hname, hval in pairs(headers) do
    if type(hval) == "string" then
      -- Plain precheck before the allocating url_decode_once() call.
      -- Shellshock is "() {"; URL-encoded form starts with %28%29.
      -- Nearly all headers pass neither, so the decode is almost never reached.
      if hval:find("() {", 1, true) or hval:find("%28%29", 1, true) then
        local decoded = url_decode_once(hval)
        if decoded:find(pat) then
          return "SHELLSHOCK_HDR:" .. tostring(hname):sub(1, 32)
        end
      end
    end
  end

  return nil
end

-- [top-6c] Header presence vulnerability checks.
-- Sources: uusec header-vulnerability.lua + cve-2025-24813.lua.
--   * Proxy:     – httpoxy: CGI/FastCGI sees HTTP_PROXY env var, can redirect outbound traffic.
--   * Lock-Token: / If: – CVE-2017-7269: IIS 6.0 WebDAV ScStoragePathFromUrl overflow.
--   * PUT /…/session + Content-Range – CVE-2025-24813: Tomcat partial PUT RCE (March 2025).
-- All are pure header presence checks – zero FP on normal browser traffic.
function _M.detect_header_vulns(headers, uri, method)
  headers = headers or {}

  if headers["proxy"] or headers["Proxy"] then
    return "HEADER_HTTPOXY"
  end

  if headers["lock-token"] or headers["Lock-Token"] then
    return "HEADER_LOCK_TOKEN"
  end

  if headers["if"] or headers["If"] then
    return "HEADER_IF_WEBDAV"
  end

  -- CVE-2025-24813: PUT request to a path ending in /session with Content-Range
  if lower(method or "") == "put" then
    local u = lower(uri or "")
    if u:match("/session$")
       and (headers["content-range"] or headers["Content-Range"]) then
      return "CVE_2025_24813"
    end
  end

  return nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- RESEARCH ADDITIONS – CONTENT-TYPE / PROTOCOL ANOMALY CHECKS
-- ─────────────────────────────────────────────────────────────────────────────

-- [top-7] Content-Type header anomaly detection.
-- Sources: uusec abnormal-character-encoding-requests.lua +
--          uusec boundary-exception-interception.lua.
--
-- Charset bypass: attackers set Content-Type: application/x-www-form-urlencoded;
--   charset=IBM037 (or IBM500, cp875 etc.) so the WAF can't decode the payload
--   while the backend still processes it using its own charset logic.
--   Only allow the small set of charsets that nginx/PHP legitimately uses.
--
-- Boundary bypass: PHP's non-RFC-compliant multipart boundary parsing can be
--   exploited by sending a malformed boundary= value to confuse content scanners.

-- Content-Type charset allowlist for detect_content_type_anomaly.
--
-- Threat: a charset the WAF cannot decode but the backend can (EBCDIC/IBM037,
-- UTF-7, UTF-16) lets an exploit's metacharacters (< > ' " ( ) ;) be smuggled
-- past the raw-byte scan and reconstituted server-side. A charset is SAFE here
-- iff it is an ASCII SUPERSET — the 0x00-0x7F range, which holds every exploit
-- metacharacter, maps to ASCII unchanged — so the WAF and the backend see the
-- same bytes and no evasion is possible. That covers UTF-8, every ISO-8859-*
-- and Windows-125x NATIONAL charset (incl. Greek `iso-8859-7`/`windows-1253`,
-- Cyrillic, Hebrew, Arabic, Turkish, Baltic, Vietnamese), KOI8, TIS-620, and
-- the ASCII-compatible CJK multibyte encodings. It excludes EBCDIC
-- (IBM0xx/cp5xx/cp875/cp1026 — a wholly different byte map), UTF-7 (`+ADw-`=`<`)
-- and UTF-16/UTF-32 (NUL-interleaved) — the real evasion vectors — which stay
-- flagged, as do unknown charsets (fail-safe allowlist).
--
-- Before this list only Latin + Chinese were allowed, so a legitimate Greek (or
-- any non-Latin) form/API POST declaring its charset was challenged (rule 604).
local CHARSET_SAFE = {
  ["utf-8"]=true, ["utf8"]=true, ["us-ascii"]=true, ["ascii"]=true,
  -- CJK multibyte (ASCII-compatible low range)
  ["gbk"]=true, ["gb2312"]=true, ["gb-2312"]=true, ["gb18030"]=true,
  ["big5"]=true, ["big5-hkscs"]=true,
  ["shift_jis"]=true, ["shift-jis"]=true, ["sjis"]=true, ["x-sjis"]=true,
  ["cp932"]=true, ["ms932"]=true, ["windows-31j"]=true,
  ["euc-jp"]=true, ["eucjp"]=true, ["euc-kr"]=true, ["euckr"]=true,
  ["ks_c_5601-1987"]=true, ["ksc5601"]=true, ["ksc_5601"]=true,
  ["windows-936"]=true, ["windows-949"]=true, ["windows-950"]=true,
  -- Thai / Cyrillic / national-charset aliases
  ["tis-620"]=true, ["windows-874"]=true, ["cp874"]=true,
  ["koi8-r"]=true, ["koi8-u"]=true,
  ["latin1"]=true, ["latin-1"]=true, ["latin2"]=true, ["latin5"]=true,
  ["greek"]=true, ["iso-ir-126"]=true, ["ecma-118"]=true,
  ["cyrillic"]=true, ["hebrew"]=true, ["arabic"]=true,
}

local function charset_is_safe(cs)
  if CHARSET_SAFE[cs] then return true end
  -- ISO-8859-N single-byte national charsets (Latin-1..Latin-10, Greek=7,
  -- Cyrillic=5, Hebrew=8, Arabic=6, Turkish=9, Baltic=13, ...) — all ASCII
  -- supersets. `iso8859-7` (no dash) and `iso-8859-7` both accepted.
  if cs:match("^iso%-?8859%-%d%d?$") then return true end
  -- Windows-125x (and the `cp125x` alias): 1250 Central-Euro, 1251 Cyrillic,
  -- 1252 Western, 1253 GREEK, 1254 Turkish, 1255 Hebrew, 1256 Arabic,
  -- 1257 Baltic, 1258 Vietnamese. NOT cp5xx/cp0xx/cp875/cp1026 (EBCDIC).
  if cs:match("^windows%-125%d$") then return true end
  if cs:match("^cp125%d$") then return true end
  return false
end

function _M.detect_content_type_anomaly(headers)
  headers = headers or {}
  local ct = headers["content-type"] or headers["Content-Type"] or ""
  if ct == "" then return nil end

  -- Non-string Content-Type indicates header injection
  if type(ct) ~= "string" then return "CT_NON_STRING" end

  local ctl = lower(ct)

  if has(ctl, "charset") then
    -- Accept a quoted value too (RFC 2045 quoted-string) so a dangerous charset
    -- can't dodge the check by quoting: `charset="ibm037"`. `_` is allowed so
    -- `shift_jis`/`ks_c_5601-1987` capture whole.
    local charset_val = ctl:match('charset%s*=%s*"([^"]+)"')
                     or ctl:match("charset%s*=%s*([%w%-_]+)")
    if charset_val and not charset_is_safe(charset_val) then
      return "CT_CHARSET_BYPASS:" .. charset_val:sub(1, 32)
    end
    -- Multiple charset= declarations in one Content-Type
    local _, n = ctl:gsub("charset", "charset")
    if n > 1 then return "CT_MULTI_CHARSET" end
  end

  if has(ctl, "boundary") then
    -- Count boundary= *declarations*, not bare substring occurrences.
    -- Browser-generated boundary strings (e.g. ----WebKitFormBoundaryXxx,
    -- ---------------------------1234567890) contain the word "boundary"
    -- inside the value itself, so counting the raw word gives n=2 on every
    -- normal file upload.  Counting "boundary=" is safe and correct.
    local _, n = ctl:gsub("boundary%s*=", "boundary=")
    if n > 1 then return "CT_MULTI_BOUNDARY" end
    -- Boundary value: allow leading dashes (RFC 2046 permits up to 70 chars
    -- of printable ASCII; browsers use long dash prefixes by convention).
    local bval = ctl:match("boundary%s*=%s*([^%s;,]+)")
    -- RFC 2045 allows the parameter value to be a quoted-string. cPanel
    -- webmail (and other server-internal multipart producers) emit
    -- `boundary="----WebKitFormBoundary..."` with literal surrounding
    -- quotes. Strip them before validating, mirroring the helper at
    -- detect_polyglot_upload.
    if bval then
      bval = bval:gsub('^"', ''):gsub('"$', '')
    end
    -- Validate against RFC 2046 `bcharsnospace` — the exact legal boundary
    -- alphabet: DIGIT / ALPHA / ' ( ) + _ , - . / : = ?. (`,` is in the class
    -- for completeness but never actually reaches here: the extraction above,
    -- `[^%s;,]+`, truncates at any comma — `,` doubles as a Content-Type param
    -- separator — so the effective accepted set is bcharsnospace minus `,`.)
    -- The old class allowed
    -- only [A-Za-z0-9._-], so legit server-to-server MIME producers that use the
    -- RFC-legal `=` / `+` / `/` / `:` were flagged (audit F15): JavaMail
    -- (`----=_Part_0_…`), Python email (`===============…==`), SOAP/Axis. Those
    -- are non-browser clients that cannot solve a JS challenge, so rule 604 broke
    -- the POST outright. Chars OUTSIDE bcharsnospace (space, control bytes, `<`
    -- `>` `;` `"` `@` `$` `%` backtick …) — the ones that actually desync a
    -- WAF-vs-PHP multipart split — are still rejected, so the anti-evasion value
    -- is preserved; this only stops rejecting RFC-legal boundaries.
    if bval and bval ~= "" and not bval:match("^%-*[0-9A-Za-z'()+_,./:=?%-]+$") then
      return "CT_BAD_BOUNDARY"
    end
  end

  return nil
end

-- [top-8] Single-quote SQLi in proxy IP headers.
-- Source: uusec proxy-header-sql-injection.lua.
-- Why: some apps log or query-build using XFF/X-Real-IP without sanitization.
--
-- Note: the original detector also flagged "non-string (table) value" as
-- PROXY_HDR_INJECT — i.e. the same header sent more than once. A 2026-05
-- log review found that branch was an FP factory: carrier-grade NAT (Vodafone
-- TR) and chained edge proxies legitimately produce multiple XFF headers,
-- and real users browsing normal pages were getting challenged. The
-- duplicate-header signal is too weak to act on by itself, so we drop it
-- and keep only the single-quote SQLi check (which is unambiguous).
-- header_string() collapses any table value to the first non-empty string
-- so the quote scan still works on duplicated XFFs.
function _M.detect_proxy_header_sqli(headers)
  headers = headers or {}
  local suspects = {
    ["x-forwarded-for"] = headers["x-forwarded-for"] or headers["X-Forwarded-For"],
    ["x-real-ip"]       = headers["x-real-ip"]       or headers["X-Real-IP"],
    ["client-ip"]       = headers["client-ip"]        or headers["Client-IP"],
    ["x-client-ip"]     = headers["x-client-ip"]      or headers["X-Client-IP"],
  }
  for hname, hval in pairs(suspects) do
    if hval ~= nil then
      local s = header_string(hval)
      if has(s, "'") then
        return "PROXY_HDR_SQLI:" .. hname
      end
    end
  end
  return nil
end


-- ─────────────────────────────────────────────────────────────────────────────
-- RESEARCH ADDITIONS – ARGS / BODY INJECTION CHECKS
-- ─────────────────────────────────────────────────────────────────────────────

-- [top-9a] SSRF via dangerous protocol schemes and IP obfuscation.
-- Source: uusec universal-attack.lua (protocol list + IP obfuscation patterns).
-- Notes:
--   * Only flag schemes that are never legitimate in form parameter values.
--     http:// and https:// are intentionally excluded (redirect/callback params).
--   * IP obfuscation checks are narrow to avoid FP: octal, hex, and decimal
--     longform IPs inside :// scheme context only.
function _M.detect_ssrf_proto(args, body, _ns)
  local s = _ns or normalize(cap(args or "", CFG.max_scan_len) .. "&" .. cap(body or "", CFG.max_scan_len))
  if s == "" then return nil end

  if has(s, "file://")        then return "SSRF_FILE" end
  if has(s, "gopher://")      then return "SSRF_GOPHER" end
  if has(s, "dict://")        then return "SSRF_DICT" end
  if has(s, "ldap://")        then return "SSRF_LDAP" end
  if has(s, "ldaps://")       then return "SSRF_LDAPS" end
  if has(s, "tftp://")        then return "SSRF_TFTP" end
  -- Coinminer pool URL scheme. Folded into rule 701 (rather than added as
  -- part of a future X2 detector) per the X2/rule-701 design call recorded
  -- in docs/waf.md row 16. X2 will then cover only the tool/pool fingerprints.
  if has(s, "stratum+tcp://") then return "SSRF_STRATUM" end
  if has(s, "stratum+ssl://") then return "SSRF_STRATUM" end
  -- sftp:// and ftp:// in param values are suspicious but occur in some
  -- legitimate file-picker integrations; tag them differently for easier triage
  if has(s, "sftp://")   then return "SSRF_SFTP" end
  if has(s, "ftp://")    then return "SSRF_FTP" end

  -- Octal IPv4 notation: 0177.0.0.1 = 127.0.0.1
  -- Restrict to URL-host context (://) to avoid ad/tracking token false positives.
  if s:match("://0[0-7]+%.0[0-7]+%.0[0-7]+%.0[0-7]+") then
    return "SSRF_OCTAL_IP"
  end
  -- Hex IPv4: 0x7f000001
  if s:match("://0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]%f[^0-9a-f]") then
    return "SSRF_HEX_IP"
  end
  -- Decimal longform IP inside a URL: ://2130706433 (= 127.0.0.1)
  if s:match("://[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]%f[^0-9]") then
    return "SSRF_DWORD_IP"
  end

  return nil
end

-- [top-9b] JavaScript prototype pollution.
-- Source: uusec universal-attack.lua.
-- __proto__ and constructor.prototype in JSON bodies or args are the two
-- canonical pollution vectors in Node.js/JS backend frameworks.
function _M.detect_js_proto(args, body, _ns)
  local s = _ns or normalize(cap(args or "", CFG.max_scan_len) .. "&" .. cap(body or "", CFG.max_scan_len))
  if s == "" then return nil end

  if has(s, "__proto__") then return "JS_PROTO_PROTO" end
  if has(s, "constructor") and (has(s, ".prototype") or has(s, "[prototype")) then
    return "JS_PROTO_CONSTRUCTOR"
  end

  return nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- RESEARCH ADDITIONS – BODY CHECKS
-- ─────────────────────────────────────────────────────────────────────────────

-- [top-10a] XXE – XML External Entity injection.
-- Source: uusec xxe-attack.lua.
-- Only scans XML / form-encoded / text bodies.  Checks for SYSTEM or PUBLIC
-- entity declarations which are the canonical XXE primitives.
function _M.detect_xxe(body, headers)
  if not body or body == "" then return nil end

  headers = headers or {}
  local ct = lower(headers["content-type"] or headers["Content-Type"] or "")

  -- Skip clearly non-XML binary / JSON bodies to limit false positives
  if ct ~= ""
     and not has(ct, "xml")
     and not has(ct, "text/")
     and not has(ct, "application/x-www-form-urlencoded") then
    return nil
  end

  local bl = lower(cap(body, CFG.max_scan_len))

  if (has(bl, "<!doctype") or has(bl, "<!entity")) and has(bl, "system") then
    return "XXE_SYSTEM"
  end
  if has(bl, "<!entity") and has(bl, "public") then
    return "XXE_PUBLIC"
  end

  return nil
end

-- [top-10b] CRLF / HTTP response-splitting injection.
-- Source: uusec http-response-splitting.lua.
-- Checks for CR or LF followed by a header name in args and body.
-- Also checks for URL-encoded %0d%0a sequences.
function _M.detect_crlf_injection(args, body)
  -- Cap args and body independently so a padded query string can't evict the
  -- body from CRLF-injection detection (audit F09; this detector builds its
  -- own scan surface rather than taking the shared get_norm_ab string).
  local a = cap(args or "", CFG.max_scan_len)
  local b = cap(body or "", CFG.max_scan_len)
  local s = a .. "&" .. b
  if s == "" then return nil end

  -- Lowercase once and match the header names against the lowercased copy.
  -- Response headers are conventionally capitalized (Set-Cookie:, Location:),
  -- so a raw newline + capitalized header name must still trip the raw branch
  -- (audit F34; the raw branch used to match the lowercase literals against the
  -- unlowered `s` and missed canonical casing). lower() leaves CR/LF bytes
  -- untouched, so the [\r\n] anchor is unaffected. `sl` is the full surface
  -- (args+body); `al` is the args-only surface used for the FP-prone headers.
  local sl = lower(s)
  local al = lower(a)

  -- Content-Type / Content-Length are LOW-IMPACT response-splitting targets and
  -- the dominant FP source: they appear legitimately in request BODIES all the
  -- time — every multipart/form-data part header, and page-builder / API / oEmbed
  -- save payloads that embed HTTP header text (a wp-admin/admin-ajax page-builder
  -- POST carrying `\r\nContent-Type:` in its data tripped CRLF_CONTENT_TYPE — a
  -- confirmed FP against a logged-in admin, 2026-07). A request-BODY param is
  -- essentially never reflected into a *response* Content-Type/Length header, so
  -- scope these two to the ARGS surface only (query-string reflection is the real
  -- vector). Set-Cookie / Location are HIGH-impact (session fixation / open
  -- redirect) and CAN be reflected from a body, so they stay full-surface
  -- (args+body). This GENERALISES — and subsumes — the earlier multipart-only
  -- carve-out (#1109): a body Content-Type is now tolerated whether or not the
  -- request is multipart, so no request Content-Type header inspection is needed.

  -- Raw CR/LF followed by a header keyword
  if al:find("[\r\n]%W*content%-type%s*:",   1) then return "CRLF_CONTENT_TYPE" end
  if al:find("[\r\n]%W*content%-length%s*:", 1) then return "CRLF_CONTENT_LENGTH" end
  if sl:find("[\r\n]%W*set%-cookie%s*:",     1) then return "CRLF_SET_COOKIE" end
  if sl:find("[\r\n]%W*location%s*:",        1) then return "CRLF_LOCATION" end

  -- URL-encoded CRLF sequences. Content-Type stays args-scoped here too (else a
  -- body carrying a literal `%0a` before `Content-Type:` re-trips the same FP as
  -- CRLF_URL_ENCODED); Set-Cookie / Location decode the full surface.
  if has(sl, "%0d%0a") or has(sl, "%0a") then
    local function decode(x)
      return (x:gsub("%%0d%%0a", "\r\n"):gsub("%%0d", "\r"):gsub("%%0a", "\n"))
    end
    local decoded = decode(sl)
    if decode(al):find("[\r\n]%W*content%-type%s*:") or
       decoded:find("[\r\n]%W*set%-cookie%s*:")      or
       decoded:find("[\r\n]%W*location%s*:")         then
      return "CRLF_URL_ENCODED"
    end
  end

  return nil
end

-- [CVE] Simple File List (WordPress) unauthenticated upload -> rename RCE.
-- Covers CVE-2025-34085 and CVE-2020-36847 (same plugin, same endpoints, same
-- png->php exploit; the ACSC July-2026 CMS campaign probes this).
--
-- Two vulnerable endpoints under /wp-content/plugins/simple-file-list/:
--   ee-upload-engine.php — unauth multipart upload; the exploit uploads PHP code
--                          disguised as an image (filename .png, image/png).
--   ee-file-engine.php    — unauth rename; the exploit renames the uploaded file
--                          to .php/.phtml/.php3/.php5 = code execution.
--
-- Fingerprint is keyed on ENDPOINT + exploit marker, NOT on parameter names:
-- public PoCs use different field names for the rename (oldFile/newFile vs
-- eeFileOld/eeFileAction/eeListFolder), so param-name matching would be fragile.
-- Near-zero FP: no legitimate flow renames TO a php-executable extension through
-- ee-file-engine.php, and no legitimate image upload carries a `<?php` open tag.
-- `method` is expected already lowercased (m_lower from the caller).
-- php-executable extension at a value boundary. Kept in step with bad_fname()
-- in detect_upload_filename (rule 401): .php[%d]* / .phtm[l] / .pht / .phar. If
-- that set grows, grow this too (they intentionally match the same engine-mapped
-- extensions; bad_fname is a nested local, so this is a parallel matcher).
local function _cve_sfl_has_exec_ext(s)
  if s:find("%.pht%f[%W]")       then return true end  -- .pht
  if s:find("%.phtml?%f[%W]")    then return true end  -- .phtm / .phtml
  if s:find("%.phar%f[%W]")      then return true end  -- .phar
  if s:find("%.php[0-9]*%f[%W]") then return true end  -- .php / .php3 / .php5 / .php7 / .php56 / .php74 (MultiPHP handlers)
  return false
end

function _M.detect_cve_simple_file_list_upload(uri, method, args, body, headers)
  if method ~= "post" then return nil end
  local u = lower(uri or "")

  -- Rename leg (the RCE trigger): POST to ee-file-engine.php whose args/body
  -- carries a php-executable rename target. Zero legitimate use.
  if has(u, "/simple-file-list/ee-file-engine.php") then
    local s = lower(cap(args or "", CFG.max_scan_len) .. "&" .. cap(body or "", CFG.max_scan_len))
    if _cve_sfl_has_exec_ext(s) then
      return "RENAME_TO_PHP"
    end
  end

  -- Upload leg: POST to ee-upload-engine.php carrying PHP content. REUSE the
  -- hardened rule-402 scanner (detect_upload_content) instead of a naive
  -- `<?php` substring — 402 already mitigates the binary-image false positive
  -- (a `<?php` byte run appearing by chance in a large uploaded image; see the
  -- note above detect_upload_content). We only add CVE attribution when 402's
  -- content check fires on THIS endpoint.
  if has(u, "/simple-file-list/ee-upload-engine.php") then
    if _M.detect_upload_content(body, headers) then
      return "UPLOAD_PHP"
    end
  end

  return nil
end

-- [CVE] Joomla JCE (< 2.9.99.5) unauthenticated arbitrary PHP file upload -> RCE.
-- CVE-2026-48907 (ACSC July-2026 CMS campaign; CISA KEV). JCE's "profile
-- import" admin action is reachable unauthenticated and accepts a multipart
-- upload that is written under /tmp and served as PHP.
--
-- Exploit request (public PoC 0xgh057r3c0n/CVE-2026-48907):
--   POST /index.php?option=com_jce   (multipart/form-data)
--     task = profiles.import
--     profile_file = <file>  filename "cve-....xml.php" (double-ext -> .php),
--                            Content-Type application/xml, PHP payload inside.
--
-- Fingerprint keyed on the exact component (option=com_jce) + action
-- (task=profiles.import) + a php-executable UPLOAD FILENAME — NOT on the
-- volatile random filename or the CSRF field. Near-zero FP: a legitimate JCE
-- profile import ships an .xml/.zip profile, never a php-executable file. Reuse
-- the hardened rule-401 matcher (detect_upload_filename) so the
-- double-extension / alt-handler coverage AND the multipart/form-data
-- content-type gate come for free. `method` is m_lower from the caller.
--
-- Note: the generic rule 401 (WAF_UPLOAD_FNAME) would also catch this php
-- upload; the check() call site runs this BEFORE 401 so the CVE reason wins
-- attribution for the same request.
function _M.detect_cve_joomla_jce_profile_import(uri, method, args, body, headers)
  if method ~= "post" then return nil end
  -- Cheap gate FIRST: option=com_jce lives in the query string (uri/args), both
  -- small — check it before touching the (capped) body, so the ~99.9% of POSTs
  -- that aren't JCE traffic skip the body copy (mirrors the SFL detector, which
  -- gates on its endpoint path first).
  local qs = lower((uri or "") .. "&" .. (args or ""))
  if not has(qs, "com_jce") then return nil end
  -- Match the distinctive VALUE substring, not `key=value` — the PoC sends both
  -- `files=` and `data=`, so requests encodes EVERYTHING as multipart and `task`
  -- becomes a field part (`name="task"\r\n\r\nprofiles.import`), never a literal
  -- `task=profiles.import` pair. `profiles.import` is the JCE action value; it
  -- rides in the body (accept it from the query surface too).
  if not (has(qs, "profiles.import")
          or has(lower(cap(body or "", CFG.max_scan_len)), "profiles.import")) then
    return nil
  end
  -- Exploit marker: a php-executable file in the multipart upload (also gates
  -- on multipart/form-data internally). The com_jce + profiles.import + php-exec
  -- upload triple is what makes this near-zero FP — a legitimate JCE profile
  -- import ships an .xml/.zip profile, never a php file.
  if _M.detect_upload_filename(body, headers) then
    return "PROFILE_IMPORT"
  end
  return nil
end

-- [CVE] Ninja Forms "File Uploads" add-on unauthenticated arbitrary file upload
-- + path traversal -> RCE. CVE-2026-0740 (ACSC July-2026 CMS campaign).
--
-- Exploit request (public PoC 0xgh057r3c0n/CVE-2026-0740):
--   POST /wp-admin/admin-ajax.php   (multipart/form-data)
--     action  = nf_fu_upload                      (the vulnerable add-on action)
--     nonce, form_id, field_id
--     image_jpg = ../../../                        (path-traversal dest path)
--     files-<field_id> = <file>                    (arbitrary upload; RCE if .php)
--   (preceded by action=nf_fu_get_new_nonce to mint the nonce.)
--
-- Keyed on the SPECIFIC action `nf_fu_upload` — a bare admin-ajax.php match is
-- deliberately NOT enough (WAF_CVE_PLAN.md: form submissions are common). The
-- action alone is a legitimate upload handler, so we additionally require an
-- exploit marker: (A) a php-executable upload filename (a contact form never
-- accepts a .php), or (B) path traversal in the `image_jpg` dest-path param
-- (../ is never a legitimate upload destination). `method` is m_lower.
function _M.detect_cve_ninja_forms_fu_upload(uri, method, args, body, headers)
  if method ~= "post" then return nil end
  -- Cheap gate FIRST: the endpoint is admin-ajax.php (tiny), check it before
  -- touching the (capped) body.
  if not has(lower(uri or ""), "admin-ajax.php") then return nil end
  -- The vulnerable action value. In the PoC it rides as a multipart field
  -- (`name="action"\r\n\r\nnf_fu_upload`), so match the distinctive value
  -- substring, not a `key=value` pair. `nf_fu_` is the add-on's action prefix.
  local scope = lower(cap(args or "", CFG.max_scan_len) .. "&" .. cap(body or "", CFG.max_scan_len))
  if not has(scope, "nf_fu_upload") then return nil end
  -- Marker A: php-executable file in the multipart upload (RCE payload). Also
  -- gates on multipart/form-data internally.
  if _M.detect_upload_filename(body, headers) then
    return "UPLOAD_PHP"
  end
  -- Marker B: path traversal in the image_jpg dest-path VALUE specifically —
  -- NOT anywhere in the buffer. A whole-buffer `../` scan false-positives on a
  -- legitimate upload of a code/config file whose CONTENT contains `../` (e.g.
  -- `require('../../lib')`), which lands in the capped body after the fields.
  -- Extract the value from both urlencoded (image_jpg=<v>) and multipart
  -- (name="image_jpg"\r\n\r\n<v>) encodings and test only that. `image_jpg=../`
  -- is never a legitimate upload destination.
  local function _trav(v)
    if not v or v == "" then return false end
    return has(v, "../") or has(v, "..\\") or has(v, "..%2f")
        or has(v, "..%5c") or has(v, "%2e%2e")
  end
  if _trav(scope:match("image_jpg=([^&\r\n]*)"))
     or _trav(scope:match('name="image_jpg".-\r?\n\r?\n([^\r\n]*)'))
     or _trav(scope:match("name='image_jpg'.-\r?\n\r?\n([^\r\n]*)")) then
    return "TRAVERSAL"
  end
  return nil
end

-- [CVE] LiteSpeed Cache (< 6.4) unauthenticated privilege escalation.
-- CVE-2024-28000. The plugin's crawler "role simulation" validates a 6-char
-- security hash (Str::rand(6) — only ~1M possible values) taken from the
-- `litespeed_hash` cookie against the stored `litespeed.router.hash`. Because
-- the space is tiny, an unauthenticated attacker brute-forces it (up to ~1M
-- requests, each carrying a guessed `litespeed_hash` cookie, alongside a
-- `litespeed_role` cookie set to the target user id) and gets simulated as
-- user ID 1 = admin. Patched in 6.4.
--
-- Fingerprint: the request presents a `litespeed_hash` (or `litespeed_role`)
-- COOKIE. These are an INTERNAL crawler-simulation mechanism — a real external
-- visitor NEVER sets them (Wordfence/Patchstack both note zero FP). `cookie` is
-- the raw Cookie header. Runs on ALL methods (the brute-force is a GET to the
-- REST API), so this is NOT gated on a POST body.
--
-- Armed autoblock is ideal here: the FIRST guessed-hash request 403s AND trips
-- the per-IP threshold, nft-banning the source and killing the ~1M-request
-- brute-force after a single attempt.
function _M.detect_cve_litespeed_privesc(cookie)
  if not cookie or cookie == "" then return nil end
  -- Cookie NAMES are case-sensitive (PHP reads $_COOKIE['litespeed_hash']), so
  -- the exploit always sends the exact lowercase name — match it exactly, no
  -- lowercasing needed. Anchor at the header start OR a ';' delimiter, tolerating
  -- ANY run of whitespace after the ';' (PHP explodes on ';' then trim()s each
  -- pair, so `;\tlitespeed_hash=` and `;  litespeed_hash=` are still parsed as
  -- the cookie — a fixed `; ` match would miss those padded evasions). Matching
  -- the `name=` boundary also stops a value that merely contains the string.
  if cookie:find("^litespeed_hash=") or cookie:find(";%s*litespeed_hash=") then
    return "HASH_COOKIE"
  end
  if cookie:find("^litespeed_role=") or cookie:find(";%s*litespeed_role=") then
    return "ROLE_COOKIE"
  end
  return nil
end

-- [CVE] Slider Revolution (revslider) — behavioural virtual-patch for the two
-- classic UNAUTH exploit shapes. This is deliberately NOT version-specific: the
-- request shapes below are malicious on ANY version (nothing legitimate reads
-- `../wp-config.php` through revslider_show_image, and no front-end visitor
-- triggers the update_plugin admin action), so keying on the shape protects the
-- fleet's whole revslider spread rather than only the one ancient install a
-- version match would flag. `method` is m_lower from the caller.
--
-- Leg A — LFI, CVE-2015-1579 (revslider < 4.2): arbitrary file read via
--   GET/POST admin-ajax.php?action=revslider_show_image&img=../wp-config.php
--   Ref: exploit-db 36554. The `../` in img IS the marker; malicious regardless
--   of auth, so no unauth gate.
--
-- Leg B — arbitrary plugin/zip upload -> RCE (Metasploit
--   wp_revslider_upload_execute; revslider <= 3.0.95 / 4.1.4):
--   POST admin-ajax.php action=revslider_ajax_action&client_action=update_plugin
--   with a multipart ZIP containing a PHP shell. `update_plugin` is a real ADMIN
--   client_action, so gate on UNAUTH (no wordpress_logged_in_* cookie) to avoid
--   FPing a logged-in admin — an unauth caller hitting it is the exploit. The
--   cookie gate is a forgeable FP-reduction heuristic, not a security control.
--
-- Reason attribution differs per leg, so the caller maps the returned tag:
--   "LFI" -> WAF_CVE:CVE_2015_1579:REVSLIDER:LFI
--   "UPDATE_PLUGIN" -> WAF_CVE:REVSLIDER:PLUGIN_UPLOAD (the 2014 upload has no
--       clean single CVE id; no CVE_ token means it notifies as WAF/CVE).
function _M.detect_cve_revslider(method, args, body, cookie)
  -- Cheap prefilter WITHOUT lowercasing: WP routes AJAX on the exact action
  -- string, so every exploit sends the lowercase `revslider_` prefix. The LFI
  -- rides in the query; the upload action rides in the POST body.
  local raw_args = args or ""
  local is_post = (method == "post")
  if not (has(raw_args, "revslider_")
          or (is_post and has(body or "", "revslider_"))) then
    return nil
  end
  local qs = lower(cap(raw_args, CFG.max_scan_len))

  -- Leg A — LFI: revslider_show_image + a traversal sequence. Scoped to the
  -- QUERY only (`?action=revslider_show_image&img=../` — both are URL params).
  -- NOT the body: a legit upload of a file whose CONTENT mentions the action +
  -- `../` (a log, a writeup) must not be blocked as an exploit.
  if has(qs, "revslider_show_image")
     and (has(qs, "../") or has(qs, "..%2f") or has(qs, "..%5c")
          or has(qs, "%2e%2e")) then
    return "LFI"
  end

  -- Leg B — plugin/zip upload -> RCE: revslider_ajax_action + update_plugin.
  -- These ride as multipart FIELD values, so this leg must scan the body — but
  -- it requires BOTH exploit-specific markers AND UNAUTH, keeping FP negligible.
  local scope = is_post and (qs .. "&" .. lower(cap(body or "", CFG.max_scan_len))) or qs
  if has(scope, "revslider_ajax_action") and has(scope, "update_plugin")
     and not has(lower(cookie or ""), "wordpress_logged_in_") then
    return "UPDATE_PLUGIN"
  end
  return nil
end

-- [CVE] W3 Total Cache (W3TC) dynamic-fragment (mfunc) attack surface. Two
-- UNAUTH legs of the same eval-via-cached-render bug class.
--
-- Leg A — CVE-2026-5032 (W3TC <= 2.9.3): a request whose User-Agent CONTAINS
--   "W3 Total Cache" bypasses the output-buffering pipeline (can_ob()) and
--   renders raw mfunc/mclude fragments — leaking the W3TC_DYNAMIC_SECURITY
--   token into the page source, which the attacker then uses to sign a working
--   mfunc RCE payload. Nothing legitimate sends that UA (WPScan/spec: zero FP).
--   Ref: rcesecurity.com CVE-2025-9501 writeup, WPScan CVE-2026-5032.
--
-- Leg B — CVE-2025-9501 (pre-auth RCE): a `mfunc`/`mclude` dynamic-fragment tag
--   is submitted as a blog COMMENT; once the page is cached, W3TC's
--   _parse_dynamic_mfunc() passes the tag content to eval(). Delivery is a POST
--   to the comment-submit endpoints. Per the fleet spec, match the marker
--   SUBSTRING (not the exact `<!--mfunc ...-->` tag form) — three vendor fixes
--   were bypassed by nesting the tag inside itself. `mfunc`/`mclude` are
--   near-zero in real comment text; scoped to comment endpoints to keep it so.
--   `dynamic_cache` is deliberately NOT matched (higher FP, and not the eval
--   tag). `method` is m_lower from the caller.
--
-- Caller maps the returned tag:
--   "UA_TOKEN_LEAK" -> WAF_CVE:CVE_2026_5032:W3TC:UA_TOKEN_LEAK
--   "MFUNC"         -> WAF_CVE:CVE_2025_9501:W3TC:MFUNC
function _M.detect_cve_w3tc(uri, method, headers, body)
  -- Leg A — the W3TC User-Agent bypass. All methods / all URIs.
  -- Safety: W3TC's OWN internal cache-priming loopback requests carry this UA,
  -- but they never reach here — cfm.lua short-circuits self-origin requests
  -- (loopback / self-IP set / IGNORE_NETS via is_self_origin) before the WAF
  -- runs, and check() re-guards on ctx.self_origin. So this only ever fires on
  -- EXTERNAL requests forging the UA. (A cross-server cache-priming peer, if any,
  -- would need to be in the self-IP set / IGNORE_NETS — the same allowlist.)
  local ua = lower(header_string((headers or {})["user-agent"]
                              or (headers or {})["User-Agent"] or ""))
  if has(ua, "w3 total cache") then
    return "UA_TOKEN_LEAK"
  end

  -- Leg B — mfunc/mclude injected via a comment submission.
  if method == "post" then
    local u = lower(uri or "")
    if has(u, "/wp-comments-post.php") or has(u, "/wp-json/wp/v2/comments") then
      local b = lower(cap(body or "", CFG.max_scan_len))
      if has(b, "mfunc") or has(b, "mclude") then
        return "MFUNC"
      end
    end
  end
  return nil
end

-- [CVE] Post SMTP — unauthenticated email-log disclosure -> account takeover.
-- CVE-2025-11833 (<= 3.6.0, actively exploited) + CVE-2023-6875 (<= 2.8.7,
-- connect-app auth bypass). A missing capability check lets an unauth caller
-- read logged emails — including password-reset links — and take over admin.
-- This is the fleet's "mass-mailer pivot": post-smtp is an SMTP relay, so
-- takeover hands the attacker working outbound mail credentials.
--
-- Vulnerable surfaces (from WPScan / ZeroPath / the public exploit):
--   Leg A: the plugin's REST namespace /wp-json/post-smtp/ — the v1/get-log,
--          v1/get-logs and v1/connect-app endpoints expose the log / reset the
--          mailer API key. Admin/internal only; never a public feature.
--   Leg B: the Postman email-log admin page reached unauth
--          (admin.php?page=postman_email_log).
--
-- UNAUTH gate: a legit admin — and the plugin's own admin-UI AJAX — carries the
-- WP logged-in cookie, so gating on its absence exempts real usage and only
-- fires on the unauthenticated exploit. Forgeable FP-reduction heuristic, per
-- the fleet spec, not a security control. All methods (get-log is a GET,
-- connect-app a POST).
function _M.detect_cve_post_smtp(uri, args, cookie)
  -- Cheap markers FIRST (this runs on every request): the REST path is in the
  -- URI; the admin-log page is `page=postman_email_log` in args. WP registers
  -- both slugs in exact lowercase, so a case-sensitive prefilter on args avoids
  -- lowercasing it on the ~99.9% of requests that aren't post-smtp.
  local u = lower(uri or "")
  local tag
  if has(u, "/wp-json/post-smtp/") then
    tag = "REST"
  elseif has(args or "", "postman")
     and (u .. "&" .. lower(args or "")):find("postman_%a+_log") then
    tag = "EMAIL_LOG"
  end
  if not tag then return nil end
  -- Only now pay for the cookie: exempt logged-in admins (and the plugin's own
  -- admin-UI AJAX). Forgeable FP-reduction heuristic, not a security control.
  if has(lower(cookie or ""), "wordpress_logged_in_") then return nil end
  return tag
end

-- Dangerous PHP callables that a CVE-2026-6279 render_logics payload injects
-- into call_user_func. Legit wp_conditional_tags render logic only ever calls
-- WP conditional tags (is_front_page, is_page, is_single, …) — none of these —
-- so their presence in the decoded payload is the exploit marker. `exec` is
-- omitted (substring of shell_exec / "execute"); shell_exec/proc_open cover it.
local FUSION_RCE_FUNCS = {
  "call_user_func", "shell_exec", "system", "passthru", "proc_open", "popen",
  "assert", "create_function", "file_put_contents", "move_uploaded_file",
  "base64_decode", "gzinflate", "phpinfo", "<?php", "<?=",
}

-- [CVE] Avada / Fusion Builder (fusion-builder) — two UNAUTH admin-ajax nopriv
-- vulns. Both POST /wp-admin/admin-ajax.php.
--
-- Leg A — RCE, CVE-2026-6279 (<= 3.15.2): action=fusion_get_widget_markup with a
--   base64 `render_logics` param that decodes to
--   {"type":"wp_conditional_tags","value":{"function":"system","args":"id"}} —
--   the `function` value reaches call_user_func() with no allowlist. Ref:
--   github xxconi/CVE-2026-6279, WPScan. We decode render_logics and flag a
--   dangerous callable (a legit wp_conditional_tags only calls is_* tags).
--
-- Leg B — arbitrary file delete, CVE-2026-8713 (<= 3.15.3): action=
--   fusion_form_submit_ajax with `privacy_expiration_action` — a SERVER-side-only
--   field a client never sends. The Fusion_Form_DB_Privacy shutdown hook then
--   runs maybe_delete_files() on the attacker path (no realpath) -> delete
--   wp-config.php -> takeover. `privacy_expiration_action` is the near-zero-FP
--   anchor (per the fleet spec: never legitimate in a client request).
--
-- `method` is m_lower from the caller. Caller maps the returned tag:
--   "RCE"         -> WAF_CVE:CVE_2026_6279:FUSION_BUILDER:RCE
--   "FILE_DELETE" -> WAF_CVE:CVE_2026_8713:FUSION_BUILDER:FILE_DELETE
function _M.detect_cve_fusion_builder(uri, method, args, body)
  if method ~= "post" then return nil end
  if not has(lower(uri or ""), "admin-ajax.php") then return nil end
  local scope = lower(cap(args or "", CFG.max_scan_len) .. "&" .. cap(body or "", CFG.max_scan_len))

  -- Leg B — file delete. Cheapest + cleanest, check first.
  if has(scope, "fusion_form_submit_ajax") and has(scope, "privacy_expiration_action") then
    return "FILE_DELETE"
  end

  -- Leg A — RCE via render_logics. Decode the base64 (case-sensitive, so use the
  -- RAW body, not the lowercased scope) and scan the decoded blob.
  if has(scope, "fusion_get_widget_markup") and has(scope, "render_logics") then
    local src = cap((args or "") .. "&" .. (body or ""), CFG.max_scan_len)
    for cand in src:gmatch("render_logics=([^&\r\n]+)") do
      local dec = ngx.decode_base64(url_decode_once(cand))
      if dec and #dec >= 8 then
        local d = lower(dec)
        for _, fn in ipairs(FUSION_RCE_FUNCS) do
          if has(d, fn) then return "RCE" end
        end
      end
    end
  end
  return nil
end

-- [CVE] Kirki (Freeform Page Builder / customizer framework) unauthenticated
-- account takeover via password reset. CVE-2026-8206 (Kirki 6.0.0–6.0.6, CVSS
-- 9.8, actively mass-exploited). The plugin exposes an UNAUTH REST endpoint
-- `/wp-json/KirkiComponentLibrary/v1/kirki-forgot-password` whose
-- handle_forgot_password() accepts a `username` and an `email` INDEPENDENTLY
-- without checking the email belongs to that user — so an attacker requests a
-- reset for any admin username, supplies their OWN email, and receives the
-- reset link. Ref: WPScan / bleepingcomputer / Jenderal92 PoC.
--
-- Both `username` (target) and `email` (attacker) are REQUIRED for the exploit,
-- so keying on the endpoint + both params catches every variant while letting a
-- hypothetical single-field legitimate reset through — strictly fewer FPs than
-- blocking the bare endpoint. On a typical fleet Kirki is a bundled theme
-- dependency (not the site's reset mechanism), so this endpoint sees ~zero legit
-- traffic anyway. `method` is m_lower from the caller.
function _M.detect_cve_kirki_forgot_password(uri, method, args, body)
  if method ~= "post" then return nil end
  if not has(lower(uri or ""), "kirki-forgot-password") then return nil end
  local scope = lower(cap(args or "", CFG.max_scan_len) .. "&" .. cap(body or "", CFG.max_scan_len))
  if has(scope, "username") and has(scope, "email") then
    return "FORGOT_PASSWORD"
  end
  return nil
end

-- [CVE] Multi Uploader for Gravity Forms (<= 1.1.3) unauthenticated arbitrary
-- file upload -> RCE. CVE-2025-23921 (CVSS 9.0, actively exploited since Aug
-- 2024). A multipart POST to the `gf_page=upload` endpoint whose
-- `gform_unique_id` field — meant to be a UUID — is set to a PATH-TRAVERSAL
-- destination ending in a php-executable extension (`../../../…/shell.phtml`),
-- writing a webshell outside the intended upload dir. Ref: WPScan / Wordfence /
-- Patchstack + operator threat-intel (Snort sigs on gf_page=upload +
-- gform_unique_id + ../ + .phtml).
--
-- Genuine gap over rule 401: the php-exec extension rides in the gform_unique_id
-- FIELD VALUE (the traversal destination), not the multipart `filename=`, so
-- 401's filename matcher misses it. We EXTRACT the gform_unique_id value and
-- require both traversal AND a php-exec extension in it — so a legit upload
-- whose file CONTENT happens to contain `../`/`.phtml` can't false-positive it
-- (a legit gform_unique_id is a bare UUID). `method` is m_lower from the caller.
function _M.detect_cve_gf_multi_uploader(uri, method, args, body)
  if method ~= "post" then return nil end
  -- Cheap endpoint gate: gf_page=upload rides in the query string.
  if not has(lower((uri or "") .. "&" .. (args or "")), "gf_page=upload") then return nil end
  -- Extract the gform_unique_id value (multipart field part or urlencoded).
  local b = body or ""
  local val = b:match('[Nn]ame="gform_unique_id".-\r?\n\r?\n([^\r\n]*)')
           or b:match("gform_unique_id=([^&\r\n]*)")
  if not val then return nil end
  local v = lower(val)
  if (has(v, "../") or has(v, "..%2f") or has(v, "..%5c") or has(v, "%2e%2e"))
     and _cve_sfl_has_exec_ext(v) then
    return "TRAVERSAL_PHTML"
  end
  return nil
end

-- wp2shell — WordPress CORE unauthenticated RCE chain, actively exploited, public
-- PoC (Icex0/wp2shell-poc). Two chained WordPress-core bugs:
--   • CVE-2026-63030 — REST batch route confusion. An anonymous POST to the batch
--     endpoint (/wp-json/batch/v1 or /?rest_route=/batch/v1) nests a batch inside a
--     sub-request `body` and uses a desync primer sub-request whose path is "///"
--     to confuse route parsing, smuggling a raw GET to /wp/v2/users past the REST
--     parameter sanitiser.
--   • CVE-2026-60137 — SQL injection in core. The smuggled GET carries
--     author_exclude=<value>; the value lands unsanitised in `post_author NOT IN
--     (<value>)`. The PoC breaks out with `0) OR SLEEP(n)-- -` / `0) AND (<cond>)-- -`.
-- Affects WP 6.9–6.9.4 and 7.0–7.0.1; fixed 6.9.5 / 7.0.2 (forced auto-update).
--
-- Gate on the batch endpoint (_wp2shell_is_batch_endpoint) BEFORE materialising the
-- normalized body, then key on two near-zero-FP markers in `nab` (the shared
-- normalized+lowercased args+body; the PoC url-encodes the batch value with
-- urllib.quote, so normalize()'s url-decode reveals the raw SQL):
--   SQLI   — author_exclude / author_not_in (a strict integer-list REST param) whose
--            EXTRACTED VALUE contains any byte outside `[0-9, ]`. Value-scoped so
--            legit prose elsewhere in the batch body can't trip it, and technique-
--            agnostic so it can't be dodged with /**/ or # comment obfuscation.
--   DESYNC — the "///" primer PATH value, not seen in legit batch traffic.
-- Each leg is attributed to its own CVE id at the call site.
local function _wp2shell_is_batch_endpoint(uri, args)
  -- normalize (url-decode x2 + lower) so an encoded rest_route=%2fbatch%2fv1 —
  -- which WordPress still routes to the batch controller — can't dodge the gate.
  -- Cheap: uri/args are short and normalize() fast-paths strings with no '%'.
  if has(normalize(uri or ""), "batch/v1") then return true end
  return has(normalize(args or ""), "batch/v1")
end
_M.wp2shell_is_batch_endpoint = _wp2shell_is_batch_endpoint

-- Extract every author_exclude / author_not_in value out of nab (the param rides
-- inside a JSON path string like `/wp/v2/users?author_exclude=<v>`, value ending at
-- the JSON quote, next query param, or JSON escape) and flag any that is not a
-- clean integer list. A legit REST value is digits, commas and whitespace ONLY
-- (wp_parse_id_list splits on both `,` and spaces) — plus a literal `+`, which is
-- the form-urlencoded spelling of a separator space (normalize() only decodes
-- %xx, not `+`, so a legit `author_exclude=5,+6` reaches here with the `+` intact).
-- ANY other byte — a ")" breakout, a SQL keyword, an inline /**/ or # comment, a
-- quote — means the route confusion smuggled a raw value past the sanitiser.
-- Allowing `+` can't weaken this: a SQL breakout always needs a paren, a keyword
-- letter, a quote or a comment marker, none of which live in `[0-9,%s+]`.
-- Scoping to the extracted VALUE (not the whole body) is what keeps
-- a legit batch that merely mentions ") or " in post prose from tripping, AND it
-- catches injection shapes a fixed keyword list misses (e.g. `0)/**/or/**/(1=1)#`).
-- The `[%[%]0-9]*=` between key and value tolerates the array forms
-- (author_exclude[]= / author_exclude[0]=) without matching the key inside prose
-- (where no `=` follows it).
local function _wp2shell_sqli_in_author_param(s)
  for _, key in ipairs({ "author_exclude", "author_not_in" }) do
    for val in s:gmatch(key .. "[%[%]0-9]*=([^\"&\\]*)") do
      -- legit value = integers separated by commas/whitespace (wp_parse_id_list),
      -- incl. a form-encoded `+` space; any other byte is a smuggled injection.
      if val ~= "" and val:find("[^0-9,%s+]") then
        return true
      end
    end
  end
  return false
end

function _M.detect_cve_wp2shell(nab)
  local s = nab or ""
  if s == "" then return nil end
  -- Leg A — CVE-2026-60137: SQLi in the author-exclusion REST param (value-scoped).
  if _wp2shell_sqli_in_author_param(s) then
    return "SQLI"
  end
  -- Leg B — CVE-2026-63030: the batch route-confusion desync primer, a sub-request
  -- whose PATH is "///". Keyed on the `path` key (not a bare "///") so a post/slug
  -- whose value happens to be `///` can't trip it. Tolerant of the colon spacing
  -- of both compact and pretty-printed JSON, and of a JSON-escaped slash (`\/`,
  -- a valid JSON spelling of `/` that WordPress's parser still routes to `///`) so
  -- the primer can't be hidden as "\/\/\/". `%\?` = an optional literal backslash.
  if s:find('path"%s*:%s*"%\\?/%\\?/%\\?/"') then
    return "DESYNC"
  end
  return nil
end

-- [CVE] WooCommerce Payments (woocommerce-payments 4.8.0–5.6.1) unauthenticated
-- authentication bypass -> privilege escalation. CVE-2023-28121 (CVSS 9.8,
-- mass-exploited since Jul 2023).
--
-- determine_current_user_for_platform_checkout() trusts the
-- `X-WCPAY-Platform-Checkout-User` request header and returns its value as the
-- CURRENT USER ID with no validation. An unauthenticated attacker sets it to `1`
-- and then drives any privileged action as that admin — the public PoC
-- (rcesecurity patch-diff) POSTs /wp-json/wp/v2/users with roles=[administrator]
-- to mint a fresh admin account.
--
-- The header is the ENTIRE exploit primitive and is set only server-side by
-- WCPay's own WooPay / platform-checkout infrastructure — a browser or external
-- client never sends it. So keying on header PRESENCE (any value, any method,
-- any path) is the canonical near-zero-FP virtual patch (Wordfence / Patchstack
-- ship the same shape). We deliberately do NOT gate on the WP logged-in cookie:
-- the header alone is already never-legit, and a cookie gate would only hand the
-- attacker a trivial bypass (append a junk wordpress_logged_in_ cookie) for zero
-- FP gain. Header keys arrive lowercased from ngx.req.get_headers(); the extra
-- casings cover a raw/test table. Collateral note: a site that genuinely runs
-- WooPay receives this header from WooPay's servers — exempt those source nets
-- with waf_security ALLOW_NETS rather than un-arming the family.
function _M.detect_cve_woocommerce_payments(headers)
  headers = headers or {}
  if headers["x-wcpay-platform-checkout-user"]
     or headers["X-WCPAY-Platform-Checkout-User"]
     or headers["X-Wcpay-Platform-Checkout-User"] then
    return "PLATFORM_CHECKOUT_HDR"
  end
  return nil
end

-- [CVE] Gravity SMTP (gravitysmtp <= 2.1.4) unauthenticated sensitive-information
-- exposure via REST API. CVE-2026-4020 (CVSS 7.5).
--
-- The plugin registers the REST route /gravitysmtp/v1/tests/mock-data with a
-- permission_callback that unconditionally returns `true`. An unauthenticated
-- request (the PoC appends ?page=gravitysmtp-settings) makes
-- register_connector_data() populate the full System Report — ~365 KB of JSON
-- leaking PHP/DB/server versions, absolute paths, active plugins/theme, DB table
-- names, and any configured connector API keys/tokens.
--
-- Key on the plugin-unique REST route, matched in EITHER permalink form (pretty
-- `/wp-json/gravitysmtp/v1/tests/mock-data` in the URI, or plain
-- `/?rest_route=/gravitysmtp/v1/tests/mock-data` where the route rides in args).
-- It's a `tests/mock-data` endpoint external visitors never hit; the only legit
-- caller is the plugin's own settings screen, which runs in wp-admin and so
-- carries the WP logged-in cookie — gate on its ABSENCE (forgeable FP-reduction
-- heuristic, per the fleet spec, not a security control), exactly like the Post
-- SMTP detector. All methods (permission_callback=true accepts any). Ref: WPScan
-- / Patchstack CVE-2026-4020, atomicedge PoC.
function _M.detect_cve_gravity_smtp(uri, args, cookie)
  -- Cheap prefilter FIRST — this runs on every request. The plugin slug is a
  -- literal even in the %2f-slash evasion below (only the SLASHES are encoded),
  -- and WordPress routes the REST namespace case-sensitively, so a case-sensitive
  -- substring test is exact and lets us skip the normalize() url-decode+lower on
  -- the ~99.99% of requests that never mention the plugin (the post_smtp detector
  -- uses the same case-sensitive-args-prefilter trick to stay off the hot path).
  if not (has(uri or "", "gravitysmtp") or has(args or "", "gravitysmtp")) then
    return nil
  end
  -- normalize = url-decode x2 + lower, so an encoded plain-permalink form
  -- (?rest_route=%2fgravitysmtp%2fv1%2ftests%2fmock-data, which WordPress still
  -- routes to the same controller) can't dodge the literal route match.
  local scope = normalize((uri or "") .. "&" .. (args or ""))
  if not has(scope, "gravitysmtp/v1/tests/mock-data") then return nil end
  if has(lower(cookie or ""), "wordpress_logged_in_") then return nil end
  return "MOCK_DATA"
end

-- [top-10c] HTTP request smuggling – verb embedded in args / body.
-- Source: uusec http-request-smuggling.lua.
-- Attackers embed a second HTTP request line inside a parameter value to inject
-- a request past a frontend proxy.  Matches: VERB<space>PATH<space>HTTP/N
-- HTTP methods whose "VERB <path> HTTP/n" shape inside a parameter value
-- signals a smuggled request line. Module-scope (not rebuilt per call). Lua
-- patterns have no `(a|b|c)` alternation, so each verb is tested at a word
-- boundary rather than in a fake alternation group. [audit F12]
local SMUG_VERBS = {
  "get", "post", "head", "put", "delete", "options", "patch", "connect",
  "trace", "track", "propfind", "proppatch", "mkcol", "copy", "move",
  "lock", "unlock",
}

function _M.detect_http_smuggling(args, body)
  local function smug_check(s)
    if not s or s == "" then return nil end
    -- Lowercase FIRST. A smuggled request line is normally "GET /x HTTP/1.1"
    -- (uppercase), so the old case-sensitive " http/" prefilter never matched
    -- — the rule was doubly dead (case + the `|` alternation below). [F12]
    local sl = lower(s)
    if not (has(sl, " http/") or has(sl, "%20http/") or has(sl, "+http/")) then
      return nil
    end
    -- "VERB <path> HTTP/n" where VERB is a known method at a word boundary.
    -- Only runs on the rare strings that passed the http/ gate above, so the
    -- per-verb find loop is negligible.
    for _, verb in ipairs(SMUG_VERBS) do
      -- Require the request-target to start with "/" (origin-form, the form a
      -- smuggled line takes inside a param). This rejects English prose such
      -- as "connect to http/2" / "options for http/2" where the middle token
      -- is a word, not a path — a genuine FP source at logonly. [review F12]
      local pat = "%f[%a]" .. verb .. "%s+/[^%s]*%s+http/%d"
      local init = 1
      while true do
        local s_pos, e_pos = sl:find(pat, init)
        if not s_pos then break end
        -- Pasted-access-log carve-out [FP 2026-07-21]: support tickets, forum
        -- posts and CMS articles routinely quote combined/common-log lines —
        --   1.2.3.4 - - [21/Jul/2026:11:36:13 +0300] "GET /x HTTP/1.1" 200 26307
        -- which IS a literal request line inside a body. The log fingerprint
        -- is unambiguous: the line sits in double quotes AND is immediately
        -- followed by a 3-digit status. Skip that occurrence only — a bare
        -- smuggled line (the actual attack shape) has neither. Raw quotes
        -- only (the FP surface is multipart/raw bodies); a %22-encoded paste
        -- inside args still flags — extend here if that ever bites.
        local quoted = s_pos > 1 and sl:sub(s_pos - 1, s_pos - 1) == '"'
        local log_tail = sl:find('^[%d%.]*"%s+%d%d%d%f[%D]', e_pos + 1) ~= nil
        if not (quoted and log_tail) then
          return "SMUG_" .. verb:upper()
        end
        init = e_pos + 1
      end
    end
    return nil
  end

  local t = smug_check(args)
  if t then return t end
  t = smug_check(body)
  if t then return t end
  return nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- RESEARCH ADDITIONS – UPLOAD CHECKS (multipart body)
-- ─────────────────────────────────────────────────────────────────────────────

-- [top-4a] Webshell extension in multipart upload filename.
-- Source: uusec upload-file-name-filtering.lua (extended).
-- Key shared-hosting additions: user.ini (per-dir PHP config override),
-- php.ini, .htaccess, .env – all can reconfigure execution without needing
-- a direct .php upload.
-- Checks quoted, single-quoted, and unquoted Content-Disposition filenames.
function _M.detect_upload_filename(body, headers)
  if not body or body == "" then return nil end

  headers = headers or {}
  local ct = lower(headers["content-type"] or headers["Content-Type"] or "")
  if not has(ct, "multipart/form-data") then return nil end

  local function bad_fname(fname)
    fname = lower(fname or "")
    -- HTML entity decode (basic)
    fname = fname:gsub("&#(%d+);", function(n)
      local c = tonumber(n)
      if c and c < 128 then return string.char(c) end
      return ""
    end)

    -- Special full-name matches (shared hosting critical paths)
    if has(fname, "user.ini")   then return "user.ini" end
    if has(fname, "php.ini")    then return "php.ini" end
    if has(fname, ".htaccess")  then return ".htaccess" end
    if has(fname, ".htpasswd")  then return ".htpasswd" end
    if has(fname, ".env")       then return ".env" end
    if has(fname, "web.config") then return "web.config" end

    -- Extension checks: match anywhere in filename to catch double-extensions
    if fname:match("%.php[%d]*[^%w]") or fname:match("%.php[%d]*$") then return "php" end
    -- PHP alt-handlers Apache/LiteSpeed commonly map to the engine: .phtml/.phtm
    -- and the bare .pht slip past the .php[%d]* matcher above, so they join the
    -- block-tier set. (.phtml is also Magento's server-side template extension,
    -- but templates ship via code/FTP, not a web-form upload, so a multipart
    -- .phtml upload is still overwhelmingly an attack.)
    -- NOTE: SSI pages (.shtml/.shtm) are deliberately NOT blocked here. They are
    -- a first-class *static* file type on cPanel (`AddHandler server-parsed`),
    -- so a customer uploading legit .shtml pages through a web file manager would
    -- be blocked AND (rule 401 being autoblock-armed) earn a 6h nft IP ban — an
    -- FP that outweighs the SSI-exec risk (usually off via IncludesNOEXEC, and
    -- no .shtml appeared in any captured upload sample). Revisit with a
    -- content-based SSI-exec check if that threat ever shows up in the wild.
    if fname:match("%.phtml?[^%w]") or fname:match("%.phtml?$") then return "phtml" end  -- .phtm/.phtml, anchored (no x.phtmz overmatch)
    if fname:match("%.pht[^%w]") or fname:match("%.pht$") then return "pht" end
    -- Anchored exactly like the .php/.phtml/.pht matchers above: the extension
    -- must be followed by a non-word char (a further ".ext", a separator) or
    -- end-of-string, so `shell.phar` and the `shell.phar.jpg` double-extension
    -- are caught while the extension appearing as a mid-word SUBSTRING is not.
    -- These were previously unanchored (`fname:match("%.phar")` etc.), and rule
    -- 401 is block + autoblock-armed (6h nft ban) — so a mid-word match banned a
    -- legitimate uploader's IP: `.phar`⊂`company.pharma.pdf`,
    -- `.asp`⊂`trip.aspen.jpg`, `.asa`⊂`team.asana.csv`,
    -- `.jsp`⊂`vendor.jspdf.min.js`, `.cer`⊂`vase.ceramic.jpg`. The `.cer[^t]`
    -- guard (kept `.cert` certificates out) is subsumed by `[^%w]`, since 't' is
    -- a word char.
    if fname:match("%.phar[^%w]")  or fname:match("%.phar$")  then return "phar" end
    if fname:match("%.aspx?[^%w]") or fname:match("%.aspx?$") then return "asp" end
    if fname:match("%.asax?[^%w]") or fname:match("%.asax?$") then return "asa" end
    if fname:match("%.asmx[^%w]")  or fname:match("%.asmx$")  then return "asmx" end
    if fname:match("%.ascx[^%w]")  or fname:match("%.ascx$")  then return "ascx" end
    if fname:match("%.jspx?[^%w]") or fname:match("%.jspx?$") then return "jsp" end
    if fname:match("%.cer[^%w]")   or fname:match("%.cer$")   then return "cer" end
    if fname:match("%.cdx[^%w]")   or fname:match("%.cdx$")   then return "cdx" end
    if fname:match("%.war$")    then return "war" end
    if fname:match("%.class$")  then return "class" end
    if fname:match("%.exe$")    then return "exe" end
    if fname:match("%.sh$")     then return "sh" end
    if fname:match("%.cgi$")    then return "cgi" end
    if fname:match("%.pl$")     then return "pl" end

    return nil
  end

  -- The Content-Disposition parameter name is case-INSENSITIVE per RFC
  -- 2183/7578, and PHP's rfc1867 parser compares it with strcasecmp — so
  -- `FileName`, `FILENAME`, `fileName` are all honoured by the backend. The
  -- token must therefore be matched case-insensitively (Lua patterns have no
  -- `i` flag), or a capitalised parameter name skips extraction entirely and
  -- every matcher above with it (webshell delivered as `FileName="shell.php"`).
  local FN = "[Ff][Ii][Ll][Ee][Nn][Aa][Mm][Ee]"

  -- Match double-quoted, single-quoted, and unquoted filename= values
  for fname in body:gmatch(FN .. '%s*=%s*"([^"]+)"') do
    local hit = bad_fname(fname)
    if hit then return "UPLOAD_FNAME:" .. hit .. ":" .. fname:sub(1, 64) end
  end
  for fname in body:gmatch(FN .. "%s*=%s*'([^']+)'") do
    local hit = bad_fname(fname)
    if hit then return "UPLOAD_FNAME:" .. hit .. ":" .. fname:sub(1, 64) end
  end
  for fname in body:gmatch(FN .. "%s*=%s*([^%s;\"'][^%s;\"']*)") do
    local hit = bad_fname(fname)
    if hit then return "UPLOAD_FNAME:" .. hit .. ":" .. fname:sub(1, 64) end
  end

  -- RFC 5987 / RFC 6266 extended parameter: `filename*=charset'lang'value`,
  -- where value is percent-encoded. ASP.NET/IIS (ContentDispositionHeaderValue
  -- FileNameStar) honour it, so `.aspx/.asmx/.ascx/.asa/.asax/.cer/.cdx` (or any
  -- handler) can be delivered this way and skip the three matchers above — those
  -- require `filename` directly before `=`, but here a `*` sits between. Strip
  -- the optional charset'lang' prefix and percent-decode ('+' is literal in an
  -- ext-value, NOT space) before checking. A double-decode is not needed: the
  -- server decodes the ext-value exactly once, so a `%252e` never becomes a dot
  -- on the backend either.
  for raw in body:gmatch(FN .. "%s*%*%s*=%s*([^%s;\r\n\"]+)") do
    local v = raw:match("^[^']*'[^']*'(.*)$") or raw
    v = v:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
    local hit = bad_fname(v)
    if hit then return "UPLOAD_FNAME:" .. hit .. ":" .. v:sub(1, 64) end
  end

  -- Backstop for PHP's lenient quote parsing (php_ap_getword_conf, shared by
  -- cPanel/LiteSpeed lsphp): it honours a `\"` escaped quote and even an
  -- UNTERMINATED opening quote, so `filename="a\".php"` and `filename="a.php`
  -- <CRLF> both deliver a `.php` file that the precise quote patterns above
  -- under-read (they stop at the first inner `"` / need a closing `"`). Capture
  -- the whole value to end-of-Content-Disposition-line and let bad_fname's
  -- anchored matchers decide — the required leading dot plus the `[^%w]`/`$`
  -- extension anchoring keeps benign values (a trailing quote, `;`, junk) from
  -- tripping. Runs only after the precise patterns miss, so normal uploads keep
  -- their clean forensic echo. `%*?` also covers a raw (un-decoded) `filename*=`.
  for raw in body:gmatch(FN .. "%s*%*?%s*=%s*([^\r\n]+)") do
    local hit = bad_fname(raw)
    if hit then return "UPLOAD_FNAME:" .. hit .. ":" .. raw:sub(1, 64) end
  end

  return nil
end

-- [top-4c] Webshell PHP file hidden INSIDE an uploaded ZIP archive.
-- Vector (2026-07 Joomla mass-defacement "ANTONKILL"): com_sppagebuilder
-- `asset.uploadCustomIcon` (and sibling asset/media endpoints) accept a .zip and
-- extract it server-side. A webshell `.php` compressed inside that zip is
-- invisible to every existing upload check:
--   * detect_upload_filename (401) sees only the OUTER multipart filename
--     (`ico*.zip` — an allowed extension);
--   * detect_upload_content  (402) scans for a literal `<?php`, but the PHP
--     bytes are DEFLATE-compressed inside the zip, so the tag never appears;
--   * ClamAV extracts and scans, but the payload is obfuscated → signature miss.
-- The one thing the attacker cannot hide is the archive DIRECTORY: a ZIP stores
-- every entry's filename in CLEARTEXT (only the file *data* is compressed). We
-- scan the multipart body for local file headers (`PK\3\4`, name at +30) AND
-- central-directory headers (`PK\1\2`, name at +46 — this is the name PHP's
-- ZipArchive::extractTo actually writes, so a benign-local / malicious-central
-- name mismatch is caught too), and flag PHP-executable / handler-override
-- entries. Obfuscation-proof: it keys on the entry NAME, never the content.
-- The detector itself is endpoint-agnostic (it just answers "does this upload
-- body carry a PHP-named zip entry?"). Callers MUST gate it on a POSITIVE
-- media-asset allowlist (is_php_hostile_asset_upload) — a php-bearing zip is
-- legitimate for the whole plugin/theme/extension/backup ecosystem, so it may
-- only be treated as malicious on endpoints that exist to receive media assets.
local function _zip_entry_bad_ext(name)
  -- `name` must already be lowercased. Kept intentionally tight (no
  -- .asp/.jsp/.exe): the threat is a PHP webshell / handler dropped into a
  -- Joomla/WP tree, plus the two config files that make a dir execute PHP.
  if name == "" then return nil end
  -- %d* (not %d?) so multi-digit MultiPHP handler extensions are caught:
  -- .php56 / .php70 / .php74 / .php80 / .php81 execute on cPanel/Plesk MultiPHP
  -- hosts. (2026-07 SP Page Builder drop hid its webshell as fonts/kamley.php56.)
  if name:match("%.php%d*$")  or name:match("%.php%d*[^%w]")  then return "PHP" end
  if name:match("%.phtml?$")  or name:match("%.phtml?[^%w]")  then return "PHTML" end
  if name:match("%.pht$")     or name:match("%.pht[^%w]")     then return "PHT" end
  if name:match("%.phar$")    or name:match("%.phar[^%w]")    then return "PHAR" end
  if name:match("%.phps$")    or name:match("%.phps[^%w]")    then return "PHPS" end
  if name:match("%.htaccess$")   or name:match("%.htaccess[^%w]")   then return "HTACCESS" end
  if name:match("%.user%.ini$")  or name:match("%.user%.ini[^%w]")  then return "USERINI" end
  return nil
end

function _M.detect_upload_archive_php(body, headers)
  if not body or body == "" then return nil end
  headers = headers or {}
  local ct = lower(headers["content-type"] or headers["Content-Type"] or "")
  if not has(ct, "multipart/form-data") then return nil end

  local blen = #body

  -- sig: 4-byte ZIP header magic. len_off/name_off: byte offsets (from the 'P')
  -- of the 2-byte LE filename length and the filename itself.
  local function scan(sig, len_off, name_off)
    local pos = body:find(sig, 1, true)
    local iters = 0
    while pos and iters < 512 do
      iters = iters + 1
      local a, b = body:byte(pos + len_off), body:byte(pos + len_off + 1)
      if a and b then
        local nlen = a + b * 256
        if nlen > 0 and nlen <= 512 and (pos + name_off + nlen - 1) <= blen then
          local raw = body:sub(pos + name_off, pos + name_off + nlen - 1)
          local hit = _zip_entry_bad_ext(lower(raw))
          if hit then return hit, raw end
        end
      end
      pos = body:find(sig, pos + 4, true)
    end
    return nil
  end

  local hit, name = scan("PK\3\4", 26, 30)   -- local file header
  if not hit then hit, name = scan("PK\1\2", 28, 46) end  -- central directory
  if hit then return "ZIP_" .. hit .. ":" .. lower(name):sub(1, 64) end
  return nil
end

-- A bare `<?=` PHP short-echo opener is only three bytes (`3C 3F 3D`) and
-- collides with the high-entropy byte stream of legitimate binary uploads.
-- A product photo (JPEG / WebP / PNG) statistically contains that sequence
-- roughly once per ~16 MB of image data, which fired UPLOAD_PHP_TAG (rule
-- 402) and POLYGLOT_DEEP_* (rule 432) on innocent e-shop image uploads.
-- (2026-06-04 e-vafeiadis.gr report: the same product save alternated 200 /
-- 403 across retries — proof the trigger was image *content*, not the
-- request shape; the admin was uploading WebP product photos.)
--
-- A real short-echo tag is always immediately followed by a PHP expression:
-- a variable / superglobal (`$`), a backtick exec, a quoted string, a
-- parenthesised expression, or a function call (`name(`). Requiring that
-- context keeps every short-tag webshell shape while making the opener
-- binary-safe. The 5-byte `<?php` opener needs no such guard — it is rare
-- enough in binary that the codebase already treats it as a safe marker
-- (see rule 432: "Legit binary files never contain `<?php`").
--
-- `s` MUST already be lowercased (matches both detector call sites).
local function has_php_short_echo(s)
  if not s or s == "" then return false end
  -- An optional `@` error-suppression operator may sit between the opener
  -- and the expression (`<?=@eval(...)`). PHP function names may contain
  -- digits (`base64_decode`, `md5`, `sha1`, `str_rot13`), so the name class
  -- is `[%w_]` (NOT `[%a_]` — excluding digits was a real bypass for
  -- input-driven shells like `<?=base64_decode(file_get_contents(...))`).
  return (s:find("<%?=%s*@?%s*%$")            -- <?=$_GET / <?= $x / <?=@$x
       or s:find("<%?=%s*@?%s*`")             -- <?=`id`
       or s:find("<%?=%s*@?%s*['\"]")         -- <?='cmd' / <?="cmd"
       or s:find("<%?=%s*@?%s*%(")            -- <?=(expr)
       or s:find("<%?=%s*@?%s*%a[%w_]*%s*%(") -- <?=base64_decode( / <?=md5( / <?=system(
       ) ~= nil
end

-- [top-4b] Webshell / malicious content in uploaded file bytes.
-- Sources: uusec upload-file-content-filtering.lua + imagemagick-vulnerability.lua.
-- Scans the raw multipart body for PHP tags, JSP tags, and ImageMagick MVG
-- injection patterns.  Only fires on multipart/form-data.
-- Note: detect_php_webshell_body already covers direct PHP POSTs; this rule
-- adds coverage for files disguised with a different Content-Type / extension.
function _M.detect_upload_content(body, headers)
  if not body or body == "" then return nil end

  headers = headers or {}
  local ct = lower(headers["content-type"] or headers["Content-Type"] or "")
  if not has(ct, "multipart/form-data") then return nil end

  local b = lower(cap(body, CFG.max_scan_len))

  -- `<?php` matched bare (binary-safe); `<?=` requires PHP-expression context
  -- so it can't fire on a stray 3-byte collision inside a real image upload.
  if has(b, "<?php") or has_php_short_echo(b) then return "UPLOAD_PHP_TAG" end
  if has(b, "<jsp:")                          then return "UPLOAD_JSP_TAG" end

  -- PHP superglobals inside file content = almost certainly a webshell
  if has(b, "$_get")    or has(b, "$_post")   or has(b, "$_request")
     or has(b, "$_files") or has(b, "$_server") or has(b, "$_cookie") then
    return "UPLOAD_PHP_SUPERGLOBAL"
  end

  -- ImageMagick MVG / SVG command injection (ImageTragick)
  if has(b, "push graphic-context") then return "UPLOAD_IMAGEMAGICK_MVG" end
  if b:find("<image%s") and has(b, "url%(") then return "UPLOAD_IMAGEMAGICK_URL" end

  return nil
end

-- SP Page Builder unauthenticated arbitrary file upload -> RCE (CVE-2026-48908,
-- the "ANTONKILL" vector, actively exploited 2026-07). The Joomla component
-- com_sppagebuilder exposes asset.upload* tasks (uploadCustomIcon / uploadImage /
-- uploadFont) with NO auth check and NO server-side file-type restriction, so an
-- anonymous POST can drop a webshell. Confirmed in the wild dropping payload.zip
-- (a php webshell inside an icon-pack zip; ClamAV: Win.Trojan.Hide-1).
--
-- Cheap gate FIRST on the component + task (both live in the query string, small)
-- before touching the capped body. Then reuse the hardened upload detectors — the
-- com_sppagebuilder + asset.upload + php-executable-payload triple is near-zero FP
-- (a real icon/image/font upload never carries PHP):
--   PHP_FILENAME — a php-exec multipart filename (rule 401's detector).
--   PHP_IN_ZIP   — a php-exec entry inside the uploaded zip (rule 414's scanner).
--   PHP_CONTENT  — raw php webshell bytes in the upload (rule 402's scanner).
-- Body-budget caveat: a php entry past waf_body_max_len is not visible in-path
-- (ClamAV is the backstop, as it was for the reported payload.zip).
function _M.detect_cve_sppagebuilder_upload(uri, method, args, body, headers)
  if method ~= "post" then return nil end
  local qs = lower((uri or "") .. "&" .. (args or ""))
  if not has(qs, "com_sppagebuilder") then return nil end
  -- the vulnerable asset-upload task family; accept it from the body too, in case
  -- a client sends `task` as a multipart field rather than a query param.
  if not (has(qs, "asset.upload")
          or has(lower(cap(body or "", CFG.max_scan_len)), "asset.upload")) then
    return nil
  end
  if _M.detect_upload_filename(body, headers)   then return "PHP_FILENAME" end
  if _M.detect_upload_archive_php(body, headers) then return "PHP_IN_ZIP" end
  if _M.detect_upload_content(body, headers)     then return "PHP_CONTENT" end
  return nil
end

-- phpfuck / numeric-XOR obfuscation blob detector. Shared by the vBulletin
-- runMaths CVE rule below and the generic obfuscation rule (439). Matches the
-- INVARIANT shape of a PHP payload built to survive an eval() sink that permits
-- only digits and arithmetic/bitwise operators, e.g.
--   ((((999…).(9))^((2).(0).(4)))^((8).(6).(((9).(9))^((9).(9)))))((6).(5))…
-- where each ASCII byte is XOR-built from parenthesised digit literals.
--
-- DESIGN (two adversarial rounds, red-team review 2026-08):
--   Round 1 broke a naive tight `[0-9().^]` contiguous run by interspersing
--   either sink-STRIPPED chars (spaces/letters/commas — deleted by runMaths()
--   and reconstructed for eval()) or sink-ALLOWED no-op operators (`+ * / |`).
--   The first fix (project onto the survivor set, count globally) then
--   FALSE-POSITIVE-BANNED legitimate forum/admin content: projecting away the
--   letters/`;`/whitespace that naturally separate a caret-region from a
--   dot-region merged ordinary code/math into one qualifying run, and global
--   counting summed tokens across unrelated fields.
--
--   The stable design keeps three properties at once:
--   1. Scan the RAW (normalized, NOT projected) input in CONTIGUOUS runs, so
--      letters / `;` / whitespace / commas stay as natural run breakers — this
--      is what keeps ordinary code and math from scoring (their sub-expressions
--      fragment, and identifiers ARE letters).
--   2. Run charset = the phpfuck-constructible subset `[0-9().^]` PLUS the
--      arithmetic/bitwise operators an attacker can insert value-preservingly
--      (`+ - * / |`), so no-op-operator interspersing cannot fragment the
--      payload. `& < > =` are deliberately EXCLUDED (they can't be no-op
--      inserted into a numeric expression, and they delimit real params).
--   3. Require a SINGLE run to carry a storm of ALL THREE tokens — nested
--      parens AND XOR carets AND concatenation dots. Legitimate content never
--      interleaves all three (XOR chains have no dots, float lists have no
--      carets); phpfuck does by construction, at hundreds-of-each scale.
--
--   Accepted residual (documented in WAF_CVE.md): interspersing sink-STRIPPED
--   chars (letters/spaces) still evades — but that payload is, by construction,
--   indistinguishable at request time from a forum code paste (same letters),
--   so closing it re-introduces the FP-ban. This is defence-in-depth; the
--   vBulletin patch is the real fix.
--
-- min_concat is the minimum concatenation-DOT count (not the `).(` triad, which
-- a `).+(` no-op would break).
local function has_phpfuck_blob(s, min_len, min_caret, min_concat)
  if not s or s == "" then return false end
  min_len    = min_len    or 40
  min_caret  = min_caret  or 3
  min_concat = min_concat or 3
  for run in s:gmatch("[0-9%(%)%.%^|%+%*/%-]+") do
    if #run >= min_len then
      local carets = select(2, run:gsub("%^", ""))
      if carets >= min_caret then
        local dots = select(2, run:gsub("%.", ""))
        if dots >= min_concat then
          local parens = select(2, run:gsub("%(", ""))
          if parens >= 10 then
            return true
          end
        end
      end
    end
  end
  return false
end

-- [CVE] vBulletin `runMaths()` unauthenticated remote code execution.
-- CVE-2026-61511 (vBulletin 5.x <= 5.7.5 and 6.x <= 6.2.1; fixed 6.2.2).
-- `vB5_Template_Runtime::runMaths()` strips its input to
-- `[0-9().^<>&|+*/=-]` and passes it straight to `eval("$str = $str;")`. An
-- attacker reaches it UNAUTHENTICATED via the `ajax/render/<template>` route:
-- the default "pagenav" template assigns the user-tainted
-- `pagenav[pagenumber]` to a `{vb:math}` tag, so the value flows to
-- `runMaths()` → `eval()`. Because the sink only permits digits and
-- operators, arbitrary PHP is smuggled with "phpfuck": every character of the
-- target function/argument (`system`, the shell command) is built from XOR
-- (`^`) of parenthesised digit literals. Ref: Egidio Romano / SSD Secure
-- Disclosure advisory KIS-2026-13; public PoC CVE-2026-61511.php
-- (karmainsecurity.com). Signature sourced from the PoC, not from memory.
--
-- Keyed on the ajax/render route (path OR a `routestring=ajax/render` param,
-- both permalink forms) AND a phpfuck-shaped blob in args/body. Either signal
-- alone is weak — the route sees legit paging traffic, and a phpfuck blob is
-- the near-zero-FP half — so the PAIR is what fires. `method` is m_lower from
-- the caller; the PoC POSTs, but vBulletin also routes ajax/render via GET, so
-- both methods are accepted.
--
-- The route gate runs on DECODED surfaces (normalize = url-decode x2 + lower),
-- NOT a raw substring — an earlier raw-`has(...,"routestring=ajax")` pre-gate
-- was bypassable by url-encoding a letter (`routestring=%61jax/render`, which
-- vBulletin still decodes+routes) or the path (`/ajax/%72ender/`). It is also
-- SEGMENT-ANCHORED with the trailing slash (`ajax/render/`): a bare
-- `has(...,"ajax/render")` substring fired on unrelated paths like
-- `/api/ajax/render-widget` or `/js/myajax/renderer`, blocking non-vBulletin
-- sites (red-team review 2026-08). Residual: `cap(...,max_scan_len)` bounds the
-- scan window; a payload padded past it is the codebase's standard bounded-scan
-- limitation (host / ClamAV backstop), shared by every body-aware rule.
function _M.detect_cve_vbulletin_runmaths(uri, method, args, body, headers)
  local u = normalize(uri or "")
  local scope = normalize(cap(args or "", CFG.max_scan_len) .. "&" .. cap(body or "", CFG.max_scan_len))
  if not (has(u, "ajax/render/") or has(scope, "routestring=ajax/render")) then
    return nil
  end
  if has_phpfuck_blob(scope) then
    return "RUNMATHS_RCE"
  end
  return nil
end

-- [top-4c] Obfuscation scorer for raw POST bodies (forms, JSON, text, XML).
-- Catches JS/PHP payload delivery that bypasses detect_b64_injection by using
-- client-side decode (atob+XOR+new Function) instead of PHP-side base64_decode.
-- Multipart uploads are intentionally excluded here; they are covered by the
-- dedicated detect_upload_obfuscation below to keep log tags distinct.
function _M.detect_script_obfuscation(body, headers)
  if not body or body == "" then return nil end

  headers = headers or {}
  local ct = lower(headers["content-type"] or headers["Content-Type"] or "")

  -- Only scan textual / structured body types; skip multipart (handled separately)
  if ct ~= ""
     and not has(ct, "application/x-www-form-urlencoded")
     and not has(ct, "application/json")
     and not has(ct, "text/")
     and not has(ct, "application/xml") then
    return nil
  end

  local s = lower(cap(body, tonumber(CFG.script_obfuscation_max_scan_len) or 8192))
  return score_obfuscation_blob(s, tonumber(CFG.script_obfuscation_min_score) or 6)
end

-- [top-4d] Obfuscation scorer for multipart uploaded file content.
-- Catches obfuscated payloads (e.g. base64+XOR+new Function bundles) uploaded
-- inside plugin/archive slots.  Complements detect_upload_content's byte-exact
-- checks with a scored heuristic path.
function _M.detect_upload_obfuscation(body, headers)
  if not body or body == "" then return nil end

  headers = headers or {}
  local ct = lower(headers["content-type"] or headers["Content-Type"] or "")
  if not has(ct, "multipart/form-data") then return nil end

  local s = lower(cap(body, tonumber(CFG.upload_obfuscation_max_scan_len) or 8192))
  return score_obfuscation_blob(s, tonumber(CFG.upload_obfuscation_min_score) or 6)
end

-- ─────────────────────────────────────────────────────────────────────────────
-- PHASE 1 — webshell delivery + reverse shell + webshell ping (W1 / R1 / B5)
--
-- Landed at logonly per the rollout playbook in docs/waf.md, then promoted on a
-- one-week `cfm webtop waf hit-rates` sample: the webshell drop-path (W1) and
-- ping (B5) rules now ship at `challenge`, and the proper-noun subset of drop
-- names ships at `block` (rule 413). Promote further only on fresh evidence.
-- ─────────────────────────────────────────────────────────────────────────────

-- Webshell drop-name basenames are matched on the URI's final path segment
-- (after the last "/", before "?"), so legitimate paths like
-- `/help/r57.php-explained.html` don't trigger. New entries: append the
-- lowered basename to the appropriate set. Don't include path prefixes
-- (e.g. `/uploads/c99.php` would never match — `c99.php` is what we test).
--
-- The list is split by confidence into two tiers (mirrors the 437/438 split):
--
--   WEBSHELL_NAMES_KNOWN — proper-noun webshell/tool names with essentially
--   zero legitimate use (c99, r57, wso, b374k, indoxploit, p0wny, aspxspy,
--   jspspy, …). A request for one of these at any path is a drop probe.
--   Routed to rule 413 (`rule_webshell_path_known`), block-tier.
--
--   WEBSHELL_NAMES — generic / ambiguous names that are OVERWHELMINGLY attack
--   probes but carry a residual false-positive tail: `adminer.php` (a real DB
--   tool), `alfa.php` (the ALFA shell, but "alfa" is a real word/brand), and
--   short numeric/single-letter names (`1.php`, `x.php`, `a.php`, `shell.php`,
--   `cmd.jsp`) that can be a developer's scratch file. Routed to rule 410
--   (`rule_webshell_path`), challenge-tier. NOTE: WAF_WEBSHELL is a high-risk
--   reason, so this challenge is only recoverable for an as-yet-uncleared
--   client — a client already holding a clearance cookie has its 410 challenge
--   converted to block (post_clearance_action). An automated dropper is stopped
--   either way.
local WEBSHELL_NAMES_KNOWN = {
  ["c99.php"]            = true,
  ["c99shell.php"]       = true,
  ["r57.php"]            = true,
  ["r57shell.php"]       = true,
  ["b374k.php"]          = true,
  ["wso.php"]            = true,
  ["wsoshell.php"]       = true,
  ["ws0.php"]            = true,  -- wso/wso-shell variant, not generic "ws"
  ["webshell.php"]       = true,
  ["minishell.php"]      = true,
  ["p0wny.php"]          = true,
  ["p0wny-shell.php"]    = true,
  ["alfashell.php"]      = true,  -- unambiguous; bare alfa.php is challenge-tier (below)
  ["indoxploit.php"]     = true,
  ["aspxspy.aspx"]       = true,
  ["aspxshell.aspx"]     = true,
  ["jspspy.jsp"]         = true,
  ["jshell.jsp"]         = true,
}

local WEBSHELL_NAMES = {
  ["adminer.php"]        = true,  -- legit DB tool; challenge, never hard-block
  ["alfa.php"]           = true,  -- ALFA TEaM shell, but "alfa" is a real word/brand (Alfa Romeo/Insurance, alpha) → challenge, not block
  ["shell.php"]          = true,
  ["mini.php"]           = true,
  ["ws.php"]             = true,
  ["x.php"]              = true,
  ["xx.php"]             = true,
  ["xxx.php"]            = true,
  ["1.php"]              = true,
  ["2.php"]              = true,
  ["3.php"]              = true,
  ["a.php"]              = true,
  ["cmd.aspx"]           = true,
  ["cmd.jsp"]            = true,
}

-- [W1] Webshell drop path. Returns "PATH:<basename>", is_known on hit; nil on
-- miss. `is_known` is true for the block-tier proper-noun set, false for the
-- ambiguous challenge-tier set — the caller picks the rule id / mode from it.
-- Pure URI inspection — no body, headers, or normalisation beyond lower().
-- Cost: one lower() + a single string.match for the basename + set lookups.
function _M.detect_webshell_path(uri)
  if not uri or uri == "" then return nil end

  -- Strip query and fragment, isolate basename. lower() last so the table
  -- keys can be lowercase only.
  local path = uri:match("^([^?#]+)") or uri
  local base = path:match("([^/]+)$")
  if not base or base == "" then return nil end
  base = lower(base)

  if WEBSHELL_NAMES_KNOWN[base] then
    return "PATH:" .. base, true
  end
  if WEBSHELL_NAMES[base] then
    return "PATH:" .. base, false
  end
  return nil
end

-- REVERSE_SHELL_PATTERNS — literal substrings of well-known reverse-shell
-- one-liners. Each entry is { needle, tag }. The needles are intentionally
-- specific (multi-token) so they don't match prose like "import socket"
-- alone in a forum post body.
--
-- Sources: PayloadsAllTheThings reverse-shell cheatsheet, GTFOBins,
-- HighOn.Coffee one-liners, observed AbuseIPDB samples 2026-04..05.
-- Patterns are deliberately multi-token so they don't fire on prose like
-- "import socket" or "fsockopen(" alone (both common in tutorial pages that
-- get scraped through the proxy). Each entry must contain at least one
-- shell metacharacter or argument that signals invocation, not just the API
-- name.
local REVERSE_SHELL_PATTERNS = {
  -- bash /dev/tcp redirection — "bash -i >& /dev/tcp/host/port" and variants.
  { "bash -i >& /dev/tcp/",                  "BASH_TCP" },
  { "bash -i >&/dev/tcp/",                   "BASH_TCP" },
  { "bash -i &>/dev/tcp/",                   "BASH_TCP" },
  { "exec 196<>/dev/tcp/",                   "BASH_FD_TCP" },
  { "exec 5<>/dev/tcp/",                     "BASH_FD_TCP" },

  -- Plain /dev/tcp redirection (file-descriptor variant); the leading "/"
  -- byte avoids matching prose "dev/tcp" mentions.
  { ">/dev/tcp/",                            "DEV_TCP_REDIR" },
  { "</dev/tcp/",                            "DEV_TCP_REDIR" },

  -- python -c reverse shells. Both quote styles (the proxy also sees URL-
  -- decoded variants thanks to scan_str's double-decode).
  { "python -c 'import socket",              "PY_SOCKET" },
  { 'python -c "import socket',              "PY_SOCKET" },
  { "python3 -c 'import socket",             "PY_SOCKET" },
  { 'python3 -c "import socket',             "PY_SOCKET" },
  { "import pty;pty.spawn",                  "PY_PTY" },

  -- perl / ruby one-liners.
  { "perl -e 'use socket",                   "PERL_SOCKET" },
  { 'perl -e "use socket',                   "PERL_SOCKET" },
  { "ruby -rsocket -e",                      "RUBY_SOCKET" },

  -- netcat / ncat / socat with the invocation flags that turn them into
  -- reverse shells. Bare "nc" is too common to match alone.
  { "nc -e /bin/",                           "NC_EXEC" },
  { "ncat -e /bin/",                         "NCAT_EXEC" },
  { "nc.traditional -e",                     "NC_EXEC" },
  { "socat tcp-connect:",                    "SOCAT_CONNECT" },
  { "socat exec:",                           "SOCAT_EXEC" },
  { "socat openssl-connect:",                "SOCAT_TLS" },

  -- mkfifo named-pipe + reverse-shell trick.
  { "mkfifo /tmp/",                          "MKFIFO_PIPE" },

  -- powershell reverse shell + IEX-WebClient downloader.
  { "iex(new-object net.webclient",                       "PS_IEX_WEBCLIENT" },
  { "$client = new-object system.net.sockets.tcpclient",  "PS_TCPCLIENT" },
}

-- [R1] Reverse-shell payload. Searches uri/args/body for any of the literal
-- one-liners above. Returns the matching tag ("BASH_TCP", "PY_SOCKET", …) or
-- nil. Body is body-capped to CFG.max_scan_len like other detectors.
--
-- Note on FP: a few patterns ("/bin/sh -i", "fsockopen(", "/dev/tcp/")
-- could appear in legitimate documentation/code-paste sites. The detector
-- ships at logonly so the hit-rate sampler quantifies that before any
-- promotion; if a specific tag is noisy it can be removed from the table
-- without renumbering rule_id 322.
function _M.detect_reverse_shell(uri, args, body, _s, _bl)
  -- Combined args+body+uri scan string (already normalised + lowered for
  -- uri/args; body is added raw and lowered here).
  local scan_ua = _s or scan_str(uri, args)

  -- Body inspection: the engine doesn't gate this rule on body_inspect_ok
  -- because reverse-shell strings can also arrive in GET args. When body is
  -- present, fold a capped+lowered slice into the search string. _bl is the
  -- per-request memoized lower(cap(body,max_scan_len)) (audit F59) — five RCE
  -- detectors share it instead of each rebuilding it.
  local s
  if body and body ~= "" then
    s = scan_ua .. " " .. (_bl or lower(cap(body, CFG.max_scan_len)))
  else
    s = scan_ua
  end

  for i = 1, #REVERSE_SHELL_PATTERNS do
    local p = REVERSE_SHELL_PATTERNS[i]
    if has(s, p[1]) then
      return p[2]
    end
  end
  return nil
end

-- Shared helper for the Phase 2 RCE-marker detectors (R2/R3/R4). Builds
-- the same uri+args+body lowered scan string and walks a {needle, tag}
-- table. Kept local because it leaks the body cap policy: we cap body at
-- CFG.max_scan_len (same as detect_reverse_shell) rather than the larger
-- per-detector limits other body scanners use, since the patterns we look
-- for are shell one-liners that fit comfortably in 2 KB.
local function search_rce_markers(uri, args, body, scan_ua, patterns, _bl)
  local s
  if body and body ~= "" then
    s = scan_ua .. " " .. (_bl or lower(cap(body, CFG.max_scan_len)))
  else
    s = scan_ua
  end
  for i = 1, #patterns do
    local p = patterns[i]
    if has(s, p[1]) then
      return p[2]
    end
  end
  return nil
end

-- [R2] Persistence markers — cron/systemd one-liners that an attacker
-- runs once they have RCE to keep their foothold across reboots. Also
-- matches the boundary case where a CGI/admin endpoint receives the
-- persistence payload as a parameter.
local PERSISTENCE_PATTERNS = {
  -- Cron edits. `crontab -l` alone is too benign to flag; the append form
  -- `(crontab -l; echo …) | crontab -` is the persistence shape.
  { "crontab -e",                "CRONTAB_EDIT" },
  { "(crontab -l;",              "CRONTAB_APPEND" },
  { "echo '* * * * *",           "CRON_INLINE" },
  { 'echo "* * * * *',           "CRON_INLINE" },

  -- Cron drop-in directory writes. The `>` redirect is what distinguishes a
  -- write attempt from someone merely mentioning the path in prose.
  { ">/etc/cron.d/",             "CRON_D_DROP" },
  { "> /etc/cron.d/",            "CRON_D_DROP" },
  { ">/etc/cron.hourly/",        "CRON_HOURLY_DROP" },
  { ">/etc/cron.daily/",         "CRON_DAILY_DROP" },
  { ">/var/spool/cron/",         "CRON_SPOOL_DROP" },

  -- Systemd unit files. `[Unit]` + `ExecStart=/` together is the canonical
  -- pair; either alone would be too noisy.
  { "[unit]\nexecstart=/",       "SYSTEMD_UNIT" },
  { "[service]\nexecstart=/",    "SYSTEMD_SERVICE" },

  -- Shell autorun appends. The `>>` shape is what flags the intent —
  -- mere references to ~/.bashrc in docs/articles don't include the
  -- redirection operator.
  { ">> ~/.bashrc",                  "BASHRC_APPEND" },
  { ">> ~/.profile",                 "PROFILE_APPEND" },
  { ">> /etc/profile",               "ETC_PROFILE_APPEND" },
  { ">> /etc/bash.bashrc",           "ETC_BASHRC_APPEND" },

  -- SSH key persistence — the `>>` append form is the attack shape.
  { ">> ~/.ssh/authorized_keys",     "AUTHKEYS_APPEND" },
  { ">> /root/.ssh/authorized_keys", "ROOT_AUTHKEYS_APPEND" },
}

function _M.detect_persistence(uri, args, body, _s, _bl)
  return search_rce_markers(uri, args, body,
    _s or scan_str(uri, args), PERSISTENCE_PATTERNS, _bl)
end

-- [R3] Rootkit / LD_PRELOAD artifacts. LD_PRELOAD by itself appears in
-- legitimate environment debugging (the PHP `extension_dir` topic on
-- Stack Overflow gets crawled), so the patterns require the assignment
-- shape (`LD_PRELOAD=/path/`) or an explicit kernel-module insmod.
local ROOTKIT_PATTERNS = {
  -- LD_PRELOAD as an environment-variable assignment with a path. Bare
  -- `LD_PRELOAD` text alone (e.g. blog post mentioning the variable name)
  -- doesn't fire; the `=/` or `="/` shape is what marks invocation.
  { "ld_preload=/",              "LD_PRELOAD_PATH" },
  { 'ld_preload="/',             "LD_PRELOAD_QUOTED" },
  { ">/etc/ld.so.preload",       "LD_SO_PRELOAD_DROP" },
  { "> /etc/ld.so.preload",      "LD_SO_PRELOAD_DROP" },

  -- Kernel-module insmod from a writable temp/web path. `insmod ./mod.ko`
  -- and bare `modprobe` are intentionally NOT here — too generic. We only
  -- flag insmod targets pointing at /tmp / /var/tmp / /dev/shm.
  { "insmod /tmp/",              "INSMOD_TMP" },
  { "insmod /var/tmp/",          "INSMOD_VAR_TMP" },
  { "insmod /dev/shm/",          "INSMOD_DEV_SHM" },

  -- Direct memory devices — extremely strong indicator. Any HTTP request
  -- that mentions /dev/mem or /dev/kmem inside command-execution context
  -- is overwhelmingly an exploit attempt.
  { "/dev/mem",                  "DEV_MEM_ACCESS" },
  { "/dev/kmem",                 "DEV_KMEM_ACCESS" },
}

function _M.detect_rootkit_artifacts(uri, args, body, _s, _bl)
  return search_rce_markers(uri, args, body,
    _s or scan_str(uri, args), ROOTKIT_PATTERNS, _bl)
end

-- [R4] Living-off-the-land binaries. Trimmed to avoid overlap with R1's
-- REVERSE_SHELL table — we deliberately do NOT include `iex(new-object`,
-- TcpClient, or socat, because those already fire under rule 322 and
-- double-counting wastes hit-rate slots. R4 covers the *download* /
-- *encoded-command* side of post-exploitation, R1 covers the shell.
local LOLBIN_PATTERNS = {
  -- Windows certutil / bitsadmin downloaders. Both are classic LOLbins —
  -- legitimate but rarely seen in HTTP traffic body content.
  { "certutil -urlcache -split", "CERTUTIL_URLCACHE" },
  { "certutil.exe -urlcache",    "CERTUTIL_URLCACHE" },
  { "bitsadmin /transfer",       "BITSADMIN_TRANSFER" },
  { "bitsadmin.exe /transfer",   "BITSADMIN_TRANSFER" },

  -- Powershell encoded command + IEX webrequest variants not in R1.
  -- `-enc ` short form is intentionally NOT here — three-char flag has too
  -- many false-positive substring matches; the spelled-out form is fine.
  { "-encodedcommand ",          "PS_ENCODED_CMD" },
  { "iex(iwr ",                  "PS_IEX_IWR" },
  { "iex(invoke-webrequest",     "PS_IEX_IWR" },
  { ".downloadstring(",          "PS_DOWNLOAD_STRING" },
  { ".downloadfile(",            "PS_DOWNLOAD_FILE" },

  -- Linux LOLbin downloaders dropping into world-writable paths. Bare
  -- `wget http://` is too noisy (legit content links); the `-o /tmp/` /
  -- `-O /tmp/` shape is what marks dropper intent.
  { "wget -o /tmp/",             "WGET_TMP_DROP" },
  { "wget --output-document=/tmp/", "WGET_TMP_DROP" },
  { "curl -o /tmp/",             "CURL_TMP_DROP" },
  { "curl --output /tmp/",       "CURL_TMP_DROP" },
}

function _M.detect_lolbin(uri, args, body, _s, _bl)
  return search_rce_markers(uri, args, body,
    _s or scan_str(uri, args), LOLBIN_PATTERNS, _bl)
end

-- [C2] Java ObjectOutputStream deserialization. Three wire-form variants:
--
--   1. Raw bytes 0xAC 0xED 0x00 0x05 anywhere in the body. This is the
--      JVM's STREAM_MAGIC + STREAM_VERSION pair, prepended to every Java
--      serialized object stream. Match is plain-byte (no normalize) so we
--      catch binary uploads / multipart parts that include them.
--   2. Base64 prefix "rO0AB" (case-insensitive). Encoding 0xAC 0xED 0x00
--      0x05 followed by any byte yields a stream that always starts with
--      these five chars; six-byte prefix "rO0ABXNyA" / "rO0ABXcE" are
--      common but the stable five-char form is what we match. Wide enough
--      to catch all gadget chains, narrow enough to make accidental match
--      against random base64 payloads negligible.
--   3. Hex literal "aced0005" (case-insensitive). Less common in attack
--      traffic but appears in pen-test write-ups and in some debug-logging
--      reflections that get reposted into vulnerable forms.
--
-- Distinct from PHP serialize (rule 306) which detects O:N:"ClassName":N:{
-- markers; the two formats share zero bytes so neither rule shadows the
-- other. Family WAF_RCE so the rule shares post-clearance escalation.
function _M.detect_java_deserialize(headers, args, body)
  -- Java-serialization markers are whole VALUES — a query/body parameter
  -- value, or a Cookie/Authorization/XFF token — so the magic sits at the
  -- start of the scanned string or right after a non-base64 separator
  -- (`=`, `"`, `'`, `:`, `,`, `[`, `{`, `;`, whitespace, ...). A long
  -- base64url token can contain the prefix mid-string by chance; the
  -- canonical case is a Facebook click id on e-shop ad traffic
  -- (`fbclid=...VrO0ABr5e...`), which challenged a real shopper arriving
  -- from a paid ad. Anchoring to a value boundary kills that false positive
  -- while keeping every real gadget delivery (the blob IS the value).
  -- base64/base64url continuation chars are A-Za-z0-9 + / - _  — note `=`
  -- is padding/separator, NOT a continuation, so it counts as a boundary.
  local function at_boundary(s, needle)
    if s:sub(1, #needle) == needle then return true end       -- value start
    return s:find("[^%w+/_-]" .. needle) ~= nil               -- after a separator
  end
  local function check_text(s)
    if not s or s == "" then return nil end
    -- B64 prefix matched case-SENSITIVELY: base64 of AC ED 00 05 is always
    -- exactly "rO0AB"; a case-insensitive substring match was the other half
    -- of the fbclid FP. Hex prefix stays case-insensitive (hex literals vary).
    if at_boundary(s, "rO0AB")           then return "B64_PREFIX" end
    if at_boundary(lower(s), "aced0005") then return "HEX_PREFIX" end
    return nil
  end

  -- args arrives raw (ngx.var.args — URL-encoded, original case); check_text
  -- handles case per-branch (case-sensitive base64, lowered hex). The base64
  -- magic is offset-0 in a real serialized value, so it survives URL-encoding
  -- of the surrounding query without needing a decode pass here.
  local t = check_text(args)
  if t then return t end

  -- Body: raw 4-byte magic match first (cheaper, no normalize), then
  -- text-form fallback for base64 / hex deliveries.
  if body and body ~= "" then
    if string.find(body, "\xac\xed\x00\x05", 1, true) then
      return "RAW_MAGIC"
    end
    t = check_text(body)
    if t then return t end
  end

  -- Common header injection vectors for Java deserialize gadgets — both
  -- Cookie (session-replay attacks) and Authorization (Vaadin-style token
  -- bombs) are the typical entry points; X-Forwarded-For is occasionally
  -- abused when an upstream parses the value into a Java object.
  if headers then
    local cookie = header_string(headers["cookie"] or headers["Cookie"])
    t = check_text(cookie); if t then return t end

    local auth = header_string(headers["authorization"] or headers["Authorization"])
    t = check_text(auth); if t then return t end

    local xff = header_string(headers["x-forwarded-for"] or headers["X-Forwarded-For"])
    t = check_text(xff); if t then return t end
  end

  return nil
end

-- [B5] Webshell ping fingerprint — POST + empty/missing UA + Content-Length:0
-- + URI ending in .php / .phtml / .phar. The combination is what makes this
-- low-FP: any one signal alone is common (legit POST forms, monitoring HEAD
-- pings with empty UA, browser preflights with CL:0); all four together is
-- a pattern operators see in webshell C2 channels keeping their drop alive.
--
-- Returns "PING" on hit, nil otherwise. Single tag — there's no sub-pattern
-- to distinguish.
function _M.detect_webshell_ping(method, headers, uri)
  if lower(method or "") ~= "post" then return nil end

  headers = headers or {}

  -- Empty / missing UA — header_string normalises array headers (some
  -- bridges hand them over as tables) into a single string.
  local ua = header_string(headers["user-agent"] or headers["User-Agent"])
  if ua and ua ~= "" then
    -- Whitespace-only UA also counts as empty.
    if ua:find("%S") then return nil end
  end

  -- Content-Length: 0. Accept the literal "0"; reject anything else
  -- including missing CL (chunked POSTs are not the C2 fingerprint).
  local cl = header_string(headers["content-length"] or headers["Content-Length"])
  if cl ~= "0" then return nil end

  -- URI ends in .php / .phtml / .phar (path component, not query).
  local path = (uri or ""):match("^([^?#]+)") or uri or ""
  path = lower(path)
  if not (path:sub(-4) == ".php"
       or path:sub(-6) == ".phtml"
       or path:sub(-5) == ".phar") then
    return nil
  end

  return "PING"
end

-- ─────────────────────────────────────────────────────────────────────────────
-- PHASE 4 — C2 / EXFILTRATION (X1, X2)
-- ─────────────────────────────────────────────────────────────────────────────

-- C2_TUNNEL_HOSTS — hostnames known to be popular for attacker exfil and
-- payload-hosting (paste services with raw-content URLs, request-bin /
-- webhook services, free tunnel/relay services, ephemeral file hosts).
-- Matched against the lower-cased, normalised args+body (get_norm_ab in
-- cfm_waf.lua), anchored on a LEFT host boundary — see detect_c2_tunnel.
--
-- Operators on shared hosting may host pastebin clones legitimately — hence
-- specific noisy entries can be removed without renumbering rule_id 702.
local C2_TUNNEL_HOSTS = {
  -- Paste services with raw-content endpoints
  { "pastebin.com/raw/",        "PASTEBIN_RAW" },
  { "paste.ee/r/",              "PASTE_EE" },
  { "dpaste.com/",              "DPASTE" },
  { "rentry.co/",               "RENTRY" },
  { "0x0.st/",                  "0X0_ST" },
  { "transfer.sh/",             "TRANSFER_SH" },
  { "controlc.com/",            "CONTROLC" },
  { "ix.io/",                   "IX_IO" },

  -- Code-host raw content (gist / github raw URLs are heavily abused)
  { "gist.githubusercontent.com/", "GIST_RAW" },
  { "raw.githubusercontent.com/",  "GITHUB_RAW" },

  -- Request-bin / webhook services
  { "webhook.site/",            "WEBHOOK_SITE" },
  { "requestbin.net/",          "REQUESTBIN" },
  { "pipedream.com/",           "PIPEDREAM" },

  -- Tunneling / relay services
  { "ngrok.io/",                "NGROK" },
  { "ngrok-free.app/",          "NGROK" },
  { "trycloudflare.com/",       "CLOUDFLARE_TUNNEL" },
  { "loca.lt/",                 "LOCALTUNNEL" },
  { "serveo.net/",              "SERVEO" },

  -- Discord/Telegram CDN URLs frequently host malicious payloads
  { "cdn.discordapp.com/attachments/", "DISCORD_CDN" },
  { "media.discordapp.net/attachments/", "DISCORD_CDN" },
  { "api.telegram.org/bot",     "TELEGRAM_BOT" },
}

-- Precompute a LEFT-boundary-anchored pattern for each host token. A plain
-- substring match had no left edge, so a short token like "ix.io/" matched any
-- longer hostname ending in it — "matrix.io/", "phoenix.io/" — tagging benign
-- traffic as C2 (audit F36; rule 702 is at `challenge`, so those were real
-- user-facing false positives, not just log noise). `%f[%w]` requires the char
-- before the host to be a non-word char (URL host starts are always preceded by
-- `//`, `.`, `@`, `/`, a delimiter, or the string start — never an alphanumeric
-- that would make the label part of a longer name), so no real C2 URL is lost.
-- Pattern magic in the tokens (`.`, `-`) is escaped.
for i = 1, #C2_TUNNEL_HOSTS do
  local esc = C2_TUNNEL_HOSTS[i][1]:gsub("[%(%)%.%%%+%-%*%?%[%]%^%$]", "%%%0")
  C2_TUNNEL_HOSTS[i][3] = "%f[%w]" .. esc
end

function _M.detect_c2_tunnel(args, body, _ns)
  local s = _ns or normalize(cap(args or "", CFG.max_scan_len) .. "&" .. cap(body or "", CFG.max_scan_len))
  if s == "" then return nil end

  for i = 1, #C2_TUNNEL_HOSTS do
    local p = C2_TUNNEL_HOSTS[i]
    -- Cheap plain-substring precheck (fast path) before the boundary pattern:
    -- the token must be present at all, and only then do we pay for the frontier
    -- match that rejects longer-hostname suffixes (matrix.io/ vs ix.io/).
    if has(s, p[1]) and string.find(s, p[3], 1, false) then
      return p[2]
    end
  end
  return nil
end

-- COINMINER_PATTERNS — multi-token patterns specific to crypto-mining
-- malware. Bare protocol scheme (stratum+tcp://) is intentionally NOT
-- here — it's already in detect_ssrf_proto (rule 701) per the X2/rule-701
-- design call recorded in docs/waf.md row 16.
local COINMINER_PATTERNS = {
  -- xmrig invocation flags. Multi-token pairs reduce FP risk vs. matching
  -- "xmrig" alone (which appears in security-research articles).
  { "xmrig --url",        "XMRIG_URL" },
  { "xmrig -o ",          "XMRIG_O" },
  { "xmrig --pool",       "XMRIG_POOL" },
  { "xmr-stak --url",     "XMRSTAK_URL" },
  { "xmr-stak -o ",       "XMRSTAK_O" },

  -- Public XMR pool hostnames. These are the long-running "free pool"
  -- endpoints that repeatedly show up in compromised-host telemetry.
  { "pool.minexmr.com",   "POOL_MINEXMR" },
  { "supportxmr.com",     "POOL_SUPPORTXMR" },
  { "xmrpool.eu",         "POOL_XMRPOOL_EU" },
  { "moneroocean.stream", "POOL_MONEROOCEAN" },
  { "nanopool.org",       "POOL_NANOPOOL" },
  { "fr.minexmr.com",     "POOL_MINEXMR" },

  -- Generic miner control daemon names + binary fetch markers.
  { "monerod -p ",        "MONEROD" },
  { "ethminer --pool",    "ETHMINER" },
}

function _M.detect_coinminer(uri, args, body, _s, _bl)
  return search_rce_markers(uri, args, body,
    _s or scan_str(uri, args), COINMINER_PATTERNS, _bl)
end

-- ─────────────────────────────────────────────────────────────────────────────
-- PHASE 5 — BEHAVIOURAL / COMBINED-SIGNAL (B1, B3, B4)
-- ─────────────────────────────────────────────────────────────────────────────

-- [B1] HTTP smuggling header pairs. Operates on header presence/value
-- shape, NOT on body bytes — keeps the rule independent of the cfm body
-- cap (a body that's too large to buffer locally would trip false rules
-- if we tried to do byte-level CL/body-length comparison).
--
-- Returns:
--   "CL_AND_TE"     — both Content-Length and Transfer-Encoding present.
--                     RFC 7230 §3.3.3 forbids this combination; it's the
--                     classic CL.TE smuggling primitive.
--   "MULTI_CL"      — two Content-Length header lines. ngx.req.get_headers()
--                     returns duplicate headers as a Lua ARRAY (it does NOT
--                     comma-join them), so a table value trips this directly;
--                     a single value that itself contains a comma ("5, 10")
--                     also does. Two CL values means two parsers can disagree.
--   "MULTI_TE"      — two Transfer-Encoding header lines (array value), OR a
--                     single Transfer-Encoding value whose comma-list contains
--                     "chunked" but does not END in it (e.g. "chunked, identity"
--                     smuggles; "gzip, chunked" is a valid chained encoding).
--   "CL_MALFORMED"  — Content-Length value isn't a non-negative integer.
function _M.detect_smuggling_cl(headers)
  if not headers then return nil end

  -- Keep the RAW values: a DUPLICATE header line arrives from
  -- ngx.req.get_headers() as a Lua array (e.g. {"5","10"}), NOT a comma-joined
  -- string. header_string() collapses that to the first element, so the
  -- comma-based MULTI_* checks below can never see the second value — genuine
  -- duplicate CL/TE lines were silently missed. Guard on the table shape first,
  -- mirroring detect_range_abuse's MULTI_RANGE_HEADER handling (audit F37).
  local cl_raw = headers["content-length"] or headers["Content-Length"]
  local te_raw = headers["transfer-encoding"] or headers["Transfer-Encoding"]
  local cl = header_string(cl_raw)
  local te = header_string(te_raw)

  -- Both present → classic CL.TE smuggling primitive (RFC 7230 §3.3.3), the
  -- strongest signal — check before the per-header duplicate/value shapes.
  if cl ~= "" and te ~= "" then
    return "CL_AND_TE"
  end

  -- Two CL / two TE lines (array value) — a front/back-end parser disagreement
  -- primitive that header_string() would otherwise hide.
  if type(cl_raw) == "table" then return "MULTI_CL" end
  if type(te_raw) == "table" then return "MULTI_TE" end

  if cl ~= "" then
    if has(cl, ",") then
      return "MULTI_CL"
    end
    -- Strict integer parse: must be all digits, non-empty, non-negative.
    if not cl:match("^%d+$") then
      return "CL_MALFORMED"
    end
  end

  if te ~= "" then
    -- "gzip, chunked" / "chunked" / "identity" are valid. Multiple values
    -- with chunked NOT in the last position are a classic smuggling shape.
    local te_low = lower(te)
    if has(te_low, ",") then
      -- Allow "gzip, chunked" / "deflate, chunked" / "identity" — only
      -- flag when chunked appears but isn't the final element.
      local last = te_low:match("([^,%s]+)%s*$")
      if last and last ~= "chunked" and has(te_low, "chunked") then
        return "MULTI_TE"
      end
    end
  end

  return nil
end

-- [B3] Long URL path segment. "Path segment" = substring between two `/`
-- in the URI's path component (query/fragment stripped first). Threshold
-- is 800 bytes: WordPress / Joomla shops with UTF-8 (especially Greek /
-- Cyrillic / CJK) product slugs URL-encode each character to 6-9 bytes,
-- so a single legitimate Greek product title routinely lands in the
-- 300-700 byte range (e.g. SEG_603 on news1.gr, SEG_319 on nitromag.gr).
-- Real abuse on the same surface is base64-stuffed redirect paths well
-- past 1 KB. Threshold therefore sits above legitimate UTF-8 slugs and
-- below all observed scanner payloads. Returns "SEG_<len>".
local LONG_PATH_THRESHOLD = 800

-- A path that carries a data: URI artifact is a template bug, not an
-- attack. Three known sources from the 2026-05-13..16 FP audit:
--   * Bricks Builder (WP) injects `<script src="data:text/javascript,...">`
--     and Facebook's OG-preview crawler dereferences it as a relative URL
--     (52 hits on mobian.eu, 11 on www.ezbeauty.gr).
--   * SP Page Builder slick_carousel (Joomla) emits an unquoted
--     `url(data:image/svg+xml;base64,...)` in a CSS rule, so the browser
--     resolves it relative to the stylesheet (saneco.gr).
--   * `<img src="image/jpeg;base64,...">` (data: prefix omitted by a
--     broken template) — single Greek visitor on tehni.eu hit it 10x in
--     one session.
-- The check is path-wide (not per-segment) because base64 payloads
-- contain `/` and the URI parser splits them into many short segments
-- followed by one extremely long one — the trailing chunk has no
-- contextual marker of its own. Two markers cover every observed FP:
--   1. literal `data:<type>/<subtype>` followed by `,` or `;`
--   2. literal `;base64,` somewhere in the path
-- Neither token is needed by a real attacker to deliver a payload:
-- other detectors (RCE, traversal, SQLi, base64 obfuscation scorer)
-- still inspect the path content irrespective of LONG_PATH.
local function path_has_data_uri_artifact(path)
  -- Defensive case-fold: every real-world FP in 2026-05 logs was
  -- lowercase, but case-folding is cheap on the slow path (this rule
  -- only matters for paths approaching LONG_PATH_THRESHOLD) and
  -- future-proofs against templates that emit `Data:` or `DATA:`.
  local lp = string.lower(path)
  if string.find(lp, ";base64,", 1, true) then return true end
  if string.find(lp, "data:[%w][%w.+-]*/[%w][%w.+-]*[,;]", 1, false) then return true end
  return false
end

function _M.detect_long_path_segment(uri)
  if not uri or uri == "" then return nil end

  local path = uri:match("^([^?#]+)") or uri
  if path_has_data_uri_artifact(path) then return nil end

  local max_len = 0
  for seg in path:gmatch("[^/]+") do
    local n = #seg
    if n > max_len then max_len = n end
  end

  if max_len >= LONG_PATH_THRESHOLD then
    return "SEG_" .. max_len
  end
  return nil
end

-- [B4] Header bag flood. Sums header byte volume excluding Cookie /
-- Authorization (those are session-state, frequently legit-large on
-- shared hosting with WordPress / cPanel sessions). Anything > 16 KB
-- in the remainder is well above legit traffic — typical request headers
-- are 1-3 KB total.
--
-- Returns "FLOOD:<bytes>" — the value is the non-session header total.
local HEADER_FLOOD_THRESHOLD = 16 * 1024  -- 16 KB

function _M.detect_header_flood(headers)
  if not headers then return nil end

  local total = 0
  for k, v in pairs(headers) do
    local kl = lower(k)
    if kl ~= "cookie" and kl ~= "authorization" then
      local v_str = header_string(v)
      -- Approximate "Key: Value\r\n" wire size; close enough for a threshold.
      total = total + #k + #v_str + 4
    end
  end

  if total >= HEADER_FLOOD_THRESHOLD then
    return "FLOOD:" .. total
  end
  return nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- PHASE 1 — W4 POLYGLOT UPLOAD
-- ─────────────────────────────────────────────────────────────────────────────

-- POLYGLOT_OPENERS — first-bytes signatures that mark a "claimed image"
-- part as actually executable. Order matters: more-specific tags first
-- (`<%@` before `<%`, `<?php` before `<?`).
local POLYGLOT_OPENERS = {
  { "<?php",   "POLYGLOT_PHP" },
  { "<?=",     "POLYGLOT_PHP_SHORT" },
  { "<%@",     "POLYGLOT_JSP_DIRECTIVE" },
  { "<jsp:",   "POLYGLOT_JSP" },
  { "<%",      "POLYGLOT_ASP" },
  { "<script", "POLYGLOT_SCRIPT" },
}

-- Image extensions that, combined with PHP/ASP/JSP/script content, mark
-- a polyglot upload. Matched as suffixes on the lowered filename.
local POLYGLOT_IMAGE_EXTS = {
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".ico", ".tif", ".tiff",
}

-- [W4] Polyglot upload — image-claimed multipart part whose payload starts
-- with an executable opener. Distinct from rule 402 (detect_upload_content)
-- which substring-scans the entire raw body: this rule parses parts and
-- bounds the executable-opener check to the first 64 bytes of payload, so
-- legitimate form fields containing PHP code samples can't trigger.
--
-- Returns "POLYGLOT_<TYPE>" on hit, nil on miss. Same family as rule 402
-- (WAF_UPLOAD_CONTENT — already in WAF_HIGH_RISK_REASONS).
function _M.detect_polyglot_upload(body, headers)
  if not body or body == "" then return nil end

  headers = headers or {}
  -- Boundary tokens are case-sensitive (RFC 2046 §5.1.1) — extract from the
  -- original header value, not a lowered copy. Only the multipart/form-data
  -- check itself is case-insensitive.
  local ct_raw = headers["content-type"] or headers["Content-Type"] or ""
  if not has(lower(ct_raw), "multipart/form-data") then return nil end

  local boundary = ct_raw:match("[Bb][Oo][Uu][Nn][Dd][Aa][Rr][Yy]=([^;%s]+)")
  if not boundary then return nil end
  boundary = boundary:gsub('^"', ''):gsub('"$', '')
  if boundary == "" then return nil end

  local sep = "--" .. boundary

  -- Bound the part-walk to a safe iteration cap so a malformed body can't
  -- spin the loop. Legit multipart uploads almost always have <10 parts.
  local pos = 1
  local iter_cap = 64
  local iter = 0

  while iter < iter_cap do
    iter = iter + 1

    local sep_at = body:find(sep, pos, true)
    if not sep_at then break end

    local hdr_start = sep_at + #sep
    -- "--<boundary>--" marks end of multipart; stop walking.
    if body:sub(hdr_start, hdr_start + 1) == "--" then break end
    -- Skip the CRLF (or bare LF) that follows the boundary.
    if body:sub(hdr_start, hdr_start + 1) == "\r\n" then
      hdr_start = hdr_start + 2
    elseif body:sub(hdr_start, hdr_start) == "\n" then
      hdr_start = hdr_start + 1
    end

    -- Find header/payload split (blank line). Try CRLF first, then LF.
    local split_at = body:find("\r\n\r\n", hdr_start, true)
    local split_skip = 4
    if not split_at then
      split_at = body:find("\n\n", hdr_start, true)
      split_skip = 2
    end
    if not split_at then break end

    local part_headers = body:sub(hdr_start, split_at - 1)
    local payload_start = split_at + split_skip
    -- Only look at the first 64 bytes of payload; image polyglots that
    -- wrap a PHP shell put the opener at the very start of the file so
    -- that PHP's parser sees it before the rest of the "image" data.
    local payload = body:sub(payload_start, payload_start + 63)

    -- Decide if this part is image-claimed: either Content-Type: image/*
    -- in the part headers, or a filename ending in a known image extension.
    local part_ct = lower(part_headers:match("[Cc]ontent%-[Tt]ype:%s*([^\r\n]+)") or "")
    local is_image_ct = has(part_ct, "image/")

    local fname = part_headers:match('[Ff]ilename%s*=%s*"([^"]+)"')
                  or part_headers:match("[Ff]ilename%s*=%s*'([^']+)'")
                  or part_headers:match("[Ff]ilename%s*=%s*([^%s;\"'][^%s;\"']*)")
                  or ""
    local fname_low = lower(fname)
    local is_image_ext = false
    if fname_low ~= "" then
      for i = 1, #POLYGLOT_IMAGE_EXTS do
        local ext = POLYGLOT_IMAGE_EXTS[i]
        if fname_low:sub(-#ext) == ext then
          is_image_ext = true
          break
        end
      end
    end

    if is_image_ct or is_image_ext then
      local p_low = lower(payload)
      for i = 1, #POLYGLOT_OPENERS do
        local opener = POLYGLOT_OPENERS[i]
        if has(p_low, opener[1]) then
          return opener[2]
        end
      end
    end

    -- Advance past this part for the next iteration.
    pos = payload_start
  end

  return nil
end

-- ─────────────────────────────────────────────────────────────────────────────
-- DDoS / SLOW-HTTP HARDENING — Range / Request-Range header abuse
-- ─────────────────────────────────────────────────────────────────────────────
-- Apache Killer (CVE-2011-3192) and follow-on tools (slowhttptest range
-- mode, RangeAmp variants) abuse the Range header by stuffing dozens or
-- hundreds of byte-ranges into a single request to force the upstream to
-- buffer/compute many overlapping body slices. Real clients send one Range
-- header with one byte-range (resume / video chunk); two ranges is already
-- rare. Double-digit ranges have no legitimate web use.
--
-- The legacy `Request-Range:` header is a Netscape-era variant deprecated
-- in HTTP/1.1; modern UAs do not emit it but some exploit kits / scanners
-- still set it to bypass naive Range:-only filters.
--
-- Logonly rollout per the standard playbook — we want a week of production
-- data to confirm that no upload accelerator, video player or CDN edge in
-- our footprint sends >= 8 ranges before we promote.
function _M.detect_range_abuse(headers)
  headers = headers or {}

  -- 1) Legacy Request-Range header. Deprecated for decades; not emitted
  --    by any modern browser, fetch library, CDN or media player. Presence
  --    alone is sufficient.
  if headers["request-range"] or headers["Request-Range"] then
    return "REQUEST_RANGE_HEADER"
  end

  local r = headers["range"] or headers["Range"]
  if not r then return nil end

  -- 2) Multiple Range: headers in one request. RFC 7233 expects a single
  --    Range header; duplicate Range: lines are an HTTP-level oddity used
  --    by some smuggling / WAF-bypass probes.
  if type(r) == "table" then
    return "MULTI_RANGE_HEADER"
  end

  if type(r) ~= "string" or r == "" then return nil end

  -- 3) Oversized Range value. Apache Killer payloads run into kilobytes;
  --    legitimate Range values are under ~64 bytes. 512 is a generous cap.
  if #r > 512 then
    return "RANGE_OVERSIZED:" .. tostring(#r)
  end

  -- 4) Many byte-ranges in a single header (Apache Killer signature).
  --    Count commas; the range count is commas + 1. Flag at >= 8 ranges
  --    (7 commas) — real clients send 1, occasionally 2.
  local commas = count_occurs(r, ",")
  if commas >= 7 then
    return "MANY_RANGES:" .. tostring(commas + 1)
  end

  return nil
end

-- Log4Shell (CVE-2021-44228) evasion-variant detector. rule_rce (320) already
-- catches the bare "${jndi:" / "${j{n{d{i" / URL-encoded forms. This rule
-- covers the JNDI-lookup syntax tricks that defeat naive substring matching:
--
--   * Default-value evasion:  ${${::-j}${::-n}${::-d}${::-i}:ldap://...}
--   * Case-conversion:        ${lower:jndi}, ${upper:J}ndi
--   * Property expansion:     ${env:FOO:-j}ndi, ${sys:X}, ${main:Y}, ${date:Z}
--   * Base64 wrap:            ${base64:...}
--   * Generic nesting marker: "${${" — multi-layer lookups never appear in
--                             legitimate request data
--
-- Scans the same normalized args+body buffer the other body-aware rules use,
-- plus every header value (Log4j-vulnerable apps logged UA / Referer /
-- X-Forwarded-For / Authorization). Cheap precheck: skip the header walk
-- when no "${" appears anywhere.
-- FP-risk note: the NESTED ("${${") and ENV/SYS/MAIN/DATE/BASE64 tags can
-- collide with legitimate template-engine syntax. The biggest concrete
-- offender is **Apache Commons Configuration2** (widely deployed under
-- Spring Boot / Apache Camel), which ships EnvironmentLookup, Systems-
-- PropertiesLookup, DateLookup, Base64DecoderLookup and exposes them
-- with EXACTLY the same `${env:VAR}` / `${sys:user.home}` / `${date:yyyy}`
-- / `${base64:...}` prefix syntax as Log4j JNDI lookups. Java apps that
-- render their own pages via Commons Configuration WILL emit these strings
-- in form posts.
--
-- ${${ is also rare-but-non-zero in legitimate output: AngularJS `ng-bind`
-- attribute strings, some Vue SFCs, and Prettier-formatted JavaScript
-- template literals can produce `${${expr}.field}`-shaped tokens.
--
-- Rolling out at logonly so the operator can grep cfm.waf.log for
-- "WAF_CVE:LOG4SHELL:NESTED" / ":ENV" / ":SYS" / ":MAIN" / ":DATE" /
-- ":BASE64" before promotion and add per-vhost exclusions for affected
-- apps. See docs/waf.md "Operating the WAF" for the playbook.
function _M.detect_log4shell(args, body, headers, _norm_ab)
  local s = _norm_ab or normalize(cap(args or "", CFG.max_scan_len) .. "&" .. cap(body or "", CFG.max_scan_len))

  -- Single cheap precheck on the (potentially 32 KB) scan buffer. The
  -- dominant case is "no '${' anywhere" → one find() returns nil and we
  -- fall through to the header walk. Without this gate we'd run 10
  -- linear scans on every request.
  if has(s, "${") then
    if has(s, "${jndi:")     then return "JNDI"        end
    if has(s, "${${")        then return "NESTED"      end
    if has(s, "${::-")       then return "DEFAULT_VAL" end
    if has(s, "${lower:")    then return "LOWER"       end
    if has(s, "${upper:")    then return "UPPER"       end
    if has(s, "${env:")      then return "ENV"         end
    if has(s, "${sys:")      then return "SYS"         end
    if has(s, "${main:")     then return "MAIN"        end
    if has(s, "${date:")     then return "DATE"        end
    if has(s, "${base64:")   then return "BASE64"      end
  end

  -- Header walk: Log4Shell historically arrived in User-Agent, X-Forwarded-
  -- For, Referer, Authorization, X-Api-Version, Cookie, etc. Precheck with
  -- the plain "${" needle on the raw value before allocating a url_decode.
  --
  -- Note: this path runs ONE url_decode_once pass vs. normalize()'s two.
  -- A doubly-encoded payload in a header (%2524%257bjndi:) slips past
  -- here but is caught by the body/args path above (normalize double-
  -- decodes). Real-world Log4Shell campaigns didn't double-encode
  -- headers, so the asymmetry is acceptable.
  if type(headers) == "table" then
    for hname, hval in pairs(headers) do
      local raw = header_string(hval)
      -- Precheck for a "${" that url_decode_once could reveal, in EVERY
      -- single-`%xx`-encoded adjacency form, so the gate stays consistent with
      -- the decode+match below (which flags anything that one-pass-decodes to a
      -- ${...} lookup). `$` is literal or %24; `{` is literal, %7b or %7B
      -- (url_decode_once handles either hex case) — six raw forms, covered by
      -- four plain needles (F35):
      --   ${      both literal
      --   %24%7   both encoded          (matches %24%7b / %24%7B)
      --   %24{    $ encoded, { literal
      --   $%7     $ literal, { encoded  (matches $%7b / $%7B)
      -- Plain substring finds (no per-header lowercase allocation on the hot
      -- path). The decode+match still decides the actual hit, so the loose
      -- needles (%24%7c…, $%70…) that gate-pass but don't decode to a lookup add
      -- NO false positive. Double-encoded (%2524%257b…) and %u007b forms don't
      -- one-pass-decode to "${" and remain the documented args/body-normalize
      -- asymmetry.
      if raw ~= "" and (raw:find("${", 1, true)
                        or raw:find("%24%7", 1, true)
                        or raw:find("%24{", 1, true)
                        or raw:find("$%7", 1, true)) then
        local h = lower(url_decode_once(raw))
        if     has(h, "${jndi:")   then return "JNDI:HDR:"   .. tostring(hname):sub(1, 32)
        elseif has(h, "${${")      then return "NESTED:HDR:" .. tostring(hname):sub(1, 32)
        elseif has(h, "${::-")     then return "DEFAULT_VAL:HDR:" .. tostring(hname):sub(1, 32)
        elseif has(h, "${lower:")  then return "LOWER:HDR:"  .. tostring(hname):sub(1, 32)
        elseif has(h, "${upper:")  then return "UPPER:HDR:"  .. tostring(hname):sub(1, 32)
        elseif has(h, "${env:")    then return "ENV:HDR:"    .. tostring(hname):sub(1, 32)
        elseif has(h, "${sys:")    then return "SYS:HDR:"    .. tostring(hname):sub(1, 32)
        elseif has(h, "${main:")   then return "MAIN:HDR:"   .. tostring(hname):sub(1, 32)
        elseif has(h, "${date:")   then return "DATE:HDR:"   .. tostring(hname):sub(1, 32)
        elseif has(h, "${base64:") then return "BASE64:HDR:" .. tostring(hname):sub(1, 32)
        end
      end
    end
  end

  return nil
end

-- Bad UTF-8 encoding detector. Port of Coraza's validateUtf8Encoding operator
-- (corazawaf/coraza internal/operators/validate_utf8_encoding.go). Malformed
-- UTF-8 that survives the normalize() pipeline is an encoding-bypass primitive:
-- overlong sequences encode ASCII (".", "/") in 2-4 bytes that the WAF's
-- substring matchers miss but the downstream app may decode back to ASCII.
--
-- Flags on the first invalid sequence:
--   * UTF8_BAD_LEAD     — high-bit byte that isn't a valid leading byte
--   * UTF8_TRUNC        — leading byte indicating N continuations but < N follow
--   * UTF8_BAD_CONT     — non-continuation byte (not 0x80..0xBF) where one's required
--   * UTF8_OVERLONG     — codepoint encoded in more bytes than its value needs
--   * UTF8_SURROGATE    — codepoint in the U+D800..U+DFFF surrogate range
--   * UTF8_OUT_OF_RANGE — codepoint > U+10FFFF
--
-- FP-risk note: legitimate Latin-1 / ISO-8859-x form posts, multipart
-- file-upload bodies (raw JPEG / PDF / ZIP bytes), and URLs truncated
-- mid-percent-encoded-UTF-8 by upstream ad redirectors (Facebook /
-- Instagram link-preview crawlers do this) all carry byte sequences
-- that the strict Coraza-style walker would flag as BAD_LEAD /
-- BAD_CONT / TRUNC — but none of those tags are an actual encoding-
-- bypass attack. They just mean "not UTF-8 right now".
--
-- The only attack-specific tags this rule was added for are:
--   * UTF8_OVERLONG     — multi-byte encoding of a codepoint that
--                         fits in fewer bytes. The classic bypass
--                         primitive: `%C0%AF` for `/`, `%C0%AE` for
--                         `.`, `%E0%80%AE` for `.`, etc. — bypasses
--                         substring-based path-traversal checks.
--   * UTF8_SURROGATE    — codepoint U+D800..U+DFFF encoded in UTF-8.
--                         RFC 3629 forbids; only attackers produce.
--   * UTF8_OUT_OF_RANGE — codepoint > U+10FFFF. Same as above.
--
-- The walker therefore runs in a single "relaxed" mode: it still
-- has to detect BAD_LEAD / BAD_CONT / TRUNC internally to advance
-- the cursor correctly, but only the three attack-specific tags
-- are RETURNED. Stray bytes are skipped silently and the walk keeps
-- going.
--
-- 2-byte overlongs (lead 0xC0 or 0xC1) are caught explicitly: RFC
-- 3629 reserves 0xC0..0xC1 specifically because they can ONLY
-- produce overlong encodings of ASCII. So any 0xC0/0xC1 followed
-- by a valid continuation byte IS the attack signature, regardless
-- of mode.
--
-- Production data backing this design (4-day Greek-WP shop sample,
-- 2026-05): 770+ BAD_LEAD/BAD_CONT events on /wp-admin/async-upload.php,
-- /wp-admin/admin-ajax.php, /wp-admin/post.php, CF7 feedback, and
-- 47 BAD_CONT events on a mformama.gr Facebook ad landing page where
-- AS32934 Facebook's `facebookexternalhit` crawler hit URLs whose
-- double-percent-encoded UTF-8 was truncated mid-sequence. All 817
-- were legitimate traffic; zero were encoding-bypass primitives.

local function utf8_walk(s)
  local n = #s
  if n == 0 then return nil end

  local i = 1
  while i <= n do
    local b = s:byte(i)
    if b < 0x80 then
      i = i + 1
    elseif b == 0xC0 or b == 0xC1 then
      -- RFC-3629-forbidden lead. If followed by a valid continuation,
      -- this is an explicit 2-byte overlong encoding of ASCII —
      -- always an encoding-bypass primitive.
      local c = s:byte(i + 1)
      if c and c >= 0x80 and c <= 0xBF then
        return "UTF8_OVERLONG"
      end
      i = i + 1   -- stray bad byte, keep walking
    else
      local need, min_cp
      if     b >= 0xF0 and b <= 0xF4 then need, min_cp = 3, 0x10000
      elseif b >= 0xE0 and b <= 0xEF then need, min_cp = 2, 0x800
      elseif b >= 0xC2 and b <= 0xDF then need, min_cp = 1, 0x80
      else
        i = i + 1   -- stray byte (0xC2-0xC1 already handled, 0xF5-0xFF land here)
      end

      if need then
        if i + need > n then
          -- Buffer truncated mid-sequence (our cap() or upstream cut).
          -- Never an attack — overlong/surrogate/out-of-range all need
          -- a fully-formed sequence to decode into a codepoint.
          return nil
        end

        local cp
        if     need == 1 then cp = (b - 0xC0) * 64
        elseif need == 2 then cp = (b - 0xE0) * 4096
        else                  cp = (b - 0xF0) * 262144
        end

        local cont_bad = false
        for k = 1, need do
          local c = s:byte(i + k)
          if not c or c < 0x80 or c > 0xBF then
            cont_bad = true
            break
          end
          cp = cp + (c - 0x80) * (64 ^ (need - k))
        end

        if cont_bad then
          i = i + 1   -- stray lead, keep walking
        else
          if cp < min_cp                   then return "UTF8_OVERLONG"     end
          if cp >= 0xD800 and cp <= 0xDFFF then return "UTF8_SURROGATE"    end
          if cp > 0x10FFFF                 then return "UTF8_OUT_OF_RANGE" end
          i = i + need + 1
        end
      end
    end
  end
  return nil
end

function _M.detect_bad_utf8(args, body, headers, uri, _na)
  -- Skip known legitimate binary-ish endpoints (WP optimization-detective
  -- metrics, async-upload media) — same carve-out the ctrl-chars detector uses.
  -- These produced the bulk of the WAF_BAD_UTF8 logonly FP noise on real Greek
  -- traffic (mobile web-vitals POSTs + admin image uploads).
  if is_known_binaryish_uri(uri) then return nil end

  local tag = utf8_walk(_na or normalize(cap(args or "", CFG.max_scan_len)))
  if tag then return tag end

  -- Walk the body only for TEXTUAL content types (urlencoded / JSON / XML /
  -- text, or an empty CT). Binary uploads carry raw bytes (JPEG / WebP / PNG /
  -- ZIP) that routinely form 0xC0/0xC1 + continuation pairs (JPEG SOF markers
  -- 0xFFC0/0xFFC1 etc.) and E0/F0 leads decoding to overlong / surrogate /
  -- out-of-range codepoints — none of which are encoding-bypass primitives,
  -- just binary that isn't UTF-8 text. This mirrors the ctrl-chars (601) and
  -- webshell-body (404) gating, which already skip any non-textual CT. Rule 611
  -- previously skipped only `multipart/form-data`, so a RAW binary upload on a
  -- non-multipart endpoint still FP'd — e.g. the WP REST media route POSTs a
  -- raw JPEG to /wp-json/wp/v2/media with `Content-Type: image/jpeg` (a legit
  -- Greek admin on mygreecetours.org logged WAF_BAD_UTF8:UTF8_OVERLONG on every
  -- image upload, 2026-07-04). The args walk above still covers the URL /
  -- path-traversal vector, and the textual-body walk below still covers the
  -- urlencoded / JSON / XML overlong-slash bypass (test 77c keeps firing).
  headers = headers or {}
  local ct = lower(headers["content-type"] or headers["Content-Type"] or "")
  if not is_textual_body_content_type(ct) then return nil end

  return utf8_walk(normalize(cap(body or "", CFG.max_scan_len)))
end

-- ─────────────────────────────────────────────────────────────────────────────
-- PHP dropper / canary family (rules 421-425)
--
-- Source: production /tmp artefacts captured 2026-05-19 — a shared-hosting
-- compromise that left behind both first-stage exec-probes ("does this
-- server run PHP?") and second-stage wget/curl droppers with size-and-mtime
-- integrity verification. The five rules below split that observed workflow
-- into independent detectors so per-vhost exclusions stay surgical.
-- ─────────────────────────────────────────────────────────────────────────────

-- 421 — split-string PHP canary.
-- Shape: `<?php print "AAA"."BBB"; exit;` (or echo/die, single quotes, etc.)
-- The `.`-concat is the attacker's anti-substring trick: each random half is
-- meaningless alone, only the runtime-concatenated whole is a known token in
-- their response parser. We catch on the canary's negative shape — PHP opener
-- + print/echo/die immediately followed by quoted-string concat + no control
-- flow constructs. Real PHP code always has at least one of `function`,
-- `class`, `if`, `for`, `while`, `foreach`, or `{`.
function _M.detect_php_split_string_canary(body, _headers)
  if not body or body == "" then return nil end

  local cap_len = tonumber(CFG.php_webshell_max_scan_len) or CFG.max_scan_len
  local s = cap(body, cap_len)

  if not s:find("<%?php") and not s:find("<%?=") then return nil end

  local ls = lower(s)
  if ls:find("function%s*[%(%w_]") or ls:find("class%s+[%w_]")
     or ls:find("if%s*%(") or ls:find("else%s")
     or ls:find("for%s*%(") or ls:find("while%s*%(") or ls:find("foreach")
     or ls:find("{") then
    return nil
  end

  -- Every captured canary in the source workload ends with `;exit;` (or a
  -- `die(...)`). Requiring an exit/die keyword as a *whole word* (frontier
  -- pattern, so `died` / `exiting` / `exited` don't satisfy it) suppresses
  -- the legit "code snippet plugin save" FP shape:
  --   <?php print "Hello, " . "World";
  -- which has the print+concat signature but no termination call.
  if not (ls:find("%f[%w_]exit%f[^%w_]") or ls:find("%f[%w_]die%f[^%w_]")) then
    return nil
  end

  if s:find('print%s+%b""%s*%.%s*%b""')       then return "PRINT_CONCAT" end
  if s:find("print%s+%b''%s*%.%s*%b''")       then return "PRINT_CONCAT" end
  if s:find('echo%s+%b""%s*%.%s*%b""')        then return "ECHO_CONCAT"  end
  if s:find("echo%s+%b''%s*%.%s*%b''")        then return "ECHO_CONCAT"  end
  if s:find('die%s*%(?%s*%b""%s*%.%s*%b""')   then return "DIE_CONCAT"   end
  if s:find("die%s*%(?%s*%b''%s*%.%s*%b''")   then return "DIE_CONCAT"   end

  return nil
end

-- 422 — wget+curl fallback dropper.
-- The dropper-as-a-service shape: try `wget -O <path> <url>`, then try
-- `curl -o <path> <url>` as a redundant fallback, with a `filesize()`
-- integrity check between the two. The pair is the giveaway — almost no
-- legitimate PHP body invokes both downloaders for the same target.
function _M.detect_php_dropper_wget_curl(body, _headers)
  if not body or body == "" then return nil end

  local cap_len = tonumber(CFG.php_webshell_max_scan_len) or CFG.max_scan_len
  local s = lower(cap(body, cap_len))

  if not (has(s, "wget -o") or has(s, "wget --output")) then return nil end
  if not (has(s, "curl -o") or has(s, "curl --output")) then return nil end

  if not has(s, "filesize(") then return nil end
  if not (has(s, "@touch(") or has(s, "file_exists(")) then return nil end

  return "WGET_CURL_FALLBACK"
end

-- 423 — distinctive dropper exit markers `!success!` / `!ended!`.
-- The samples wrap their success/failure path with `die('!success!')` and
-- `die('!ended!')` — framing strings the attacker's automation greps for in
-- the HTTP response. Both literals in the same body is bespoke enough that
-- a generic dictionary of leetspeak markers will not collide.
function _M.detect_php_dropper_markers(body, _headers)
  if not body or body == "" then return nil end

  local cap_len = tonumber(CFG.php_webshell_max_scan_len) or CFG.max_scan_len
  local s = cap(body, cap_len)

  local has_success = s:find("['\"]!success!['\"]") ~= nil
  local has_ended   = s:find("['\"]!ended!['\"]")   ~= nil
  if not (has_success and has_ended) then return nil end

  local ls = lower(s)
  if not (has(ls, "die(") or has(ls, "die ") or has(ls, "exit(") or has(ls, "exit;")) then
    return nil
  end
  return "SUCCESS_ENDED_PAIR"
end

-- 424 — `<fs>`-tagged filesize recon stub.
-- `<?php $p=$_SERVER['SCRIPT_FILENAME']; die("<fs>".filesize($p)."</fs>...");`
-- The literal `<fs>` tag plus `filesize(` plus a SCRIPT_FILENAME reference is
-- distinctive: it is the attacker's "where am I and how big is the script I
-- got dropped at?" probe, used to pick the right second-stage payload.
function _M.detect_php_filesize_recon(body, _headers)
  if not body or body == "" then return nil end

  local cap_len = tonumber(CFG.php_webshell_max_scan_len) or CFG.max_scan_len
  local s = lower(cap(body, cap_len))

  if not has(s, "<fs>") then return nil end
  if not has(s, "filesize(") then return nil end
  if not has(s, "script_filename") then return nil end
  return "FS_TAG_RECON"
end

-- 425 — `@touch()` with a forged literal unix timestamp (mtime backdating).
-- Anti-forensic primitive: after a successful drop, the attacker matches the
-- new file's mtime to a surrounding-directory timestamp so `find -newer` and
-- audit walks miss it. Legit code uses bare `touch()` with `time()` — the
-- `@` error-suppression plus a 10-digit literal timestamp is malware-only.
function _M.detect_php_touch_antiforensic(body, _headers)
  if not body or body == "" then return nil end

  local cap_len = tonumber(CFG.php_webshell_max_scan_len) or CFG.max_scan_len
  local s = lower(cap(body, cap_len))

  if not has(s, "@touch(") then return nil end

  -- Literal unix-timestamp second arg covering 2017-08 → 2038-01.
  if not s:find("@touch%s*%([^,)]+,%s*1[5-9]%d%d%d%d%d%d%d%d")
     and not s:find("@touch%s*%([^,)]+,%s*20%d%d%d%d%d%d%d%d")
     and not s:find("@touch%s*%([^,)]+,%s*21[0-3]%d%d%d%d%d%d%d") then
    return nil
  end

  if not (has(s, "file_put_contents") or has(s, "fwrite")
          or has(s, "wget ") or has(s, "curl ")
          or has(s, "file_exists(") or has(s, "filesize(")) then
    return nil
  end
  return "FORGED_MTIME_TOUCH"
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Backdoor / obfuscation family (rules 430-437)
--
-- Defensive coverage against the modern PHP-backdoor surface: config-file
-- poisoning of upload sandboxes, obfuscator output where function names are
-- never substrings of the source, deep polyglots (magic-byte prefix + PHP
-- code further in than rule 412's 64-byte window), and generic "decode then
-- eval" loader shapes.
--
-- Reason family WAF_BACKDOOR (added to _M.WAF_HIGH_RISK_REASONS in cfm_waf
-- so post-clearance escalation behaves correctly when promoted past
-- logonly). Each rule emits its own tag for forensic granularity but shares
-- the family for hit-rate dashboarding and per-vhost exclusion grouping.
-- ─────────────────────────────────────────────────────────────────────────────

-- 430 — `.htaccess` / `.user.ini` poisoning.
-- Uploaded webserver-config files that turn benign uploads into PHP
-- executors. The canonical shape after a successful file-upload bypass:
--   AddType application/x-httpd-php .jpg .gif .png
--   SetHandler application/x-httpd-php
--   php_value auto_prepend_file /tmp/shell.php
-- Legit plugins write rewrite / cache headers, not these handler-flip anchors.
-- NOTE: kept at `logonly` — `AddType application/x-httpd-php` is also a legit
-- hand-written shared-hosting directive, and the addtype/sethandler/addhandler
-- branches below are NOT prose-gated (the `.user.ini` branch is), so a body that
-- merely discusses the directive matches. Add that gating before promoting.
function _M.detect_htaccess_poisoning(body, _headers)
  if not body or body == "" then return nil end

  local cap_len = tonumber(CFG.php_webshell_max_scan_len) or CFG.max_scan_len
  local s = lower(cap(body, cap_len))

  -- Handler-flip primitives — these are the high-confidence kill shots.
  if s:find("addtype%s+[%w/.%-_]*x%-httpd%-php") then return "HTACCESS_ADDTYPE_PHP"   end
  if s:find("sethandler%s+[%w/.%-_]*x%-httpd%-php") then return "HTACCESS_SETHANDLER_PHP" end
  if s:find("addhandler%s+[%w/.%-_]*x%-httpd%-php") then return "HTACCESS_ADDHANDLER_PHP" end

  -- auto_prepend_file / auto_append_file via php_value or .user.ini —
  -- malicious upload pattern. Real php.ini config never travels in a
  -- request body.
  if s:find("php_value%s+auto_prepend_file")       then return "HTACCESS_AUTO_PREPEND"  end
  if s:find("php_value%s+auto_append_file")        then return "HTACCESS_AUTO_APPEND"   end
  if s:find("php_admin_value%s+auto_prepend_file") then return "HTACCESS_AUTO_PREPEND"  end
  if s:find("php_admin_value%s+auto_append_file")  then return "HTACCESS_AUTO_APPEND"   end

  -- .user.ini shape — same primitives without the Apache wrappers.
  -- Gated on an `=` to distinguish from the same tokens appearing in prose.
  if s:find("auto_prepend_file%s*=%s*[%w/.%-_]") then return "USER_INI_AUTO_PREPEND" end
  if s:find("auto_append_file%s*=%s*[%w/.%-_]")  then return "USER_INI_AUTO_APPEND"  end

  -- Forced ExecCGI in a request body is server-admin territory only.
  if s:find("options%s+[+%-]?execcgi") then return "HTACCESS_EXEC_CGI" end

  return nil
end

-- 431 — character-pool function-name builder.
-- The signature obfuscator pattern observed in 2026-05-19 wp-themes/bridge
-- compromise sample: a variable holds a random alphanumeric pool, then
-- function names ("gzinflate", "base64_decode", "eval") are assembled by
-- character-index extraction from that pool:
--   $t = "8Njlp26zFZ1PYvUsn…";
--   $f = $t[61].$t[7].$t[34]…;   // ← three+ indexed accesses, concat'd
-- The grammar `$VAR[N].$VAR[N].$VAR[N]` (same variable, 3+ accesses, dot-
-- concatenated) appears in no legitimate PHP idiom — loops are the legit
-- way to read sequential array elements. This catches the entire
-- FOPO / PHP-Obfuscator / Code-Eater class regardless of pool content.
function _M.detect_php_char_pool_obfuscation(body, _headers)
  if not body or body == "" then return nil end

  local cap_len = tonumber(CFG.php_webshell_max_scan_len) or CFG.max_scan_len
  local s = cap(body, cap_len)

  -- Lua's %1 backreference enforces same-variable across all three accesses.
  -- %s* around the dots lets the obfuscator pretty-print without bypassing.
  -- [%w_] (not %w) because PHP var names contain underscores — `%w` in Lua
  -- patterns is `[A-Za-z0-9]` only, so the captured sample's `$t_Ohw` would
  -- otherwise truncate at the underscore and the backreference would fail.
  if s:find("%$([%w_]+)%[%d+%]%s*%.%s*%$%1%[%d+%]%s*%.%s*%$%1%[%d+%]") then
    return "CHAR_POOL_BUILDER"
  end
  return nil
end

-- 439 — generic phpfuck / numeric-XOR obfuscation blob. Technique-level
-- companion to the vBulletin runMaths CVE rule (10015,
-- detect_cve_vbulletin_runmaths): that rule is endpoint-anchored, this one has
-- NO route context and catches the same phpfuck construction against any
-- restricted-charset eval() sink (custom code, another CMS). Reuses the shared
-- has_phpfuck_blob helper (contiguous-run, all-three-token scan) at STRICTER
-- thresholds (min 60 chars, >=4 carets, >=4 concatenation dots) precisely
-- because there is no endpoint to lean on, and normalizes the body first so the
-- url-encoded form-POST shape (`%28%28...%5E...`) is decoded before the scan.
-- Ships logonly (see the check site) — WAF_BACKDOOR is autoblock-armed but
-- Phase-1 autoblock feeds edge-`block` hits only, so logonly logs/alerts without
-- banning during burn-in.
function _M.detect_php_numeric_xor_obfuscation(body, _headers)
  if not body or body == "" then return nil end
  local cap_len = tonumber(CFG.php_webshell_max_scan_len) or CFG.max_scan_len
  local s = normalize(cap(body, cap_len))
  if has_phpfuck_blob(s, 60, 4, 4) then
    return "NUMERIC_XOR_OBFUSCATION"
  end
  return nil
end

-- 432 — full-body polyglot (image/PDF/ZIP magic + PHP opener anywhere).
-- Rule 412 covers the first 64 bytes of multipart parts; this rule covers
-- the case where `<?php` sits further in than 64 bytes after a magic-byte
-- prefix. The 2026-05-19 sample had `%PDF-\n%PDF-\n<?php` (opener at byte
-- 13 — within 412's window) but the class generalises: a JPEG / PNG / GIF
-- / PDF / ZIP that contains `<?php` anywhere in body is malicious. Legit
-- binary files never contain `<?php`.
function _M.detect_php_polyglot_full_body(body, headers)
  if not body or body == "" or #body < 4 then return nil end

  -- Magic byte prefix check — first 16 bytes only. Raw bytes, NEVER
  -- lowercased: image / PDF / ZIP magic is case-sensitive (a real PDF
  -- starts with `%PDF-` not `%pdf-`, JPEG with `\xff\xd8\xff` literally).
  local head = body:sub(1, 16)
  local magic_tag
  if     head:sub(1, 5) == "%PDF-"                 then magic_tag = "PDF"
  elseif head:sub(1, 3) == "\xff\xd8\xff"          then magic_tag = "JPEG"
  elseif head:sub(1, 8) == "\x89PNG\r\n\x1a\n"     then magic_tag = "PNG"
  elseif head:sub(1, 6) == "GIF87a"                then magic_tag = "GIF"
  elseif head:sub(1, 6) == "GIF89a"                then magic_tag = "GIF"
  elseif head:sub(1, 4) == "PK\x03\x04"            then magic_tag = "ZIP"
  elseif head:sub(1, 2) == "BM"                    then magic_tag = "BMP"
  elseif head:sub(1, 4) == "RIFF"                  then magic_tag = "RIFF"
  end
  if not magic_tag then return nil end

  local cap_len = tonumber(CFG.php_webshell_max_scan_len) or CFG.max_scan_len
  -- Lowercase the scan buffer for opener search: PHP openers are
  -- case-insensitive per spec (`<?PHP`, `<?Php` are valid). Mirrors
  -- detect_polyglot_upload (rule 412) which also lowers before opener
  -- match. The magic-byte check above already happened on the raw bytes,
  -- so lowering here is safe — it doesn't affect the gating decision.
  local s = lower(cap(body, cap_len))

  -- has() over literal openers — faster and clearer than pattern matching
  -- when no metacharacter semantics are needed.
  -- `<?php` matched bare (binary-safe); `<?=` requires PHP-expression context
  -- (has_php_short_echo) so a stray 3-byte `<?=` in the magic-prefixed binary
  -- of a legit image / PDF / ZIP can't trip POLYGLOT_DEEP_*.
  if has(s, "<?php") or has_php_short_echo(s)
     or has(s, "<jsp:")
     or s:find("<%%@%s*page")
     or s:find("<script%s+language%s*=%s*['\"]?php") then
    return "POLYGLOT_DEEP_" .. magic_tag
  end
  return nil
end

-- 433 — variable-fed eval-loader with a large base64 literal.
-- The loader-shape fingerprint shared by every PHP obfuscator output:
--   eval($a($b("BASE64_PAYLOAD…")));
-- where $a and $b are variables (the decoder names are hidden by some
-- mechanism — char-pool, concat, string-reverse, gzinflate-of-gzinflate).
-- We don't peer into the payload, just recognise the loader: an `eval`/
-- `assert`/`call_user_func` whose argument starts with `$<var>(`, plus a
-- quoted base64-shaped string of ≥ 200 chars in the same body.
function _M.detect_php_eval_loader_b64(body, _headers)
  if not body or body == "" then return nil end

  local cap_len = tonumber(CFG.php_webshell_max_scan_len) or CFG.max_scan_len
  local s = cap(body, cap_len)
  local ls = lower(s)

  -- Variable-fed terminal call: eval(/assert(/call_user_func( followed by
  -- $varname( within ~32 characters. The %s* allows whitespace between the
  -- opener and the variable call.
  local has_var_eval =
       ls:find("eval%s*%(%s*@?%$[%w_]+%s*%(")
    or ls:find("assert%s*%(%s*@?%$[%w_]+%s*%(")
    or ls:find("call_user_func%s*%(%s*@?%$[%w_]+")
    or ls:find("call_user_func_array%s*%(%s*@?%$[%w_]+")
  if not has_var_eval then return nil end

  -- Find a quoted base64-shaped literal ≥ 200 chars. Iterate balanced
  -- quotes and length-check the inner content.
  local min_len = 200
  local function looks_b64(inner)
    if #inner < min_len then return false end
    -- Allow newlines / whitespace inside; require ≥ 90% base64 alphabet
    -- to tolerate the occasional decorator char.
    local b64_chars = 0
    local total = 0
    for i = 1, #inner do
      local c = inner:byte(i)
      total = total + 1
      if (c >= 0x30 and c <= 0x39)   -- 0-9
         or (c >= 0x41 and c <= 0x5a) -- A-Z
         or (c >= 0x61 and c <= 0x7a) -- a-z
         or c == 0x2b or c == 0x2f or c == 0x3d then -- + / =
        b64_chars = b64_chars + 1
      end
    end
    return b64_chars * 10 >= total * 9
  end

  -- Scan for both " and '-quoted literals.
  for blob in s:gmatch('%b""') do
    if #blob >= min_len + 2 and looks_b64(blob:sub(2, -2)) then
      return "EVAL_LOADER_B64"
    end
  end
  for blob in s:gmatch("%b''") do
    if #blob >= min_len + 2 and looks_b64(blob:sub(2, -2)) then
      return "EVAL_LOADER_B64"
    end
  end

  return nil
end

-- 434 — superglobal-fed callable (modern minimalist webshell).
-- The PHP-webshell shape that defeats every literal `eval(`/`system(`
-- substring scanner because the dangerous primitive is *invoked* via a
-- superglobal, not named:
--   <?php $_GET['c']($_GET['p']);
--   <?php $_REQUEST['f']();
--   <?php $f = $_POST['x']; $f();           ← assigned form, not in this rule
-- We catch the direct form (no assignment required): a superglobal
-- subscript immediately followed by a `(` is the function-call grammar
-- in PHP, and no legitimate framework uses an unfiltered superglobal as
-- the callable. Also covers $_SERVER['HTTP_X_*']( — the header-named
-- callable variant used by stealthier shells.
function _M.detect_php_superglobal_callable(body, _headers)
  if not body or body == "" then return nil end

  local cap_len = tonumber(CFG.php_webshell_max_scan_len) or CFG.max_scan_len
  local s = cap(body, cap_len)

  if s:find("%$_GET%s*%[[^%]]+%]%s*%(")     then return "SG_GET_CALL"     end
  if s:find("%$_POST%s*%[[^%]]+%]%s*%(")    then return "SG_POST_CALL"    end
  if s:find("%$_REQUEST%s*%[[^%]]+%]%s*%(") then return "SG_REQUEST_CALL" end
  if s:find("%$_COOKIE%s*%[[^%]]+%]%s*%(")  then return "SG_COOKIE_CALL"  end

  -- $_SERVER['HTTP_X_*']( — header-named callable, common in
  -- magic-header-triggered shells.
  if s:find("%$_SERVER%s*%[[^%]]-HTTP_[^%]]-%]%s*%(") then
    return "SG_SERVER_HTTP_CALL"
  end
  return nil
end

-- 435 — concatenated function-name eval.
-- The function-name version of canary 421's split-string trick:
--   $a = "sys" . "tem"; $a($_GET['c']);
--   $f = "ev" . "al";   $f($payload);
-- A short quoted-string concatenation (each piece ≤ 6 chars, lowercase
-- alpha+underscore only) is assigned to a variable that is then invoked
-- with `()`. Tight character class disqualifies path concats like
-- "/var" . "/log" and template-engine method-name builds, both of which
-- would otherwise have the same grammar.
function _M.detect_php_concat_funcname_eval(body, _headers)
  if not body or body == "" then return nil end

  local cap_len = tonumber(CFG.php_webshell_max_scan_len) or CFG.max_scan_len
  local s = cap(body, cap_len)

  -- Match $var = "p1"."p2" with both pieces alpha+underscore, len 1-6.
  -- gmatch lets us check every assignment in the body, not just the first.
  for var, p1, p2 in s:gmatch("%$([%w_]+)%s*=%s*['\"]([%a_][%a_]?[%a_]?[%a_]?[%a_]?[%a_]?)['\"]%s*%.%s*['\"]([%a_][%a_]?[%a_]?[%a_]?[%a_]?[%a_]?)['\"]") do
    if var and p1 and p2 then
      -- The combined string must look like a function name (no /, no
      -- digits, no spaces). The %a/%_ char class already enforces this
      -- per piece; this is a paranoia check.
      local joined = p1 .. p2
      if joined:match("^[%a_]+$") then
        -- Variable invocation later in body: `$var(` not preceded by `>`
        -- (so we don't match method calls $obj->$var()).
        local call_pat = "[^>]%$" .. var .. "%s*%("
        if s:find(call_pat) or s:find("^%$" .. var .. "%s*%(") then
          return "CONCAT_FUNCNAME_CALL"
        end
      end
    end
  end
  return nil
end

-- 436 — multi-decode chain (3+ decoder primitives in proximity).
-- The classic obfuscator-loader pattern when the decoder names ARE
-- substrings of the source (older obfuscators, hand-rolled droppers):
--   eval(gzinflate(base64_decode(strrev($payload))))   ← 4 decoders, ≤80 chars
-- Counts distinct decoder primitives within a 300-byte window; 3+
-- → fire. Window-gated to suppress FPs from legit code that uses
-- several decoders across hundreds of lines of unrelated logic.
-- "pack" omitted: it is a substring of "unpack", which is common in legit
-- binary-parsing code. The three-in-300 threshold doesn't protect against
-- unpack + two real decoders triggering a false positive.
local DECODE_PRIMITIVES = {
  "base64_decode", "gzinflate", "gzuncompress", "gzdecode",
  "str_rot13", "strrev", "hex2bin", "convert_uudecode",
  "bzdecompress",
}
function _M.detect_php_decode_chain(body, _headers)
  if not body or body == "" then return nil end

  local cap_len = tonumber(CFG.php_webshell_max_scan_len) or CFG.max_scan_len
  local s = lower(cap(body, cap_len))

  -- Collect first-occurrence positions of each decoder primitive,
  -- gated on `(` so prose / variable-name false hits (`my_strrev_helper`)
  -- don't count.
  local positions = {}
  for _, name in ipairs(DECODE_PRIMITIVES) do
    local pos = s:find(name .. "%s*%(")
    if pos then positions[#positions + 1] = pos end
  end
  if #positions < 3 then return nil end

  table.sort(positions)
  -- Window check: any three of the collected positions within 300 bytes.
  for i = 1, #positions - 2 do
    if positions[i + 2] - positions[i] <= 300 then
      return "DECODE_CHAIN"
    end
  end
  return nil
end

-- 437/438 — encoded `<?php` opener in a body.
-- An encoded PHP opener is a smuggling signal ONLY when the encoding is one a
-- normal client does not emit for content. Audit F16 removed the URL, HTML-
-- entity and JS-unicode forms because they are exactly how legit content is
-- transported, not evasion — a challenge on them broke real comment/forum/API
-- POSTs (the FP this rule kept generating):
--   • %3c%3fphp / %3c%3f=  — an application/x-www-form-urlencoded body is
--     url-encoded IN ITS ENTIRETY, so a user who types `<?php` into ANY form
--     field (blog comment, contact form, forum, paste tool) yields `%3c%3fphp`:
--     the normal on-wire encoding, indistinguishable from evasion. And the WAF
--     already unwraps it — the PHP webshell-body scorer (rule 404,
--     detect_php_webshell_body) normalize()-url-decodes the body, so a
--     marker-bearing payload (`<?php system($_GET…`) is caught by it (scores
--     <?php + exec-marker + superglobal, at challenge) regardless of this rule.
--   • &lt;?php / &#60;&#63;php — rich-text editors HTML-escape pasted code.
--   • the JS `\uXXXX` unicode-escape opener form — Go's encoding/json (and many
--     JS encoders) escape a literal `<` to its `\u`-prefixed unicode form by
--     DEFAULT, so a JSON API echoing user content that mentions `<?php` trips it.
-- What remains are the two forms a normal browser/JSON client never produces,
-- so they stay attack-shaped with ~zero FP:
--   • 438 B64_PHP_OPENER — base64("<?php") = PD9waHA, matched case-sensitively
--     at a base64 value boundary (see below).
--   • 437 JS_HEX_OPENER — \x3c\x3fphp, a raw \xNN byte-escape. A url-encoded
--     backslash is %5c (so a form body cannot carry a literal \x3c), and
--     normalize() does NOT unwrap \xNN — so rule 404 never sees a bare hex
--     opener; 437 is the only coverage for a MARKERLESS hex opener (a
--     marker-bearing one is still caught by 404), worth keeping.
function _M.detect_php_encoded_opener(body, _headers)
  if not body or body == "" then return nil end

  local cap_len = tonumber(CFG.php_webshell_max_scan_len) or CFG.max_scan_len
  local raw = cap(body, cap_len)   -- original case — base64 is case-sensitive
  local s   = lower(raw)           -- lowercased — for the \x hex-escape form

  -- Base64 openers are matched case-SENSITIVELY and only at a base64 value
  -- boundary (string start, or right after a non-base64 separator). base64
  -- uses a case-sensitive alphabet and a real smuggled opener is the START
  -- of a base64 payload value (`p=PD9waHA0...`). Lowercasing + mid-blob
  -- substring matching collided with legitimate base64 data — a Google
  -- product-feed module whose product text contained code samples
  -- (techking.gr OpenCart, 2026-05). Same FP class as rule 326's `rO0AB`.
  -- base64/base64url continuation chars: A-Za-z0-9 + / - _  (NOT `=` padding).
  local function b64_opener(needle)
    if raw:sub(1, #needle) == needle then return true end
    return raw:find("[^%w+/_-]" .. needle) ~= nil
  end
  if b64_opener("PD9waHA")            then return "B64_PHP_OPENER" end  -- base64("<?php") → 438
  -- base64("<?=") = "PD89" (4 chars) intentionally NOT matched: a 4-char base64
  -- prefix is too short to be reliable — it collides with legitimate base64
  -- values (Jetpack / WordPress.com xmlrpc sync, Contact Form 7 submissions).
  -- A 2026-06-25 five-server log review found "PD89" 6/6 false positives and 0
  -- real hits, so removing it lets rule 438 run at `challenge` without FPs.
  -- 437: JS `\x` hex-escape opener only. The URL (`%3c%3fphp`), HTML-entity
  -- (`&lt;?php`) and JS-unicode (`<…`) forms were REMOVED (audit F16) —
  -- they match the normal on-wire encoding of legit content and marker-bearing
  -- payloads in them are already caught by rule 404 (detect_php_webshell_body)
  -- on its url-decoded body (see header comment).
  if has(s, "\\x3c\\x3fphp")          then return "JS_HEX_OPENER" end
  return nil
end




return _M
