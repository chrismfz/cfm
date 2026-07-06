-- /var/lib/cfm/lua/cfm_waf_util.lua (CFM-managed canonical location)
--
-- Generic helpers shared by cfm_waf.lua (engine) and cfm_waf_detectors.lua
-- (detectors). Pure code: no CFG mutation, no global state besides the CFG
-- reference captured by init() so scan_str() can read max_scan_len.
--
-- Public surface: every function below is exported via _M.<name> at the
-- bottom of the file. Internal references between helpers stay as `local`s
-- for hot-path performance (every WAF request hits has/lower/scan_str).

local _M = {}

-- CFG is set by the engine via _M.init(cfg) at module load.
-- scan_str() is the only helper that needs it (max_scan_len).
local CFG

function _M.init(cfg)
  CFG = cfg
end

-- ─────────────────────────────────────────────────────────────────────────────
-- GENERIC STRING HELPERS
-- ─────────────────────────────────────────────────────────────────────────────

local function has(s, pat)
  if not s or s == "" then return false end
  if type(s) ~= "string" then return false end
  return string.find(s, pat, 1, true) ~= nil
end

-- Coerce a header value to a single string. ngx.req.get_headers() returns
-- a table when a header appears multiple times; pick the first non-empty
-- string element so downstream string ops don't crash.
local function header_string(v)
  if v == nil then return "" end
  if type(v) == "string" then return v end
  if type(v) == "table" then
    for i = 1, #v do
      local item = v[i]
      if type(item) == "string" and item ~= "" then return item end
    end
    return ""
  end
  return ""
end

-- ngx.req.get_headers() can return a table for duplicate headers
-- (e.g. multiple "Referer" or "User-Agent"); collapse those to the
-- first non-empty string so callers can treat the result as a string.
local function lower(s)
  if s == nil then return "" end
  if type(s) == "table" then
    for i = 1, #s do
      local item = s[i]
      if type(item) == "string" and item ~= "" then
        return string.lower(item)
      end
    end
    return ""
  end
  if type(s) ~= "string" then return "" end
  return string.lower(s)
end

local function cap(s, n)
  if not s then return "" end
  if #s <= n then return s end
  return string.sub(s, 1, n)
end

-- Count plain-string occurrences of pat inside s (no Lua pattern magic).
local function count_occurs(s, pat)
  local n, start = 0, 1
  while true do
    local i = s:find(pat, start, true)
    if not i then break end
    n = n + 1
    start = i + #pat
  end
  return n
end

-- Returns true if s contains a contiguous base64-looking blob >= min_len chars.
local function has_long_b64_blob(s, min_len)
  min_len = min_len or 180
  -- Cheap length guard: if the whole string is shorter than the minimum blob
  -- size, no blob can possibly exist.  Avoids the gmatch loop entirely for
  -- most short args/bodies.
  if not s or #s < min_len then return false, 0 end
  for blob in s:gmatch("[A-Za-z0-9+/=]+") do
    if #blob >= min_len and blob:match("^[A-Za-z0-9+/]+=*$") then
      return true, #blob
    end
  end
  return false, 0
end

-- is_known_legit_php_upload_endpoint reports whether the request targets an
-- endpoint that legitimately receives PHP-bearing uploads, so the upload
-- malware / webshell-content scanners (which would otherwise flag the PHP
-- that is the upload's whole point) must stand down. Takes args because the
-- WordPress plugin/theme installer is keyed on the query action.
local function is_known_legit_php_upload_endpoint(uri, args)
  local u = lower(uri or "")
  if u == "" then return false end

  -- Code Snippets plugin REST API import/parse flow.
  if u:match("^/wp%-json/code%-snippets/") then
    return true
  end

  -- WordPress plugin/theme installer. The uploaded .zip legitimately
  -- contains PHP source — a plugin/theme *is* PHP code, frequently
  -- obfuscated in commercial products — and the POST is behind WP's admin
  -- cookie-auth. update.php?action=upload-plugin / upload-theme is the only
  -- path where uploading a PHP-bearing archive is the intended function.
  -- (A plugin named e.g. "foo-block.php.zip" also trips the double-extension
  -- filename rule.) Media uploads (async-upload.php) are deliberately NOT
  -- exempted: a PHP opener inside a claimed image there is still a polyglot.
  if u == "/wp-admin/update.php" then
    local a = lower(args or "")
    -- Match action=upload-plugin / upload-theme as a *whole query parameter*
    -- (at the start or right after '&', value terminated by '&' or end), not
    -- as a loose substring of some other param's name or value (so
    -- `upload-plugins`, `xaction=...`, `foo=action=upload-plugin` don't slip
    -- through). The endpoint is already exempt to anyone who sends the exact
    -- canonical action, so this is precision/clarity, not a security gate.
    for _, act in ipairs({ "upload%-plugin", "upload%-theme" }) do
      if a:match("^action=" .. act .. "%f[%W]")
         or a:match("&action=" .. act .. "%f[%W]") then
        return true
      end
    end
  end

  return false
end

-- Upload endpoints whose declared purpose is a MEDIA ASSET (icon / image /
-- font) — a PHP-bearing archive is NEVER a legitimate payload here. Rule 414
-- (php-inside-an-uploaded-zip) fires ONLY on these. This is a deliberate
-- POSITIVE allowlist, not a global scan: the entire plugin / theme / extension
-- / backup / migration ecosystem ships `.zip` archives that legitimately
-- contain PHP, and those go to installer or plugin-specific endpoints — none of
-- which match here, so a legit plugin/backup upload is never touched. A webshell
-- zip is only unambiguously malicious when it lands on a media-asset endpoint.
--
-- SCOPED TO JOOMLA on purpose, and provably so: a match REQUIRES both
-- `option=com_<component>` AND `task=asset.upload*`, each anchored to a real
-- query-param boundary. `option=com_` is a Joomla-only routing param —
-- WordPress (`action=`), OpenCart (`route=`), Magento (path-based / `key=`),
-- PrestaShop (`controller=`) and Drupal (path / `q=`) never emit it — so this
-- rule cannot fire on those platforms, which is what lets it run at `block`
-- without risking cross-platform false positives. Extend (a second, separately
-- scoped clause) as new non-Joomla asset-upload vectors are confirmed.
local function is_php_hostile_asset_upload(uri, args)
  local a = lower(args or "")
  local u = lower(uri or "")
  -- Leading separator so the FIRST query param is also boundary-anchored.
  local hay = "&" .. a .. "&" .. u

  -- Joomla SP Page Builder asset.uploadCustomIcon / uploadImage / uploadFont
  -- (the confirmed 2026-07 ANTONKILL vector) and any Joomla component using the
  -- same media-asset upload task. Both params required + boundary-anchored so a
  -- coincidental substring in some other value can't trip it.
  if hay:match("[?&]option=com_[%w_]") and hay:match("[?&]task=asset%.upload") then
    return true
  end

  return false
end


-- Scored obfuscation detector shared by detect_script_obfuscation and
-- detect_upload_obfuscation.  s must already be lowercased + capped by caller.
-- Returns a tag string on a hit, nil otherwise.
local function score_obfuscation_blob(s, min_score)
  if not s or s == "" then return nil end

  local score, tags = 0, {}

  -- Long base64 blob
  local longb64, bloblen = has_long_b64_blob(s, 180)
  if longb64 then
    score = score + 2
    tags[#tags+1] = "LONG_B64"
    if bloblen >= 600 then
      score = score + 1
      tags[#tags+1] = "B64_600"
    end
  end

  -- PHP-side decode helpers
  if has(s, "base64_decode(") then
    score = score + 2; tags[#tags+1] = "BASE64_DECODE"
  end
  if has(s, "gzinflate(") or has(s, "gzuncompress(") then
    score = score + 2; tags[#tags+1] = "GZ"
  end
  if has(s, "str_rot13(") then
    score = score + 1; tags[#tags+1] = "ROT13"
  end
  -- hex2bin($_POST['x']) is the canonical W3 webshell delivery shape:
  -- attacker pastes a hex-encoded blob, hex2bin() turns it back into bytes
  -- that get fed to eval/assert. Same weight as base64_decode — both sit
  -- one layer below the eval call in the obfuscation stack.
  if has(s, "hex2bin(") then
    score = score + 2; tags[#tags+1] = "HEX2BIN"
  end

  -- PHP eval-in-regex (deprecated /e modifier)
  if has(s, "preg_replace") and has(s, "/e") then
    score = score + 3; tags[#tags+1] = "PREG_EVAL"
  end

  -- chr() storm (obfuscated string construction)
  local chrn = count_occurs(s, "chr(")
  if chrn >= 6 then
    score = score + 2; tags[#tags+1] = "CHR_STORM"
  end

  -- JS-side decode helpers
  if has(s, "atob(") then
    score = score + 2; tags[#tags+1] = "ATOB"
  end
  if has(s, "new function(") then
    score = score + 3; tags[#tags+1] = "NEW_FUNCTION"
  end
  if has(s, "string.fromcharcode(") then
    score = score + 2; tags[#tags+1] = "FROMCHARCODE"
  end
  if has(s, "textdecoder") then
    score = score + 1; tags[#tags+1] = "TEXTDECODER"
  end
  if has(s, "uint8array(") then
    score = score + 1; tags[#tags+1] = "UINT8ARRAY"
  end

  -- XOR decode loop: charCodeAt present + bare XOR operator (e.g. r[i]^k, x^76)
  -- Match on operator shape, not variable name, to survive renaming.
  if has(s, "charcodeat(") and s:match("[%w%)%]]%^[%w%(]") then
    score = score + 3; tags[#tags+1] = "XOR_LOOP"
  end

  -- eval() – high weight, present in almost all execution-stage payloads
  if has(s, "eval(") then
    score = score + 3; tags[#tags+1] = "EVAL"
  end

  -- Hex escape storm: \x41\x42 style encoding (different obfuscation family)
  local hex_escapes = count_occurs(s, "\\x")
  if hex_escapes >= 8 then
    score = score + 2; tags[#tags+1] = "HEX_STORM"
  end

  if score >= (min_score or 6) then
    return "OBFUSCATED:" .. table.concat(tags, "+") .. ":score=" .. score
  end
  return nil
end

local function begins(s, prefix)
  if not s or not prefix then return false end
  return string.sub(s, 1, #prefix) == prefix
end

local function url_decode_once(s)
  return (s:gsub("%%(%x%x)", function(h)
    return string.char(tonumber(h, 16))
  end))
end

local function normalize(s)
  if not s or s == "" then return "" end
  -- Fast path: a string with no "%" cannot contain any %xx escape, so both
  -- url_decode_once gsubs would walk the whole string and return it
  -- unchanged. Skip them and just lowercase. JSON / multipart bodies are
  -- the common case here — they almost never carry %xx — and at the new
  -- 32K JSON budget the gsub passes were the dominant per-request cost.
  if not string.find(s, "%", 1, true) then
    return string.lower(s)
  end
  s = url_decode_once(s)
  s = url_decode_once(s)
  return string.lower(s)
end

-- Strip SQL inline comments before SQLi scanning.
-- Catches keyword-splitting bypasses like UN/**/ION SE/**/LECT.
-- Applied only in the SQLi path; not in normalize() to avoid
-- altering the scan surface for other checks.
local function strip_sql_comments(s)
  return (s:gsub("/%*.-%*/", ""):gsub("%-%-[^\n]*", ""))
end

local function scan_str(uri, args)
  return normalize(cap((uri or "") .. "?" .. (args or ""), CFG.max_scan_len))
end

-- Pick the body-scan byte budget for a request based on its Content-Type.
-- Falls back to body_scan_budget.other when the header is missing/empty/
-- unrecognised, and to CFG.max_scan_len when the table itself is absent
-- (preserves behaviour in environments running an older config layout).
-- Header parameters after ";" (e.g. "application/json; charset=utf-8")
-- are handled — substring match on the type/subtype prefix.
--
-- Defensive: every step type-checks its inputs. A misconfigured override
-- (body_scan_budget = nil / non-table / partial table / non-positive
-- numbers) must never bubble a nil or bad value into cap(), since cap's
-- numeric comparison would error and crash the worker on every request.
local function body_budget(headers)
  local fallback = 2048
  if CFG and type(CFG.max_scan_len) == "number" and CFG.max_scan_len > 0 then
    fallback = CFG.max_scan_len
  end
  local budget = CFG and CFG.body_scan_budget
  if type(budget) ~= "table" then
    return fallback
  end

  local function pick_or(key)
    local v = budget[key]
    if type(v) == "number" and v > 0 then return v end
    local o = budget.other
    if type(o) == "number" and o > 0 then return o end
    return fallback
  end

  if not headers then return pick_or("other") end
  local raw = headers["content-type"]
  if raw == nil then raw = headers["Content-Type"] end
  local ct = header_string(raw)
  if ct == "" then return pick_or("other") end
  ct = string.lower(ct)
  if string.find(ct, "application/json", 1, true)               then return pick_or("json") end
  if string.find(ct, "multipart/form-data", 1, true)            then return pick_or("multipart") end
  if string.find(ct, "application/x-www-form-urlencoded", 1, true) then return pick_or("urlencoded") end
  if string.find(ct, "application/xml", 1, true)
     or string.find(ct, "text/xml", 1, true)                    then return pick_or("xml") end
  return pick_or("other")
end

-- ─────────────────────────────────────────────────────────────────────────────
-- HOST HELPERS
-- ─────────────────────────────────────────────────────────────────────────────

local function strip_host_port(host)
  if not host or host == "" then return "" end
  host = host:gsub("^%s+", ""):gsub("%s+$", "")

  -- Bracketed IPv6 with or without port
  local b = host:match("^%[([^%]]+)%]:%d+$") or host:match("^%[([^%]]+)%]$")
  if b then return b end

  -- Hostname / IPv4 with :port
  if host:match("^[^:]+:%d+$") then
    return host:match("^([^:]+):%d+$") or host
  end

  -- Bare hostname or bare IPv6
  return host
end

local function is_ipv4_literal(h)
  local a, b, c, d = h:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then return false end
  a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  if not a or not b or not c or not d then return false end
  return a <= 255 and b <= 255 and c <= 255 and d <= 255
end

local function is_ipv6_literal(h)
  if not h or h == "" then return false end
  if not h:find(":", 1, true) then return false end
  if h:match("^[0-9a-fA-F:]+$") then return true end
  return false
end

-- ─────────────────────────────────────────────────────────────────────────────
-- EXPORTS
-- ─────────────────────────────────────────────────────────────────────────────

_M.has                                = has
_M.header_string                      = header_string
_M.lower                              = lower
_M.cap                                = cap
_M.count_occurs                       = count_occurs
_M.has_long_b64_blob                  = has_long_b64_blob
_M.is_known_legit_php_upload_endpoint = is_known_legit_php_upload_endpoint
_M.is_php_hostile_asset_upload = is_php_hostile_asset_upload
_M.score_obfuscation_blob             = score_obfuscation_blob
_M.begins                             = begins
_M.url_decode_once                    = url_decode_once
_M.normalize                          = normalize
_M.strip_sql_comments                 = strip_sql_comments
_M.scan_str                           = scan_str
_M.body_budget                        = body_budget
_M.strip_host_port                    = strip_host_port
_M.is_ipv4_literal                    = is_ipv4_literal
_M.is_ipv6_literal                    = is_ipv6_literal

return _M
