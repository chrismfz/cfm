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

-- is_known_legit_php_upload_endpoint helper
local function is_known_legit_php_upload_endpoint(uri)
  local u = lower(uri or "")
  if u == "" then return false end

  -- Code Snippets plugin REST API import/parse flow
  if u:match("^/wp%-json/code%-snippets/") then
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
local function body_budget(headers)
  local budget = CFG and CFG.body_scan_budget
  if not budget then
    return (CFG and CFG.max_scan_len) or 2048
  end
  if not headers then return budget.other end
  local raw = headers["content-type"]
  if raw == nil then raw = headers["Content-Type"] end
  local ct = header_string(raw)
  if ct == "" then return budget.other end
  ct = string.lower(ct)
  if string.find(ct, "application/json", 1, true)               then return budget.json end
  if string.find(ct, "multipart/form-data", 1, true)            then return budget.multipart end
  if string.find(ct, "application/x-www-form-urlencoded", 1, true) then return budget.urlencoded end
  if string.find(ct, "application/xml", 1, true)
     or string.find(ct, "text/xml", 1, true)                    then return budget.xml end
  return budget.other
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
