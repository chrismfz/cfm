-- Tests for the PHP core multipart OOM detectors (rules 10021 and 10022,
-- WAF_CVE; CVE-2026-109618, the OOM producer of CVE-2026-109619). Production
-- tier: block (10021 armed, 10022 with its autoblock held).
--
-- Source: php-src advisories GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp
-- (2026-10-21). The OOM strategies they name, one leg each:
--   NO_CL         multipart POST without a usable Content-Length (10022)
--   PART_HEADERS  unlimited headers per multipart part
--   EMPTY_FILES   empty file controls (not counted by max_file_uploads)
--   NESTING       nested field names multiplying that work

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}

package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")
local det = require("cfm_waf_detectors")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end

local CT = "multipart/form-data; boundary=----WebKitFormBoundaryAbC123"
local B  = "------WebKitFormBoundaryAbC123"

local function field(name, value, extra)
  return B .. "\r\n" ..
    'Content-Disposition: form-data; name="' .. name .. '"\r\n' ..
    (extra or "") .. "\r\n" .. value .. "\r\n"
end
local function file(name, filename, bytes, ctype)
  return B .. "\r\n" ..
    'Content-Disposition: form-data; name="' .. name .. '"; filename="' .. filename .. '"\r\n' ..
    "Content-Type: " .. (ctype or "application/octet-stream") .. "\r\n\r\n" ..
    (bytes or "") .. "\r\n"
end
local function body(parts) return table.concat(parts) .. B .. "--\r\n" end

local function post(b, opts)
  opts = opts or {}
  local h = { ["Content-Type"] = opts.ct or CT }
  if not opts.no_cl then h["Content-Length"] = tostring(#b) end
  return {
    uri = opts.uri or "/wp-admin/async-upload.php", args = "", method = opts.method or "POST",
    ip = "203.0.113.91", headers = h, body = b, no_body_length = opts.no_cl == true,
  }
end

local function fires(c, label, tag)
  local hit, reason = waf.check(c)
  local want = "WAF_CVE:CVE_2026_109618:PHP:" .. tag
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want, label .. " — reason=" .. want .. " (got " .. tostring(reason) .. ")")
end
local function clean(c, label)
  local hit, reason = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end

set_only({ rule_cve_php_multipart_oom = "block", rule_cve_php_multipart_no_length = "block" })

local L = det.MP_OOM_LIMITS

-- ── Positives ───────────────────────────────────────────────────────────────
-- NO_CL: chunked / length-less multipart POST, with or without a body read.
fires(post(body({ field("a", "1") }), { no_cl = true }), "multipart POST without Content-Length", "NO_CL")
fires(post("", { no_cl = true }), "length-less multipart POST, body unread", "NO_CL")
fires(post(body({ field("a", "1") }), { no_cl = true, ct = "Multipart/Form-Data; boundary=----WebKitFormBoundaryAbC123" }),
      "media type case-insensitive", "NO_CL")
-- Both shapes on one request: the armed body rule (10021) runs first and
-- owns the hit, so the held length-less rule cannot take its ban.
do
  local hdrs = {}
  for i = 1, L.part_headers do hdrs[#hdrs + 1] = "X-Pad-" .. i .. ": a\r\n" end
  fires(post(body({ field("a", "1", table.concat(hdrs)) }), { no_cl = true }),
        "length-less AND too many part headers -> 10021", "PART_HEADERS")
end

-- PART_HEADERS: one part padded with header lines.
do
  local hdrs = {}
  for i = 1, L.part_headers do hdrs[#hdrs + 1] = "X-Pad-" .. i .. ": " .. string.rep("A", 40) .. "\r\n" end
  fires(post(body({ field("a", "1", table.concat(hdrs)) })), "part with too many headers", "PART_HEADERS")
  -- continuation lines count too (PHP stores them)
  local cont = { "X-Pad: a\r\n" }
  for _ = 1, L.part_headers do cont[#cont + 1] = " continued\r\n" end
  fires(post(body({ field("a", "1", table.concat(cont)) })), "header continuation lines", "PART_HEADERS")
end

-- EMPTY_FILES: many empty file controls (the max_file_uploads gap).
do
  local parts = {}
  for _ = 1, L.empty_files do parts[#parts + 1] = file("f[]", "", "") end
  fires(post(body(parts)), "many empty file controls", "EMPTY_FILES")
  -- truncated mid-body (the WAF scan window): still counted
  local b = table.concat(parts) .. B .. "\r\nContent-Disp"
  fires(post(b), "empty file controls, body cut at the scan window", "EMPTY_FILES")
end

-- NESTING: deeply nested names.
fires(post(body({ field("a" .. string.rep("[x]", L.nesting + 1), "1") })), "deeply nested field name", "NESTING")
fires(post(body({ file("a" .. string.rep("[]", L.nesting + 1), "", "") })), "deeply nested empty file control", "NESTING")
-- A closing delimiter does not end PHP's parse (find_boundary skips lines
-- until one EQUAL to --<bnd>): the parts after it still count.
do
  local parts = { field("a", "1"), B .. "--\r\n" }
  for _ = 1, L.empty_files do parts[#parts + 1] = file("f[]", "", "") end
  fires(post(body(parts)), "empty file controls after an early closing delimiter", "EMPTY_FILES")
  parts[2] = B .. "--x\r\n"
  fires(post(body(parts)), "empty file controls after a --<bnd>--x line", "EMPTY_FILES")
end
-- Only the FIRST Content-Disposition is read, with its own continuation lines;
-- a second one's continuation must not replace its name.
fires(post(body({ B .. "\r\n" ..
  'Content-Disposition: form-data; name="a' .. string.rep("[x]", L.nesting + 1) .. '"\r\n' ..
  "Content-Disposition: x\r\n" ..
  ' ; name="ok"\r\n\r\nv\r\n' })),
  "nested name, decoy second Content-Disposition with a continuation", "NESTING")
fires(post(body({ B .. "\r\n" ..
  'Content-Disposition: form-data;\r\n name="a' .. string.rep("[x]", L.nesting + 1) .. '"\r\n\r\nv\r\n' })),
  "nested name on the first Content-Disposition's continuation line", "NESTING")

-- ── Negatives ───────────────────────────────────────────────────────────────
-- WordPress media upload (async-upload.php).
clean(post(body({
  field("name", "photo.jpg"), field("action", "upload-attachment"), field("_wpnonce", "abcdef0123"),
  file("async-upload", "photo.jpg", "\255\216\255\224JFIF", "image/jpeg"),
})), "WP media upload")
-- WooCommerce product form with a few empty image slots and nested names.
do
  local parts = { field("product[name]", "Shoe"), field("product[attributes][0][values][1]", "red") }
  for i = 1, 10 do parts[#parts + 1] = file("product[images][" .. i .. "][file]", "", "") end
  clean(post(body(parts), { uri = "/wp-admin/post.php" }), "WooCommerce form, 10 empty file slots")
end
-- A part with the usual headers (Content-Disposition, Content-Type, CTE).
clean(post(body({ field("a", "1", "Content-Type: text/plain\r\nContent-Transfer-Encoding: 8bit\r\n") })),
      "part with three ordinary headers")
-- Exactly at the limits: not over them.
do
  local hdrs = {}
  for i = 1, L.part_headers - 1 do hdrs[#hdrs + 1] = "X-Pad-" .. i .. ": a\r\n" end
  clean(post(body({ field("a", "1", table.concat(hdrs)) })), "part headers at the limit")
  local parts = {}
  for _ = 1, L.empty_files - 1 do parts[#parts + 1] = file("f[]", "", "") end
  clean(post(body(parts)), "empty file controls below the limit")
  clean(post(body({ field("a" .. string.rep("[x]", L.nesting), "1") })), "nesting at the limit")
end
-- Brackets and many 'headers' inside a VALUE / file content are not headers.
clean(post(body({
  field("q", string.rep("[[[[", 40)),
  file("doc", "notes.txt", string.rep("X-Header: v\r\n", 50), "text/plain"),
})), "brackets and header-like lines in values / file bytes")
-- Not multipart: urlencoded / JSON without a Content-Length are other rules' job.
clean(post("a=1", { ct = "application/x-www-form-urlencoded", no_cl = true }), "urlencoded without CL")
clean(post('{"a":1}', { ct = "application/json", no_cl = true }), "json without CL")
-- A parameter merely mentioning multipart does not make PHP parse multipart.
clean(post("a=1", { ct = "text/plain; x=multipart/form-data", no_cl = true }), "text/plain naming multipart")
-- GET is never the exploit method.
clean({ uri = "/", args = "", method = "GET", ip = "203.0.113.92", headers = { ["Content-Type"] = CT }, body = "" },
      "GET with a multipart Content-Type")
-- No length flag from the caller (the panel gate, a resumed POST): the NO_CL
-- leg stays off even without a Content-Length header.
do
  local c = post(body({ field("comment", "hello") }), { no_cl = true, uri = "/wp-comments-post.php" })
  c.no_body_length = nil
  clean(c, "length unknown to the caller")
end
-- Mode disabled → silent.
set_only({ rule_cve_php_multipart_oom = "disabled" })
clean(post("", { no_cl = true }), "rule disabled")

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_waf_cve_php_multipart_oom_test: OK")
