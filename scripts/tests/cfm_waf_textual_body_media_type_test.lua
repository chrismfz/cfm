-- Rules 601 (ctrl chars) and 611 (bad UTF-8) read a body as text by its
-- MEDIA TYPE, as PHP picks its POST reader, not by a substring of the whole
-- Content-Type line. `application/x-www-form-urlencoded; x=multipart/form-data`
-- fills $_POST, and the substring test skipped it as multipart.

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
local function H(ct) return { ["content-type"] = ct } end

local CTRL = "a=\1\2\3"
local BAD  = "a=\192\175"            -- overlong `/` (0xC0 0xAF)

-- ── Positives: PHP parses these as text ──────────────────────────────────────
local TEXTUAL = {
  "application/x-www-form-urlencoded",
  "application/x-www-form-urlencoded; x=multipart/form-data",
  "application/x-www-form-urlencoded;x=multipart/form-data",
  "application/x-www-form-urlencoded,multipart/form-data; boundary=z",
  "Application/X-WWW-Form-Urlencoded; charset=multipart/form-data",
  "application/json; x=multipart/form-data",
  "text/plain; x=multipart/form-data",
  "",                                   -- no Content-Type: body read as text
}
for _, ct in ipairs(TEXTUAL) do
  check(det.detect_ctrl_chars("", CTRL, H(ct), "/") == true, "601 fires on CT " .. ct)
  check(det.detect_bad_utf8("", BAD, H(ct), "/") ~= nil, "611 fires on CT " .. ct)
end
-- A repeated Content-Type header (a table): PHP's type is the first line's.
local rep = { ["content-type"] = { "application/x-www-form-urlencoded", "multipart/form-data; boundary=z" } }
check(det.detect_ctrl_chars("", CTRL, rep, "/") == true, "601 fires: first CT line is urlencoded")
check(det.detect_bad_utf8("", BAD, rep, "/") ~= nil, "611 fires: first CT line is urlencoded")
-- Capitalised header key, as a test harness may pass it.
check(det.detect_ctrl_chars("", CTRL, { ["Content-Type"] = "application/x-www-form-urlencoded; x=multipart/form-data" }, "/") == true,
      "601 fires with a Content-Type key")

-- ── Negatives: PHP parses these as multipart / binary ────────────────────────
local BINARY = {
  "multipart/form-data; boundary=z",
  "Multipart/Form-Data; boundary=z",
  "multipart/form-data; x=application/x-www-form-urlencoded",
  "multipart/form-data; x=text/plain",
  "image/jpeg",
  "image/jpeg; x=text/plain",
  "application/octet-stream; x=application/json",
}
for _, ct in ipairs(BINARY) do
  check(det.detect_ctrl_chars("", CTRL, H(ct), "/") == false, "601 skips CT " .. ct)
  check(det.detect_bad_utf8("", BAD, H(ct), "/") == nil, "611 skips CT " .. ct)
end
local repm = { ["content-type"] = { "multipart/form-data; boundary=z", "application/x-www-form-urlencoded" } }
check(det.detect_ctrl_chars("", CTRL, repm, "/") == false, "601 skips: first CT line is multipart")
-- The query string is still read whatever the body's type.
check(det.detect_ctrl_chars(CTRL, CTRL, H("multipart/form-data; boundary=z"), "/") == true,
      "601 still reads args on a multipart request")
-- A clean body stays clean.
check(det.detect_ctrl_chars("", "a=1&b=2", H("application/x-www-form-urlencoded; x=multipart/form-data"), "/") == false,
      "601 quiet on a clean body")

-- Rule 404 shares the helper: an urlencoded body with the parameter is read.
local SHELL = "c=<?php system($_GET['x']); ?>"
check(det.detect_php_webshell_body(SHELL, H("application/x-www-form-urlencoded; x=multipart/form-data")) ~= nil,
      "404 reads an urlencoded body with a multipart parameter")
check(det.detect_php_webshell_body(SHELL, H("multipart/form-data; boundary=z")) == nil,
      "404 head pass still skips a multipart body")

-- ── End to end: cfm_waf.check with the shipped 601 tier ──────────────────────
local UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"
local function run(ct, body)
  local _, _, _, _, hits = waf.check({
    uri = "/", args = "", method = "POST", raw_uri = "/",
    host = "www.example.gr", ip = "198.51.100.9", body = body, cookie = "",
    headers = { host = "www.example.gr", ["user-agent"] = UA, accept = "*/*",
                ["content-type"] = ct },
  })
  for _, h in ipairs(hits or {}) do
    if tostring(h.waf_rule_id) == "601" then return h.action end
  end
  return nil
end
local mode601 = waf.get_config().rule_ctrl_chars
check(mode601 ~= "disabled", "premise: 601 ships enabled (" .. tostring(mode601) .. ")")
check(run("application/x-www-form-urlencoded; x=multipart/form-data", CTRL) == mode601,
      "601 hits in check() on the parameter trick")
check(run("multipart/form-data; boundary=z", CTRL) == nil, "601 silent in check() on multipart")

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_waf_textual_body_media_type_test: OK")
