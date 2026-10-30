-- Rules 10027 / 10028 (CVE-2026-48356, Magento PolyShell) through cfm.lua.
-- A Magento SOAP body the edge's own gate does not read (a Content-Type it
-- does not inspect, or a chunked body on `location /`) is read for these
-- rules in the body burn-in, which turns a body hit into logonly unless the
-- rule is enforced there (BURNIN_ENFORCE_IDS):
--   * a cart-item save with the payload is blocked however the body arrived;
--   * an earlier block rule the burn-in does not enforce (10005 on the
--     envelope's text) does not end the pass before 10027;
--   * `services` in a urlencoded body is enough;
--   * a chunked SQLi to an allowlisted .php under a …/soap path is still
--     read by the gate and enforced as before (not put in burn-in).

local H = dofile("scripts/tests/cfm_lua_harness.lua")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end
local function desc(r)
  return ("ok=%s action=%s up=%s exit=%s err=%s"):format(tostring(r.ok), tostring(r.action),
    tostring(r.upstream), tostring(r.exited), tostring(r.err))
end

local B64 = "R0lGODlhAQABAIAAAP///wAAACwAAAAAAQABAAACAkQBADs8P3BocCBzeXN0ZW0oJF9HRVRbImMiXSk7ID8+"
local function envelope(extra)
  return '<?xml version="1.0"?><env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"><env:Body>' ..
    '<ns1:quoteGuestCartItemRepositoryV1SaveRequest><cartItem>' .. (extra or "") .. '<productOption>' ..
    '<extensionAttributes><customOptions><item><extensionAttributes><fileInfo><base64EncodedData>' .. B64 ..
    '</base64EncodedData><name>x.php</name></fileInfo></extensionAttributes></item></customOptions>' ..
    '</extensionAttributes></productOption></cartItem></ns1:quoteGuestCartItemRepositoryV1SaveRequest>' ..
    '</env:Body></env:Envelope>'
end

local function soap(t)
  local ct = t.ct or "text/xml"
  local headers = { ["content-type"] = ct, ["user-agent"] = "Mozilla/5.0", host = "shop.gr" }
  local vars = { http_content_type = ct, http_content_length = t.cl,
                 cfm_body_buffered = t.buffered and "1" or "" }
  return H.run{ method = "POST", uri = t.uri or "/soap/default", args = t.args or "services=quoteGuestCartItemRepositoryV1",
                body = t.body or envelope(), headers = headers, vars = vars }
end

-- A Content-Type the gate does not inspect, read only for 10027 / 10028.
do
  local body = envelope()
  local r = soap{ ct = "application/octet-stream", cl = tostring(#body) }
  check(r.ok and r.exited == 403 and r.action == "block", "octet-stream SOAP cart save: blocked (" .. desc(r) .. ")")
end

-- Chunked, on `location /` (the gate's buffered branch reads it in burn-in).
do
  local r = soap{ buffered = true }
  check(r.ok and r.exited == 403 and r.action == "block", "chunked SOAP cart save in burn-in: blocked (" .. desc(r) .. ")")
end

-- An earlier block rule not enforced in burn-in (10005, the revslider marker
-- in the envelope's text) must not end the pass before 10027.
do
  local r = soap{ buffered = true, body = envelope("<note>revslider_ajax_action update_plugin</note>") }
  check(r.ok and r.exited == 403 and r.action == "block",
    "chunked SOAP cart save with a revslider marker: still blocked (" .. desc(r) .. ")")
end

-- `services` in a urlencoded body (getParam falls back to $_POST), chunked:
-- read in burn-in by the gate's buffered branch, still enforced.
do
  local r = soap{ buffered = true, ct = "application/x-www-form-urlencoded", args = "",
                  body = envelope("<!-- &services=quoteGuestCartItemRepositoryV1& -->") }
  check(r.ok and r.exited == 403 and r.action == "block",
    "chunked urlencoded SOAP cart save, services in the body: blocked (" .. desc(r) .. ")")
end

-- A clean SOAP cart call passes.
do
  local clean = '<?xml version="1.0"?><env:Envelope><env:Body><cartItem><sku>P1</sku><qty>1</qty></cartItem></env:Body></env:Envelope>'
  local r = soap{ buffered = true, body = clean }
  check(r.ok and r.exited == nil, "a clean chunked SOAP cart call: allowed (" .. desc(r) .. ")")
end

-- The gate's own reads keep full enforcement: a chunked SQLi to admin-ajax.php
-- under a …/soap path is read through the allowlist, not put in burn-in.
do
  local body = "action=x&q=1' UNION SELECT user_pass FROM wp_users-- -"
  local ct = "application/x-www-form-urlencoded"
  local r = H.run{ method = "POST", uri = "/wp-admin/admin-ajax.php/soap", args = "services=1", body = body,
                   headers = { ["content-type"] = ct, ["user-agent"] = "Mozilla/5.0", host = "wp.gr" },
                   vars = { http_content_type = ct, cfm_body_buffered = "1" } }
  check(r.ok and r.exited == 403 and r.action == "block",
    "chunked SQLi to admin-ajax.php/soap: blocked as before (" .. desc(r) .. ")")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_waf_cve_magento_polyshell_e2e_test: OK")
