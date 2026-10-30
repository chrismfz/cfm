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
-- (ServiceInputProcessor + hasMethod), so the detector does too. 10027 needs
-- custom_options + file_info in any web API request (/rest/, /soap); 10028 is
-- what keeps it from reading the request (held ban).

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
check(snap.rule_cve_magento_polyshell_unseen == "block", "rule 10028 ships at block (got " .. tostring(snap.rule_cve_magento_polyshell_unseen) .. ")")
for k, _ in pairs(snap) do
  if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
end
waf.set_rule("rule_cve_magento_polyshell", "block")
waf.set_rule("rule_cve_magento_polyshell_unseen", "block")

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
    uri = uri, raw_uri = opts.raw or uri, args = opts.args or "", method = opts.method or "POST",
    ip = "213.163.195.0", headers = headers, body = body, cookie = "",
    body_unread = opts.unread,
  }
end

local function fires(ctx, tag, label)
  local hit, reason, _, action, _, rule_id = waf.check(ctx)
  check(hit == true, label .. " — hit (got " .. tostring(hit) .. ")")
  check(reason == "WAF_CVE:CVE_2026_48356:MAGENTO_POLYSHELL:" .. tag,
    label .. " — reason …:" .. tag .. " (got " .. tostring(reason) .. ")")
  check(action == "block", label .. " — block (got " .. tostring(action) .. ")")
  local want = (tag == "FILE_INFO") and 10027 or 10028
  if rule_id ~= nil then
    check(tonumber(rule_id) == want, label .. " — rule " .. want .. " (got " .. tostring(rule_id) .. ")")
  end
end
local function clean(ctx, label)
  local hit, reason = waf.check(ctx)
  check(hit ~= true, label .. " — must not fire (got " .. tostring(reason) .. ")")
end

-- ── The attack, and every web API route that saves a cart item ─────────────
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
fires(req("/rest/default/V1/carts/mine", '{"quote":{"items":[{"sku":"x","qty":1,"product_option":' ..
  '{"extension_attributes":{"custom_options":[{"option_id":"1","option_value":"file","extension_attributes":' ..
  '{"file_info":{"base64_encoded_data":"' .. GIF_PHP_B64 .. '","name":"x.php"}}}]}}}]}}', { method = "PUT" }),
  "FILE_INFO", "the customer quote save (PUT /V1/carts/mine)")
fires(req(GUEST .. "/1/x", attack_json(), { method = "PUT", raw = GUEST .. "/1%2Fx" }), "FILE_INFO",
  "an itemId with %2F")

-- ── Spellings Magento reads as the same field ───────────────────────────────
fires(req(GUEST, attack_json("fileInfo", "base64EncodedData")), "FILE_INFO", "camelCase")
fires(req(GUEST, attack_json("FILE_INFO")), "FILE_INFO", "upper case")
fires(req(GUEST, attack_json("f_ile_info_")), "FILE_INFO", "extra underscores")
fires(req(GUEST, attack_json("\\u0066ile_info")), "FILE_INFO", "\\u-escaped key")
fires(req(GUEST, '{ "cartItem" : { "custom_options"\n : [ { "file_info"\n  :\t{} } ] } }'),
  "FILE_INFO", "blanks before the colon")
fires(req(GUEST, attack_json(), { ct = "application/json; charset=utf-8" }), "FILE_INFO", "JSON with a charset")

-- The query, which Magento merges into a PUT's input
fires(req(GUEST .. "/5", "{}", { method = "PUT", args =
  "cartItem[product_option][extension_attributes][custom_options][0][option_value]=file" ..
  "&cartItem[product_option][extension_attributes][custom_options][0][extension_attributes][file%5Finfo][name]=x.php" }),
  "FILE_INFO", "the payload in a PUT's query")

-- XML bodies (Magento's REST takes application/xml and text/xml)
local XML = '<?xml version="1.0"?><cartItem><sku>P1</sku><productOption><extensionAttributes>' ..
  '<customOptions><item><optionId>1</optionId><optionValue>file</optionValue><extensionAttributes>' ..
  '<fileInfo><base64EncodedData>' .. GIF_PHP_B64 .. '</base64EncodedData><name>x.php</name></fileInfo>' ..
  '</extensionAttributes></item></customOptions></extensionAttributes></productOption></cartItem>'
fires(req(GUEST, XML, { ct = "application/xml" }), "FILE_INFO", "REST XML")
fires(req(GUEST, "\239\187\191" .. XML, { ct = "text/xml" }), "FILE_INFO", "REST XML with a BOM")
fires(req(GUEST, (XML:gsub("<fileInfo>", "<ns:file_info>"):gsub("</fileInfo>", "</ns:file_info>")),
  { ct = "application/xml" }), "FILE_INFO", "namespaced snake_case element")
fires(req(GUEST, '<?xml version="1.0" encoding="windows-1252"?>' .. XML:gsub("^<%?xml[^>]*>", ""),
  { ct = "application/xml" }), "FILE_INFO", "windows-1252 is scanned")
fires(req(GUEST, '<?xml version="1.0"?><!DOCTYPE c [<!ENTITY f "x">]><cartItem>&f;</cartItem>',
  { ct = "application/xml" }), "XML_ENTITY", "XML entity declaration")
fires(req(GUEST, "<\0c\0a\0r\0t\0>\0", { ct = "application/xml" }), "UNREADABLE", "UTF-16 XML")
fires(req(GUEST, '<?xml version="1.0" encoding="UTF-7"?><cartItem/>', { ct = "application/xml" }),
  "UNREADABLE", "an exotic XML encoding")
fires(req(GUEST, 'x<cartItem/>', { ct = "application/xml" }), "UNREADABLE", "XML content type, body not XML")
local EBCDIC = "\76\111\167\148\148" -- stands for EBCDIC element bytes (not ASCII names)
fires(req(GUEST, '<?xml version="1.0"' .. string.rep(" ", 600) .. 'encoding="IBM037"?>' .. EBCDIC,
  { ct = "application/xml" }), "UNREADABLE", "an encoding padded past the first bytes")
fires(req(GUEST, '\239\187\191<?xml version="1.0" encoding="IBM037"?>' .. EBCDIC, { ct = "application/xml" }),
  "UNREADABLE", "an EBCDIC declaration after a BOM")
fires(req("/rest/V1/carts/mine", '{"a":"\0"}', { method = "PUT" }), "UNREADABLE", "a raw NUL in JSON")

-- SOAP: XML whatever the Content-Type, any route, any method with a body
local SOAP = '<?xml version="1.0"?><env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">' ..
  '<env:Body><ns1:quoteGuestCartItemRepositoryV1SaveRequest><cartItem><productOption><extensionAttributes>' ..
  '<customOptions><item><extensionAttributes><fileInfo><base64EncodedData>' .. GIF_PHP_B64 ..
  '</base64EncodedData></fileInfo></extensionAttributes></item></customOptions></extensionAttributes>' ..
  '</productOption></cartItem></ns1:quoteGuestCartItemRepositoryV1SaveRequest></env:Body></env:Envelope>'
fires(req("/soap/default", SOAP, { args = "services=quoteGuestCartItemRepositoryV1", ct = "application/soap+xml" }),
  "FILE_INFO", "SOAP guest cart item save")
fires(req("/soap", SOAP, { args = "services=quoteGuestCartItemRepositoryV1" }), "FILE_INFO", "SOAP on /soap (no store)")
fires(req("/soap/default", SOAP, { ct = "application/x-www-form-urlencoded" }), "FILE_INFO",
  "SOAP with `services` in the body, no query")
fires(req("/soap/default", SOAP, { method = "PATCH", args = "services=quoteGuestCartItemRepositoryV1" }),
  "FILE_INFO", "SOAP over PATCH")

-- ── Past the part of the body the edge reads (10028) ────────────────────────
do
  local cut = string.rep("a", 32768)
  fires(req(GUEST, cut, { cl = 106000 }), "OVERSIZE", "a body cut at the cap (the orion size)")
  fires(req(GUEST .. "/5", "", { method = "PUT", cl = 200000 }), "OVERSIZE", "a PUT the edge did not read")
  fires(req(GUEST .. "/5", "", { method = "PUT", cl = false }), "OVERSIZE", "a chunked PUT, unread")
  fires(req("/rest/V1/carts/mine/items", cut, { cl = 106000 }), "OVERSIZE", "carts/mine, cut")
  fires(req(GUEST .. "/1/v1/carts/1/items", "", { method = "PUT", cl = 200000,
    raw = GUEST .. "/1%2Fv1%2Fcarts%2F1%2Fitems" }), "OVERSIZE", "an itemId that decodes to another route")
  fires(req(GUEST .. "/async/bulk/5", "", { method = "PUT", cl = 200000,
    raw = GUEST .. "/async%2Fbulk%2F5" }), "OVERSIZE", "an itemId that decodes to async/bulk")
  -- carts/<id> is a common REST shape outside Magento: only the field blocks
  clean(req("/rest/v1/carts/123/items/9", "", { method = "PUT", cl = false }), "a non-Magento API's chunked PUT")
  clean(req("/rest/v1/carts/123/items", cut, { cl = 106000 }), "a non-Magento API's large POST")
  clean(req("/rest/async/bulk/V1/carts/mine/items", cut, { cl = 40000 }), "a large bulk request")
  clean(req("/rest/V1/carts/mine", cut, { method = "PUT", cl = 40000 }), "a large quote save")
  clean(req(GUEST, "", { cl = 300, unread = true }), "the panel gate (body_unread)")
end

-- ── Not the attack ──────────────────────────────────────────────────────────
local ADD = '{"cartItem":{"sku":"24-MB01","qty":2,"quote_id":"abc","product_option":' ..
  '{"extension_attributes":{"custom_options":[{"option_id":"3","option_value":"Engraving: file info"}]}}}}'
clean(req(GUEST, ADD), "an ordinary add-to-cart with a text option")
clean(req(GUEST .. "/77", '{"cartItem":{"qty":3,"quote_id":"abc"}}', { method = "PUT" }), "a quantity change")
clean(req(GUEST, '{"cartItem":{"sku":"x","qty":1,"custom_options":[{"option_value":"my \\"file_info\\": yes"}]}}'),
  "file_info inside a string value")
clean(req(GUEST, '{"cartItem":{"sku":"x","qty":1,"profile_information":"y","custom_options":[]}}'),
  "a key that only contains fileinfo")
clean(req(GUEST, attack_json("decoy", "base64_encoded_data")), "base64_encoded_data without file_info")
clean(req("/rest/default/V1/products/sku/media", '{"entry":{"content":{"base64_encoded_data":"' .. GIF_PHP_B64 ..
  '","type":"image/gif","name":"a.gif"}}}'), "admin product media (a legit base64 upload)")
clean(req("/rest/V1/files/upload", '{"fileInfo":{"name":"report.pdf"}}'), "a non-Magento API's fileInfo, no custom options")
clean(req("/rest/default/V1/guest-carts", ""), "creating a guest cart (no body)")
clean(req("/checkout/cart/add/", attack_json()), "the storefront form route")
clean(req("/graphql", attack_json()), "GraphQL")
clean(req("/wp-json/wc/store/v1/cart/add-item", attack_json()), "a non-/rest/ API")
clean({ uri = GUEST, args = "", method = "GET", ip = "203.0.113.1", headers = {}, body = "" }, "a GET")
clean(req(GUEST, '<?xml version="1.0"?><cartItem><sku>P1</sku><customOptions><item><optionValue>' ..
  'see file_info = attached</optionValue></item></customOptions></cartItem>', { ct = "application/xml" }),
  "file_info = in an XML text node")
clean(req(GUEST, '<?xml version="1.0" encoding="windows-1252"?><cartItem><sku>P1</sku><qty>1</qty></cartItem>',
  { ct = "application/xml" }), "a windows-1252 XML add-to-cart")
clean(req(GUEST, XML, { ct = "application/json" }), "an XML body sent as JSON (Magento cannot read it)")
fires(req(GUEST, attack_json(), { method = "PATCH" }), "FILE_INFO", "PATCH with the payload (blocked whatever the route does)")

-- ── Unit ────────────────────────────────────────────────────────────────────
check(det.detect_cve_magento_polyshell(GUEST, GUEST, "post", "", ADD, { ["content-type"] = "application/json" }) == nil,
  "unit: ordinary add")
check(det.detect_cve_magento_polyshell(GUEST, GUEST, "delete", "", attack_json(), { ["content-type"] = "application/json" }) == nil,
  "unit: DELETE is not a write")
check(det.detect_cve_magento_polyshell_unseen(GUEST, nil, "post", "", ADD,
  { ["content-type"] = "application/json", ["content-length"] = tostring(#ADD) }) == nil, "unit: an ordinary add is read whole")

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("OK: cfm_waf magento polyshell tests passed")
