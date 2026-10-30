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
-- custom_options + file_info + base64_encoded_data on a cart-save request (a
-- REST cart route, a SOAP cart service); 10028 (ban held) takes the same
-- names elsewhere and what keeps 10027 from reading the request.

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
  local deferred = opts.deferred
  local headers = { ["content-type"] = opts.ct or "application/json" }
  if opts.cl ~= false then headers["content-length"] = tostring(opts.cl or #body) end
  return {
    uri = uri, raw_uri = opts.raw or uri, args = opts.args or "", method = opts.method or "POST",
    ip = "213.163.195.0", headers = headers, body = body, cookie = "",
    body_unread = opts.unread, body_deferred = deferred,
  }
end

local function fires(ctx, tag, label, rule, want_action)
  local hit, reason, _, action, _, rule_id = waf.check(ctx)
  check(hit == true, label .. " — hit (got " .. tostring(hit) .. ")")
  check(reason == "WAF_CVE:CVE_2026_48356:MAGENTO_POLYSHELL:" .. tag,
    label .. " — reason …:" .. tag .. " (got " .. tostring(reason) .. ")")
  check(action == (want_action or "block"), label .. " — " .. (want_action or "block") .. " (got " .. tostring(action) .. ")")
  local want = rule or ((tag == "FILE_INFO") and 10027 or 10028)
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
fires(req(GUEST, '{ "cartItem" : { "custom_options"\n : [ { "file_info"\n  :\t{ "base64_encoded_data" : "R0lG" } } ] } }'),
  "FILE_INFO", "blanks before the colon")
fires(req(GUEST, attack_json(), { ct = "application/json; charset=utf-8" }), "FILE_INFO", "JSON with a charset")

-- The query, which Magento merges into a PUT's input
fires(req(GUEST .. "/5", "{}", { method = "PUT", args =
  "cartItem[product_option][extension_attributes][custom_options][0][option_value]=file" ..
  "&cartItem[product_option][extension_attributes][custom_options][0][extension_attributes][file%5Finfo][name]=x.php" ..
  "&cartItem[product_option][extension_attributes][custom_options][0][extension_attributes][file_info][base64_encoded_data]=R0lG" }),
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
fires(req("/soap/default", "<!-- &services=quoteGuestCartItemRepositoryV1& -->" .. SOAP:gsub("^<%?xml[^>]*>", ""),
  { ct = "application/x-www-form-urlencoded" }), "FILE_INFO", "SOAP with `services` in a form body")
fires(req("/soap/default", SOAP, { ct = "application/x-www-form-urlencoded" }), "FILE_INFO_ELSEWHERE",
  "SOAP naming no service: logged (10028)", 10028, "logonly")
fires(req("/shop/soap/default", SOAP, { args = "services=quoteCartRepositoryV1", ct = "text/xml" }), "FILE_INFO",
  "SOAP of a shop in a subdirectory, the quote save service")
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
  -- The cart-save routes reachable without an admin: an item is a few
  -- hundred bytes, so a cut body is refused (403, no ban), bulk included
  fires(req("/rest/default/async/bulk/V1/guest-carts/byCartId/items", "[" .. cut, { cl = 40000 }),
    "OVERSIZE", "a padded async/bulk guest call")
  fires(req("/rest/V1/carts/mine", cut, { method = "PUT", cl = 40000 }), "OVERSIZE", "a padded quote save")
  -- Anywhere else under /rest/, custom_options in the part the edge saw
  fires(req("/rest/V1/carts/5/items", '{"cartItem":{"product_option":{"extension_attributes":{"custom_options":[' ..
    string.rep(" ", 33000), { cl = 40000 }), "OVERSIZE", "custom_options seen, the rest cut (admin route)")
  -- SOAP: a cut body unless `services` names only other services
  local SOAP_HEAD = '<?xml version="1.0"?><!--' .. string.rep("A", 33000)
  fires(req("/soap/default", SOAP_HEAD, { cl = 40000, args = "services=quoteGuestCartItemRepositoryV1",
    ct = "text/xml" }), "OVERSIZE", "a SOAP call padded past the cut")
  fires(req("/soap/default", SOAP_HEAD, { cl = 40000, ct = "application/x-www-form-urlencoded" }), "OVERSIZE",
    "a padded SOAP call, services possibly in the form body past the cut")
  clean(req("/soap/server.php", SOAP_HEAD, { cl = 40000, ct = "text/xml" }), "a large envelope to a non-Magento SOAP server")
  clean(req("/rest/V1/orders", '{"entity":{"items":[{"product_option":{"extension_attributes":{"custom_options":[' ..
    string.rep(" ", 33000), { cl = 40000 }), "a large order write-back (custom_options, not a cart route)")
  clean(req(GUEST .. "/5", "", { method = "DELETE", cl = 2 }), "a cart item DELETE with a body")
  clean(req("/soap/default", SOAP_HEAD, { cl = 40000, args = "services=catalogProductRepositoryV1",
    ct = "text/xml" }), "a large SOAP product save")
  fires(req("/soap/default", "", { method = "DELETE", cl = 900, args = "services=quoteGuestCartItemRepositoryV1" }),
    "OVERSIZE", "a SOAP body sent with DELETE (the edge reads none)")
  clean(req("/soap/default", "", { method = "GET", cl = false, args = "wsdl&services=quoteGuestCartItemRepositoryV1" }),
    "fetching the WSDL")
  clean(req(GUEST, "", { cl = 300, unread = true }), "the panel gate (body_unread)")
end

-- A multipart POST: PHP fills $_POST, Magento merges it into the input
do
  local B = "--x\r\n"
  local function f(name, v) return B .. 'Content-Disposition: form-data; name="' .. name .. '"\r\n\r\n' .. v .. "\r\n" end
  local base = "cartItem[product_option][extension_attributes][custom_options][0]"
  local mp = f("cartItem[sku]", "P31629") .. f("cartItem[qty]", "1") .. f(base .. "[option_value]", "file") ..
    f(base .. "[extension_attributes][file_info][base64_encoded_data]", GIF_PHP_B64) ..
    f(base .. "[extension_attributes][file_info][name]", "x.php") .. "--x--\r\n"
  fires(req(GUEST, mp, { ct = "multipart/form-data; boundary=x" }), "FILE_INFO", "multipart form fields")
end
-- The names on a route that writes no file (an order an integration writes
-- back can carry them): 403, no ban
fires(req("/rest/V1/orders", '{"entity":{"items":[{"product_option":{"extension_attributes":{"custom_options":' ..
  '[{"extension_attributes":{"file_info":{"base64_encoded_data":"R0lG","name":"logo.png"}}}]}}}]}}'),
  "FILE_INFO_ELSEWHERE", "an order write-back with a file option: logged, not blocked", 10028, "logonly")
clean(req("/rest/V1/orders", '{"entity":{"items":[{"product_option":{"extension_attributes":{"custom_options":' ..
  '[{"extension_attributes":{"file_info":{"name":"logo.png"}}}]}}}]}}'), "an order write-back, no file content")
-- ext/soap's xsi:type Map builds keys from text the name scan does not read
fires(req("/soap/default", '<?xml version="1.0"?><env:Envelope><env:Body><cartItem><extensionAttributes ' ..
  'xsi:type="ns2:Map"><item><key>custom_options</key></item></extensionAttributes></cartItem></env:Body></env:Envelope>',
  { args = "services=quoteGuestCartItemRepositoryV1", ct = "text/xml" }), "UNREADABLE", "a SOAP-encoded Map")
clean(req("/soap/default", '<?xml version="1.0"?><env:Envelope><env:Body><quote><customAttributes><item>' ..
  '<attributeCode>c</attributeCode><value xsi:type="xsd:string">x</value></item></customAttributes></quote>' ..
  '</env:Body></env:Envelope>', { args = "services=quoteCartRepositoryV1", ct = "text/xml" }),
  "a SoapClient anyType value (xsi:type=xsd:string)")
-- The per-request scan cache must not carry one request's answer to another
do
  local base = "cartItem[product_option][extension_attributes][custom_options][0][extension_attributes][file_info]"
  local function mpb(bd) return "--BBB\r\n" ..
    'Content-Disposition: form-data; name="' .. base .. '[base64_encoded_data]"\r\n\r\nR0lG\r\n--BBB--\r\n' end
  clean(req(GUEST, mpb(), { ct = "multipart/form-data; boundary=AAA" }), "a multipart body under the wrong boundary")
  fires(req(GUEST, mpb(), { ct = "multipart/form-data; boundary=BBB" }), "FILE_INFO",
    "the same body under its boundary, right after")
end
-- cfm.lua's first pass over a burn-in body (body held back for a second
-- pass): nothing was cut, nothing to refuse yet
clean(req("/soap/default", "", { cl = 900, args = "services=quoteGuestCartItemRepositoryV1",
  ct = "application/octet-stream", deferred = true }), "the first pass over a deferred SOAP body")
clean(req(GUEST, "", { cl = false, deferred = true }), "the first pass over a deferred chunked cart body")
-- A caller that passes no raw path still gets the cart route from $uri
check(det.detect_cve_magento_polyshell(GUEST, nil, "post", "", attack_json(),
  { ["content-type"] = "application/json" }, {}) == "FILE_INFO", "unit: no raw path, route from $uri")
-- ASCII-compatible multibyte encodings are read
clean(req(GUEST, '<?xml version="1.0" encoding="Shift_JIS"?><cartItem><sku>P1</sku><qty>1</qty></cartItem>',
  { ct = "application/xml" }), "a Shift_JIS XML add-to-cart")
-- An unread form POST to a shop's own …/soap page is left alone
clean(req("/products/soap", "", { cl = 2000000, ct = "application/x-www-form-urlencoded" }),
  "an unread large form POST to a /soap page")
-- 10028 runs before the rules the burn-in second pass does not enforce
do
  waf.set_rule("rule_sqli", "block")
  fires(req("/soap/default", '<?xml version="1.0" encoding="UTF-16"?><a>x=1 union select 1,2,3 from information_schema.tables</a>',
    { args = "services=quoteGuestCartItemRepositoryV1", ct = "text/xml" }), "UNREADABLE",
    "an unreadable cart envelope that also trips 301")
  waf.set_rule("rule_sqli", "disabled")
end
-- With 10027 excluded or demoted (an integration's own uploads), 10028 must
-- not refuse the same cart-save request
waf.set_rule("rule_cve_magento_polyshell", "disabled")
clean(req(GUEST, attack_json()), "10027 excluded: 10028 leaves a cart-save request alone")
waf.set_rule("rule_cve_magento_polyshell", "block")
-- nginx can normalise $uri away from the route Magento reads on the raw path
fires(req("/", attack_json(), { raw = GUEST }), "FILE_INFO", "the route only on the raw path")

-- ── Not the attack ──────────────────────────────────────────────────────────
-- A shop's own /…/soap/ pages are not Magento's SOAP endpoint
clean(req("/product/soap/", "quantity=1&add-to-cart=55", { ct = "application/x-www-form-urlencoded" }),
  "a WooCommerce add-to-cart on a product called soap")
clean(req("/shop/soap/", '--x\r\nContent-Disposition: form-data; name="add-to-cart"\r\n\r\n55\r\n--x--\r\n',
  { ct = "multipart/form-data; boundary=x" }), "the same as multipart")
clean(req("/el/katigoria/soap", "a=1", { ct = "application/x-www-form-urlencoded" }), "a category called soap")
clean(req("/api/soap/check", '{"a":1}'), "an app folder called soap")
clean(req("/rest/V1/files/upload", "--json\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\n\r\n\0\1\2\r\n--json--\r\n",
  { ct = "multipart/form-data; boundary=json" }), "a binary multipart upload whose boundary says json")
clean(req("/soap/", "quantity=1&add-to-cart=55", { ct = "application/x-www-form-urlencoded" }),
  "a WooCommerce category at /soap/ (no services)")
-- /rest/ without Magento's /V<n>/ (Atlassian and the like)
clean(req("/rest/api/2/issue", '{"fields":{"customfield_1":{"custom_options":[1]},"attachment":{"file_info":"x"}}}'),
  "a Jira-style /rest/ API with both names")
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

-- The edge reads Magento's SOAP bodies whatever their Content-Type
do
  local f = assert(io.open("configs/lua/cfm.lua"))
  local src = f:read("*a"); f:close()
  local gate = src:find("local function waf_should_read_body(uri, method)", 1, true)
  local wrap = src:find("local function waf_should_read_body_or_soap(uri, method)", 1, true)
  local soap = src:find("pcall(wdet.magento_soap_call, lower(uri or \"\"), ngx.var.args)", 1, true)
  local flag = src:find("if soap then ngx.ctx.cfm_soap_burnin = true end", 1, true)
  local first = src:find("if waf_should_read_body(uri, method) then return true end", 1, true)
  check(gate and wrap and soap and flag and first and gate < wrap and wrap < soap and soap < flag and flag < first,
    "cfm.lua flags every Magento SOAP body, then reads one only where its gate would not")
  check(src:find('local BURNIN_ENFORCE_IDS = { ["10021"] = true, ["10024"] = true }', 1, true)
        and src:find('local SOAP_BURNIN_ENFORCE_IDS = { ["10027"] = true, ["10028"] = true }', 1, true)
        and src:find("ngx.ctx.cfm_soap_burnin and SOAP_BURNIN_ENFORCE_IDS[", 1, true),
    "10027 / 10028 are enforced in the burn-in of a SOAP body read for them only")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("OK: cfm_waf magento polyshell tests passed")
