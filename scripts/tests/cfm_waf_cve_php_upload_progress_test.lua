-- Tests for the PHP2Shell detectors (rules 10023 and 10024, WAF_CVE;
-- CVE-2026-109619, the session upload progress path, as the public PHP2Shell
-- tool exploits it). Production tier: block, both armed; 10024 is logonly when
-- the request carries a same-site Referer or Origin.
--
-- Sources: Imunify360 WAF ruleset 8.85 (rules 77318849, 77866818, 77236259)
-- and this fleet's edge logs of 2026-10-21 (ua="php2shell-scanner", POST /).

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}

package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")

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

local function field(name, value)
  return B .. "\r\n" .. 'Content-Disposition: form-data; name="' .. name .. '"\r\n\r\n' .. value .. "\r\n"
end
local function file(name, filename, bytes)
  return B .. "\r\n" ..
    'Content-Disposition: form-data; name="' .. name .. '"; filename="' .. filename .. '"\r\n' ..
    "Content-Type: application/octet-stream\r\n\r\n" .. (bytes or "") .. "\r\n"
end
local function body(parts) return table.concat(parts) .. B .. "--\r\n" end

-- The upload-progress body as PHP2Shell (and the php-src advisory) shape it:
-- the progress field first, then a file.
local PROGRESS = body({ field("PHP_SESSION_UPLOAD_PROGRESS", "x"), file("f", "a.txt", "zz") })

local function post(b, h)
  local headers = { ["Content-Type"] = CT, ["Host"] = "shop.example.gr" }
  for k, v in pairs(h or {}) do headers[k] = v end
  return { uri = "/", args = "", method = "POST", ip = "203.0.113.95", host = "shop.example.gr",
           headers = headers, body = b }
end

local function fires(c, label, tag, action)
  local hit, reason, _, act = waf.check(c)
  local want = "WAF_CVE:CVE_2026_109619:PHP:" .. tag
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want, label .. " — reason=" .. want .. " (got " .. tostring(reason) .. ")")
  if action then check(act == action, label .. " — action=" .. action .. " (got " .. tostring(act) .. ")") end
end
local function clean(c, label)
  local hit, reason = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end

set_only({ rule_cve_php_upload_progress = "block", rule_cve_php2shell_tool = "block" })

-- ── 10024 positives ─────────────────────────────────────────────────────────
fires(post(PROGRESS), "progress field, no Referer / Origin", "NO_REFERER", "block")
fires(post(PROGRESS, { Referer = "https://evil.example/x" }), "progress field, cross-site Referer", "XSITE", "block")
fires(post(PROGRESS, { Origin = "https://evil.example" }), "progress field, cross-site Origin", "XSITE", "block")
-- a Referer naming the host only in its path or as userinfo is cross-site
fires(post(PROGRESS, { Referer = "https://evil.example/shop.example.gr" }), "host in the Referer path", "XSITE")
fires(post(PROGRESS, { Referer = "https://shop.example.gr@evil.example/" }), "host as Referer userinfo", "XSITE")
fires(post(PROGRESS, { Referer = "https://shop.example.gr.evil.example/" }), "host as a Referer prefix", "XSITE")
-- "null" Origin, a relative Referer: no usable site
fires(post(PROGRESS, { Origin = "null" }), "Origin: null", "NO_REFERER")
fires(post(PROGRESS, { Referer = "/upload" }), "relative Referer", "NO_REFERER")
-- any case of the name (PHP compares it exactly: a superset)
fires(post(body({ field("php_session_upload_progress", "x") })), "lowercase name", "NO_REFERER")
-- as a file part's name too (Imunify reads FILES_NAMES)
fires(post(body({ file("PHP_SESSION_UPLOAD_PROGRESS", "a.txt", "zz") })), "file part named after it", "NO_REFERER")
-- after other fields, and with a quoted boundary
fires(post(body({ field("a", "1"), field("b", "2"), field("PHP_SESSION_UPLOAD_PROGRESS", "x") }),
           { ["Content-Type"] = 'multipart/form-data; boundary="----WebKitFormBoundaryAbC123"' }),
      "progress field third, quoted boundary", "NO_REFERER")
-- a same-site Referer on ANOTHER host of the same box is still cross-site
fires(post(PROGRESS, { Referer = "https://other.example.gr/" }), "Referer of another vhost", "XSITE")
-- a name split across header lines: PHP joins a continuation line, and a
-- NUL ends a 5120-byte line piece (both confirmed on PHP 8.3 to reach
-- upload progress); the name is read from the parse, never the raw body
local function raw_part(disp) return B .. "\r\n" .. disp .. "\r\n\r\nx\r\n" end
fires(post(body({ raw_part('Content-Disposition: form-data; name="PHP_SESSION_\r\nUPLOAD_PROGRESS"'),
                  file("f", "a.txt", "zz") })), "name split by a continuation line", "NO_REFERER", "block")
do
  local head = 'Content-Disposition: form-data; name="PHP_SESSION_'
  local pad = ("A"):rep(5120 - #head - 1)
  fires(post(body({ raw_part(head .. "\0" .. pad .. 'UPLOAD_PROGRESS"'), file("f", "a.txt", "zz") })),
        "name split by the 5120-byte line cut", "NO_REFERER", "block")
end
-- Sec-Fetch-Site same-site does not make an unrelated host same-site
fires(post(PROGRESS, { ["Sec-Fetch-Site"] = "same-site", Referer = "https://evil.example/" }),
      "same-site header, unrelated Referer", "XSITE", "block")
fires(post(PROGRESS, { ["Sec-Fetch-Site"] = "same-site", Host = "example.gr", Referer = "https://other.gr/" }),
      "same-site header, a different registrable domain", "XSITE", "block")
-- same-origin with Origin null but a Referer of another site
fires(post(PROGRESS, { ["Sec-Fetch-Site"] = "same-origin", Origin = "null", Referer = "https://evil.example/" }),
      "Origin null with a cross-site Referer", "XSITE", "block")
-- Origin null without Fetch Metadata
fires(post(PROGRESS, { Origin = "null" }), "Origin null, no Sec-Fetch-Site", "NO_REFERER", "block")

-- ── 10024: same site is logonly ─────────────────────────────────────────────
fires(post(PROGRESS, { ["Sec-Fetch-Site"] = "same-origin", Referer = "https://shop.example.gr/upload" }), "same-site Referer", "SAME_SITE", "logonly")
fires(post(PROGRESS, { ["Sec-Fetch-Site"] = "Same-Site", Referer = "http://SHOP.example.gr:8443/upload" }), "same-site Referer, case + port", "SAME_SITE", "logonly")
-- Referrer-Policy: no-referrer: the browser still sends Origin on a POST
fires(post(PROGRESS, { ["Sec-Fetch-Site"] = "same-origin", Origin = "https://shop.example.gr" }), "same-site Origin, no Referer", "SAME_SITE", "logonly")
fires(post(PROGRESS, { ["Sec-Fetch-Site"] = "same-origin", Host = "shop.example.gr:443", Origin = "https://shop.example.gr" }),
      "Host header with a port", "SAME_SITE", "logonly")
-- Sec-Fetch-Site same-site from www. or a sibling host
fires(post(PROGRESS, { ["Sec-Fetch-Site"] = "same-site", Host = "example.gr", Referer = "https://www.example.gr/up",
                       Origin = "https://www.example.gr" }), "www Referer to the apex", "SAME_SITE", "logonly")
fires(post(PROGRESS, { ["Sec-Fetch-Site"] = "same-site", Host = "www.example.gr", Origin = "https://example.gr" }),
      "apex Origin to www", "SAME_SITE", "logonly")
fires(post(PROGRESS, { ["Sec-Fetch-Site"] = "same-site", Referer = "https://cdn.example.gr/" }),
      "sibling host", "SAME_SITE", "logonly")
-- Referrer-Policy: no-referrer: Origin null, no Referer
fires(post(PROGRESS, { ["Sec-Fetch-Site"] = "same-origin", Origin = "null" }), "no-referrer policy", "SAME_SITE", "logonly")
fires(post(PROGRESS, { ["Sec-Fetch-Site"] = "same-site", Origin = "null" }), "no-referrer policy, sibling host", "SAME_SITE", "logonly")
-- no Host header: the request host (h2/h3 :authority) stands in
do
  local c = post(PROGRESS, { ["Sec-Fetch-Site"] = "same-origin", Referer = "https://shop.example.gr/" })
  c.headers.Host = nil
  local hit, reason, _, act = waf.check(c)
  check(hit and reason == "WAF_CVE:CVE_2026_109619:PHP:SAME_SITE" and act == "logonly",
        "no Host header falls back to ctx.host (got " .. tostring(reason) .. ")")
end
-- a trailing dot on the Host
fires(post(PROGRESS, { ["Sec-Fetch-Site"] = "same-origin", Host = "shop.example.gr.", Referer = "https://shop.example.gr/" }),
      "Host with a trailing dot", "SAME_SITE", "logonly")

-- A forged same-site Referer without Fetch Metadata (the scanner did this).
fires(post(PROGRESS, { Referer = "https://shop.example.gr/" }), "same-site Referer, no Sec-Fetch-Site", "NO_FETCH_METADATA", "block")
fires(post(PROGRESS, { ["Sec-Fetch-Site"] = "cross-site", Origin = "https://shop.example.gr" }),
      "same-site Origin, Sec-Fetch-Site cross-site", "NO_FETCH_METADATA", "block")
fires(post(PROGRESS, { ["Sec-Fetch-Site"] = "none", Referer = "https://shop.example.gr/" }),
      "same-site Referer, Sec-Fetch-Site none", "NO_FETCH_METADATA", "block")
-- Fetch Metadata alone does not make a request same-site.
fires(post(PROGRESS, { ["Sec-Fetch-Site"] = "same-origin" }), "Sec-Fetch-Site only", "NO_REFERER", "block")

-- ── 10024 negatives ─────────────────────────────────────────────────────────
clean(post(body({ field("comment", "PHP_SESSION_UPLOAD_PROGRESS is a PHP setting") })), "name only in a value")
clean(post(body({ field("PHP_SESSION_UPLOAD_PROGRESS_X", "1") })), "a longer field name")
clean(post(body({ field("a", "1") })), "plain multipart form")
clean(post("PHP_SESSION_UPLOAD_PROGRESS=1", { ["Content-Type"] = "application/x-www-form-urlencoded" }),
      "urlencoded body (PHP tracks multipart only)")
clean({ uri = "/", args = "PHP_SESSION_UPLOAD_PROGRESS=1", method = "GET", ip = "203.0.113.96",
        headers = { ["Content-Type"] = CT }, body = "" }, "GET with the name in the query")

-- ── 10023 positives ─────────────────────────────────────────────────────────
local function head_only(h)
  local headers = { Host = "shop.example.gr" }
  for k, v in pairs(h) do headers[k] = v end
  return { uri = "/", args = "", method = "GET", ip = "203.0.113.97", headers = headers, body = "" }
end
fires(head_only({ ["User-Agent"] = "php2shell-scanner" }), "tool UA (seen 2026-10-21)", "TOOL_UA", "block")
fires(head_only({ ["User-Agent"] = "PHP2Shell-1.0" }), "tool UA, case", "TOOL_UA")
fires(head_only({ ["Content-Type"] = "multipart/form-data; boundary=B7kQpoc614" }), "boundary B7kQpoc61N", "TOOL_BOUNDARY")
fires(head_only({ ["Content-Type"] = 'multipart/form-data; boundary="UctxPoc2077"' }), "boundary UctxPoc20NN quoted", "TOOL_BOUNDARY")
fires(head_only({ ["Content-Type"] = "multipart/form-data; boundary=------nphp619abc" }), "boundary --nphp619", "TOOL_BOUNDARY")
fires(head_only({ ["Content-Type"] = "multipart/form-data; boundary=x_php2shell_42" }), "boundary *php2shell*", "TOOL_BOUNDARY")
fires(head_only({ ["Content-Type"] = "multipart/form-data;boundary = B7kQpoc610" }), "spaces around =", "TOOL_BOUNDARY")
-- the tool's POST: the head rule owns it even before the body is read
fires(post(PROGRESS, { ["User-Agent"] = "php2shell-scanner", Referer = "https://shop.example.gr/",
                       ["Sec-Fetch-Site"] = "same-origin" }),
      "tool UA with forged same-site Referer + Fetch Metadata", "TOOL_UA", "block")
-- with only a forged Referer, 10024 (earlier in step 0) blocks it first
fires(post(PROGRESS, { ["User-Agent"] = "php2shell-scanner", Referer = "https://shop.example.gr/" }),
      "tool UA with a forged same-site Referer", "NO_FETCH_METADATA", "block")

-- ── 10023 negatives ─────────────────────────────────────────────────────────
clean(head_only({ ["User-Agent"] = "Mozilla/5.0 (php2shell-research)" }), "tool name not at the UA start")
clean(head_only({ ["Content-Type"] = "multipart/form-data; boundary=B7kQpoc6123" }), "B7kQpoc61 + two digits")
clean(head_only({ ["Content-Type"] = "multipart/form-data; boundary=UctxPoc2012x" }), "UctxPoc20NN + suffix")
clean(head_only({ ["Content-Type"] = "multipart/form-data; boundary=----WebKitFormBoundaryphp" }), "WebKit boundary ending in php")
clean(head_only({ ["Content-Type"] = "multipart/form-data; boundary=" .. ("-"):rep(71) .. "nphp618" }), "71 dashes before nphp618")
clean(head_only({ ["Content-Type"] = "text/plain; note=php2shell" }), "php2shell outside a boundary")

-- ── Modes ───────────────────────────────────────────────────────────────────
set_only({ rule_cve_php_upload_progress = "disabled", rule_cve_php2shell_tool = "disabled" })
clean(post(PROGRESS, { ["User-Agent"] = "php2shell-scanner" }), "both rules disabled")
set_only({ rule_cve_php_upload_progress = "logonly" })
fires(post(PROGRESS), "10024 set to logonly", "NO_REFERER", "logonly")

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_waf_cve_php_upload_progress_test: OK")
