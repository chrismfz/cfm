-- Tests for the WP Rocket beacon detectors (CVE-2026-125812; WP Rocket
-- < 3.24.2):
--
--   rule 10034  rule_cve_wp_rocket_beacon         (WAF_CVE, block, autoblock held)
--     POST admin-ajax.php action=rocket_beacon whose `results` JSON carries a
--     preconnect_external_domain entry that is not a bare origin (NON_ORIGIN).
--
--   rule 10035  rule_cve_wp_rocket_beacon_unseen  (WAF_CVE, logonly)
--     the same request with a list the edge could not read: UNPARSED / OVERSIZE.
--
-- The legitimate request is the one wpr-beacon.js builds
-- (BeaconManager._saveFinalResultIntoDB, 3.24.1):
-- FormData action, rocket_beacon_nonce, url, is_mobile, status, results, the
-- preconnect entries `url.origin` values. The fix is OriginTrait::get_origin
-- (3.24.2): only scheme://host[:port] is kept.

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

local cfg = waf.get_config()
check(cfg.rule_cve_wp_rocket_beacon == "block",
      "rule_cve_wp_rocket_beacon ships at block (got " .. tostring(cfg.rule_cve_wp_rocket_beacon) .. ")")
check(cfg.rule_cve_wp_rocket_beacon_unseen == "logonly",
      "rule_cve_wp_rocket_beacon_unseen ships at logonly (got " .. tostring(cfg.rule_cve_wp_rocket_beacon_unseen) .. ")")

local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end

local UE = "application/x-www-form-urlencoded"
local AJAX = "/wp-admin/admin-ajax.php"
local function post(path, args, body, ct, extra_headers)
  local h = { ["Content-Type"] = ct or UE, ["Content-Length"] = tostring(#body) }
  for k, v in pairs(extra_headers or {}) do h[k] = v end
  return { uri = path, raw_uri = path .. (args ~= "" and ("?" .. args) or ""), args = args,
           method = "POST", ip = "203.0.113.93", headers = h, body = body, cookie = "" }
end
local function multipart(fields)
  local b = {}
  for _, f in ipairs(fields) do
    b[#b + 1] = "------WebKitFormBoundaryR\r\nContent-Disposition: form-data; name=\"" .. f[1] .. "\"\r\n\r\n" .. f[2] .. "\r\n"
  end
  b[#b + 1] = "------WebKitFormBoundaryR--\r\n"
  return table.concat(b), "multipart/form-data; boundary=----WebKitFormBoundaryR"
end
local function urlenc(s)
  return (s:gsub("[^%w%-_%.~]", function(c) return string.format("%%%02X", c:byte()) end))
end

-- the beacon's own request, `results` as given
local function beacon(results, ct_kind)
  local fields = {
    { "action", "rocket_beacon" }, { "rocket_beacon_nonce", "4f1c2e9ab0" },
    { "url", "https://shop.example.gr/product/x" }, { "is_mobile", "false" },
    { "status", "success" }, { "results", results },
  }
  if ct_kind == "ue" then
    local parts = {}
    for _, f in ipairs(fields) do parts[#parts + 1] = f[1] .. "=" .. urlenc(f[2]) end
    return post(AJAX, "", table.concat(parts, "&"), UE)
  end
  local b, ct = multipart(fields)
  return post(AJAX, "", b, ct)
end

local function fires(c, label, want, want_id, want_action)
  local hit, reason, _, action, _, id = waf.check(c)
  want_action = want_action or "block"
  check(hit == true and action == want_action, label .. " — " .. want_action .. " (got hit=" .. tostring(hit) .. " action=" .. tostring(action) .. ")")
  check(reason == want, label .. " — reason=" .. want .. " (got " .. tostring(reason) .. ")")
  if want_id then
    check(id == want_id, label .. " — rule id " .. want_id .. " (got " .. tostring(id) .. ")")
  end
end
local function clean(c, label)
  local hit, reason = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end

local NON = "WAF_CVE:CVE_2026_125812:WP_ROCKET:NON_ORIGIN"
local UNPARSED = "WAF_CVE:CVE_2026_125812:WP_ROCKET:UNPARSED"
local OVERSIZE = "WAF_CVE:CVE_2026_125812:WP_ROCKET:OVERSIZE"

set_only({ rule_cve_wp_rocket_beacon = "block", rule_cve_wp_rocket_beacon_unseen = "logonly" })

-- ═══ Legitimate beacons ══════════════════════════════════════════════════════
local LEGIT = '{"lcp":{"type":"img","src":"https://shop.example.gr/wp-content/uploads/hero.webp"},' ..
  '"lrc":["a1b2c3","d4e5f6"],"preload_fonts":["/wp-content/themes/t/fonts/inter.woff2"],' ..
  '"preconnect_external_domain":["https://fonts.googleapis.com","https://www.googletagmanager.com",' ..
  '"https://cdn.example.com:8443","http://[2001:db8::1]","null"]}'
clean(beacon(LEGIT), "real beacon (multipart, as FormData sends it)")
clean(beacon(LEGIT, "ue"), "real beacon, urlencoded")
clean(beacon('{"lcp":null,"lrc":null,"preload_fonts":null,"preconnect_external_domain":null}'),
      "beacon with every feature off")
clean(beacon('{"lcp":null,"lrc":null,"preload_fonts":null,"preconnect_external_domain":[]}'),
      "beacon with no external domain")
clean(beacon('{"preconnect_external_domain":["https://fonts.googleapis.com/"]}'),
      "origin with a trailing slash (the fix accepts it)")
clean(post(AJAX, "", "action=rocket_check_beacon&rocket_beacon_nonce=x&url=https%3A%2F%2Fa.gr&is_mobile=false"),
      "rocket_check_beacon (the read-back call)")
clean(post(AJAX, "", "action=other_action&results=" .. urlenc('{"preconnect_external_domain":["http://x/y.php"]}')),
      "another action with the same field")
do
  local c = beacon('{"preconnect_external_domain":["http://203.0.113.5/s.php"]}', "ue")
  c.method = "GET"
  clean(c, "GET (add_data reads $_POST)")
end

-- ═══ Rule 10034 — NON_ORIGIN ═════════════════════════════════════════════════
fires(beacon('{"preconnect_external_domain":["http://203.0.113.5/shell.php"]}'),
      "bare-IP payload host, .php path", NON, 10034)
fires(beacon('{"lcp":null,"lrc":null,"preload_fonts":null,"preconnect_external_domain":["https://fonts.googleapis.com","https://x.203-0-113-5.nip.io/a/wp-media-1.php"]}', "ue"),
      "nip.io payload behind a real origin, urlencoded", NON, 10034)
fires(beacon('{"preconnect_external_domain":["https://fonts.googleapis.com/css2?family=x"]}'),
      "the Host Fonts Locally leg (a Google Fonts CSS URL)", NON, 10034)
fires(beacon('{"preconnect_external_domain":"https://abc.trycloudflare.com/x.css.php"}'),
      "a single string, not a list ((array) cast)", NON, 10034)
fires(beacon('{"preconnect_external_domain":{"a":"https://ok.example","b":"//evil.example/x.php"}}'),
      "an object of entries, scheme-relative URL", NON, 10034)
fires(beacon('{"preconnect\\u005fexternal\\u005fdomain":["http:\\/\\/evil.example\\/x.ph\\u0070"]}'),
      "key and value written with JSON escapes", NON, 10034)
fires(beacon('{"preconnect_external_domain":[],"preconnect_external_domain":["http://e.example/?x=1"]}'),
      "duplicate key, the last one carries the payload", NON, 10034)
fires(beacon('{"preconnect_external_domain":["http://user@evil.example"]}'),
      "userinfo in the authority", NON, 10034)
fires(beacon('{"preconnect_external_domain":["http://evil.example\\\\x.php"]}'),
      "backslash", NON, 10034)
fires(beacon('{"preconnect_external_domain":["http://evil.example#frag"]}'),
      "fragment", NON, 10034)
fires(post(AJAX, "action=rocket_beacon", "results=" .. urlenc('{"preconnect_external_domain":["http://e.example/x.php"]}')),
      "action in the query ($_REQUEST), results in the body", NON, 10034)
fires(post("/blog/wp-admin/admin-ajax.php", "", "action=rocket_beacon&results=" .. urlenc('{"preconnect_external_domain":["http://e.example/x.php"]}')),
      "multisite subdirectory admin-ajax", NON, 10034)
fires(post("/wp-admin/admin-ajax.php/x", "", "action=rocket_beacon&results=" .. urlenc('{"preconnect_external_domain":["http://e.example/x.php"]}')),
      "PATH_INFO after admin-ajax.php", NON, 10034)
fires(post("/ajax", "", "action=rocket_beacon&results=" .. urlenc('{"preconnect_external_domain":["http://e.example/x.php"]}')),
      "renamed admin-ajax URL (Hide My WP) — keyed on the fields, not the path", NON, 10034)
fires(post(AJAX, "", "action=rocket%5Fbeacon&results=" .. urlenc('{"preconnect_external_domain":["http://e.example/x.php"]}')),
      "percent-encoded action value", NON, 10034)
fires(post(AJAX, "", "action=rocket_beacon&results=" .. urlenc('{"preconnect_external_domain":[]}') .. "&results=" .. urlenc('{"preconnect_external_domain":["http://e.example/x.php"]}')),
      "two results fields (PHP keeps the last)", NON, 10034)
fires(post("/WP-ADMIN/ADMIN-AJAX.PHP", "", "action=rocket_beacon&results=" .. urlenc('{"preconnect_external_domain":["http://e.example/x.php"]}')),
      "upper-case path", NON, 10034)
fires(post(AJAX, "", "action%00x=rocket_beacon&results=" .. urlenc('{"preconnect_external_domain":["http://e.example/x.php"]}')),
      "NUL-cut action name (PHP registers `action`)", NON, 10034)
fires(post(AJAX, "", "action=rocket_beacon&results=" .. urlenc(' \n{ "preconnect_external_domain" : [ "http://e.example/x.php" ] } ')),
      "JSON whitespace around the document", NON, 10034)

-- ═══ Rule 10035 — UNPARSED / OVERSIZE (logonly) ═════════════════════════════
fires(beacon('{"preconnect_external_domain":["http://e.example/x.php"]'),
      "truncated JSON naming preconnect", UNPARSED, 10035, "logonly")
fires(beacon('{"\\u0070reconnect_external_domain":["http://e.example/x.php"],}'),
      "escaped key in JSON the reader refuses", UNPARSED, 10035, "logonly")
clean(beacon('{"lcp":'), "broken JSON that names no preconnect entry")
do
  -- Content-Length says more than the edge holds: the list may be past the
  -- cut (the review's PoC: padding, or a benign results then an evil one)
  local c = post(AJAX, "", "action=rocket_beacon&pad=" .. string.rep("A", 100) .. "&results=" .. urlenc('{"preconnect_external_domain":[]}'))
  c.headers["Content-Length"] = "40000"
  fires(c, "body cut past waf_body_max_len (benign results seen, evil one past the cut)", OVERSIZE, 10034)
  -- the edge's own cap: a body of waf_body_max_len bytes is cut
  local pad = string.rep("A", 33000)
  local c2 = post(AJAX, "", "action=rocket_beacon&pad=" .. pad .. "&results=x")
  c2.body = c2.body:sub(1, 32768)
  fires(c2, "body at the edge's read cap", OVERSIZE, 10034)
  -- declared and never read (an HTTP/3 read failure under fail_open), action in the query
  local c3 = post(AJAX, "action=rocket_beacon", "")
  c3.headers["Content-Length"] = "900"
  fires(c3, "body declared and not read", OVERSIZE, 10034)
  -- cfm.lua's burn-in first pass holds the body back for the second: no hit
  local c4 = post(AJAX, "action=rocket_beacon", "")
  c4.headers["Content-Length"] = "900"
  c4.body_deferred = true
  clean(c4, "burn-in first pass (body deferred)")
  -- the panel gate reads no body
  local c5 = post(AJAX, "action=rocket_beacon", "")
  c5.headers["Content-Length"] = "900"
  c5.body_unread = true
  clean(c5, "a gate that reads no body")
end

-- ═══ Burn-in second pass: 10034 runs early and blocks ════════════════════════
do
  local c = beacon('{"preconnect_external_domain":["http://203.0.113.5/shell.php"]}')
  c.burnin_pass = true
  fires(c, "burn-in second pass (renamed path, chunked body)", NON, 10034)
end
-- the early copy must not double-record outside the burn-in pass, nor the late one inside it
do
  set_only({ rule_cve_wp_rocket_beacon = "block", rule_cve_wp_rocket_beacon_unseen = "logonly" })
  local c = beacon('{"preconnect_external_domain":["http://203.0.113.5/shell.php"]}')
  local _, _, _, _, hits = waf.check(c)
  local n = 0
  for _, h in ipairs(hits or {}) do if tostring(h):find("WP_ROCKET", 1, true) or (type(h) == "table" and tostring(h.reason or ""):find("WP_ROCKET", 1, true)) then n = n + 1 end end
  check(n <= 1, "one WP_ROCKET record per request (got " .. n .. ")")
end

-- ═══ Origin shapes ═══════════════════════════════════════════════════════════
clean(beacon('{"preconnect_external_domain":["chrome-extension://abcdefghijklmnop"]}'),
      "an extension origin (any scheme)")
fires(beacon('{"preconnect_external_domain":["http://e.example:80:x"]}'), "two ports", NON, 10034)
fires(beacon('{"preconnect_external_domain":["http://e.example:x"]}'), "a non-numeric port", NON, 10034)
fires(beacon('{"preconnect_external_domain":["http://a]b.php"]}'), "a bracket in a DNS host", NON, 10034)
fires(beacon('{"preconnect_external_domain":["http://.evil"]}'), "a host starting with a dot", NON, 10034)

-- ═══ The JSON reader ═════════════════════════════════════════════════════════
local J = det._rocket_json
check(J('{"a":[1,-2.5e3,true,false,null,"x"]}') ~= nil, "json: scalars")
check(J('{"a":01}') == nil, "json: a leading zero is refused (as json_decode does)")
check(J('{"a":1.}') == nil, "json: `1.` is refused")
check(J('{"a":"\\x"}') == nil, "json: an unknown escape is refused")
check(J('{"a":"' .. "\t" .. '"}') == nil, "json: a raw control character is refused")
check(J('[1] x') == nil, "json: trailing text is refused")
check(J('"\\ud83d\\ude00"') == "\240\159\152\128", "json: a surrogate pair decodes to UTF-8")
do
  -- PHP 8.3.6, default depth 512: 511 nested containers decode, 512 do not
  local deep = string.rep("[", 511) .. string.rep("]", 511)
  check(J(deep) ~= nil, "json: 511 nested containers decode")
  check(J("[" .. deep .. "]") == nil, "json: 512 are refused (Maximum stack depth exceeded)")
end

-- ═══ Both disabled → silent ══════════════════════════════════════════════════
set_only({})
clean(beacon('{"preconnect_external_domain":["http://203.0.113.5/shell.php"]}'), "rules disabled")

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_waf_cve_wp_rocket_test: OK")
