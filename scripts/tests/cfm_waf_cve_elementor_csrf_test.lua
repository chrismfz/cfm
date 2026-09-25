-- Tests for the Elementor 4.3.0/4.3.1 REST nonce bypass detector (rule 10018,
-- WAF_CVE). Production tier: block; autoblock held per rule (the source IP of a
-- CSRF is the victim). Fixed in Elementor 4.3.2 (advisory 2026-09-25, no CVE id).
--
-- 4.3.1's events proxy skipped core's REST nonce check whenever the raw
-- REQUEST_URI merely contained `elementor/v1/events/`; 4.3.2 checks the resolved
-- rest_route. The rule fires on the literal marker in the raw request target
-- when the route WordPress resolves ($_POST, then $_GET rest_route, else the
-- path after the first /wp-json/) is not /elementor/v1/events/.

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

-- raw: the raw request target ($request_uri). uri/args are derived from it the
-- way nginx exposes them (path + query string); pass no_raw to model the panel
-- gate, which sends no raw_uri.
local function req(method, raw, opts)
  opts = opts or {}
  local q = raw:find("?", 1, true)
  local headers = { ["user-agent"] = "Mozilla/5.0" }
  if opts.ct then headers["content-type"] = opts.ct end
  local body = opts.body or ""
  if opts.cl ~= false and (opts.ct or body ~= "") then
    headers["content-length"] = tostring(opts.cl or #body)
  end
  return {
    uri = q and raw:sub(1, q - 1) or raw, args = q and raw:sub(q + 1) or "",
    raw_uri = (not opts.no_raw) and raw or nil,
    method = method, ip = "203.0.113.18", headers = headers, body = body,
    cookie = opts.cookie or "wordpress_logged_in_abc=admin%7C1%7Cx",
  }
end

local function fires(c, label, tag)
  local hit, reason = waf.check(c)
  local want = "WAF_CVE:ELEMENTOR_4_3_2:ELEMENTOR:" .. tag
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want, label .. " — reason=" .. want .. " (got " .. tostring(reason) .. ")")
end
local function clean(c, label)
  local hit, reason = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end

local FORM = "application/x-www-form-urlencoded"
local MP   = "multipart/form-data; boundary=----b"
local function mp(name, value)
  return "------b\r\nContent-Disposition: form-data; name=" .. name .. "\r\n\r\n"
      .. value .. "\r\n------b--\r\n"
end

set_only({ rule_cve_elementor_events_nonce_bypass = "block" })

-- ── Positives: marker in the target, route resolves elsewhere ───────────────
fires(req("GET", "/wp-json/wp/v2/users/1?_method=POST&roles=administrator&x=elementor/v1/events/"),
      "top-level GET CSRF with ?_method=POST, marker in an unrelated param", "URI_MARKER")
fires(req("POST", "/wp-json/wp/v2/settings?elementor/v1/events/", { ct = "application/json", body = '{"title":"x"}' }),
      "JSON POST to core settings, marker as a bare query key", "URI_MARKER")
fires(req("DELETE", "/wp-json/wp/v2/posts/7?force=1&z=elementor/v1/events/"),
      "DELETE — every method is covered", "URI_MARKER")
fires(req("POST", "/wp-json/wp/v2/templates/theme//x/elementor/v1/events/", { ct = FORM, body = "content=x" }),
      "marker deep in the path of another route (catch-all route regex)", "URI_MARKER")
fires(req("GET", "/wp-json/wp/v2/x/wp-json/elementor/v1/events/"),
      "a second /wp-json/ later in the path is not the REST prefix", "URI_MARKER")
fires(req("GET", "/blog/sub/elementor/v1/events/?p=1"),
      "two segments before the marker and none is wp-json", "URI_MARKER")

fires(req("GET", "/?rest_route=/wp/v2/users/1&_method=POST&x=elementor/v1/events/"),
      "plain permalink: query rest_route names another route", "ROUTE_OVERRIDE")
fires(req("GET", "/?rest_route=/elementor/v1/events/api/x;rest_route=/wp/v2/users"),
      "`;` as a pair separator (arg_separator.input) smuggles a second rest_route", "ROUTE_OVERRIDE")
fires(req("GET", "/?rest_route[]=/elementor/v1/events/api/x"),
      "array rest_route is never Elementor's own call", "ROUTE_OVERRIDE")
fires(req("GET", "/?rest_route=%252Felementor%252Fv1%252Fevents%252F&x=elementor/v1/events/"),
      "double-encoded route value — PHP decodes once, so it is not the events route", "ROUTE_OVERRIDE")
fires(req("POST", "/wp-json/elementor/v1/events/api/track", { ct = FORM, body = "rest_route=/wp/v2/users/1&roles=administrator" }),
      "genuine events path, POST body rest_route overrides it ($_POST wins)", "ROUTE_OVERRIDE")
fires(req("POST", "/wp-json/elementor/v1/events/api/track", { ct = FORM, body = "rest.route=/wp/v2/users/1" }),
      "PHP name mangling: rest.route registers as rest_route", "ROUTE_OVERRIDE")
fires(req("POST", "/wp-json/elementor/v1/events/api/track", { ct = FORM, body = "rest%5Broute=/wp/v2/users/1" }),
      "PHP name mangling: encoded rest[route registers as rest_route", "ROUTE_OVERRIDE")
fires(req("POST", "/wp-json/elementor/v1/events/api/track", { ct = FORM, body = "a=1&rest_route%00zz=/wp/v2/users/1" }),
      "NUL ends the PHP variable name", "ROUTE_OVERRIDE")
fires(req("POST", "/wp-json/elementor/v1/events/api/track?rest_route=/elementor/v1/events/api/track",
          { ct = FORM, body = "rest_route=/wp/v2/users/1" }),
      "legit query rest_route does not excuse a POST override", "ROUTE_OVERRIDE")
fires(req("POST", "/wp-json/elementor/v1/events/api/track", { ct = MP, body = mp('"rest_route"', "/wp/v2/users/1") }),
      "multipart field rest_route overrides the path", "ROUTE_OVERRIDE")
fires(req("POST", "/wp-json/elementor/v1/events/api/track", { ct = MP, body = mp("rest_route", "/wp/v2/users/1") }),
      "multipart bare (unquoted) field name", "ROUTE_OVERRIDE")

fires(req("POST", "/wp-json/elementor/v1/events/api/track", { ct = FORM, body = ("a"):rep(32768), cl = 90000 }),
      "form body larger than the WAF window could hide an override", "BODY_UNSEEN")
fires(req("POST", "/?rest_route=/elementor/v1/events/api/track", { ct = FORM, body = "", cl = false }),
      "chunked form body the WAF did not read", "BODY_UNSEEN")

-- ── Negatives: Elementor's own proxy calls and near misses ──────────────────
clean(req("GET", "/wp-json/elementor/v1/events/libs/mixpanel-2-latest.min.js"),
      "pretty permalink: the Mixpanel library fetch")
clean(req("POST", "/wp-json/elementor/v1/events/api/track/?verbose=1&ip=1&_=1727250000",
          { ct = FORM, body = "data=eyJldmVudCI6InRlc3QifQ%3D%3D" }),
      "pretty permalink: a Mixpanel track batch")
clean(req("POST", "/wp-json/elementor/v1/events/api/record?format=body", { ct = "application/octet-stream", body = "\31\139binary" }),
      "session-replay upload (not a form body, so no $_POST)")
clean(req("POST", "/wp-json/elementor/v1/events/api/engage", { ct = "application/json", body = '{"rest_route":"/wp/v2/users"}' }),
      "JSON body text never reaches rest_route")
clean(req("POST", "/blog/wp-json/elementor/v1/events/api/track", { ct = FORM, body = "data=x" }),
      "subdirectory install")
clean(req("GET", "/index.php/wp-json/elementor/v1/events/libs/mixpanel.js"),
      "PATHINFO (/index.php/) permalinks")
clean(req("GET", "/api/elementor/v1/events/libs/mixpanel.js"),
      "root install with a custom rest_url_prefix")
clean(req("POST", "/?rest_route=/elementor/v1/events/api/track/?verbose=1&ip=1", { ct = FORM, body = "data=x" }),
      "plain permalink: Elementor's own call")
clean(req("POST", "/index.php?rest_route=/elementor/v1/events/api/track", { ct = FORM, body = "rest_route=/elementor/v1/events/api/track&data=x" }),
      "plain permalink with the same route echoed in the body")
clean(req("POST", "/?rest_route=/elementor/v1/events/api/track", { ct = FORM, body = "data=x", cl = false }),
      "resumed/chunked POST whose body the WAF did read")
clean(req("GET", "/wp-json/elementor/v1/events/api/track?next=elementor/v1/events/"),
      "marker twice, but the route really is the events proxy")
clean(req("GET", "/wp-json/wp/v2/users/me?x=elementor%2Fv1%2Fevents%2F"),
      "encoded marker — 4.3.1's raw strpos never saw it")
clean(req("GET", "/wp-json/wp/v2/users/me?x=Elementor/v1/events/"),
      "case-changed marker — strpos is case-sensitive")
clean(req("GET", "/wp-json/elementor/v1/kit-elements-defaults"),
      "other Elementor REST routes")
clean(req("GET", "/wp-json/wp/v2/posts?per_page=5"),
      "unrelated REST traffic")
clean(req("GET", "/wp-json/wp/v2/users/me?x=elementor/v1/events/", { no_raw = true }),
      "no raw_uri (the panel gate) — inert")

set_only({ rule_cve_elementor_events_nonce_bypass = "disabled" })
clean(req("GET", "/wp-json/wp/v2/users/1?_method=POST&x=elementor/v1/events/"), "rule disabled")

-- ── Order: the held rule never shadows an armed block rule ──────────────────
set_only({ rule_cve_elementor_events_nonce_bypass = "block", rule_sqli = "block" })
do
  local hit, reason = waf.check(req("GET", "/wp-json/wp/v2/posts?x=elementor/v1/events/&id=1%20union%20select%201,2,3--"))
  check(hit == true and reason and reason:sub(1, 8) == "WAF_SQLI",
        "armed SQLi keeps the headline over held rule 10018 (got " .. tostring(reason) .. ")")
end

if fails > 0 then
  io.stderr:write(("cfm_waf Elementor REST nonce bypass tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf Elementor 4.3.0/4.3.1 REST nonce bypass (rule 10018)")
