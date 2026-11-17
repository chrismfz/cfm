-- Tests for rule 530 (rule_wc_cart_get_crawl, WAF_CART_CRAWL, logonly): a
-- WooCommerce add-to-cart GET from a crawler, or from a browser UA with no
-- same-site Referer / Fetch Metadata and no cart or login cookie.
--
-- The positives are requests from the fleet's edge logs (2026-11-17):
-- meta-externalagent on a shop listing, SERankingBacklinksBot, the rotating
-- residential "Chrome" clients Imunify360 also caught (/index.php and the
-- /ilv-blocked.txt decoy path). The negatives are a shopper's click (same-site
-- Referer, www or not; Fetch Metadata under a no-referrer policy), a shopper
-- with a cart or a login, the product form's POST, an empty id, the
-- add-to-cart scripts and a different parameter that only starts the same.

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

local CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
local META = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 (compatible; meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler))"
local SERANKING = "Mozilla/5.0 (compatible; SERankingBacklinksBot/1.0; +https://seranking.com/backlinks-crawler)"
local INDEXER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 (compatible; meta-webindexer/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler))"

-- o: { method, uri, args, ua, referer, site, cookie, host }
local function req(o)
  local host = o.host or "dreamworld.gr"
  local h = { host = host, ["user-agent"] = o.ua or CHROME, referer = o.referer,
              ["sec-fetch-site"] = o.site, cookie = o.cookie,
              accept = "text/html,application/xhtml+xml", ["accept-language"] = "el-GR,el;q=0.9" }
  if o.ua == false then h["user-agent"] = nil end
  return { uri = o.uri or "/", args = o.args or "", method = o.method or "GET",
           raw_uri = (o.uri or "/") .. ((o.args and o.args ~= "") and ("?" .. o.args) or ""),
           host = host, ip = "57.141.20.29", headers = h, body = o.body or "",
           cookie = o.cookie or "" }
end

local function fires(c, label, tag)
  local hit, reason, _, action, _, rid = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == "WAF_CART_CRAWL:" .. tag, label .. " — reason WAF_CART_CRAWL:" .. tag .. " (got " .. tostring(reason) .. ")")
  check(rid == 530, label .. " — rule 530 (got " .. tostring(rid) .. ")")
  check(action == "logonly", label .. " — logonly (got " .. tostring(action) .. ")")
end
local function clean(c, label)
  local hit, reason, _, _, _, rid = waf.check(c)
  check(not (hit == true and rid == 530), label .. " — must NOT fire 530 (got " .. tostring(reason) .. ")")
end

-- ── Shipped configuration ──────────────────────────────────────────────────
check(waf.get_config().rule_wc_cart_get_crawl == "logonly", "530 ships logonly")
fires(req({ uri = "/product-category/seasonally/", args = "max_price=20&per_page=12&add-to-cart=28781", ua = META }),
      "defaults: meta-externalagent on a listing", "CRAWLER")

set_only({ rule_wc_cart_get_crawl = "logonly" })

-- ── Crawlers (the fleet's 85%) ──────────────────────────────────────────────
fires(req({ uri = "/product-category/seasonally/", args = "max_price=20&per_page=12&add-to-cart=28781", ua = META }),
      "meta-externalagent", "CRAWLER")
fires(req({ uri = "/shop/page/15/", args = "add_to_wishlist=4784&_wpnonce=f22f48e363&add-to-cart=5030", ua = META }),
      "meta-externalagent, wishlist + add-to-cart", "CRAWLER")
fires(req({ uri = "/product/x/", args = "add-to-cart=12368", ua = SERANKING }), "SERankingBacklinksBot", "CRAWLER")
fires(req({ uri = "/product/x/", args = "add-to-cart=12368", ua = INDEXER }), "meta-webindexer", "CRAWLER")
-- A same-site Referer stands the rule down whatever the UA (forgeable; see
-- the in-app browser cases below for why).
clean(req({ uri = "/product/x/", args = "add-to-cart=12368", ua = META, referer = "https://dreamworld.gr/shop/" }),
      "crawler UA with a same-site Referer")
fires(req({ method = "HEAD", uri = "/product/x/", args = "add-to-cart=12368", ua = META }), "HEAD by a crawler", "CRAWLER")

-- ── Browser UA, no Referer (the residential rotation) ──────────────────────
fires(req({ uri = "/index.php", args = "add-to-cart=3308", host = "armafabrics.gr" }), "/index.php?add-to-cart", "NO_REFERER")
fires(req({ uri = "/ilv-blocked.txt", args = "add-to-cart=4280&avia_extended_shop_select=yes&product_order=price&product_sort=asc", host = "olicatessen.gr" }),
      "the /ilv-blocked.txt decoy path", "NO_REFERER")
fires(req({ uri = "/product/x/", args = "add-to-cart=3801", ua = false }), "no UA at all", "NO_REFERER")
-- The name as PHP reads it: an encoded name is the same field.
fires(req({ uri = "/", args = "add%2Dto%2Dcart=3801" }), "encoded name", "NO_REFERER")
-- Fetch Metadata that is not same-site does not stand it down.
fires(req({ uri = "/", args = "add-to-cart=3801", site = "none" }), "Sec-Fetch-Site none (typed / bookmark)", "NO_REFERER")
-- A cookie that is not a cart or a login does not either.
fires(req({ uri = "/", args = "add-to-cart=3801", cookie = "_ga=GA1.1.1; _fbp=fb.1.2" }), "tracking cookies only", "NO_REFERER")

-- ── Browser UA, another site's Referer ─────────────────────────────────────
fires(req({ uri = "/product/x/", args = "add-to-cart=3801", referer = "https://www.google.com/" }), "Referer google.com", "XSITE")
fires(req({ uri = "/product/x/", args = "add-to-cart=3801", referer = "https://www.skroutz.gr/s/123/x.html", site = "cross-site" }),
      "a comparison site, cross-site Fetch Metadata", "XSITE")

-- ── A shopper ──────────────────────────────────────────────────────────────
clean(req({ uri = "/shop/", args = "add-to-cart=3801", referer = "https://dreamworld.gr/shop/" }), "same-site Referer")
clean(req({ uri = "/shop/", args = "add-to-cart=3801", referer = "https://www.dreamworld.gr/shop/" }), "Referer on www., host bare")
clean(req({ uri = "/shop/", args = "add-to-cart=3801", host = "www.dreamworld.gr", referer = "https://dreamworld.gr/shop/" }),
      "Referer bare, host www.")
clean(req({ uri = "/shop/", args = "add-to-cart=3801", site = "same-origin" }), "no Referer, Sec-Fetch-Site same-origin")
clean(req({ uri = "/shop/", args = "add-to-cart=3801", site = "same-site" }), "no Referer, Sec-Fetch-Site same-site")
clean(req({ uri = "/shop/", args = "add-to-cart=3801", cookie = "wp_woocommerce_session_8e1e=1%7C%7C1%7C%7C2; woocommerce_items_in_cart=1" }),
      "a shopper with a cart")
clean(req({ uri = "/shop/", args = "add-to-cart=3801", cookie = "wordpress_logged_in_8e1e=staff%7C1%7Cabc" }), "a logged-in user")

-- ── People whose UA looks like a bot ──────────────────────────────────────
local PINTEREST_APP = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [Pinterest/iOS]"
local CUBOT = "Mozilla/5.0 (Linux; Android 13; CUBOT X50 Build/TP1A.220624.014) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Mobile Safari/537.36"
clean(req({ uri = "/shop/", args = "add-to-cart=3801", ua = PINTEREST_APP, referer = "https://dreamworld.gr/shop/" }),
      "Pinterest in-app browser, a same-site click")
clean(req({ uri = "/shop/", args = "add-to-cart=3801", ua = PINTEREST_APP, site = "same-origin" }),
      "Pinterest in-app browser, same-origin Fetch Metadata")
fires(req({ uri = "/shop/", args = "add-to-cart=3801", ua = CUBOT }), "a CUBOT phone is a browser UA", "NO_REFERER")
clean(req({ uri = "/shop/", args = "add-to-cart=3801", ua = CUBOT, referer = "https://dreamworld.gr/shop/" }),
      "a CUBOT phone, a same-site click")

-- ── Same site, strictly ────────────────────────────────────────────────────
clean(req({ uri = "/shop/", args = "add-to-cart=3801", referer = "https://m.dreamworld.gr/shop/" }), "Referer on a subdomain")
fires(req({ uri = "/shop/", args = "add-to-cart=3801", host = "shop.com.gr", referer = "https://other.com.gr/" }),
      "a sibling under a public suffix is another site", "XSITE")
fires(req({ uri = "/shop/", args = "add-to-cart=3801", host = "dreamworld.gr", referer = "https://notdreamworld.gr/" }),
      "a host that only ends the same", "XSITE")

-- ── Out of scope ───────────────────────────────────────────────────────────
clean(req({ method = "POST", uri = "/product/x/", args = "add-to-cart=3801" }), "POST (the product form)")
clean(req({ uri = "/product/x/", args = "add-to-cart=" }), "empty id")
clean(req({ uri = "/product/x/", args = "add-to-cart=abc" }), "non-numeric id")
clean(req({ uri = "/wp-content/plugins/woocommerce/assets/js/frontend/add-to-cart.min.js", args = "ver=9.2.5" }), "the add-to-cart script")
clean(req({ uri = "/product/x/", args = "add-to-cart-variation=5" }), "a different parameter (add-to-cart-variation)")
clean(req({ uri = "/product/x/", args = "page=add-to-cart" }), "add-to-cart as a value")
clean(req({ uri = "/product/x/", args = "ADD-TO-CART=3801" }), "upper-case name (PHP keys are case-sensitive)")
clean(req({ uri = "/product/x/", args = "Add-To-Cart=3801", ua = META }), "mixed-case name, crawler")

-- ── Disabled ───────────────────────────────────────────────────────────────
set_only({ rule_wc_cart_get_crawl = "disabled" })
clean(req({ uri = "/", args = "add-to-cart=3801", ua = META }), "rule disabled")

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_waf_cart_crawl_test: OK")
