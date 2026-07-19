-- Tests for the WooCommerce Payments unauth auth-bypass -> privesc detector
-- (rule 10012, WAF_CVE). Production tier: block. CVE-2023-28121.
--
-- determine_current_user_for_platform_checkout() trusts the
-- X-WCPAY-Platform-Checkout-User request header as the current user id with no
-- validation. Presence of the header is the entire exploit primitive and is
-- near-zero FP (server-set by WooPay only), so we key on header PRESENCE alone,
-- all methods / all paths. No cookie gate (it would only hand a trivial bypass).

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

local function req(method, uri, headers, body)
  return { uri = uri or "/", args = "", method = method or "GET", ip = "203.0.113.71",
           headers = headers or { ["User-Agent"] = "Mozilla/5.0" },
           body = body or "", cookie = "" }
end

local function fires(c, label, want_reason)
  local hit, reason = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want_reason, label .. " — reason=" .. want_reason .. " (got " .. tostring(reason) .. ")")
end
local function clean(c, label)
  local hit = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got hit=" .. tostring(hit) .. ")")
end

set_only({ rule_cve_woocommerce_payments = "block" })

local HDR = "WAF_CVE:CVE_2023_28121:WOOCOMMERCE_PAYMENTS:PLATFORM_CHECKOUT_HDR"

-- ── Positives — header presence, any casing / method / path ─────────────────
fires(req("POST", "/wp-json/wp/v2/users",
          { ["x-wcpay-platform-checkout-user"] = "1" },
          '{"username":"x","roles":["administrator"]}'),
      "lowercased header (production ngx form) on the admin-mint POST", HDR)
fires(req("GET", "/",
          { ["X-WCPAY-Platform-Checkout-User"] = "1" }),
      "PoC wire casing on a bare GET (all-methods / all-paths)", HDR)
fires(req("POST", "/wp-json/wc/v3/orders",
          { ["X-Wcpay-Platform-Checkout-User"] = "42" }),
      "Title casing, non-1 user id", HDR)

-- ── Negatives ───────────────────────────────────────────────────────────────
clean(req("POST", "/wp-json/wp/v2/users",
          { ["User-Agent"] = "Mozilla/5.0" },
          '{"username":"x","roles":["administrator"]}'),
      "same privesc request WITHOUT the WCPay header")
clean(req("GET", "/wp-admin/", { ["User-Agent"] = "Mozilla/5.0" }),
      "normal admin browse, no header")
clean(req("GET", "/", { ["X-Forwarded-For"] = "1.2.3.4" }),
      "unrelated X- header present")

if fails > 0 then
  io.stderr:write(("cfm_waf WooCommerce Payments CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf WooCommerce Payments auth-bypass -> privesc (rule 10012, CVE-2023-28121)")
