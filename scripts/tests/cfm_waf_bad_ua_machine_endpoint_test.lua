-- Regression: rule 201 (WAF_BAD_UA scored tier) must not challenge payment
-- webhooks. FP 2026-09-22 (rigel): Viva Wallet's webhooks POST with no
-- User-Agent, Accept or Referer, scoring UA_EMPTY(2)+NO_ACCEPT(1)+NO_REFERER(1)
-- = 4, the challenge threshold — a server-to-server POST can never solve it, so
-- every payment notification failed. The machine-style endpoint list exists to
-- drop those two browser-behaviour penalties on exactly these routes, but:
--   * its `/?wc-api=` entry never matched: the detector gets the decoded PATH
--     only, so WooCommerce's `?wc-api=<Gateway>` callbacks were scored like
--     browsers (mountain-house.gr, megashopgr.gr: /index.php?wc-api=wc_vivawallet);
--   * `/webhook` missed a receiver named after its gateway
--     (eloop.gr: /includes/payments/viva/viva_webhook.php).
-- The negatives are the fleet's other 30-day score=4 hits — every one an attack
-- or spam — which must keep firing.

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR = 0, WARN = 1, INFO = 2,
}

package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local snap = waf.get_config()
for k, _ in pairs(snap) do
  if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
end
waf.set_rule("rule_bad_ua", "challenge")

-- No User-Agent, no Accept, no Referer — the webhook sender's header set.
local function bare(method, uri, args, ct)
  return { uri = uri, args = args or "", method = method, ip = "51.138.37.238",
           headers = { ["Content-Type"] = ct }, body = "", cookie = "" }
end
local function clean(c, label)
  local hit, reason = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end
local function fires(c, label, want)
  local hit, reason = waf.check(c)
  check(hit == true, label .. " — must fire (got hit=" .. tostring(hit) .. ")")
  if want then check(reason == want, label .. " — reason " .. want .. " (got " .. tostring(reason) .. ")") end
end

local JSON = "application/json; charset=utf-8"
local SCORE4 = "WAF_BAD_UA:UA_EMPTY+NO_ACCEPT+NO_REFERER:score=4"

-- ── The FP: gateway webhooks stay clean ──────────────────────────────────────
clean(bare("POST", "/includes/payments/viva/viva_webhook.php", "", JSON),
      "Viva webhook receiver named after the gateway (eloop.gr)")
clean(bare("POST", "/index.php", "wc-api=wc_vivawallet&vivawallet=webhook", JSON),
      "WooCommerce ?wc-api= on /index.php (mountain-house.gr, megashopgr.gr)")
clean(bare("POST", "/shop/", "wc-api=wc_gateway_x", JSON),
      "WooCommerce ?wc-api= on a subdirectory home")
clean(bare("POST", "/index.php", "foo=1&wc-api=wc_vivawallet", JSON),
      "wc-api as a later query key")
clean(bare("POST", "/stripe-webhook.php", "", JSON), "stripe-webhook.php")
clean(bare("POST", "/wc-api/wc_vivawallet/", "", JSON), "pretty /wc-api/<Gateway>/ (already listed)")

-- ── The fleet's other score=4 hits (30 d) — attacks/spam, must keep firing ───
fires(bare("POST", "/hnap1"), "HNAP1 router exploit", SCORE4)
fires(bare("POST", "/guest_auth/guestIsUp.php"), "guest_auth probe", SCORE4)
fires(bare("POST", "/wp-comments-post.php", "", "application/x-www-form-urlencoded"),
      "no-UA comment spam", SCORE4)
fires(bare("POST", "/vpnsvc/connect.cgi", "", "image/jpeg"), "vpnsvc probe", SCORE4)
fires(bare("POST", "/cgi-bin/test-cgi", "", "application/x-www-form-urlencoded"), "test-cgi probe", SCORE4)
fires(bare("PUT", "/SDK/webLanguage", "", "application/xml"), "Hikvision SDK probe", SCORE4)
fires(bare("OPTIONS", "/forum/viewtopic.php", "t=30800"), "OPTIONS probe", SCORE4)

-- ── The wc-api relaxation is scoped, and machine-style never hides a target ──
-- (On `/` itself NO_REFERER never scores — it is an entry point — so the key
-- checks use /index.php, where a browser-less POST does reach score 4.)
fires(bare("POST", "/cgi-bin/test-cgi", "wc-api=1", "application/x-www-form-urlencoded"),
      "?wc-api= appended to an arbitrary probe path does not relax it", SCORE4)
fires(bare("POST", "/index.php", "wc-api=", JSON), "empty wc-api value", SCORE4)
fires(bare("POST", "/index.php", "x=wc-api=1", JSON), "wc-api inside another param's value (key-precise)", SCORE4)
fires(bare("GET", "/webhook/.env"), "sensitive file under a webhook-ish path still scores")

if fails > 0 then
  io.stderr:write(("cfm_waf bad-UA machine-endpoint tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf bad-UA machine-style endpoints (rule 201 webhook FP)")
