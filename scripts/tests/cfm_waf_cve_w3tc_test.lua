-- Tests for the W3 Total Cache mfunc RCE-surface detector
-- (rule 10006, WAF_CVE). Production tier: block. Two unauth legs:
--
-- Leg A — CVE-2026-5032: User-Agent containing "W3 Total Cache" bypasses output
--   buffering and leaks the W3TC_DYNAMIC_SECURITY token (zero FP — no legit UA).
-- Leg B — CVE-2025-9501: mfunc/mclude dynamic-fragment tag submitted as a blog
--   COMMENT -> W3TC evals it on cached render. Match the marker substring in a
--   POST to the comment endpoints.

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

local function req(method, uri, body, ua)
  return { uri = uri or "/", args = "", method = method or "GET", ip = "203.0.113.97",
           headers = { ["User-Agent"] = ua or "Mozilla/5.0" },
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

set_only({ rule_cve_w3tc = "block" })

local UA    = "WAF_CVE:CVE_2026_5032:W3TC:UA_TOKEN_LEAK"
local MFUNC = "WAF_CVE:CVE_2025_9501:W3TC:MFUNC"

-- ── Leg A — User-Agent token-leak bypass ────────────────────────────────────
fires(req("GET", "/", "", "Mozilla/5.0 W3 Total Cache"),
      "UA contains 'W3 Total Cache'", UA)
fires(req("GET", "/some/page/", "", "w3 total cache"),
      "UA marker case-insensitive", UA)

-- ── Leg B — mfunc/mclude via comment submission ─────────────────────────────
fires(req("POST", "/wp-comments-post.php", "author=x&comment=<!--mfunc%20echo%201;-->"),
      "mfunc in comment POST (wp-comments-post.php)", MFUNC)
fires(req("POST", "/wp-json/wp/v2/comments", '{"content":"<!--mclude /etc/passwd-->"}'),
      "mclude in REST comment POST", MFUNC)

-- ── Negatives ───────────────────────────────────────────────────────────────
clean(req("GET", "/", "", "Mozilla/5.0 (Windows NT 10.0)"),
      "normal UA")
clean(req("POST", "/wp-comments-post.php", "author=x&comment=Great post, thanks!"),
      "legit comment, no mfunc/mclude")
clean(req("POST", "/wp-json/wp/v2/posts", "content=<!--mfunc evil-->"),
      "mfunc but NOT a comment endpoint (scoped)")
clean(req("GET", "/wp-comments-post.php?comment=<!--mfunc-->", ""),
      "mfunc on a GET (comment submit is POST)")
clean(req("POST", "/wp-comments-post.php", "comment=I love dynamic_cache tuning"),
      "dynamic_cache is deliberately NOT matched (higher FP)")

if fails > 0 then
  io.stderr:write(("cfm_waf W3TC CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf W3 Total Cache mfunc RCE surface (rule 10006, CVE-2026-5032 + CVE-2025-9501)")
