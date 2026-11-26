-- Tests for rule 202 (rule_ua_quoted, WAF_BAD_UA:QUOTED, logonly): a
-- User-Agent whose first byte is a double quote.
--
-- The positives are the tool's two UAs from the fleet's edge logs
-- (2026-11-26, every edge node; nginx logs the quote as \x22). The negatives
-- are real browsers, a UA with a quote inside it, a single quote, an empty
-- and an absent UA.

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

local MAC = '"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"'
local IPHONE = '"Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Mobile/15E148 Safari/604.1"'
local CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"

local function req(o)
  local h = { host = "e-athlos.com", accept = "text/html,application/xhtml+xml",
              ["accept-language"] = "el-GR,el;q=0.9", referer = "https://e-athlos.com/contact/" }
  if o.ua ~= false then h["user-agent"] = o.ua end
  local uri = o.uri or "/wp-json/contact-form-7/v1/contact-forms/1964/feedback"
  return { uri = uri, args = "", method = o.method or "POST", raw_uri = uri,
           host = "e-athlos.com", ip = "185.220.101.37", headers = h,
           body = o.body or "your-name=x&your-message=y", cookie = "" }
end

local function fires(c, label, want_action)
  local hit, reason, _, action, _, rid = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == "WAF_BAD_UA:QUOTED", label .. " — reason WAF_BAD_UA:QUOTED (got " .. tostring(reason) .. ")")
  check(rid == 202, label .. " — rule 202 (got " .. tostring(rid) .. ")")
  check(action == want_action, label .. " — " .. want_action .. " (got " .. tostring(action) .. ")")
end
local function clean(c, label)
  local hit, reason, _, _, hits, rid = waf.check(c)
  check(not (hit == true and rid == 202), label .. " — must NOT fire 202 (got " .. tostring(reason) .. ")")
  for _, h in ipairs(hits or {}) do
    check(h.waf_rule_id ~= 202, label .. " — 202 in hits")
  end
end

-- ── Shipped configuration ──────────────────────────────────────────────────
check(waf.get_config().rule_ua_quoted == "logonly", "202 ships logonly")
do
  -- With every shipped rule on, the quoted UA is still recorded.
  local _, _, _, _, hits = waf.check(req({ ua = MAC }))
  local seen = false
  for _, h in ipairs(hits or {}) do if h.waf_rule_id == 202 then seen = true end end
  check(seen, "defaults: 202 is in hits")
end

set_only({ rule_ua_quoted = "logonly" })

-- ── The tool ───────────────────────────────────────────────────────────────
fires(req({ ua = MAC }), "Mac Chrome 142, quoted, CF7 POST", "logonly")
fires(req({ ua = IPHONE, method = "GET", uri = "/", body = "" }), "iPhone, quoted, GET /", "logonly")
fires(req({ ua = '"' }), "a lone quote", "logonly")

-- ── Not the tool ───────────────────────────────────────────────────────────
clean(req({ ua = CHROME }), "a real Chrome")
clean(req({ ua = 'Mozilla/5.0 (compatible; Foo "bar")' }), "a quote inside the UA")
clean(req({ ua = CHROME .. '"' }), "a trailing quote only")
clean(req({ ua = "'Mozilla/5.0'" }), "single quotes")
clean(req({ ua = "" }), "empty UA")
clean(req({ ua = false }), "no UA header")
clean(req({ ua = ' "Mozilla/5.0"' }), "leading space (nginx strips it; not the measured shape)")

-- ── Modes ──────────────────────────────────────────────────────────────────
set_only({ rule_ua_quoted = "challenge_v2" })
fires(req({ ua = MAC }), "challenge_v2", "challenge_v2")
set_only({ rule_ua_quoted = "block" })
fires(req({ ua = MAC }), "block is capped at challenge_v2", "challenge_v2")
set_only({ rule_ua_quoted = "disabled" })
clean(req({ ua = MAC }), "disabled")

-- ── A block elsewhere still wins the headline ─────────────────────────────
set_only({ rule_ua_quoted = "logonly", rule_sqli = "block" })
do
  local c = req({ ua = MAC, method = "GET", uri = "/", body = "" })
  c.args = "id=1%20UNION%20SELECT%20username,password%20FROM%20users--"
  c.raw_uri = "/?" .. c.args
  local hit, _, _, action, hits, rid = waf.check(c)
  check(hit == true and action == "block" and rid == 301, "SQLi block keeps the headline (got " .. tostring(rid) .. ")")
  local also = waf.also_rule_ids(hits, rid) or {}
  local seen = false
  for _, id in ipairs(also) do if id == 202 then seen = true end end
  check(seen, "202 in also_rule_ids under a block")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_waf_ua_quoted_test: OK")
