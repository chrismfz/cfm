-- Tests for the fetch-metadata-missing headless tell (rule 612,
-- WAF_FETCH_METADATA; Track-2 Stage 1b). Production tier: logonly (SHADOW).
--
-- The tell: a request that CLAIMS a modern Sec-Fetch-capable browser
-- (Chrome >= 76 / Firefox >= 90) yet sends a text/html GET|HEAD navigation with
-- NO Sec-Fetch-* AND NO Accept-Language — headers a real browser always emits on
-- a page load. Stacked so honest CLI clients (they don't claim a browser) and
-- self-declared crawlers (skipped) never match. See docs/challenge-score.md.

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

-- Isolate rule 612: disable every rule, then enable only this one at logonly.
local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end

-- A modern Chrome navigation UA and a Firefox one (both Sec-Fetch-capable).
local CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " ..
               "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
local FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"

-- Build a request ctx. headers keys are lowercase, matching ngx.req.get_headers().
local function req(method, ua, hdr)
  local headers = { ["user-agent"] = ua, ["accept"] = "text/html,application/xhtml+xml" }
  for k, v in pairs(hdr or {}) do headers[k] = v end
  return { uri = "/", args = "", method = method, ip = "203.0.113.50",
           headers = headers, body = "" }
end

local WANT = "WAF_FETCH_METADATA:NO_FETCH_META_NO_ACCEPT_LANG"

local function fires(c, label)
  local hit, reason, _, action = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == WANT, label .. " — reason (got " .. tostring(reason) .. ")")
  check(action == "logonly", label .. " — action=logonly (got " .. tostring(action) .. ")")
end
local function clean(c, label)
  local hit = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got hit=" .. tostring(hit) .. ")")
end

set_only({ rule_fetch_metadata_missing = "logonly" })

-- ── Positives: browser-claiming automation with no fetch metadata ────────────
fires(req("GET", CHROME), "Chrome UA, GET, no Sec-Fetch, no Accept-Language")
fires(req("HEAD", CHROME), "Chrome UA, HEAD navigation")
fires(req("GET", FIREFOX), "Firefox 115 UA, GET, no Sec-Fetch, no Accept-Language")
-- Chromium-family (Edge/Brave/Opera embed Chrome/NNN) is Sec-Fetch-capable too.
fires(req("GET", "Mozilla/5.0 ... Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0"),
      "Edge (Chrome/119 token) UA")

-- ── Negatives: real browsers (at least one of the two headers present) ───────
clean(req("GET", CHROME, { ["sec-fetch-site"] = "none", ["sec-fetch-mode"] = "navigate",
                           ["sec-fetch-dest"] = "document", ["accept-language"] = "en-US,en;q=0.9" }),
      "real Chrome: full Sec-Fetch + Accept-Language")
clean(req("GET", CHROME, { ["accept-language"] = "en-US,en;q=0.9" }),
      "Chrome with Accept-Language but no Sec-Fetch (needs BOTH missing)")
clean(req("GET", CHROME, { ["sec-fetch-mode"] = "navigate" }),
      "Chrome with a Sec-Fetch header present (any one stands the rule down)")
clean(req("GET", CHROME, { ["sec-fetch-user"] = "?1" }),
      "Sec-Fetch-User present is enough to stand down")
-- Presence, not value: a present-but-EMPTY Accept-Language counts as "sent"
-- (uniform with the Sec-Fetch treatment) and stands the rule down.
clean(req("GET", CHROME, { ["accept-language"] = "" }),
      "present-but-empty Accept-Language stands down (presence, not value)")
-- A real Chromium in-app WebView (Android `; wv`) IS Sec-Fetch-capable and sends
-- both headers on a navigation, so it never trips the tell.
clean(req("GET", "Mozilla/5.0 (Linux; Android 13; Pixel 7; wv) AppleWebKit/537.36 " ..
                 "(KHTML, like Gecko) Version/4.0 Chrome/120.0.0.0 Mobile Safari/537.36",
          { ["sec-fetch-site"] = "none", ["accept-language"] = "en-US" }),
      "real Android WebView with fetch metadata + Accept-Language")
-- Duplicate Accept-Language arrives as a TABLE from ngx.req.get_headers(); the
-- presence check (~= nil) must stand the rule down on it (pins the fold-in).
clean(req("GET", CHROME, { ["accept-language"] = { "en-US", "en" } }),
      "duplicate Accept-Language (table value) stands down via presence check")
-- Chrome-on-iOS uses the CriOS token, NOT chrome/, so it's a WebKit engine and is
-- correctly out of scope (same rationale as Safari) — pins the exclusion.
clean(req("GET", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 " ..
                 "(KHTML, like Gecko) CriOS/120.0.0.0 Mobile/15E148 Safari/604.1"),
      "Chrome-on-iOS (CriOS, WebKit engine) is out of scope like Safari")

-- ── Negatives: honest non-browser clients (never claim a browser) ────────────
clean(req("GET", "curl/8.4.0"), "curl does not claim a browser")
clean(req("GET", "python-requests/2.31.0"), "python-requests does not claim a browser")
clean(req("GET", "Wget/1.21.3"), "wget does not claim a browser")
clean(req("GET", ""), "empty UA is rule_bad_ua's job, not this tell")

-- ── Negatives: self-declared crawlers (separate category, skipped) ───────────
clean(req("GET", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html) " ..
                 "Chrome/120.0.0.0 Safari/537.36"),
      "Googlebot (carries Chrome/ token but self-declares)")
clean(req("GET", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"),
      "bingbot self-declares")
clean(req("GET", "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"),
      "ClaudeBot self-declares (AI crawler)")
clean(req("GET", "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com) " ..
                 "Chrome/120.0.0.0 Safari/537.36"),
      "Bytespider self-declares (spider token)")

-- ── Negatives: browser UA that predates Sec-Fetch (not a lie) ────────────────
clean(req("GET", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) " ..
                 "Chrome/60.0.3112.113 Safari/537.36"),
      "Chrome 60 predates Sec-Fetch (76+) — omitting it is honest, not a lie")
clean(req("GET", "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"),
      "Firefox 78 predates Sec-Fetch (90+)")
-- Safari is intentionally out of scope (16.4+ only; old iOS is a live FP pool).
clean(req("GET", "Mozilla/5.0 (iPhone; CPU iPhone OS 15_6 like Mac OS X) AppleWebKit/605.1.15 " ..
                 "(KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1"),
      "Safari-only UA is out of scope by design")

-- ── Negatives: not an HTML navigation ────────────────────────────────────────
clean(req("POST", CHROME), "POST is not a navigation this tell scopes to")
clean({ uri = "/api/x", args = "", method = "GET", ip = "203.0.113.51", body = "",
        headers = { ["user-agent"] = CHROME, ["accept"] = "application/json" } },
      "GET asking for application/json (API/XHR, not a text/html nav)")

-- ── Negatives: infrastructure paths (suppress-only path carve-out) ───────────
-- Legit crawlers + ACME/DCV/security validators fetch these header-poor; the
-- tell there is noise. A flagged client's real page fetches still trip it.
local function at(p, ua, hdr)
  local c = req("GET", ua, hdr)
  c.uri = p
  return c
end
clean(at("/robots.txt", CHROME), "/robots.txt is a header-poor legit fetch — exempt")
clean(at("/.well-known/acme-challenge/tokenXYZ", CHROME), "/.well-known/ (ACME/DCV) is exempt")
clean(at("/.well-known/security.txt", CHROME), "/.well-known/security.txt is exempt")
-- Control: a normal page path is still measured (the carve-out is path-scoped,
-- NOT a blanket disable of the tell).
fires(at("/product/asimenio-dachtylidi/", CHROME), "a normal page path still trips the tell")

-- ── Negatives: self-declared monitoring bot named in CRAWLER_UA_TOKENS ───────
-- SleepBot carries a Chrome/ token (so it would trip the tell) but self-declares
-- as SleepBot; it is exempted by its NAMED token, not a generic +http escape
-- (which would hand an attacker a one-substring skip of the shadow).
clean(req("GET", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; " ..
                 "SleepBot/1.0; +http://sleepbot.com/) Chrome/131.0.0.0 Safari/537.36"),
      "SleepBot self-declares (named token) — kept out of the shadow")

if fails > 0 then
  io.stderr:write(("cfm_waf fetch-metadata tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf fetch-metadata-missing headless tell (rule 612, WAF_FETCH_METADATA)")
