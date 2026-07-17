-- Tests for the CRLF / HTTP response-splitting detector's case-sensitivity fix
-- (audit F34, rule 605 WAF_CRLF, production tier: challenge).
--
-- The raw-CR/LF branch matched the lowercase header-name literals (set-cookie,
-- location, content-type/length) against the UN-lowercased scan string, so a
-- body value injecting a raw newline followed by a conventionally-capitalized
-- header name (Set-Cookie:, Location:) evaded detection. The URL-encoded branch
-- already lowercased. Fix: lowercase once and match the raw branch against the
-- lowercased copy too (CR/LF bytes are unaffected by lower()).
--
-- Tested at "block" for a crisp hit=true assertion (rule-319/606 test
-- convention); the production tier is unchanged (challenge).

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

local function post(body)
  return {
    uri = "/submit.php", args = "", method = "POST", ip = "203.0.113.71",
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" }, body = body,
  }
end
local function get(qs)
  return { uri = "/index.php", args = qs, method = "GET", ip = "203.0.113.72", headers = {}, body = "" }
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

set_only({ rule_crlf_injection = "block" })

-- ── F34: raw newline + CANONICALLY-CAPITALIZED header name (was missed) ──────
fires(post("x=foo\r\nSet-Cookie: sid=evil"),      "capitalized Set-Cookie (body)",   "WAF_CRLF:CRLF_SET_COOKIE")
fires(post("x=foo\r\nLocation: http://evil/"),    "capitalized Location (body)",     "WAF_CRLF:CRLF_LOCATION")
-- Content-Type / Content-Length in a BODY are now tolerated (args-scoped): a
-- request body carrying `\r\nContent-Type:` is legit data (multipart part
-- headers, page-builder save payloads), never reflected into a response header.
clean(post("x=foo\r\nContent-Type: text/html"),   "Content-Type in BODY tolerated (FP fix)")
clean(post("x=foo\r\nContent-Length: 0"),         "Content-Length in BODY tolerated (FP fix)")
-- …but Content-Type / Content-Length in the ARGS (query string) still fire —
-- query-string reflection into a response header is the real vector.
fires(get("r=/x\r\nContent-Type: text/html"),     "Content-Type in ARGS still fires", "WAF_CRLF:CRLF_CONTENT_TYPE")
fires(get("r=/x\r\nContent-Length: 0"),           "Content-Length in ARGS still fires", "WAF_CRLF:CRLF_CONTENT_LENGTH")
fires(post("x=a\r\nSeT-cOOkIe: y"),               "mixed-case Set-Cookie",           "WAF_CRLF:CRLF_SET_COOKIE")
fires(get("r=/x\r\nLocation: http://evil/"),      "capitalized Location (args)",     "WAF_CRLF:CRLF_LOCATION")
-- Bare LF (no CR) with a capital header name also trips.
fires(post("x=a\nSet-Cookie: z"),                 "bare-LF capitalized Set-Cookie",  "WAF_CRLF:CRLF_SET_COOKIE")

-- ── Regressions: lowercase raw and URL-encoded branches still fire ───────────
fires(post("x=a\r\nset-cookie: y"),               "lowercase set-cookie (regression)", "WAF_CRLF:CRLF_SET_COOKIE")
fires(post("x=a%0d%0aSet-Cookie:%20y"),           "URL-encoded capitalized (regression)", "WAF_CRLF:CRLF_URL_ENCODED")

-- ── FP-negatives: the [\r\n] anchor is required; a header name alone is fine ──
clean(post("x=set-cookie: foo"),                  "header name but NO newline")
clean(post("x=Set-Cookie preferences saved"),     "capitalized token, no colon/newline")
clean(get("q=how to set a cookie in php"),         "benign prose mentioning set cookie")
clean(post("comment=hello world\r\nthanks again"), "body newline but no header injection")

if fails > 0 then
  io.stderr:write(("cfm_waf CRLF case-sensitivity tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf CRLF case-insensitive raw-header matching (F34, rule 605)")
