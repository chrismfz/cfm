-- Tests for detect_xss event-handler matching (audit F33, rule 302 WAF_XSS,
-- production tier: challenge).
--
-- The old checks required the handler name to be immediately followed by "="
-- (`onload=`), so an HTML-legal `onload =` / `onload\t=` (whitespace before the
-- `=`, which attribute parsers accept) evaded them — and only four handlers
-- were covered. Fix: one frontier gmatch captures each `on<word>` followed by
-- optional whitespace + `=` and checks it against an explicit handler set
-- (whitespace-tolerant; the set keeps benign `on…=` params like onboarding=
-- from matching; the frontier keeps the WPML `creationError=` non-match).
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

-- Payload in the query string (reflected-XSS vector); scan_str normalizes
-- (url-decode + lowercase) uri.."?"..args, so raw chars here are fine.
local function q(qs)
  return { uri = "/page", args = qs, method = "GET", ip = "203.0.113.90", headers = {}, body = "" }
end

local function fires(ctx, label)
  local hit, reason = waf.check(ctx)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == "WAF_XSS", label .. " — reason=WAF_XSS (got " .. tostring(reason) .. ")")
end
local function clean(ctx, label)
  local hit = waf.check(ctx)
  check(hit ~= true, label .. " — must NOT fire (got hit=" .. tostring(hit) .. ")")
end

set_only({ rule_xss = "block" })

-- ── F33: whitespace before '=' (was evaded) ──────────────────────────────────
-- All HTML after-attribute-name whitespace: space, tab, LF, CR, FF (%s covers
-- them; guards a future %s -> [ \t] regression).
fires(q("x=<svg onload =alert(1)>"),      "onload SPACE = (F33)")
fires(q("x=<svg onerror\t=alert(1)>"),    "onerror TAB = (F33)")
fires(q("x=<svg onload\n=alert(1)>"),     "onload LF = (F33)")
fires(q("x=<svg onload\r=alert(1)>"),     "onload CR = (F33)")
fires(q("x=<svg onload\f=alert(1)>"),     "onload FF = (F33)")
fires(q("x=<svg onLOAD =alert(1)>"),      "onLOAD uppercase + space (lowercased upstream)")
fires(q("x=<svg/onload=alert(1)>"),       "slash separator onload=")

-- ── Regressions: existing 4 handlers, immediate '=' ─────────────────────────
fires(q("x=<svg onerror=alert(1)>"),      "onerror= (regression)")
fires(q("x=<svg onload=alert(1)>"),       "onload= (regression)")
fires(q("x=<a onmouseover=alert(1)>"),    "onmouseover= (regression)")
fires(q("x=<input onfocus=alert(1) autofocus>"), "onfocus= (regression)")

-- ── New handlers now covered ────────────────────────────────────────────────
fires(q("x=<b style=animation-name:x onanimationstart=alert(1)>"), "onanimationstart (auto-fire)")
fires(q("x=<details open ontoggle=alert(1)>"),   "ontoggle (auto-fire)")
fires(q("x=<svg><animate onbegin=alert(1)>"),    "onbegin SVG SMIL (auto-fire)")
fires(q("x=<div onclick=alert(1)>"),             "onclick (interaction)")
fires(q("x=<body onpageshow=alert(1)>"),         "onpageshow")
fires(q("x=<div onpointerover =alert(1)>"),      "onpointerover + space")
fires(q("x=<marquee onstart=alert(1)>"),         "onstart marquee (auto-fire)")
fires(q("x=<video src=x onended=alert(1)>"),     "onended media")
fires(q("x=<div onpointerdown=alert(1)>"),       "onpointerdown")

-- ── Other XSS forms (regression: not handler-based) ─────────────────────────
fires(q("x=<script>alert(1)</script>"),          "<script>")
fires(q("x=%3cscript%3ealert(1)"),               "encoded <script")
fires(q("x=<a href=javascript:alert(1)>"),       "=javascript:")

-- ── FP-negatives ─────────────────────────────────────────────────────────────
clean(q("ateJobCreationError=101"),   "WPML creationError=101 (onerror inside creationError)")
clean(q("onboarding=1"),              "benign param onboarding= (in set-reject range)")
clean(q("online=true&once=1"),        "benign params online=/once=")
clean(q("callback=onload"),           "handler name as a VALUE, no '=' after")
clean(q("onclick_handler=x"),         "handler name is a prefix of a longer ident before '='")
clean(q("q=how to add an onclick in js"), "benign prose mentioning onclick (no '=' after handler)")

-- ── Accepted FP (documented tradeoff, not a bug) ─────────────────────────────
-- The frontier fires after ANY non-word boundary, so a reflected GET search for
-- a literal `handler=` code snippet trips a CHALLENGE (not a block). This
-- already applied to the old four handlers; the expanded set widens it to the
-- more search-common onclick/onchange. Kept intentionally: these are real
-- reflected-XSS vectors and challenge is a solvable interstitial. Asserted here
-- so the tradeoff is explicit and a future editor doesn't "fix" it by accident.
fires(q("q=how to use onclick=foo in html"), "ACCEPTED FP: reflected search for 'onclick=' snippet")
fires(q("s=onchange=handler"),               "ACCEPTED FP: search box value 'onchange=handler'")

if fails > 0 then
  io.stderr:write(("cfm_waf XSS event-handler tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf XSS event-handler whitespace + expanded set (F33, rule 302)")
