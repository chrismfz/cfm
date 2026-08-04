-- Tests for the vBulletin runMaths() unauth RCE detector (rule 10015,
-- WAF_CVE). Production tier: block. CVE-2026-61511 (vBulletin 5.x <=5.7.5 /
-- 6.x <=6.2.1).
--
-- vB5_Template_Runtime::runMaths() strips its input to [0-9().^<>&|+*/=-] then
-- eval()s it. It is reached UNAUTHENTICATED via ajax/render/<template> — the
-- default "pagenav" template routes the tainted pagenav[pagenumber] into a
-- {vb:math} tag. Because the sink allows only digits + operators, the exploit
-- ("phpfuck") builds every character of system()/the command from XOR (^) of
-- parenthesised digit literals, so NO literal system/eval/<?php/chr/base64
-- token appears — every generic RCE/webshell/obfuscation detector misses it.
-- We key on the ajax/render route + the phpfuck blob SHAPE. Payloads below are
-- modelled on the public PoC (karmainsecurity CVE-2026-61511.php), not memory.

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

-- Body-capable request (the PoC POSTs routestring + pagenav[pagenumber]).
local function req(method, uri, args, body)
  return { uri = uri or "/", args = args or "", method = method or "POST", ip = "203.0.113.90",
           headers = { ["User-Agent"] = "Mozilla/5.0", ["Content-Type"] = "application/x-www-form-urlencoded" },
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

set_only({ rule_cve_vbulletin_runmaths = "block" })

local R = "WAF_CVE:CVE_2026_61511:VBULLETIN:RUNMATHS_RCE"

-- The PoC's per-character constant ($chr_fun), 9-run trimmed for the test but
-- structurally identical: parenthesised digit literals XOR-combined.
local CHR = "((((99999999999999999999).(9))^((2).(0).(4)))^((8).(6).(((9).(9))^((9).(9)))))"
-- makePayload("system", cmd) shape: chr-constant chained with `.` + a call.
local PHPFUCK = CHR .. "((6).(5))." .. CHR .. "((7).(3))." .. CHR .. "((1).(2).(1))"
-- URL-encoded form of the same blob (what http_build_query actually sends).
local ENC = (PHPFUCK:gsub("[%(%)%^]", { ["("] = "%28", [")"] = "%29", ["^"] = "%5E" }))

-- ── Positives ───────────────────────────────────────────────────────────────
fires(req("POST", "/", "", "routestring=ajax/render/pagenav&pagenav[pagenumber]=" .. PHPFUCK),
      "PoC: POST body routestring=ajax/render/pagenav + phpfuck pagenav[pagenumber]", R)
fires(req("POST", "/", "", "routestring=ajax%2Frender%2Fpagenav&pagenav%5Bpagenumber%5D=" .. ENC),
      "PoC url-encoded body (normalize decodes route + payload)", R)
fires(req("GET", "/ajax/render/pagenav", "pagenav[pagenumber]=" .. PHPFUCK, ""),
      "friendly-URL GET: ajax/render in the path + phpfuck in args", R)
fires(req("POST", "/index.php", "routestring=ajax/render/pagenav", "pagenav[pagenumber]=" .. PHPFUCK),
      "route in query string, phpfuck in body", R)

-- ── Adversarial regressions (red-team review 2026-08) ────────────────────────
-- Bypass 1: intersperse characters runMaths() STRIPS (spaces + letters) between
-- tokens. The sink deletes them and reconstructs the clean payload for eval();
-- the projection in has_phpfuck_blob must delete them too so the blob is scored.
local STRIP_EVADE = (PHPFUCK:gsub("%)", ")x ")) -- inject a letter+space after every ')'
fires(req("POST", "/", "", "routestring=ajax/render/pagenav&pagenav[pagenumber]=" .. STRIP_EVADE),
      "bypass1: strip-char (letter/space) interspersing — projection reconstructs", R)
-- Bypass 2: url-encode a letter of the route. vBulletin decodes routestring
-- before routing, so `%61jax` still hits the vulnerable template; the gate must
-- decide on the DECODED surface, not a raw substring.
fires(req("POST", "/", "", "routestring=%61jax/render/pagenav&pagenav[pagenumber]=" .. PHPFUCK),
      "bypass2: url-encoded route letter (routestring=%61jax) — decoded gate", R)
fires(req("GET", "/ajax/%72ender/pagenav", "pagenav[pagenumber]=" .. PHPFUCK, ""),
      "bypass2: url-encoded path letter (/ajax/%72ender/) — normalize decodes", R)

-- ── Negatives ───────────────────────────────────────────────────────────────
-- Projection must not create FPs: a body with letters, parens and dots but no
-- caret storm stays clean even after the survivor-set projection.
clean(req("POST", "/", "", "routestring=ajax/render/pagenav&note=see(fig.1)and(fig.2)for(details.here)"),
      "prose with parens/dots but no caret storm — projection stays clean")
clean(req("POST", "/", "", "routestring=ajax/render/pagenav&pagenav[pagenumber]=2"),
      "legit pagination: real integer page number on the same route")
clean(req("GET", "/ajax/render/pagenav", "pagenav[pagenumber]=(1+2)^3", ""),
      "short arithmetic on the route — below phpfuck thresholds")
clean(req("POST", "/", "", "routestring=ajax/render/breadcrumb&foo=bar"),
      "ajax/render to another template with ordinary params")
-- Route gate: a phpfuck blob NOT on the ajax/render route must not trip THIS
-- (CVE) rule — that off-route case is the Phase-2 generic rule's job.
clean(req("POST", "/wp-admin/admin-ajax.php", "", "data=" .. PHPFUCK),
      "phpfuck blob off the ajax/render route — CVE rule is route-gated")
clean(req("GET", "/", "", ""),
      "empty root request")

if fails > 0 then
  io.stderr:write(("cfm_waf vBulletin runMaths CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf vBulletin runMaths() unauth RCE (rule 10015, CVE-2026-61511)")
