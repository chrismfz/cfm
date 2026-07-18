-- Tests for the WordPress-core "wp2shell" detector (rule 10011, WAF_CVE).
-- Chained CVE-2026-63030 (REST batch route confusion) + CVE-2026-60137 (core
-- SQLi). Production tier: block. Modelled on the public PoC (Icex0/wp2shell-poc):
-- an anonymous POST to the batch endpoint (/wp-json/batch/v1 or /?rest_route=
-- /batch/v1) whose JSON body nests a batch and a "///" desync primer, smuggling a
-- GET to /wp/v2/users?author_exclude=<url-encoded SQLi>. The batch value is
-- url-encoded on the wire (urllib.quote), which normalize()'s url-decode reveals.

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

local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end

local function post(uri, args, body)
  return { uri = uri, args = args or "", method = "POST", ip = "198.51.100.66",
           headers = { ["Content-Type"] = "application/json" }, body = body, cookie = "" }
end

local function fires(c, label, want)
  local hit, reason = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want, label .. " — reason=" .. want .. " (got " .. tostring(reason) .. ")")
end
local function clean(c, label)
  local hit = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got hit=" .. tostring(hit) .. ")")
end

set_only({ rule_cve_wp2shell = "block" })

local SQLI   = "WAF_CVE:CVE_2026_60137:WP_CORE:BATCH_SQLI"
local DESYNC = "WAF_CVE:CVE_2026_63030:WP_CORE:BATCH_DESYNC"

-- The smuggled author_exclude value as it rides the wire: urllib.quote(safe="")
-- of `0) OR SLEEP(0)-- -` => `0%29%20OR%20SLEEP%280%29--%20-`
local ENC_SQLI = "0%29%20OR%20SLEEP%280%29--%20-"

-- ── Positives ───────────────────────────────────────────────────────────────
-- Leg A: SQLi in author_exclude, via /wp-json/batch/v1
fires(post("/wp-json/batch/v1", "",
      '{"requests":[{"method":"POST","path":"/wp/v2/posts","body":{"requests":['
      .. '{"method":"POST","path":"///"},'
      .. '{"method":"GET","path":"/wp/v2/users?author_exclude=' .. ENC_SQLI .. '"},'
      .. '{"method":"GET","path":"/wp/v2/posts"}]}}]}'),
      "wp2shell SQLi via /wp-json/batch/v1", SQLI)

-- Leg A via ?rest_route=/batch/v1 form (endpoint in args), author_not_in variant
fires(post("/", "rest_route=/batch/v1",
      '{"requests":[{"method":"GET","path":"/wp/v2/users?author_not_in=0%29%20AND%20%281%3D1%29--%20-"}]}'),
      "wp2shell SQLi via ?rest_route=/batch/v1 (author_not_in)", SQLI)

-- Endpoint-encoding evasion: rest_route=%2fbatch%2fv1 still routes in WP, so the
-- gate must url-decode. SQLi present -> still fires.
fires(post("/", "rest_route=%2fbatch%2fv1",
      '{"requests":[{"method":"GET","path":"/wp/v2/users?author_exclude=' .. ENC_SQLI .. '"}]}'),
      "wp2shell SQLi via URL-encoded rest_route batch endpoint", SQLI)

-- Leg B: the "///" desync primer alone (route confusion), no SQL present
fires(post("/wp-json/batch/v1", "",
      '{"requests":[{"method":"POST","path":"///"},{"method":"POST","path":"/wp/v2/posts"}]}'),
      "wp2shell batch desync primer (///)", DESYNC)

-- Pretty-printed JSON (spaced colon) must still match the primer.
fires(post("/wp-json/batch/v1", "",
      '{"requests": [{"method": "POST", "path": "///"}]}'),
      "wp2shell desync primer, pretty-printed JSON", DESYNC)

-- Escape evasion: "\/\/\/" is a valid JSON spelling of "///" that WordPress still
-- routes to the primer path; normalize() does not JSON-unescape, so the primer
-- match must tolerate the optional backslash before each slash.
fires(post("/wp-json/batch/v1", "",
      '{"requests":[{"method":"POST","path":"\\/\\/\\/"}]}'),
      "wp2shell desync primer, JSON-escaped slashes (\\/\\/\\/)", DESYNC)

-- Comment-obfuscated SQLi (MySQL # comment, /**/ around OR) must NOT be dodgeable:
-- author_exclude=0)/**/OR/**/(1=1)#  — no sleep/union/`) or `/`-- -` keyword present,
-- but the extracted value has non-integer bytes, so the value-scoped check fires.
fires(post("/wp-json/batch/v1", "",
      '{"requests":[{"method":"GET","path":"/wp/v2/users?author_exclude='
      .. '0%29%2F%2A%2A%2FOR%2F%2A%2A%2F%281%3D1%29%23"}]}'),
      "wp2shell SQLi via /**/+# comment obfuscation (no keyword marker)", SQLI)

-- ── Negatives ───────────────────────────────────────────────────────────────
-- Legit batch request: real integer author_exclude, no primer, no SQL.
clean(post("/wp-json/batch/v1", "",
      '{"requests":[{"method":"GET","path":"/wp/v2/posts?author_exclude=5,6"}]}'),
      "legit batch: integer author_exclude CSV")

-- Legit REST array form + a second query param: value must be extracted per-param.
clean(post("/wp-json/batch/v1", "",
      '{"requests":[{"method":"GET","path":"/wp/v2/posts?author_exclude[]=5&author_exclude[]=6&per_page=10"}]}'),
      "legit batch: author_exclude[] array form")

-- Legit space-separated id list (wp_parse_id_list tolerates spaces).
clean(post("/wp-json/batch/v1", "",
      '{"requests":[{"method":"GET","path":"/wp/v2/posts?author_exclude=5%2C%206"}]}'),
      "legit batch: author_exclude=5, 6 (spaced list)")

-- Legit list whose separator space is form-encoded as `+` (normalize() decodes
-- %xx but NOT `+`, so the `+` reaches the value check literally). wp_parse_id_list
-- treats it as a space, so it must stay clean — `+` alone can't form an injection.
clean(post("/wp-json/batch/v1", "",
      '{"requests":[{"method":"GET","path":"/wp/v2/posts?author_exclude=5,+6"}]}'),
      "legit batch: author_exclude=5,+6 (plus-encoded space)")

-- FP GUARD: a legit batch that filters by integer author_exclude AND creates a post
-- whose PROSE contains ") or " / ") and " — the old whole-body keyword match blocked
-- this; the value-scoped check must not. This is the core WordPress-fleet FP.
clean(post("/wp-json/batch/v1", "",
      '{"requests":[' ..
      '{"method":"GET","path":"/wp/v2/posts?author_exclude=5"},' ..
      '{"method":"POST","path":"/wp/v2/posts","body":{"content":"Pick option (a) or (b), then (this) and (that)."}}' ..
      ']}'),
      "FP guard: integer author_exclude + prose ') or '/') and ' in another sub-request")

-- FP GUARD: a post that merely *mentions* author_exclude in prose (no `=` param).
clean(post("/wp-json/batch/v1", "",
      '{"requests":[{"method":"POST","path":"/wp/v2/posts","body":{"content":'
      .. '"Use author_exclude to hide authors; combine (this) and (that)."}}]}'),
      "FP guard: author_exclude named in prose, not a query param")

-- FP GUARD: a field VALUE that happens to be /// must not read as the primer path.
clean(post("/wp-json/batch/v1", "",
      '{"requests":[{"method":"POST","path":"/wp/v2/posts","body":{"slug":"foo","title":"about /// slashes"}}]}'),
      "FP guard: /// inside content, not a path value")

-- SQL-looking payload but NOT the batch endpoint -> this rule stays scoped
-- (generic SQLi rule 301 is what would catch it elsewhere).
clean(post("/wp-json/wp/v2/users", "author_exclude=" .. ENC_SQLI, "{}"),
      "author_exclude SQLi but NOT the batch endpoint (out of scope here)")

-- Batch endpoint but a completely benign nested batch (no primer, no SQL).
clean(post("/wp-json/batch/v1", "",
      '{"requests":[{"method":"POST","path":"/wp/v2/comments","body":{"content":"hello"}}]}'),
      "legit nested batch, benign body")

if fails > 0 then
  io.stderr:write(("cfm_waf wp2shell CVE tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf WordPress-core wp2shell (rule 10011, CVE-2026-63030 + CVE-2026-60137)")
