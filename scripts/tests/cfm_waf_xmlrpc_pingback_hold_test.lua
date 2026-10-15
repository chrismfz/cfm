-- Rule 511 (xmlrpc pingback.ping) blocks at the edge, but its waf_security ban
-- is held in code (WAFRule.HoldAutoblock, RULE_511 = 0): WordPress's own
-- pingback client got the sender's shared hosting server banned fleet-wide
-- (fleet review 2026-10-15). A held block rule shadows armed ones, so its
-- block is recorded late (after every armed family), and the pingback no
-- longer short-circuits at step 26:
--   * an armed block hit on the same body owns the headline (and the ban);
--   * a real pingback (pingback.ping is the method IXR dispatches, in a body
--     the edge saw whole) that 511 stops (block / challenge) never counts
--     toward 512 (a block used to end evaluation before 512 ran), and its IP
--     decision is block_ttl_sec; the words anywhere else, a padded or short-
--     read decoy, or a pingback 511 lets through still count;
--   * a rule that raises behind the deferred block still ends in a 511 block.

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

-- Minimal shared dict: enough for cfm_shdict.incr (incr / add with ttl).
local function new_dict()
  local store = {}
  local d = {}
  function d.get(_, k) return store[k] end
  function d.set(_, k, v) store[k] = v; return true end
  function d.add(_, k, v)
    if store[k] ~= nil then return false, "exists" end
    store[k] = v; return true
  end
  function d.incr(_, k, n)
    if store[k] == nil then return nil, "not found" end
    store[k] = store[k] + n; return store[k]
  end
  return d
end

local WP_UA = "The Incutio XML-RPC PHP Library -- WordPress/7.1.3"
local function pingback(extra)
  return '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params>'
    .. '<param><value><string>https://friend.example/post/</string></value></param>'
    .. '<param><value><string>https://evexis.example/</string></value></param>'
    .. (extra or "") .. '</params></methodCall>'
end

local function run(t)
  local hit, reason, ttl, action, hits, rule_id = waf.check({
    skip_rule_ids = t.skip, shdict = t.shdict,
    uri = "/xmlrpc.php", args = "", raw_uri = "/xmlrpc.php",
    method = "POST", ip = t.ip or "203.0.113.7", body = t.body, cookie = "",
    headers = { ["user-agent"] = t.ua or WP_UA, accept = "*/*", ["content-type"] = "text/xml" },
  })
  local ids = {}
  for _, h in ipairs(hits or {}) do ids[#ids + 1] = tostring(h.waf_rule_id) end
  return { hit = hit, reason = tostring(reason), ttl = ttl, action = action, rule_id = rule_id,
           ids = "," .. table.concat(ids, ",") .. "," }
end
local function show(r) return r.reason .. "/" .. tostring(r.action) .. " id=" .. tostring(r.rule_id) .. " hits=" .. r.ids end

-- ── A plain pingback: still a 511 block, as before ───────────────────────────
-- The IP block it leaves is block_ttl_sec (10 s), not 30 min: the sender is a
-- shared hosting server, and an ipState block 403s it on every vhost.
do
  local r = run{ body = pingback() }
  check(r.hit and r.action == "block" and r.rule_id == 511 and r.reason == "WAF_AUTH_BURST:AUTH_WP_XMLRPC_PINGBACK",
        "plain pingback: 511 block (" .. show(r) .. ")")
  check(r.ttl == waf.get_config().block_ttl_sec, "plain pingback: ttl is block_ttl_sec (" .. tostring(r.ttl) .. ")")
end

-- ── An armed block rule on the same body owns the headline ──────────────────
-- Rule 329 (WAF_RCE:PHP_OBJECT_INJECTION, armed) runs after step 26: before
-- the deferral the held 511 owned the headline and the object never reached
-- the ban.
do
  local r = run{ body = pingback('<param><value><string>O:4:"Evil":0:{}</string></value></param>') }
  check(r.action == "block" and r.rule_id == 329 and r.reason:find("^WAF_RCE:PHP_OBJECT_INJECTION"),
        "pingback + serialized object: 329 is the headline (" .. show(r) .. ")")
  check(r.ids:find(",511,", 1, true), "pingback + object: the 511 hit is kept (" .. show(r) .. ")")
end

-- ── Multicall is unchanged: 510 (armed) at step 26 ───────────────────────────
do
  local r = run{ body = '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName>'
                        .. '<params><param><value><string>pingback.ping</string></value></param></params></methodCall>' }
  check(r.action == "block" and r.rule_id == 510, "multicall carrying pingback.ping: 510 headline (" .. show(r) .. ")")
end

-- ── Pingbacks never count toward 512 (POST burst, armed) ─────────────────────
do
  local dict = new_dict()
  local last
  for _ = 1, 10 do last = run{ body = pingback(), shdict = dict, ip = "198.51.100.20" } end
  check(last.rule_id == 511 and not last.ids:find(",512,", 1, true),
        "10 pingbacks from one IP: still 511, no 512 burst (" .. show(last) .. ")")
  -- Other xmlrpc POSTs from the same IP start their own count from zero.
  local other = '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params></params></methodCall>'
  local r
  for _ = 1, 5 do r = run{ body = other, shdict = dict, ip = "198.51.100.20" } end
  check(not r.ids:find(",512,", 1, true), "5 other xmlrpc POSTs after 10 pingbacks: below 512's threshold (" .. show(r) .. ")")
  for _ = 1, 3 do r = run{ body = other, shdict = dict, ip = "198.51.100.20" } end
  check(r.rule_id == 512, "8 other xmlrpc POSTs: 512 burst (" .. show(r) .. ")")
end

-- ── The words as a param of another call: still 511, but 512 counts it ──────
-- IXR dispatches the LAST method name; a wp.getUsersBlogs (password guess)
-- carrying "pingback.ping" as a string is not a pingback. Were it treated as
-- one, adding the words would buy a sprayer out of 512 and every ban.
do
  local dict = new_dict()
  local spray = '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params>'
    .. '<param><value><string>admin</string></value></param><param><value><string>pass1</string></value></param>'
    .. '<param><value><string>pingback.ping</string></value></param></params></methodCall>'
  local r = run{ body = spray, shdict = dict, ip = "198.51.100.30" }
  check(r.rule_id == 511 and r.ttl == waf.get_config().auth_xmlrpc_pingback_ttl_sec,
        "disguised pingback: 511 block with the long ttl (" .. show(r) .. " ttl=" .. tostring(r.ttl) .. ")")
  for _ = 1, 7 do r = run{ body = spray, shdict = dict, ip = "198.51.100.30" } end
  check(r.rule_id == 512 and r.ids:find(",511,", 1, true),
        "8 disguised pingbacks from one IP: 512 burst is the headline, 511 kept (" .. show(r) .. ")")
  -- pingback.ping named first but another call last: IXR runs the last one.
  local two = '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName>'
    .. '<methodName>wp.getUsersBlogs</methodName><params></params></methodCall>'
  r = run{ body = two }
  check(r.rule_id == 511 and r.ttl == waf.get_config().auth_xmlrpc_pingback_ttl_sec,
        "pingback.ping not the last name: the long ttl (" .. show(r) .. " ttl=" .. tostring(r.ttl) .. ")")
  -- A decoy pingback.ping, padded past the edge's body window, with the real
  -- call behind the cut: the edge cannot see IXR's last name, so it is not a
  -- real pingback (long ttl, counts toward 512).
  local det = require("cfm_waf_detectors")
  local cut = '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params>'
    .. '<param><value><string>' .. string.rep("A", 33000) .. '</string></value></param></params>'
  local tag, real = det.detect_xmlrpc_probe("/xmlrpc.php", "post", cut, "198.51.100.31", "", {})
  check(tag == "AUTH_WP_XMLRPC_PINGBACK" and real == false,
        "padded decoy past the cut: tagged 511 but not a real pingback (" .. tostring(tag) .. " " .. tostring(real) .. ")")
  -- cfm.lua hands the WAF exactly waf_body_max_len (32768) bytes of a longer
  -- body: that boundary is a cut, not a whole body.
  local head = '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>'
  local exact = head .. string.rep("A", 32768 - #head)
  tag, real = det.detect_xmlrpc_probe("/xmlrpc.php", "post", exact, "198.51.100.31", "", {})
  check(#exact == 32768 and tag == "AUTH_WP_XMLRPC_PINGBACK" and real == false,
        "decoy cut at exactly 32768 bytes: not a real pingback (" .. tostring(real) .. ")")
  -- A short read (Content-Length larger than what the edge got) is a cut too.
  tag, real = det.detect_xmlrpc_probe("/xmlrpc.php", "post", pingback(), "198.51.100.31", "",
                                      { ["content-length"] = "40000" })
  check(tag == "AUTH_WP_XMLRPC_PINGBACK" and real == false,
        "short read (Content-Length > body): not a real pingback (" .. tostring(real) .. ")")
  tag, real = det.detect_xmlrpc_probe("/xmlrpc.php", "post", pingback(), "198.51.100.31", "",
                                      { ["content-length"] = tostring(#pingback()) })
  check(tag == "AUTH_WP_XMLRPC_PINGBACK" and real == true,
        "whole body (Content-Length == body): a real pingback (" .. tostring(real) .. ")")
  local dict2 = new_dict()
  for _ = 1, 8 do r = run{ body = cut, shdict = dict2, ip = "198.51.100.31" } end
  check(r.rule_id == 512, "8 padded decoys from one IP: 512 burst (" .. show(r) .. ")")
end

-- ── Excluding 511 for a vhost still drops it ─────────────────────────────────
-- ...and a pingback 511 lets through (excluded, logonly) reaches WordPress,
-- so 512 keeps counting it, as before the hold. Only a real pingback that
-- 511 stops (block, challenge) skips 512.
do
  local dict = new_dict()
  local r
  for _ = 1, 10 do r = run{ body = pingback(), skip = { [511] = true }, shdict = dict, ip = "198.51.100.40" } end
  check(not r.ids:find(",511,", 1, true) and r.rule_id == 512,
        "511 excluded, 10 pingbacks: no 511, 512 burst (" .. show(r) .. ")")
  local saved = waf.get_config().rule_xmlrpc_pingback
  waf.set_rule("rule_xmlrpc_pingback", "logonly")
  r = run{ body = pingback(), shdict = dict, ip = "198.51.100.41" }
  check(r.action == "logonly" and r.ttl == waf.get_config().auth_xmlrpc_pingback_ttl_sec,
        "511 logonly: logged with its own ttl, not block_ttl_sec (" .. show(r) .. " ttl=" .. tostring(r.ttl) .. ")")
  for _ = 1, 9 do r = run{ body = pingback(), shdict = dict, ip = "198.51.100.41" } end
  check(r.rule_id == 512, "511 logonly, 10 pingbacks: 512 burst (" .. show(r) .. ")")
  -- At challenge 511 still STOPS the request (a server never solves it), so
  -- a real pingback skips 512 and gets the short IP decision, like a block.
  waf.set_rule("rule_xmlrpc_pingback", "challenge")
  local dict3 = new_dict()
  for _ = 1, 10 do r = run{ body = pingback(), shdict = dict3, ip = "198.51.100.42" } end
  check(r.rule_id == 511 and r.action == "challenge" and not r.ids:find(",512,", 1, true)
        and r.ttl == waf.get_config().block_ttl_sec,
        "511 challenge, 10 pingbacks: challenged, no 512, block_ttl_sec (" .. show(r) .. " ttl=" .. tostring(r.ttl) .. ")")
  waf.set_rule("rule_xmlrpc_pingback", saved)
end

-- ── A rule that raises behind the deferred block still blocks as 511 ─────────
do
  local det = require("cfm_waf_detectors")
  local orig = det.detect_php_object_injection
  det.detect_php_object_injection = function() error("boom") end
  local logged = 0
  local olog = ngx.log
  ngx.log = function(_, ...)
    if table.concat({ ... }):find("deferred rule-511", 1, true) then logged = logged + 1 end
  end
  local ok, hit, reason, _, action, hits, rule_id = pcall(waf.check, {
    uri = "/xmlrpc.php", args = "", raw_uri = "/xmlrpc.php", method = "POST", ip = "203.0.113.7",
    body = pingback(), cookie = "",
    headers = { ["user-agent"] = WP_UA, accept = "*/*", ["content-type"] = "text/xml" } })
  check(ok and hit and action == "block" and rule_id == 511 and reason == "WAF_AUTH_BURST:AUTH_WP_XMLRPC_PINGBACK"
        and hits and #hits == 1 and hits[1].waf_rule_id == 511,
        "pingback + a raising rule: blocked as 511 (" .. tostring(ok) .. " " .. tostring(reason) .. ")")
  check(logged == 1, "pingback + a raising rule: one ERR line (" .. logged .. ")")
  -- With 511 excluded nothing is deferred: the error goes up.
  ok = pcall(waf.check, {
    uri = "/xmlrpc.php", args = "", raw_uri = "/xmlrpc.php", method = "POST", ip = "203.0.113.7",
    body = pingback(), cookie = "", skip_rule_ids = { [511] = true },
    headers = { ["user-agent"] = WP_UA, accept = "*/*", ["content-type"] = "text/xml" } })
  check(not ok, "511 excluded + a raising rule: the error goes up")
  -- A scanner-UA pingback has both 511 and 201 pending: 511 is the headline,
  -- the 201 hit is kept beside it.
  local hits2, rid2
  ok, _, _, _, _, hits2, rid2 = pcall(waf.check, {
    uri = "/xmlrpc.php", args = "", raw_uri = "/xmlrpc.php", method = "POST", ip = "203.0.113.7",
    body = pingback(), cookie = "",
    headers = { ["user-agent"] = "sqlmap/1.8.2#stable (https://sqlmap.org)", accept = "*/*", ["content-type"] = "text/xml" } })
  check(ok and rid2 == 511 and hits2 and #hits2 == 2 and hits2[2].waf_rule_id == 201,
        "scanner-UA pingback + a raising rule: 511 headline, 201 kept (" .. tostring(ok) .. " " .. tostring(rid2) .. ")")
  ngx.log = olog
  det.detect_php_object_injection = orig
end

if fails > 0 then
  io.stderr:write(("xmlrpc pingback hold tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: rule 511 blocks, deferred behind the armed families; a real pingback 511 stops skips 512")
