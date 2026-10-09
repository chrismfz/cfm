-- The XML-RPC rules 510-512 (and the auth burst 501) had three gaps (edge Lua
-- sweep 2026-10-09, PR 7):
--   * The Jetpack carve-out keyed on markers the client sends (`?for=jetpack`,
--     a Jetpack / WordPress.com UA, the word "jetpack" in the body): any client
--     could add one and run system.multicall / pingback.ping past the block
--     rules and every burst limit. A marker now counts only from a Jetpack
--     network (jetpack.com/ips-v4.txt).
--   * 510 / 511 looked for the method name in the first 2 KB of the body:
--     a comment or blanks before <methodName> hid it, and WordPress's IXR
--     decodes `system&#46;multicall`, CDATA and comments in the name. The
--     method names are read as IXR reads them, from the whole body.
--   * The burst counters were a get-then-set pair (lost increments between
--     workers, a window restarted by a race); one atomic cfm_shdict.incr each.

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}
package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")
local det = require("cfm_waf_detectors")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- A shared dict with TTLs on a settable clock.
local clock = 1000
local function newdict()
  local store, exp = {}, {}
  local d = {}
  local function live(k) if exp[k] and exp[k] <= clock then store[k] = nil; exp[k] = nil end return store[k] end
  function d:get(k) return live(k) end
  function d:set(k, v, ttl) store[k] = v; exp[k] = (ttl and ttl > 0) and clock + ttl or nil; return true end
  function d:add(k, v, ttl) if live(k) ~= nil then return false, "exists" end return d:set(k, v, ttl) end
  function d:incr(k, n, init)
    assert(init == nil, "dict:incr with an init (use cfm_shdict.incr)")
    if live(k) == nil then return nil, "not found" end
    store[k] = store[k] + n; return store[k]
  end
  return d
end

local CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
-- The pad goes inside <methodCall>: WordPress rejects anything else before
-- its root tag.
local function call(name, pad)
  return '<?xml version="1.0"?><methodCall>' .. (pad or "") .. "<methodName>" .. name ..
         "</methodName><params><param><value><string>admin</string></value></param></params></methodCall>"
end
local function run(body, t)
  t = t or {}
  local hit, reason, _, action, hits = waf.check({
    uri = "/xmlrpc.php", args = t.args or "", method = "POST", ip = t.ip or "203.0.113.7", body = body,
    headers = { ["user-agent"] = t.ua or CHROME, ["content-type"] = "text/xml", accept = "*/*" },
    shdict = t.dict or newdict(),
  })
  local ids = {}
  for _, h in ipairs(hits or {}) do ids[#ids + 1] = tostring(h.waf_rule_id) end
  return { hit = hit, reason = tostring(reason), action = action, ids = "," .. table.concat(ids, ",") .. "," }
end
local function show(r) return r.reason .. "/" .. tostring(r.action) .. " ids=" .. r.ids end

-- ── Jetpack markers count only from a Jetpack network ───────────────────────
do
  local MC = call("system.multicall")
  for _, t in ipairs({
    { args = "for=jetpack" }, { ua = "Jetpack by WordPress.com" }, { ua = "WordPress.com; https://x" },
  }) do
    local r = run(MC .. "<!-- jetpack -->", t)
    check(r.ids:find(",510,", 1, true) and r.action == "block",
          "multicall with a spoofed Jetpack marker from 203.0.113.7: 510 block (" .. show(r) .. ")")
    t.ip = "192.0.84.10"
    r = run(MC, t)
    check(not r.ids:find(",510,", 1, true), "the same from a Jetpack network: exempt (" .. show(r) .. ")")
  end
end

-- ── The method name, as IXR reads it ─────────────────────────────────────────
do
  for _, b in ipairs({
    call("system.multicall", "<!--" .. ("x"):rep(3000) .. "-->"),            -- padded past 2 KB
    call("system.multicall", (" "):rep(3000)),
    call("system&#46;multicall"), call("system&#x2E;multicall"),
    call("<![CDATA[system.multicall]]>"), call("system<!-- -->.multicall"),
    call("  system.multicall\n"),
    call("wp.getUsersBlogs") .. "<methodName>system.multicall</methodName>",  -- the last one is the call
    -- IXR clears its text buffer at every tag: the name is the text after the
    -- last inner tag. A `>` in an attribute value does not end the tag.
    call("x" .. ("a"):rep(3000) .. "<x/>system.multicall"),
    call("<x>" .. ("j"):rep(3000) .. "</x>system.multicall"),
    '<?xml version="1.0"?><methodCall><!--' .. ("p"):rep(3000) .. '--><methodName a=">">system.multicall</methodName></methodCall>',
    call("<?pi > ?>system.multicall", "<!--" .. ("p"):rep(3000) .. "-->"),
    call("&#13;&#9;&#10;&#xd;system.multicall", "<!--" .. ("p"):rep(3000) .. "-->"),
    ("<methodName>decoy</methodName>"):rep(80):gsub("^", '<?xml version="1.0"?><methodCall>') .. "<methodName>system.multicall</methodName></methodCall>",
    call("<x><![CDATA[<!--]]></x>system.multicall", "<!--" .. ("p"):rep(3000) .. "-->"),
    -- IXR first drops one `<?xml…?>` from the first 100 bytes, wherever it is:
    -- inside an attribute it would otherwise desync the reader.
    "<methodCall><x a='<?xml' b=\"?>'/><methodName>system&#46;multicall</methodName>" ..
      "<params><param><value><string>admin</string></value></param></params></methodCall>",
  }) do
    local r = run(b)
    check(r.ids:find(",510,", 1, true), "510 sees " .. b:sub(1, 90):gsub("\n", "<LF>") .. "… (" .. show(r) .. ")")
  end
  for _, b in ipairs({ call("pingback&#46;ping", "<!--" .. ("x"):rep(3000) .. "-->"), call("<![CDATA[pingback.ping]]>"),
                       "<methodCall><methodName <?xml >?>>pingback&#46;ping</methodName></methodCall>" }) do
    local r = run(b)
    check(r.ids:find(",511,", 1, true), "511 sees " .. b:sub(1, 90) .. "… (" .. show(r) .. ")")
  end
  -- A single ordinary call is not a multicall or a pingback.
  local r = run(call("wp.getUsersBlogs", "<!--" .. ("x"):rep(3000) .. "-->"))
  check(not r.ids:find(",510,", 1, true) and not r.ids:find(",511,", 1, true),
        "wp.getUsersBlogs past 2 KB: neither 510 nor 511 (" .. show(r) .. ")")
  local names = det.xmlrpc_method_names(call("a&amp;b&#999999;&bogus;"))
  check(names[1] == "a&b?&bogus;", "entities decoded, non-ASCII neutral, unknown ones kept: " .. tostring(names[1]))
  -- A name the edge cannot see (padded past the 32 KB it reads): reported
  -- under 510 at logonly (burn-in), never blocked.
  local hidden = '<?xml version="1.0"?><methodCall><!--' .. ("p"):rep(33000) .. "--><methodName>system.multicall</methodName></methodCall>"
  local r2 = run(hidden:sub(1, 32768))
  check(r2.ids:find(",510,", 1, true) and r2.action ~= "block" and r2.reason:find("HIDDEN_METHOD", 1, true),
        "a call with no method name in the first 32 KB: 510 logonly (" .. show(r2) .. ")")
  -- A decoy name up front and the real one past the cut: IXR calls the last.
  local decoy = '<?xml version="1.0"?><methodCall><methodName>wp.getOptions</methodName><!--' .. ("p"):rep(33000) ..
                "--><methodName>system.multicall</methodName></methodCall>"
  r2 = run(decoy:sub(1, 32768))
  check(r2.reason:find("HIDDEN_METHOD", 1, true) and r2.action ~= "block",
        "a decoy name before the cut: 510 logonly (" .. show(r2) .. ")")
  -- An entity decodes to its own case: `wp.upload&#x46;ile` is still the
  -- upload call (lowercased after decoding).
  local nm = det.xmlrpc_method_names(call("wp.upload&#x46;ile"))
  check(nm[1] == "wp.uploadfile", "names are lowercased after entity decoding: " .. tostring(nm[1]))
  local big = call("metaWeblog.newMediaObject") .. ("<!-- " .. ("b"):rep(1000) .. " -->"):rep(40)
  r2 = run(big:sub(1, 32768))
  check(not r2.ids:find(",510,", 1, true), "a large call with its name up front: no 510 (" .. show(r2) .. ")")
end

-- ── The reader is linear: no pattern over attacker text backtracks ─────────
do
  for _, b in ipairs({ "<methodName>" .. ("<!--"):rep(8000), "<methodName>" .. ("<![cdata["):rep(3600),
                       "<methodName>" .. ("<"):rep(32000), "<methodName>" .. ("<a"):rep(16000),
                       "<methodName>a" .. (" "):rep(32000) .. "b</methodName>", ("<a b='>"):rep(4000),
                       ("&#"):rep(16000), ("<x>"):rep(10000), ("<>"):rep(16000), ("</>"):rep(10000) }) do
    local t0 = os.clock()
    det.xmlrpc_method_names(b:sub(1, 32768))
    local ms = (os.clock() - t0) * 1000
    check(ms < 100, ("method-name reader on %q… took %.1f ms"):format(b:sub(1, 16), ms))
  end
end

-- ── 512: an atomic per-IP window ────────────────────────────────────────────
do
  local dict = newdict()
  local one = call("wp.getUsersBlogs")
  local fired
  for i = 1, 6 do
    local r = run(one, { dict = dict, ip = "198.51.100.5" })
    if r.ids:find(",512,", 1, true) then fired = fired or i end
  end
  check(fired == 6, "512 fires on the 6th POST in its window (fired on " .. tostring(fired) .. ")")
  clock = clock + 61
  local r = run(one, { dict = dict, ip = "198.51.100.5" })
  check(not r.ids:find(",512,", 1, true), "a new window after 60 s starts over (" .. show(r) .. ")")
  -- And a Jetpack network's bursts are not counted.
  local jd = newdict()
  for _ = 1, 10 do r = run(one, { dict = jd, ip = "192.0.84.10", args = "for=jetpack" }) end
  check(not r.ids:find(",512,", 1, true), "a Jetpack network's POSTs: no 512 (" .. show(r) .. ")")
end

if fails > 0 then
  io.stderr:write(("xmlrpc hardening tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: xmlrpc 510-512 (Jetpack network, IXR method names, atomic burst window)")
