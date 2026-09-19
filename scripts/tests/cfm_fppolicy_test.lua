-- Tests for cfm_fppolicy.lua — edge-local fingerprint-policy lookup (master
-- plan E3 node slice). Pure luajit: ngx is mocked (md5 as an identity tag,
-- escape_uri passthrough), the shared dict is a TTL-less table (TTL behaviour
-- is the dict's, not this module's), and the RPC is a scripted stub.

package.path = "configs/lua/?.lua;" .. package.path

-- Stub cjson.safe (house pattern, cfm_decision_test.lua): a tiny decoder for
-- the flat {"action":..,"id":..,"ttl":..} objects this module consumes; any
-- other body decodes to nil, exactly like cjson.safe on invalid JSON.
package.loaded["cjson.safe"] = {
  decode = function(s)
    if type(s) ~= "string" or s:sub(1, 1) ~= "{" then return nil end
    local out = {}
    for k, v in s:gmatch('"(%w+)"%s*:%s*"([^"]*)"') do out[k] = v end
    for k, v in s:gmatch('"(%w+)"%s*:%s*(%d+)') do out[k] = tonumber(v) end
    return out
  end,
}

_G.ngx = {
  md5 = function(s) return "md5(" .. tostring(s) .. ")" end,
  escape_uri = function(s) return (tostring(s or ""):gsub("|", "%%7C")) end,
}

local fpp = require("cfm_fppolicy")

local fails = 0
local function check(c, m)
  if c then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. m .. "\n")
end

-- ── strip_grease: mirrors internal/tlsfp.isGREASE ────────────────────────────
check(fpp.strip_grease("") == "", "empty list unchanged")
check(fpp.strip_grease("TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256")
      == "TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256", "no grease → unchanged")
check(fpp.strip_grease("0x1a1a:TLS_AES_128_GCM_SHA256") == "TLS_AES_128_GCM_SHA256",
      "leading grease stripped")
check(fpp.strip_grease("X25519:0xfafa:prime256v1") == "X25519:prime256v1",
      "middle grease stripped")
check(fpp.strip_grease("0xAaAa:X25519") == "X25519", "mixed-case grease stripped")
check(fpp.strip_grease("0x1a2a:X25519") == "0x1a2a:X25519",
      "unequal hex bytes are NOT grease (Go parity)")
check(fpp.strip_grease("0x1b1b:X25519") == "0x1b1b:X25519",
      "low nibble must be 'a' (Go parity)")
check(fpp.strip_grease("0x1a1a7:X25519") == "0x1a1a7:X25519",
      "length must be exactly 6 (Go parity)")

-- ── key_input: the daemon's id input, positional fields preserved ────────────
local raw = "1|TLSv1.3|0x2a2a:TLS_AES_128_GCM_SHA256|0x3a3a:X25519|h2|HTTP/2.0|r"
check(fpp.key_input(raw) == "1|TLSv1.3|TLS_AES_128_GCM_SHA256|X25519|h2",
      "key_input strips grease and drops per-request fields (http ver, resumed)")
check(fpp.key_input("1|TLSv1.3||||HTTP/1.1|") == "1|TLSv1.3|||",
      "empty positional fields preserved, not collapsed (5 fields, 4 separators)")
check(fpp.key_input(nil) == nil, "nil tuple → nil")
check(fpp.key_input("") == nil, "empty tuple → nil")
check(fpp.key_input("2|TLSv1.3|a|b|c") == nil, "unknown version → nil")
check(fpp.key_input("1||a|b|c") == nil, "missing protocol → nil")

-- ── lookup: cache + RPC interplay ────────────────────────────────────────────
local function new_dict()
  local store = {}
  return {
    get = function(_, k) local e = store[k]; return e and e.v or nil end,
    set = function(_, k, v, ttl) store[k] = { v = v, ttl = ttl } end,
    incr = function(_, k, by, init, ttl)
      local e = store[k]
      if not e then store[k] = { v = (init or 0) + by, ttl = ttl }; return store[k].v end
      e.v = e.v + by
      return e.v
    end,
    _store = store,
  }
end

-- Armed answer is cached: second lookup makes NO rpc call.
do
  local sh, calls = new_dict(), 0
  local deps = {
    raw = raw, sh = sh,
    rpc = function(path)
      calls = calls + 1
      check(path:find("/nginx/fppolicy?fp=", 1, true) == 1, "rpc path shape")
      return '{"action":"deny","id":"c28caa00","ttl":30}', nil
    end,
  }
  local a1, id1 = fpp.lookup(deps)
  check(a1 == "deny" and id1 == "c28caa00", "armed lookup returns action+id")
  local a2, id2 = fpp.lookup(deps)
  check(a2 == "deny" and id2 == "c28caa00", "cached lookup same answer")
  check(calls == 1, "second lookup served from cache (calls=" .. calls .. ")")
end

-- GREASE rotation hits the SAME cache entry (the whole point of the key).
do
  local sh, calls = new_dict(), 0
  local deps = {
    sh = sh,
    rpc = function() calls = calls + 1; return '{"action":"challenge_v2","id":"aabbccdd","ttl":30}', nil end,
  }
  deps.raw = "1|TLSv1.3|0x1a1a:C1|0x2a2a:X25519|h2|HTTP/2.0|"
  local a1 = fpp.lookup(deps)
  deps.raw = "1|TLSv1.3|0xfafa:C1|0xbaba:X25519|h2|HTTP/2.0|r"
  local a2 = fpp.lookup(deps)
  check(a1 == "challenge_v2" and a2 == "challenge_v2", "v2 floor answer")
  check(calls == 1, "grease-rotated tuple reuses the cache entry (calls=" .. calls .. ")")
end

-- No-policy answers are cached too (the common case).
do
  local sh, calls = new_dict(), 0
  local deps = { raw = raw, sh = sh,
    rpc = function() calls = calls + 1; return '{"action":"","id":"11223344","ttl":30}', nil end }
  local a1 = fpp.lookup(deps)
  local a2 = fpp.lookup(deps)
  check(a1 == "" and a2 == "", "no-policy answer is empty")
  check(calls == 1, "negative answer cached")
end

-- RPC failure: fail-open + short negative cache (bounded retry pressure).
do
  local sh, calls = new_dict(), 0
  local deps = { raw = raw, sh = sh,
    rpc = function() calls = calls + 1; return nil, "timeout" end }
  local a1 = fpp.lookup(deps)
  local a2 = fpp.lookup(deps)
  check(a1 == "" and a2 == "", "rpc failure fails open")
  check(calls == 1, "failure negative-cached (no per-request retry)")
end

-- Garbage body: fail-open.
do
  local sh = new_dict()
  local a = fpp.lookup({ raw = raw, sh = sh, rpc = function() return "not json", nil end })
  check(a == "", "non-JSON body fails open")
end

-- Plain HTTP (no tuple): no rpc at all.
do
  local calls = 0
  local a = fpp.lookup({ raw = nil, sh = new_dict(),
    rpc = function() calls = calls + 1; return nil, nil end })
  check(a == "" and calls == 0, "no tuple → no rpc, no action")
end

-- RPC budget: over-budget uncached lookups fail open WITHOUT caching (a
-- key-minting client must not churn the dict) and without an RPC.
do
  local sh, calls = new_dict(), 0
  sh:incr("fpp|rpc_budget", 1000, 0, 1) -- budget already exhausted this second
  local a = fpp.lookup({ raw = raw, sh = sh,
    rpc = function() calls = calls + 1; return '{"action":"deny","id":"ff","ttl":30}', nil end })
  local nkeys = 0
  for _ in pairs(sh._store) do nkeys = nkeys + 1 end
  check(a == "" and calls == 0, "over-budget lookup fails open without an rpc")
  check(nkeys == 1, -- only the budget counter itself exists
        "over-budget lookup writes no cache entry (keys=" .. nkeys .. ")")
end

-- ttl<=0 from the daemon must not pin the entry forever (exptime 0 =
-- never-expire in ngx.shared): the module substitutes its default.
do
  local sh = new_dict()
  local a = fpp.lookup({ raw = raw, sh = sh,
    rpc = function() return '{"action":"deny","id":"aa11bb22","ttl":0}', nil end })
  check(a == "deny", "ttl=0 answer still enforced")
  local pinned = false
  for k, e in pairs(sh._store) do
    if k:find("fpp|md5", 1, true) and (not e.ttl or e.ttl <= 0) then pinned = true end
  end
  check(not pinned, "ttl=0 must be replaced by a positive default, never stored")
end

-- No dict: still answers (per-request RPC degradation).
do
  local a, id = fpp.lookup({ raw = raw, sh = nil,
    rpc = function() return '{"action":"challenge","id":"ee001122","ttl":30}', nil end })
  check(a == "challenge" and id == "ee001122", "dictless lookup still answers")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("OK cfm_fppolicy_test")
