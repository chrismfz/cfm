-- Tests for should_push cooldown keying (audit F31).
--
-- should_push dedups WAF-hit pushes (the cfm.waf.log record + ip_push RPC) per
-- cooldown window using an shdict :add. The key used to embed the FULL reason,
-- but scored rules append a per-request ":score=N" (and a per-hit tag), e.g.
-- "WAF_BAD_UA:<tag>:score=6" — so every hit got a distinct key and a scanner
-- sweeping many URIs from one IP escaped the cooldown, one push per hit.
--
-- Fix: key on (ip, reason FAMILY, action tier).
--   * family (before the first ":") drops the volatile score/tag suffix.
--   * action tier is REQUIRED: WAF families mix tiers (WAF_RCE = block rule 320
--     + logonly 322-327) and Go's autoblock feeds on action=block pushes only,
--     so a family+ip-only key would let a logonly recon hit consume the window
--     and suppress a later block hit's push (no autoblock — the review's
--     MUST-FIX). Keying the action guarantees a block hit always pushes.

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

-- Mock ngx.shared dict: :add succeeds (true) only if the key is absent, else
-- returns (false, "exists") — the real dedup semantics within a cooldown window.
local function new_shdict()
  local store = {}
  return {
    _store = store,
    add = function(_, k, v, _ttl)
      if store[k] ~= nil then return false, "exists" end
      store[k] = v
      return true
    end,
  }
end

local function push(sh, ip, reason, action) return waf.should_push(sh, ip, reason, action) end

-- ── F31: scored reasons with volatile score/tag dedup to one push per family ─
local sh = new_shdict()
local IP = "203.0.113.7"
check(push(sh, IP, "WAF_BAD_UA:emptyua:score=6", "logonly") == true,  "first WAF_BAD_UA hit pushes")
check(push(sh, IP, "WAF_BAD_UA:emptyua:score=4", "logonly") == false, "F31: same family+tier, different score -> deduped")
check(push(sh, IP, "WAF_BAD_UA:othertag:score=5", "logonly") == false, "F31: same family+tier, different tag+score -> deduped")
-- The stored key is family+action, not the full scored reason.
check(sh._store["wafpush|WAF_BAD_UA|logonly|" .. IP] ~= nil, "F31: cooldown key is (family, action)")
check(sh._store["wafpush|WAF_BAD_UA:emptyua:score=6|logonly|" .. IP] == nil, "F31: full scored reason is NOT the key")

-- ── MUST-FIX (review): a non-block hit must NOT mask a later BLOCK hit of the
-- same family. WAF_RCE mixes logonly sub-rules (322-327, recon) with the block
-- base rule (320); Go autoblock only acts on action=block pushes.
local sh2 = new_shdict()
check(push(sh2, IP, "WAF_RCE:LOLBIN:foo", "logonly") == true,
      "logonly WAF_RCE recon hit pushes (consumes the logonly window)")
check(push(sh2, IP, "WAF_RCE", "block") == true,
      "F31/autoblock: a BLOCK WAF_RCE hit STILL pushes despite a prior logonly WAF_RCE (no autoblock suppression)")
check(push(sh2, IP, "WAF_RCE:REVERSE_SHELL", "block") == false,
      "second BLOCK WAF_RCE (same family+tier) -> deduped")
check(push(sh2, IP, "WAF_RCE:PERSISTENCE", "logonly") == false,
      "second logonly WAF_RCE (same family+tier) -> deduped")

-- ── Different families push independently ────────────────────────────────────
check(push(sh, IP, "WAF_TRAVERSAL", "challenge") == true, "different family (WAF_TRAVERSAL) pushes")

-- ── Different IPs never cross-dedup ──────────────────────────────────────────
check(push(sh, "203.0.113.9", "WAF_BAD_UA:x:score=6", "logonly") == true, "different IP pushes independently")

-- ── Colon-less and nil reasons ───────────────────────────────────────────────
local sh3 = new_shdict()
check(push(sh3, IP, "WAF_SQLI", "block") == true,  "colon-less reason pushes once")
check(push(sh3, IP, "WAF_SQLI", "block") == false, "colon-less reason deduped on repeat")
check(push(sh3, "1.2.3.4", nil, "block") == true,  "nil reason pushes (family 'WAF')")
check(push(sh3, "1.2.3.4", nil, "block") == false, "nil reason deduped on repeat")

-- ── Fail-open guards (no shdict / no ip) ─────────────────────────────────────
check(push(nil, IP, "WAF_RCE", "block") == true, "no shdict -> push (fail-open)")
check(push(sh,  "",  "WAF_RCE", "block") == true, "empty ip -> push (fail-open)")
check(push(sh,  nil, "WAF_RCE", "block") == true, "nil ip -> push (fail-open)")

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_waf_should_push_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: cfm_waf should_push (family, action) keyed cooldown (F31)\n")
