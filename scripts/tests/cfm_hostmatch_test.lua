-- Tests for cfm_hostmatch.lua — the shared host normalizer + minimal glob
-- matcher used by cfm_h3_config.lua and cfm_cache.lua. Pure Lua, no ngx.

package.path = "configs/lua/?.lua;" .. package.path

local hm = require("cfm_hostmatch")

local fails = 0
local function check(c, m)
  if c then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. m .. "\n")
end

-- ── normalize_host ────────────────────────────────────────────────────────────
check(hm.normalize_host("Example.COM") == "example.com", "lowercases")
check(hm.normalize_host("example.com.") == "example.com", "strips trailing dot")
check(hm.normalize_host("example.com:443") == "example.com", "strips :port")
check(hm.normalize_host("") == "", "empty → empty")
check(hm.normalize_host(nil) == "", "nil → empty")
-- NOTE: this matcher intentionally does NOT trim whitespace (matches the H3
-- original). Inputs are always clean here — ngx.var.host from nginx and the
-- daemon feed which is already Go-normalized — so a spaced host never occurs.
-- IPv6 literals keep brackets + inner colons; only a trailing :port is stripped.
check(hm.normalize_host("[2001:db8::1]") == "[2001:db8::1]", "ipv6 literal kept")
check(hm.normalize_host("[::1]:443") == "[::1]", "ipv6 :port stripped, brackets kept")

-- ── glob_match ────────────────────────────────────────────────────────────────
check(hm.glob_match("example.com", "example.com") == true, "exact match")
check(hm.glob_match("example.com", "other.com") == false, "exact mismatch")
check(hm.glob_match("*.cdn.example.com", "a.cdn.example.com") == true, "*.suffix matches")
check(hm.glob_match("*.cdn.example.com", "deep.a.cdn.example.com") == true, "*.suffix matches multi-label")
check(hm.glob_match("*.cdn.example.com", "cdn.example.com") == false, "*.suffix excludes the bare suffix host")
check(hm.glob_match("*.example.com", "example.com") == false, "*.suffix never matches the apex")

-- ── is_supported_pattern ──────────────────────────────────────────────────────
check(hm.is_supported_pattern("example.com") == true, "exact host supported")
check(hm.is_supported_pattern("*.example.com") == true, "*.suffix supported")
check(hm.is_supported_pattern("cdn.*.example.com") == false, "mid-pattern * unsupported")
check(hm.is_supported_pattern("ex?mple.com") == false, "? unsupported")
check(hm.is_supported_pattern("[abc].example.com") == false, "[abc] unsupported")
check(hm.is_supported_pattern("*.*.example.com") == false, "double * unsupported")

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("OK cfm_hostmatch_test")
