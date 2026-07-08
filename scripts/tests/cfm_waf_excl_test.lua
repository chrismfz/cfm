-- Tests for cfm_waf_excl.matches_rule — the WAF/challenge exclude value matcher.
-- Run via `make test-lua` (luajit scripts/tests/cfm_waf_excl_test.lua).
--
-- These lock the boundary semantics that replaced a plain-substring match
-- (which silently disabled the WAF on unintended vhosts/paths: a `shop.gr`
-- host exclude also covered `myshop.gr`, a `/api` path exclude `/therapy`).
-- They MUST stay in lock-step with the Go enforcement matcher
-- (internal/webdetector/exclude_store.go compiledValueMatcher) — see
-- TestCompiledValueMatcher_BoundarySemantics there for the mirror cases.

package.path = "configs/lua/?.lua;" .. package.path
local wx = require("cfm_waf_excl")

local fails = 0
local function eq(got, want, msg)
  if got == want then return end
  fails = fails + 1
  io.stderr:write(string.format("FAIL: %s (got %s, want %s)\n", msg, tostring(got), tostring(want)))
end

local function m(value, rule, kind) return wx.matches_rule(value, rule, kind) end

-- ── host: exact or dot-boundary subdomain suffix ─────────────────────────────
eq(m("shop.gr", "shop.gr", "host"), true, "host exact")
eq(m("www.shop.gr", "shop.gr", "host"), true, "host subdomain www")
eq(m("cpanel.shop.gr", "shop.gr", "host"), true, "host subdomain cpanel")
eq(m("a.b.shop.gr", "shop.gr", "host"), true, "host deep subdomain")
eq(m("myshop.gr", "shop.gr", "host"), false, "host must NOT substring-match myshop.gr")
eq(m("shop.gr.evil.com", "shop.gr", "host"), false, "host must NOT match a suffix-embedded domain")
eq(m("evil-shop.gr", "shop.gr", "host"), false, "host must NOT match a prefix-glued label")
eq(m("shop.gr", "www.shop.gr", "host"), false, "parent host must NOT match a child rule")
-- Case-insensitive.
eq(m("WWW.SHOP.GR", "shop.gr", "host"), true, "host match is case-insensitive")

-- ── path: exact or path-segment prefix ───────────────────────────────────────
eq(m("/admin", "/admin", "path"), true, "path exact")
eq(m("/admin/users", "/admin", "path"), true, "path segment child")
eq(m("/admin/", "/admin", "path"), true, "path trailing slash child")
eq(m("/administrator", "/admin", "path"), false, "path must NOT match /administrator")
eq(m("/admin-panel", "/admin", "path"), false, "path must NOT match /admin-panel")
eq(m("/therapy", "/api", "path"), false, "path must NOT substring-match /therapy for /api")
eq(m("/api", "/api", "path"), true, "path /api exact")
eq(m("/api/v1", "/api", "path"), true, "path /api child")
-- Trailing-slash rule is a pure prefix at the slash boundary.
eq(m("/.well-known/acme-challenge/x", "/.well-known/", "path"), true, "path trailing-slash rule prefix")
eq(m("/.well-known", "/.well-known/", "path"), false, "path trailing-slash rule needs the slash")

-- ── glob (unchanged): anchored `*`/`?` matching for both kinds ────────────────
eq(m("www.shop.gr", "*.shop.gr", "host"), true, "glob *.shop.gr matches subdomain")
eq(m("shop.gr", "*.shop.gr", "host"), false, "glob *.shop.gr does NOT match the bare domain")
eq(m("myshop.gr", "*shop.gr", "host"), true, "explicit *shop.gr glob DOES match (operator's choice)")
eq(m("/wp-admin/setup", "/wp-admin/*", "path"), true, "glob /wp-admin/* matches child")
eq(m("/wp-adminx", "/wp-admin/*", "path"), false, "glob /wp-admin/* anchored — no overmatch")
eq(m("/a/b", "/?/b", "path"), true, "glob ? matches exactly one char (a)")
eq(m("/ab/b", "/?/b", "path"), false, "glob ? matches ONE char only (ab is two → no match)")
eq(m("/x/b", "/x/?", "path"), true, "glob ? single-char segment")

-- ── edge: empty inputs never match ───────────────────────────────────────────
eq(m("", "shop.gr", "host"), false, "empty value")
eq(m("shop.gr", "", "host"), false, "empty rule")

if fails > 0 then
  io.stderr:write(("%d failure(s)\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf_excl.matches_rule host/path boundary + glob semantics")
