// node --test internal/webui/static/assets/webdet/site-cache-model.test.js
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  STATIC_RECIPES,
  MICRO_RECIPES,
  MICRO_RECIPES_OFFERED,
  MICRO_BUCKETS,
  MAX_AUTH_COOKIES,
  MAX_HOST_LEN,
  canonHost,
  hostError,
  parseTTLSeconds,
  ttlError,
  microBucketSeconds,
  isBucketTTL,
  cookieNameError,
  parseAuthCookies,
  isOptOut,
  emptyForm,
  formFromEntry,
  buildPatch,
  offPatch,
  validateForm,
  buildRows,
  tierCounts,
  filterRows,
  sortRows,
  nodeSwitches,
  debugCurl,
  generationSinceMs,
  coveringWildcard,
} from "./site-cache-model.js";

// The repo root, from internal/webui/static/assets/webdet/.
const ROOT = new URL("../../../../../", import.meta.url);
const read = (p) => readFileSync(new URL(p, ROOT), "utf8");

// ── Pinned to the sources it mirrors ──────────────────────────────────────

test("MICRO_BUCKETS is cfm_cache.lua's MICRO_BUCKETS", () => {
  const m = /^local MICRO_BUCKETS\s*=\s*\{([^}]*)\}/m.exec(read("configs/lua/cfm_cache.lua"));
  assert.ok(m, "no MICRO_BUCKETS in cfm_cache.lua");
  const lua = m[1].replace(/--.*$/gm, "").split(",").map((s) => s.trim()).filter(Boolean).map(Number);
  assert.deepEqual([...MICRO_BUCKETS], lua);
});

function goMapKeys(src, name) {
  const m = new RegExp(`var ${name} = map\\[string\\]struct\\{\\}\\{([\\s\\S]*?)\\n\\}`).exec(src);
  assert.ok(m, `no ${name} in site_cache.go`);
  return [...m[1].matchAll(/"([a-z0-9_]+)":/g)].map((x) => x[1]).sort();
}

test("the recipe lists are site_cache.go's recipe vocabularies", () => {
  const src = read("internal/webdetector/site_cache.go");
  assert.deepEqual([...STATIC_RECIPES].sort(), goMapKeys(src, "staticCacheRecipes"));
  assert.deepEqual([...MICRO_RECIPES].sort(), goMapKeys(src, "microCacheRecipes"));
  assert.ok(MICRO_RECIPES_OFFERED.every((r) => MICRO_RECIPES.includes(r)));
});

test("the limits are site_cache.go's", () => {
  const src = read("internal/webdetector/site_cache.go");
  const constOf = (name) => {
    const m = new RegExp(`const ${name} = (\\d+)`).exec(src);
    assert.ok(m, `no const ${name}`);
    return Number(m[1]);
  };
  assert.equal(MAX_AUTH_COOKIES, constOf("maxSiteCacheAuthCookies"));
  assert.equal(MAX_HOST_LEN, constOf("maxSiteCacheHostLen"));
});

// scripts/tests/fixtures/site_cache_ui_parity.txt: the same cases the daemon
// (site_cache_ui_parity_test.go) and the edge (cfm_cache_ui_parity_test.lua)
// are tested against.
function fixtureCases() {
  const out = [];
  read("scripts/tests/fixtures/site_cache_ui_parity.txt").split("\n").forEach((line, i) => {
    if (!line || line.startsWith("#")) return;
    const parts = line.split("\t");
    assert.equal(parts.length, 3, `fixture line ${i + 1}: want 3 TAB-separated fields`);
    const [kind, raw, want] = parts;
    out.push({ line: i + 1, kind, input: raw === "<empty>" ? "" : raw, want });
  });
  return out;
}

test("the shared ttl / bucket / host / cookie cases", () => {
  const counts = {};
  for (const c of fixtureCases()) {
    counts[c.kind] = (counts[c.kind] || 0) + 1;
    const where = `line ${c.line} (${c.kind} ${JSON.stringify(c.input)})`;
    if (c.kind === "ttl") {
      const got = parseTTLSeconds(c.input);
      assert.equal(Number.isNaN(got) ? "invalid" : String(got), c.want, where);
    } else if (c.kind === "bucket") {
      assert.equal(String(microBucketSeconds(c.input)), c.want, where);
    } else if (c.kind === "host") {
      assert.equal(hostError(c.input) === "" ? "ok" : "bad", c.want, where);
    } else if (c.kind === "cookie") {
      assert.equal(cookieNameError(c.input) === "" ? "ok" : "bad", c.want, where);
    } else {
      assert.fail(`${where}: unknown kind`);
    }
  }
  for (const k of ["ttl", "bucket", "host", "cookie"]) assert.ok(counts[k] > 0, `no ${k} cases`);
});

// ── Host / TTL / cookie helpers ───────────────────────────────────────────

test("canonHost folds ASCII only and strips a port and trailing dots", () => {
  assert.equal(canonHost("  Shop.Example.COM.. "), "shop.example.com");
  assert.equal(canonHost("example.com:8443"), "example.com");
  // A Unicode look-alike is not folded into a valid name: K (Kelvin sign) stays.
  assert.equal(canonHost("\u212a.example.com"), "\u212a.example.com");
  assert.notEqual(hostError("\u212a.example.com"), "");
});

test("ttlError allows empty, refuses what the daemon refuses", () => {
  assert.equal(ttlError(""), "");
  assert.equal(ttlError("30s"), "");
  assert.match(ttlError("30"), /invalid TTL/);
  assert.ok(isBucketTTL("5s") && isBucketTTL("1m") && !isBucketTTL("7s"));
});

test("cookieNameError refuses Go's whitespace, not JavaScript's", () => {
  assert.notEqual(cookieNameError("a\u00a0b"), ""); // NBSP: unicode.IsSpace
  assert.notEqual(cookieNameError("a\u0085b"), ""); // NEL: unicode.IsSpace, not \s
  assert.equal(cookieNameError("a\ufeffb"), ""); // BOM: \s, not unicode.IsSpace
  assert.notEqual(cookieNameError("x".repeat(257)), "");
  assert.equal(cookieNameError("x".repeat(256)), "");
});

test("parseAuthCookies de-duplicates case-insensitively and caps the list", () => {
  const r = parseAuthCookies("app_sess, APP_SESS, other");
  assert.deepEqual(r.names, ["app_sess", "other"]);
  assert.deepEqual(r.errors, []);
  const many = Array.from({ length: MAX_AUTH_COOKIES + 1 }, (_, i) => `c${i}`).join(",");
  assert.match(parseAuthCookies(many).errors.join(" "), /too many auth cookies/);
  assert.equal(parseAuthCookies(Array.from({ length: MAX_AUTH_COOKIES }, (_, i) => `c${i}`).join(",")).errors.length, 0);
});

// ── Form → patch ──────────────────────────────────────────────────────────

test("buildPatch: a new static-only policy", () => {
  const f = { ...emptyForm(), host: "Shop.Example.com.", staticOn: true };
  assert.deepEqual(buildPatch(f), {
    host: "shop.example.com",
    static: { enabled: true, recipe: "static_lean" },
    micro: { enabled: false },
    strict_cookies: false,
    auth_cookies: [],
  });
});

test("buildPatch sends a tier's recipe and TTL only while it is on", () => {
  const f = { ...emptyForm(), host: "a.example.com", microOn: true, microRecipe: "micro_aggressive", microTTL: "10S" };
  const p = buildPatch(f);
  assert.deepEqual(p.micro, { enabled: true, recipe: "micro_aggressive", ttl: "10s" });
  assert.deepEqual(p.static, { enabled: false });
  // Off again: the stored recipe is kept (no recipe in the patch), so a later
  // re-enable still starts from a fresh generation.
  assert.deepEqual(buildPatch({ ...f, microOn: false }).micro, { enabled: false });
});

test("formFromEntry round-trips a stored policy", () => {
  const entry = {
    host: "shop.example.com",
    static: { enabled: true, recipe: "static_aggressive", ttl: "7d" },
    micro: { enabled: false, recipe: "micro_safe", ttl: "7s" },
    strict_cookies: true,
    auth_cookies: ["a", "b"],
  };
  const f = formFromEntry(entry);
  assert.equal(f.staticRecipe, "static_aggressive");
  assert.equal(f.microTTL, "7s");
  assert.equal(f.authCookies, "a, b");
  const p = buildPatch(f);
  assert.deepEqual(p.static, { enabled: true, recipe: "static_aggressive" }); // the static TTL label is never sent
  assert.deepEqual(p.micro, { enabled: false });
  assert.deepEqual(p.auth_cookies, ["a", "b"]);
  assert.equal(formFromEntry({ host: "x.com", micro: { enabled: true, recipe: "micro_safe" } }).microTTL, "1s");
});

test("offPatch is the explicit opt-out", () => {
  assert.deepEqual(offPatch("*.Example.com"), { host: "*.example.com", static: { enabled: false }, micro: { enabled: false } });
  assert.ok(isOptOut({ static: { enabled: false }, micro: {} }));
  assert.ok(!isOptOut({ static: { enabled: true } }));
});

// ── Validation ────────────────────────────────────────────────────────────

test("validateForm: errors the daemon would return", () => {
  const bad = validateForm({ ...emptyForm(), host: "*.com", staticOn: true });
  assert.match(bad.errors.join(" "), /wildcard needs at least two labels/);
  const out = validateForm({ ...emptyForm(), host: "other.com", staticOn: true }, { inScope: (h) => h === "mine.com" });
  assert.match(out.errors.join(" "), /not one of your vhosts/);
  const ttl = validateForm({ ...emptyForm(), host: "a.com", microOn: true, microTTL: "5 s" });
  assert.match(ttl.errors.join(" "), /Micro TTL/);
  const ck = validateForm({ ...emptyForm(), host: "a.com", microOn: true, authCookies: "ok, a=b" });
  assert.match(ck.errors.join(" "), /Auth cookie "a=b"/);
  assert.deepEqual(validateForm({ ...emptyForm(), host: "a.com", staticOn: true }).errors, []);
});

test("validateForm: warnings for what an operator should know", () => {
  const optout = validateForm({ ...emptyForm(), host: "api.example.com" });
  assert.deepEqual(optout.errors, []);
  assert.match(optout.warnings.join(" "), /opt-out/);
  const snap = validateForm({ ...emptyForm(), host: "a.com", microOn: true, microTTL: "7s" });
  assert.match(snap.warnings.join(" "), /snaps it to 5 s/);
  const strict = validateForm({ ...emptyForm(), host: "a.com", staticOn: true, strictCookies: true });
  assert.match(strict.warnings.join(" "), /micro tier only/);
  const original = { host: "a.com", static: { enabled: false }, micro: { enabled: false, recipe: "micro_safe" } };
  const bump = validateForm({ ...emptyForm(), host: "a.com", staticOn: true, microOn: true }, { original });
  assert.equal(bump.warnings.filter((w) => /empty cache/.test(w)).length, 2);
  const dup = validateForm({ ...emptyForm(), host: "A.com", staticOn: true }, { existing: [{ host: "a.com" }] });
  assert.match(dup.warnings.join(" "), /already has a policy/);
  const covered = validateForm({ ...emptyForm(), host: "blog.shop.example.com", staticOn: true },
    { existing: [{ host: "*.example.com" }, { host: "*.shop.example.com" }] });
  assert.match(covered.warnings.join(" "), /covered by \*\.shop\.example\.com: a policy of its own replaces/);
});

test("coveringWildcard picks the most specific armed-or-not wildcard", () => {
  const e = [{ host: "*.example.com" }, { host: "*.shop.example.com" }, { host: "shop.example.com" }];
  assert.equal(coveringWildcard("a.shop.example.com", e), "*.shop.example.com");
  assert.equal(coveringWildcard("blog.example.com", e), "*.example.com");
  assert.equal(coveringWildcard("example.com", e), "", "a wildcard never covers its apex");
  assert.equal(coveringWildcard("*.shop.example.com", e), "*.example.com");
});

// ── Rows ──────────────────────────────────────────────────────────────────

const ENTRIES = [
  { host: "shop.example.com", static: { enabled: true, recipe: "static_lean" }, micro: { enabled: true, recipe: "micro_safe", ttl: "7s" }, generation: 1758600000000, updated_at: "2026-09-23T10:00:00Z" },
  { host: "*.example.com", static: { enabled: true, recipe: "static_lean" }, micro: { enabled: false }, generation: 3, updated_at: "2026-09-22T10:00:00Z" },
  { host: "api.example.com", static: { enabled: false }, micro: { enabled: false }, generation: 5, updated_at: "bad" },
  { host: "other.net", static: { enabled: false }, micro: { enabled: true, recipe: "micro_aggressive", ttl: "30s", }, auth_cookies: ["sid_x"], generation: 7 },
];
const STATS = [
  { host: "shop.example.com", hit: 90, miss: 10, cacheable_total: 100, hit_ratio_pct: 90 },
  { host: "*.example.com", hit: 0, miss: 0, bypass: 4, cacheable_total: 0, hit_ratio_pct: 0 },
];

test("buildRows joins the stats by policy key", () => {
  const rows = buildRows(ENTRIES, STATS);
  const byHost = Object.fromEntries(rows.map((r) => [r.host, r]));
  assert.equal(byHost["shop.example.com"].hitPct, 90);
  assert.equal(byHost["shop.example.com"].microBucket, 5);
  assert.equal(byHost["*.example.com"].hitPct, null, "nothing cacheable yet → no ratio");
  assert.ok(byHost["*.example.com"].wildcard);
  assert.ok(byHost["api.example.com"].optOut);
  assert.equal(byHost["api.example.com"].updatedMs, 0);
  assert.deepEqual(tierCounts(rows), { all: 4, static: 2, micro: 2, optout: 1 });
});

test("filterRows: quick filter, covering wildcard, search", () => {
  const rows = buildRows(ENTRIES, STATS);
  const hosts = (rs) => rs.map((r) => r.host).sort();
  assert.deepEqual(hosts(filterRows(rows, { quick: "micro" })), ["other.net", "shop.example.com"]);
  assert.deepEqual(hosts(filterRows(rows, { quick: "optout" })), ["api.example.com"]);
  // A vhost filter shows its own policy and every wildcard covering it.
  assert.deepEqual(hosts(filterRows(rows, { vhost: "Shop.Example.com" })), ["*.example.com", "shop.example.com"]);
  assert.deepEqual(hosts(filterRows(rows, { vhost: "blog.example.com" })), ["*.example.com"]);
  assert.deepEqual(hosts(filterRows(rows, { search: "sid_x" })), ["other.net"]);
});

test("sortRows: by column, host breaks ties, no ratio sorts last when descending", () => {
  const rows = buildRows(ENTRIES, STATS);
  assert.deepEqual(sortRows(rows, "host").map((r) => r.host), ["*.example.com", "api.example.com", "other.net", "shop.example.com"]);
  assert.deepEqual(sortRows(rows, "hit", "desc").map((r) => r.host).slice(0, 1), ["shop.example.com"]);
  assert.deepEqual(sortRows(rows, "ttl", "desc").map((r) => r.host).slice(0, 2), ["other.net", "shop.example.com"]);
  assert.deepEqual(sortRows(rows, "bogus").map((r) => r.host), sortRows(rows, "host").map((r) => r.host));
});

// ── Node switches, the debug command, generations ─────────────────────────

test("nodeSwitches reads [webdetector] as the daemon does", () => {
  const payload = (keys) => ({ config: { core: [{ name: "ssh", keys: {} }], advanced: [{ name: "webdetector", keys }] } });
  assert.deepEqual(nodeSwitches(payload({})), { siteCache: true, microEnforce: false });
  assert.deepEqual(nodeSwitches(payload({ SITE_CACHE: "0 ; panic", MICRO_CACHE_ENFORCE: "\"1\"" })), { siteCache: false, microEnforce: true });
  assert.deepEqual(nodeSwitches(payload({ site_cache: "maybe", micro_cache_enforce: "yes" })), { siteCache: true, microEnforce: true });
  assert.equal(nodeSwitches({ config: { core: [] } }), null);
  assert.equal(nodeSwitches(null), null);
});

test("debugCurl builds the runbook command for a valid host only", () => {
  assert.equal(
    debugCurl("*.Example.com", "/a b'c"),
    "curl -sk -o /dev/null -D - -H 'X-CFM-Cache-Debug: 1' --resolve www.example.com:9043:<vhost-ip> 'https://www.example.com:9043/a%20b%27c'",
  );
  assert.match(debugCurl("shop.example.com", "p"), /:9043\/p'$/);
  assert.equal(debugCurl("bad host; rm -rf /"), "");
  assert.equal(debugCurl(""), "");
});

test("generationSinceMs: a wall-clock generation is a time, a counter is not", () => {
  const now = Date.parse("2026-09-23T12:00:00Z");
  assert.equal(generationSinceMs(1758600000000, now), 1758600000000);
  assert.equal(generationSinceMs(7, now), null);
  assert.equal(generationSinceMs(now + 2 * 86400000, now), null);
});
