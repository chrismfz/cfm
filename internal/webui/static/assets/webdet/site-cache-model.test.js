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
  patchChanges,
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
  // Every quoted key, whatever it holds: a key this regex skipped would drift unseen.
  const keys = [...m[1].matchAll(/"([^"]+)":/g)].map((x) => x[1]).sort();
  assert.ok(keys.length > 0, `no keys in ${name}`);
  for (const k of keys) assert.match(k, /^[a-z0-9_]+$/, `${name}: recipe key ${k}`);
  return keys;
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
    } else if (c.kind === "cookie" || c.kind === "cookieq") {
      const name = c.kind === "cookieq" ? JSON.parse(`"${c.input}"`) : c.input;
      assert.equal(cookieNameError(name) === "" ? "ok" : "bad", c.want, where);
      // ...and through the path that builds what is sent.
      const parsed = parseAuthCookies(name);
      assert.equal(parsed.errors.length === 0 && parsed.names.length === 1 ? "ok" : "bad", c.want, `${where} via parseAuthCookies`);
    } else {
      assert.fail(`${where}: unknown kind`);
    }
  }
  for (const k of ["ttl", "bucket", "host", "cookie", "cookieq"]) assert.ok(counts[k] > 0, `no ${k} cases`);
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
  // ASCII fold only, as the daemon: K and the Kelvin sign are two names.
  assert.equal(parseAuthCookies("k, \u212a").names.length, 2);
  const r = parseAuthCookies("app_sess, APP_SESS, other");
  assert.deepEqual(r.names, ["app_sess", "other"]);
  assert.deepEqual(r.errors, []);
  const many = Array.from({ length: MAX_AUTH_COOKIES + 1 }, (_, i) => `c${i}`).join(",");
  assert.match(parseAuthCookies(many).errors.join(" "), /too many auth cookies/);
  assert.equal(parseAuthCookies(Array.from({ length: MAX_AUTH_COOKIES }, (_, i) => `c${i}`).join(",")).errors.length, 0);
});

// ── Form → patch ──────────────────────────────────────────────────────────

test("buildPatch: a new policy sends only what it turns on", () => {
  const f = { ...emptyForm(), host: "Shop.Example.com.", staticOn: true };
  assert.deepEqual(buildPatch(f), { host: "shop.example.com", static: { enabled: true, recipe: "static_lean" } });
  const m = { ...emptyForm(), host: "a.example.com", microOn: true, microRecipe: "micro_aggressive", microTTL: "10S", strictCookies: true, authCookies: "x_sess" };
  assert.deepEqual(buildPatch(m), {
    host: "a.example.com",
    micro: { enabled: true, recipe: "micro_aggressive", ttl: "10s" },
    strict_cookies: true,
    auth_cookies: ["x_sess"],
  });
  // Both off is the explicit opt-out a new host needs.
  assert.deepEqual(buildPatch({ ...emptyForm(), host: "api.example.com" }), {
    host: "api.example.com", static: { enabled: false }, micro: { enabled: false },
  });
});

const STORED = {
  host: "shop.example.com",
  static: { enabled: true, recipe: "static_aggressive", ttl: "7d" },
  micro: { enabled: true, recipe: "micro_safe", ttl: "" },
  strict_cookies: false,
  auth_cookies: ["shop_login"],
  updated_at: "2026-09-23T10:00:00Z",
};

test("buildPatch: an edit sends only the fields that changed", () => {
  const f = formFromEntry(STORED);
  assert.deepEqual(buildPatch(f, STORED), { host: "shop.example.com" }, "untouched: nothing but the host");
  assert.equal(patchChanges(buildPatch(f, STORED)), 0);
  // The empty stored TTL shows as 1 s and is not rewritten.
  assert.equal(f.microTTL, "1s");
  assert.deepEqual(buildPatch({ ...f, microTTL: "10s" }, STORED), { host: "shop.example.com", micro: { ttl: "10s" } });
  assert.deepEqual(buildPatch({ ...f, strictCookies: true }, STORED), { host: "shop.example.com", strict_cookies: true });
  assert.deepEqual(buildPatch({ ...f, authCookies: "shop_login, shop_cart" }, STORED), { host: "shop.example.com", auth_cookies: ["shop_login", "shop_cart"] });
  assert.deepEqual(buildPatch({ ...f, authCookies: "shop_login " }, STORED), { host: "shop.example.com" }, "whitespace only");
  assert.deepEqual(buildPatch({ ...f, authCookies: "" }, STORED), { host: "shop.example.com", auth_cookies: [] }, "clearing is a change");
  assert.deepEqual(buildPatch({ ...f, staticOn: false }, STORED), { host: "shop.example.com", static: { enabled: false } });
  assert.deepEqual(buildPatch({ ...f, microRecipe: "micro_custom" }, STORED), { host: "shop.example.com", micro: { recipe: "micro_custom" } });
});

test("buildPatch: a tier turned on sends its recipe (and TTL); turned off, only enabled", () => {
  const off = { host: "a.com", static: { enabled: false, recipe: "static_lean" }, micro: { enabled: false, recipe: "micro_safe", ttl: "5s" } };
  const f = formFromEntry(off);
  assert.deepEqual(buildPatch({ ...f, microOn: true }, off), { host: "a.com", micro: { enabled: true, recipe: "micro_safe", ttl: "5s" } });
  assert.deepEqual(buildPatch({ ...f, staticOn: true }, off), { host: "a.com", static: { enabled: true, recipe: "static_lean" } });
  // Off again: the stored recipe is kept (no recipe in the patch), so a later
  // re-enable still starts from a fresh generation.
  const on = { host: "a.com", micro: { enabled: true, recipe: "micro_aggressive", ttl: "10s" } };
  assert.deepEqual(buildPatch({ ...formFromEntry(on), microOn: false }, on), { host: "a.com", micro: { enabled: false } });
});

test("buildPatch: a stored cookie name the comma list cannot hold survives an edit", () => {
  const e = { host: "a.com", micro: { enabled: true, recipe: "micro_safe", ttl: "1s" }, auth_cookies: ["a,b"] };
  const f = formFromEntry(e);
  assert.deepEqual(buildPatch({ ...f, microTTL: "5s" }, e), { host: "a.com", micro: { ttl: "5s" } });
});

test("formFromEntry round-trips a stored policy", () => {
  const f = formFromEntry(STORED);
  assert.equal(f.staticRecipe, "static_aggressive");
  assert.equal(f.authCookies, "shop_login");
  assert.equal(formFromEntry({ host: "x.com", micro: { enabled: true, recipe: "micro_safe" } }).microTTL, "1s");
  assert.equal(formFromEntry({ host: "x.com", micro: { enabled: false, recipe: "micro_safe", ttl: "7s" } }).microTTL, "7s");
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
  // A first micro enable (no stored recipe) has nothing to hide: no new generation.
  const first = validateForm({ ...emptyForm(), host: "a.com", staticOn: true, microOn: true },
    { original: { host: "a.com", static: { enabled: true, recipe: "static_lean" }, micro: { enabled: false } } });
  assert.equal(first.warnings.filter((w) => /empty cache/.test(w)).length, 0);
  // An unloadable host is not a new policy.
  const frozen = validateForm({ ...emptyForm(), host: "old.example.com" }, { unloadable: ["old.example.com"] });
  assert.match(frozen.errors.join(" "), /cannot read/);
  // Stored cookie values the operator did not touch are not re-validated.
  const stored = { host: "a.com", micro: { enabled: false }, auth_cookies: ["a,[b"] };
  assert.deepEqual(validateForm(formFromEntry(stored), { original: stored }).errors, []);
  assert.deepEqual(validateForm(formFromEntry(stored), { original: stored }).warnings.filter((w) => /micro tier only/.test(w)), []);
  const dup = validateForm({ ...emptyForm(), host: "A.com", staticOn: true }, { existing: [{ host: "a.com" }] });
  assert.match(dup.errors.join(" "), /already has a policy: edit it instead/);
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
    "curl -gsk -o /dev/null -D - -H 'X-CFM-Cache-Debug: 1' --resolve www.example.com:9043:VHOST_IP 'https://www.example.com:9043/a%20b%27c'",
  );
  assert.match(debugCurl("shop.example.com", "p"), /:9043\/p'$/);
  assert.match(debugCurl("shop.example.com", "/a[1]{x,y}"), /^curl -g/, "-g: no URL globbing");
  // A wildcard's example sub-host is one without an exact policy of its own.
  assert.match(debugCurl("*.example.com", "/", ["www.example.com"]), /--resolve cfm-check\.example\.com:9043:/);
  assert.equal(debugCurl("bad host; rm -rf /"), "");
  assert.equal(debugCurl(""), "");
});

test("generationSinceMs: a wall-clock generation is a time, a counter is not", () => {
  const now = Date.parse("2026-09-23T12:00:00Z");
  assert.equal(generationSinceMs(1758600000000, now), 1758600000000);
  assert.equal(generationSinceMs(7, now), null);
  assert.equal(generationSinceMs(999999999999, now), null, "below the daemon's 1e12 floor: a legacy counter");
  assert.equal(generationSinceMs(now + 2 * 86400000, now), null);
});
