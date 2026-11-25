import test from "node:test";
import assert from "node:assert/strict";
import {
  parseScopeHosts,
  pathTypeAllowed,
  literalVhosts,
  looksLikeHostValue,
  challengePathScopeError,
  formatChallengeExcludeScope,
} from "./excludes-model.js";
import * as M from "./excludes-model.js";

test("parseScopeHosts splits, lower-cases, trims a trailing dot, de-dups", () => {
  assert.deepEqual(parseScopeHosts(" A.gr, www.a.gr  b.gr. ,a.gr"), ["a.gr", "www.a.gr", "b.gr"]);
  assert.deepEqual(parseScopeHosts(""), []);
  assert.deepEqual(parseScopeHosts(undefined), []);
});

test("literalVhosts drops globs, lower-cases, sorts", () => {
  assert.deepEqual(literalVhosts(["b.gr", "*.t3.gr", "A.gr", "a.gr"]), ["a.gr", "b.gr"]);
});

test("pathTypeAllowed: admin both; scoped both, with management and a literal vhost", () => {
  assert.equal(pathTypeAllowed("challenge", { isScoped: false }), true);
  assert.equal(pathTypeAllowed("waf", { isScoped: false }), true);
  const t = { isScoped: true, scopedExcludeManagementAllowed: true, allowedVhosts: ["t1.gr"] };
  assert.equal(pathTypeAllowed("challenge", t), true);
  assert.equal(pathTypeAllowed("waf", t), true, "one rule, with an expiry: scopedWAFAddError");
  assert.equal(pathTypeAllowed("challenge", { ...t, scopedExcludeManagementAllowed: false }), false);
  assert.equal(pathTypeAllowed("challenge", { ...t, allowedVhosts: ["*.t3.gr"] }), false);
  assert.equal(pathTypeAllowed("challenge", { ...t, allowedVhosts: [] }), false);
});

test("challengePathScopeError: admin needs a host, globs are the server's call", () => {
  const admin = { isScoped: false };
  assert.match(challengePathScopeError([], admin), /at least one scope host/);
  assert.equal(challengePathScopeError(["a.gr", "www.a.gr"], admin), "");
  assert.equal(challengePathScopeError(["*.example.gr"], admin), "");
});

test("challengePathScopeError: scoped is limited to its own literal vhosts", () => {
  const tenant = { isScoped: true, allowedVhosts: ["T1.gr", "t2.gr", "*.t3.gr"] };
  assert.match(challengePathScopeError([], tenant), /pick at least one/);
  assert.equal(challengePathScopeError(["t1.gr"], tenant), "");
  assert.equal(challengePathScopeError(["t1.gr", "t2.gr"], tenant), "");
  assert.match(challengePathScopeError(["t1.gr", "other.gr"], tenant), /outside your sites: other.gr/);
  assert.match(challengePathScopeError(["*.t3.gr"], tenant), /outside your sites/);
});

test("looksLikeHostValue: a value with no slash is a host", () => {
  assert.equal(looksLikeHostValue("t1.gr"), true);
  assert.equal(looksLikeHostValue("/images/.tmb/"), false);
  assert.equal(looksLikeHostValue("images/.tmb"), false);
  assert.equal(looksLikeHostValue(""), false);
});

test("formatChallengeExcludeScope marks an unscoped path entry inert", () => {
  assert.equal(formatChallengeExcludeScope({ type: "path", scope_hosts: [] }), "none (inert: remove it)");
  assert.equal(formatChallengeExcludeScope({ type: "path", scope_hosts: ["a.gr", "b.gr"] }), "a.gr, b.gr");
  assert.equal(formatChallengeExcludeScope({ type: "host" }), "*");
});

test("Exceptions page: tabs, what an entry skips, where, the filter and the order", async () => {
  assert.equal(M.exceptionTab("trusted"), "trusted");
  assert.equal(M.exceptionTab("nope"), "waf");
  assert.deepEqual(M.wafExcludeSkips({}), { text: "the whole WAF", whole: true });
  assert.deepEqual(M.wafExcludeSkips({ rule_ids: [402] }), { text: "rule 402", whole: false });
  assert.equal(M.wafExcludeSkips({ rule_ids: [401, 431] }).text, "rules 401, 431");
  assert.equal(M.excludeWhere({ type: "host", value: "a.gr" }), "this host");
  assert.equal(M.excludeWhere({ type: "path", value: "/x" }), "every vhost");
  assert.equal(M.excludeWhere({ type: "path", scope_hosts: ["a.gr", "b.gr"] }), "a.gr, b.gr");
  const rows = [
    { type: "path", value: "/api/callback", rule_ids: [402], scope_hosts: ["pay.gr"], created_at: "2026-11-12T10:00:00+02:00" },
    { type: "host", value: "white.gr", created_at: "2026-03-26T15:13:27+02:00" },
    { type: "path", value: "/everywhere", created_at: "2026-01-01T00:00:00Z" },
    { type: "path", value: "/k2/*", rule_ids: [305], scope_hosts: ["news.gr"], created_at: "2026-11-20T10:00:00+02:00" },
  ];
  assert.deepEqual(M.filterExcludes(rows, " PAY ").map((r) => r.value), ["/api/callback"], "matches the scope too");
  assert.deepEqual(M.filterExcludes(rows, "white").map((r) => r.value), ["white.gr"]);
  assert.equal(M.filterExcludes(rows, "").length, 4);
  assert.deepEqual(M.filterExcludes(null, "x"), []);
  // Widest first: whole WAF on every vhost, whole WAF on one host, then rule-scoped ones newest first.
  assert.deepEqual(M.sortExcludes(rows).map((r) => r.value), ["/everywhere", "white.gr", "/k2/*", "/api/callback"]);
  assert.equal(rows[0].value, "/api/callback", "the input is not reordered");
  assert.equal(M.excludeWhen({ created_at: "not a date" }), "");
  assert.notEqual(M.excludeWhen(rows[0]), "");
});

test("a site owner's WAF exclude: the switch, or one rule with an expiry", () => {
  const e = M.scopedWAFAddError;
  assert.equal(e({ type: "host", rules: "" }), "", "no rule on a host is the switch");
  assert.match(e({ type: "path", rules: "" }), /one rule/);
  assert.equal(e({ type: "host", rules: "402", ttl: "24h" }), "");
  assert.equal(e({ type: "path", rules: " 402 ", ttl: "7d" }), "");
  for (const rules of ["402,403", "4xx", "401-402", "10021", "42", "abc"]) assert.match(e({ type: "host", rules, ttl: "24h" }), /one rule/, rules);
  for (const ttl of ["", "30d", "1h", undefined]) assert.match(e({ type: "host", rules: "402", ttl }), /how long/, String(ttl));
  assert.deepEqual(M.EXCLUDE_TTLS.map((t) => t.key), ["24h", "7d"]);
  assert.equal(pathTypeAllowed("waf", { isScoped: true, scopedExcludeManagementAllowed: true, allowedVhosts: ["*.t1.gr"] }), false, "no literal vhost to pin a path to");
});

test("the families a site owner cannot switch off", () => {
  assert.equal(M.tenantKeptFamily("WAF_CVE:CVE_2026_1:X:Y"), true);
  assert.equal(M.tenantKeptFamily("WAF_WEBSHELL"), true);
  assert.equal(M.tenantKeptFamily("WAF_PHP_WEBSHELL_BODY:X"), false);
  assert.equal(M.tenantKeptFamily("WAF_RCE:PHP_BODY"), false);
  assert.equal(M.tenantKeptFamily(""), false);
  assert.equal(M.wafExcludeSkips({ keep_critical: true }).text, "the WAF (CVE and webshell rules stay on)");
  assert.equal(M.wafExcludeSkips({ keep_critical: true }).whole, true);
  assert.equal(M.wafExcludeSkips({ keep_critical: true, rule_ids: [402] }).text, "rule 402");
  assert.equal(M.wafExcludeSkips({ keep_critical: "yes" }).text, "the whole WAF");
});

test("who added an exclude, and when it expires", () => {
  const now = 1_764_000_000_000;
  const at = (s) => ({ expires_unix: now / 1000 + s });
  assert.equal(M.excludeBy({ by: "scoped" }), "site owner");
  assert.equal(M.excludeBy({}), "");
  assert.deepEqual(M.excludeExpires({}, now), { text: "", soon: false });
  assert.deepEqual(M.excludeExpires({ expires_unix: 0 }, now), { text: "", soon: false });
  assert.deepEqual(M.excludeExpires({ expires_unix: "junk" }, now), { text: "", soon: false });
  assert.deepEqual(M.excludeExpires(at(-5), now), { text: "expired", soon: true });
  assert.deepEqual(M.excludeExpires(at(20), now), { text: "in 1 min", soon: true });
  assert.deepEqual(M.excludeExpires(at(22 * 3600), now), { text: "in 22 h", soon: true });
  assert.deepEqual(M.excludeExpires(at(6 * 86400), now), { text: "in 6 d", soon: false });
});
