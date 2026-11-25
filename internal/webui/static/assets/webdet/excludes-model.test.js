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

test("parseScopeHosts splits, lower-cases, trims a trailing dot, de-dups", () => {
  assert.deepEqual(parseScopeHosts(" A.gr, www.a.gr  b.gr. ,a.gr"), ["a.gr", "www.a.gr", "b.gr"]);
  assert.deepEqual(parseScopeHosts(""), []);
  assert.deepEqual(parseScopeHosts(undefined), []);
});

test("literalVhosts drops globs, lower-cases, sorts", () => {
  assert.deepEqual(literalVhosts(["b.gr", "*.t3.gr", "A.gr", "a.gr"]), ["a.gr", "b.gr"]);
});

test("pathTypeAllowed: admin both; scoped challenge only, with management and a literal vhost", () => {
  assert.equal(pathTypeAllowed("challenge", { isScoped: false }), true);
  assert.equal(pathTypeAllowed("waf", { isScoped: false }), true);
  const t = { isScoped: true, scopedExcludeManagementAllowed: true, allowedVhosts: ["t1.gr"] };
  assert.equal(pathTypeAllowed("challenge", t), true);
  assert.equal(pathTypeAllowed("waf", t), false);
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
  const M = await import("./excludes-model.js");
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
