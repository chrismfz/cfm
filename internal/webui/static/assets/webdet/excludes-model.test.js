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
