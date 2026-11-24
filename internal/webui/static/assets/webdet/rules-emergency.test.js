// node --test: match.until (rule expiry) and the throttle_total action in
// rules-model.js; the Go side is traffic_rules_emergency_test.go.
import test from "node:test";
import assert from "node:assert/strict";
import {
  LIMITS,
  PRIORITY_BANDS,
  buildRulePayload,
  describeAction,
  describeRule,
  emptyForm,
  formFromRule,
  ruleExpired,
  shadowingRules,
  untilIn,
  validateRuleForm,
} from "./rules-model.js";

const NOW = Date.parse("2026-11-24T12:00:00Z");

test("untilIn: an RFC3339 UTC time without milliseconds; never for 0/blank", () => {
  assert.equal(untilIn(3600, NOW + 123), "2026-11-24T13:00:00Z");
  assert.equal(untilIn("", NOW), "");
  assert.equal(untilIn(0, NOW), "");
});

test("buildRulePayload: until goes in match; throttle_total carries rate + per, and no profile", () => {
  const p = buildRulePayload(emptyForm({ actionType: "throttle_total", vhosts: "*", uas: "*meta-externalagent*", throttleRate: "5", throttlePer: "Node", until: "2026-11-24T18:00:00Z" }));
  assert.equal(p.match.until, "2026-11-24T18:00:00Z");
  assert.deepEqual(p.action, { type: "throttle_total", profile: "", rate_rps: 5, per: "node" });
  const b = buildRulePayload(emptyForm({ actionType: "block", vhosts: "*", uas: "*x*" }));
  assert.equal(b.match.until, undefined, "no expiry → no key (a never-expiring rule stays readable by older builds)");
  assert.equal(b.action.rate_rps, undefined);
  assert.equal(b.action.per, undefined);
});

test("formFromRule round-trips until and the total throttle", () => {
  const row = { enabled: true, priority: 1, scope: { vhosts: ["*"] }, match: { ua_any: ["*a*"], until: "2026-11-24T18:00:00Z" }, action: { type: "throttle_total", rate_rps: 2, per: "node" } };
  const p = buildRulePayload(formFromRule(row));
  assert.equal(p.match.until, row.match.until);
  assert.equal(p.action.rate_rps, 2);
  assert.equal(p.action.per, "node");
});

test("validateRuleForm: total throttle bounds, per, past or malformed until", () => {
  const base = { vhosts: "*", uas: "*a*", enabled: true };
  const ok = validateRuleForm(emptyForm({ ...base, actionType: "throttle_total", throttleRate: 5, throttlePer: "vhost", until: "2026-11-24T18:00:00Z" }), { now: NOW });
  assert.deepEqual(ok.errors, []);
  for (const [f, re] of [
    [{ throttleRate: 0 }, /between/],
    [{ throttleRate: LIMITS.throttleTotalMax + 1 }, /between/],
    [{ throttlePer: "client" }, /per vhost or whole node/],
    [{ until: "2026-11-24T11:00:00Z" }, /past/],
    [{ until: "tomorrow" }, /RFC3339/],
  ]) {
    const v = validateRuleForm(emptyForm({ ...base, actionType: "throttle_total", throttleRate: 5, throttlePer: "vhost", until: "2026-11-24T18:00:00Z", ...f }), { now: NOW });
    assert.ok(v.errors.some((e) => re.test(e)), `${JSON.stringify(f)} → ${v.errors}`);
  }
});

test("validateRuleForm: ip_any takes up to LIMITS.ipsPerRule (a scraper's top IPs)", () => {
  const ips = (n) => Array.from({ length: n }, (_, i) => `10.0.${i >> 8}.${i & 255}`).join(", ");
  const ok = validateRuleForm(emptyForm({ actionType: "block", vhosts: "*", ips: ips(LIMITS.ipsPerRule) }), { now: NOW });
  assert.ok(!ok.errors.some((e) => /Too many IPs/.test(e)));
  const bad = validateRuleForm(emptyForm({ actionType: "block", vhosts: "*", ips: ips(LIMITS.ipsPerRule + 1) }), { now: NOW });
  assert.ok(bad.errors.some((e) => /Too many IPs/.test(e)));
});

test("describe: the total throttle and the expiry read in the sentence", () => {
  assert.equal(describeAction({ type: "throttle_total", rate_rps: 5, per: "node" }), "throttle to 5 req/s in total for the whole node");
  assert.equal(describeAction({ type: "throttle_total", rate_rps: 2, per: "vhost" }), "throttle to 2 req/s in total per vhost");
  assert.match(describeRule({ scope: { vhosts: ["*"] }, match: { ua_any: ["*a*"], until: "2026-11-24T18:00:00Z" }, action: { type: "block" } }), /\(until 2026-11-24T18:00:00Z\)\.$/);
});

test("ruleExpired and shadowingRules: a total throttle ends evaluation; an expired rule shadows nothing", () => {
  assert.equal(PRIORITY_BANDS.throttle_total.default, PRIORITY_BANDS.throttle.default);
  assert.equal(ruleExpired({ match: { until: "2026-11-24T11:00:00Z" } }, NOW), true);
  assert.equal(ruleExpired({ match: { until: "2026-11-24T13:00:00Z" } }, NOW), false);
  assert.equal(ruleExpired({ match: {} }, NOW), false);
  const row = { enabled: true, priority: 300, scope: { vhosts: ["shop.gr"] }, match: { ua_any: ["*bytespider*"] }, action: { type: "block" } };
  const tt = { id: "tt", enabled: true, priority: 150, scope: { vhosts: ["*"] }, match: { ua_any: ["*bytespider*"] }, action: { type: "throttle_total", rate_rps: 5, per: "node" } };
  assert.deepEqual(shadowingRules(row, [tt]).map((r) => r.id), ["tt"]);
  const gone = { ...tt, id: "gone", match: { ...tt.match, until: "2000-01-01T00:00:00Z" } };
  assert.deepEqual(shadowingRules(row, [gone]), []);
});
