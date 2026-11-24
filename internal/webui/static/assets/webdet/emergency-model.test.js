// node --test: the Web Traffic page's emergency deny/throttle (emergency-model.js).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  EMERGENCY_TAG, EMERGENCY_BAND, uaPattern, ipTargets, targetsFor, suggestTotalRate, throttleCut,
  emergencyPriority, buildEmergencyRule, extendedUntil, activeEmergencyRules, describeEmergency, isEmergencyRule,
} from "./emergency-model.js";
import { validateRuleForm, formFromRule, LIMITS } from "./rules-model.js";

const NOW = Date.parse("2026-11-24T12:00:00Z");
const CHROME152 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36";
const META = { class: "crawler", client: "meta-externalagent", requests: 36000, top_ips_last_hour: [{ ip: "57.141.20.1", requests: 9 }] };
const SCRAPER = { class: "automation", client: CHROME152, requests: 18000, top_ips_last_hour: [{ ip: "83.212.158.22", requests: 600 }, { ip: "2a02:587:1:2::/64", requests: 300 }, { ip: "45.66.43.21", requests: 100 }] };

test("targets: a browser UA is never a UA target; humans get nothing", () => {
  assert.equal(uaPattern(SCRAPER), "");
  assert.deepEqual(targetsFor(SCRAPER), ["ips"]);
  assert.deepEqual(targetsFor({ class: "human", client: CHROME152, top_ips_last_hour: [{ ip: "203.0.113.1" }] }), []);
  assert.equal(uaPattern(META), "*meta-externalagent*");
  assert.deepEqual(targetsFor(META), ["ua", "ips"]);
  assert.equal(uaPattern({ class: "bot", client: "(no user-agent)" }), "-");
  for (const bad of ["mozilla", "_other", "go", "a*b", "x y", ""]) assert.equal(uaPattern({ class: "bot", client: bad }), "", bad);
});

test("ipTargets: busiest first, /64s kept, capped at the rule limit", () => {
  assert.deepEqual(ipTargets(SCRAPER, 2), ["83.212.158.22", "2a02:587:1:2::/64"]);
  const many = { class: "bot", client: "x-bot", top_ips_last_hour: Array.from({ length: 600 }, (_, i) => ({ ip: `10.0.${i >> 8}.${i & 255}` })) };
  assert.equal(ipTargets(many, 10000).length, LIMITS.ipsPerRule);
});

test("suggested cap and its cut", () => {
  assert.equal(suggestTotalRate(10), 2.5);
  assert.equal(suggestTotalRate(1), 0.5);
  assert.equal(suggestTotalRate(150), 38);
  assert.equal(suggestTotalRate(1000), 250);
  assert.equal(throttleCut(10, 2.5), 0.75);
  assert.equal(throttleCut(1, 5), 0);
});

test("emergencyPriority: first free 1–9 on overlapping vhosts, 0 when full", () => {
  assert.equal(emergencyPriority(["*"], []), EMERGENCY_BAND.from);
  const rules = [{ priority: 1, scope: { vhosts: ["shop.gr"] } }, { priority: 2, scope: { vhosts: ["other.gr"] } }];
  assert.equal(emergencyPriority(["*"], rules), 3, "* overlaps every vhost");
  assert.equal(emergencyPriority(["other.gr"], rules), 1);
  const full = Array.from({ length: 9 }, (_, i) => ({ priority: i + 1, scope: { vhosts: ["*"] } }));
  assert.equal(emergencyPriority(["shop.gr"], full), 0);
});

test("buildEmergencyRule: a UA total throttle node-wide for 1 h", () => {
  const { rule, error } = buildEmergencyRule({ client: META, target: "ua", action: "throttle_total", rate: 5, per: "node", durationSec: 3600, vhosts: ["*"], reason: "titan load", now: NOW });
  assert.equal(error, undefined);
  assert.deepEqual(rule, {
    enabled: true, priority: 1, scope: { vhosts: ["*"] },
    match: { ua_any: ["*meta-externalagent*"], until: "2026-11-24T13:00:00Z" },
    action: { type: "throttle_total", rate_rps: 5, per: "node" },
    note: `${EMERGENCY_TAG} titan load`,
  });
  assert.ok(isEmergencyRule(rule));
  // The Traffic Rules editor's validator takes it as is.
  const v = validateRuleForm(formFromRule(rule), { now: NOW });
  assert.deepEqual(v.errors, []);
});

test("buildEmergencyRule: a deny on the scraper's IPs; refusals", () => {
  const { rule } = buildEmergencyRule({ client: SCRAPER, target: "ips", ipCount: 50, action: "block", durationSec: 900, vhosts: ["Shop.GR"], now: NOW });
  assert.deepEqual(rule.match.ip_any, ["83.212.158.22", "2a02:587:1:2::/64", "45.66.43.21"]);
  assert.deepEqual(rule.scope.vhosts, ["shop.gr"]);
  assert.deepEqual(rule.action, { type: "block" });
  assert.match(rule.note, /^emergency: web traffic: Mozilla/);
  assert.deepEqual(validateRuleForm(formFromRule(rule), { now: NOW }).errors, []);
  const base = { client: META, target: "ua", action: "block", durationSec: 3600, vhosts: ["*"], now: NOW };
  assert.match(buildEmergencyRule({ ...base, client: SCRAPER }).error, /browser UA/);
  assert.match(buildEmergencyRule({ ...base, durationSec: 0 }).error, /duration/);
  assert.match(buildEmergencyRule({ ...base, durationSec: 8 * 86400 }).error, /duration/);
  assert.match(buildEmergencyRule({ ...base, vhosts: [] }).error, /where/);
  assert.match(buildEmergencyRule({ ...base, action: "throttle_total", rate: 0, per: "node" }).error, /between/);
  assert.match(buildEmergencyRule({ ...base, action: "throttle", profile: "nope" }).error, /profile/);
  const full = Array.from({ length: 9 }, (_, i) => ({ priority: i + 1, scope: { vhosts: ["*"] } }));
  assert.match(buildEmergencyRule({ ...base, rules: full }).error, /slot/);
  const long = buildEmergencyRule({ ...base, reason: "ε".repeat(300) }).rule;
  assert.ok(new TextEncoder().encode(long.note).length <= LIMITS.noteLen);
});

test("extend, list and describe", () => {
  const r = { note: "emergency: x", priority: 1, scope: { vhosts: ["*"] }, match: { ua_any: ["*a*"], until: "2026-11-24T12:30:00Z" }, action: { type: "block" } };
  assert.equal(extendedUntil(r, 3600, NOW), "2026-11-24T13:30:00Z", "from its current until");
  assert.equal(extendedUntil({ match: { until: "2026-11-24T11:00:00Z" } }, 3600, NOW), "2026-11-24T13:00:00Z", "an expired one from now");
  assert.equal(extendedUntil(r, 30 * 86400, NOW), "2026-12-01T12:00:00Z", "capped at 7 days from now");
  const gone = { ...r, match: { ...r.match, until: "2026-11-24T11:00:00Z" } };
  const later = { ...r, match: { ...r.match, until: "2026-11-24T18:00:00Z" } };
  const mine = { ...r, note: "hand-written" };
  assert.deepEqual(activeEmergencyRules([later, gone, mine, r], NOW), [r, later]);
  assert.deepEqual(describeEmergency(r), { what: "UA *a*", how: "deny (403)" });
  assert.deepEqual(describeEmergency({ match: { ip_any: ["1.2.3.4", "5.6.7.8"] }, action: { type: "throttle_total", rate_rps: 5, per: "vhost" } }), { what: "2 IPs", how: "throttle 5 r/s total per vhost" });
  assert.equal(describeEmergency({ match: { ua_any: ["-"] }, action: { type: "throttle", profile: "hard_bot" } }).what, "no User-Agent");
});
