import { test } from "node:test";
import assert from "node:assert/strict";
import * as M from "./challenges-model.js";

const OUT = { origin: 900, cached: 50, challenged: 160, blocked: 20, rule_blocked: 5, rate_limited: 5, redirect: 3, other_edge: 2, verify_sent_on: 30, verify_refused: 10, challenge_pages: 60 };
const REQ = 900 + 50 + 160 + 20 + 5 + 5 + 3 + 2;

test("windows: the edge keeps 24 hours", () => {
  assert.deepEqual(M.chHours(6), { hours: 6, capped: false });
  assert.deepEqual(M.chHours(168), { hours: 24, capped: true });
  assert.deepEqual(M.chHours("x"), { hours: 24, capped: false });
  assert.deepEqual(M.query(168, "a.gr"), { outcomes: "v1/webdet/edge-outcomes?hours=24&host=a.gr", waf: "v1/waf/hit-rates?hours=24&host=a.gr" });
  assert.equal(M.query(1, "").outcomes, "v1/webdet/edge-outcomes?hours=1");
});

test("breakdown: the challenge's own requests are not the visitors'", () => {
  const b = M.breakdown(OUT, REQ);
  // 60 pages + 30 + 10 verifies are the check's own requests.
  assert.equal(b.total, REQ - 100);
  assert.deepEqual(b.values, { reached: 950, sent: 60, blocked: 20, limited: 10, other: 5 });
  assert.equal(b.parts.reduce((s, p) => s + p.value, 0), b.total);
  assert.deepEqual(b.parts.map((p) => p.key), ["reached", "sent", "blocked", "limited", "other"]);
  assert.equal(M.breakdown(null, 5), null);
  // Answers above the challenged count (a malformed reply) never go negative.
  const odd = M.breakdown({ challenged: 2, verify_sent_on: 9 }, 2);
  assert.equal(odd.values.sent, 0);
  assert.equal(odd.total, 0);
  assert.equal(odd.parts[0].pct, "–");
});

test("funnel: of the pages served", () => {
  const f = M.funnel(OUT);
  assert.deepEqual([f.pages, f.passed, f.refused, f.unanswered], [60, 30, 10, 20]);
  assert.equal(f.rate, 0.5);
  assert.equal(f.noPages, false);
  const old = M.funnel({ verify_sent_on: 3 });
  assert.equal(old.rate, null);
  assert.equal(old.noPages, true);
  assert.equal(M.funnel(undefined), null);
});

test("waf: hits over inspected, busiest rules first", () => {
  const w = M.wafSummary({ inspected_total: 10000, rules: [
    { id: 301, reason_family: "WAF_SQLI", hits: 5, default_mode: "block" },
    { id: 102, reason_family: "WAF_LONG_PATH", hits: 40, default_mode: "challenge_v2" },
    { id: 999, hits: 0 }, null,
  ] });
  assert.equal(w.hits, 45);
  assert.equal(w.rate, 0.0045);
  assert.deepEqual(w.rules.map((r) => r.id), [102, 301]);
  assert.equal(w.rules[0].pct, "0.40%");
  assert.equal(w.rules[0].mode, "challenge v2");
  assert.equal(M.wafSummary({ rules: [] }).rate, null);
  assert.equal(M.wafSummary(null), null);
});

test("tiles: a number the node did not send is a dash", () => {
  const none = M.tiles(null, null);
  assert.equal(none.length, 6);
  assert.ok(none.every((t) => t.value === "–"));
  const t = M.tiles({ requests: REQ, outcomes: OUT }, M.wafSummary({ inspected_total: 1000, rules: [{ id: 1, hits: 5 }] }));
  const by = Object.fromEntries(t.map((x) => [x.key, x.value]));
  assert.equal(by.requests, "1,045");
  assert.equal(by.passed, "50%");
  assert.equal(by.waf, "0.50%");
  assert.equal(by.sent, "5.7%");
});

test("series: stacked stops and the pass rate per step", () => {
  const edge = { series: [
    { t: 3600, requests: 100, outcomes: { origin: 90, challenged: 10, challenge_pages: 4, verify_sent_on: 2 } },
    { t: 7200, requests: 50, outcomes: { origin: 40, blocked: 10 } },
    { t: 10800, requests: 0, outcomes: {} },
  ] };
  const s = M.stack(edge);
  assert.equal(s.max, 10);
  assert.deepEqual(s.points.map((p) => p.sum), [4, 10, 0]);
  assert.equal(s.points[1].h.blocked, 1);
  assert.match(s.points[0].tip, /Sent to the check 4/);
  const p = M.passRate(edge);
  assert.equal(p[0].rate, 0.5);
  assert.equal(p[1].rate, null);
  assert.equal(p[1].h, 0);
  assert.equal(M.axis(s.points).length, 5);
  assert.deepEqual(M.axis([]), []);
  assert.deepEqual(M.stack(null).points, []);
});

test("vhost rows and reasons", () => {
  const rows = M.hostRows([{ host: "a.gr", requests: REQ, outcomes: OUT }, { requests: 3 }]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].passed, "50%");
  assert.equal(rows[0].parts.length, 5);
  const r = M.reasonRows([{ reason: "WAF_LONG_PATH:SEG", decisions: 1200, addresses: 30 }, { reason: "CHALLENGE_PATHS", decisions: 2, addresses: 2 }, { reason: "CHALLENGE_ERR_RATIO", decisions: 1, addresses: 1 }, {}]);
  assert.deepEqual(r.map((x) => x.kind), ["a WAF rule at challenge level", "odd paths", "a detector"]);
  assert.equal(r[0].decisions, "1,200");
});
