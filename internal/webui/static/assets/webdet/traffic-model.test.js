import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CLASS_ORDER, CLASS_COLORS, share, fmtPct, fmtBytes, fmtMbps, fmtRate, classMap, summary,
  segments, hostBotShare, topIPs, clientActions, uaRuleAllowed, OTHER_KEY,
} from "./traffic-model.js";

const CHROME152 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36";

// titan, 2026-11-24 07:00–10:00 (the numbers the mockup used).
const MIX = {
  schema: "webdet.traffic_mix.v1",
  window_sec: 10800,
  classes: [
    { key: "crawler", requests: 154723, origin_sec: 216855, bytes: 8.31e9, status: { "5xx": 10 } },
    { key: "bot", requests: 132531, origin_sec: 104720, bytes: 4.06e9, status: { "5xx": 5 } },
    { key: "automation", requests: 197845, origin_sec: 326550, bytes: 9.63e9, status: { "5xx": 781 } },
    { key: "human", requests: 585440, origin_sec: 243774, bytes: 13.77e9, status: { "5xx": 200 } },
  ],
  total: { requests: 1070539, origin_sec: 891899, rps_avg: 99.1 },
  clients: [
    { class: "automation", client: CHROME152, requests: 197845, origin_sec: 326550, top_ips_last_hour: [{ ip: "83.212.158.22", requests: 600 }, { ip: "154.43.67.250", requests: 300 }, { ip: "45.66.43.21", requests: 100 }], ips_last_hour: 3 },
    { class: "crawler", client: "meta-externalagent", requests: 150000, origin_sec: 210000 },
    { class: "human", client: "Mozilla/5.0 (iPhone…)", requests: 1000, origin_sec: 100 },
  ],
};

test("palettes: one color per class, both themes", () => {
  for (const theme of ["dark", "light"]) {
    assert.deepEqual(Object.keys(CLASS_COLORS[theme]).sort(), [...CLASS_ORDER].sort());
    assert.equal(new Set(Object.values(CLASS_COLORS[theme])).size, CLASS_ORDER.length);
  }
});

test("formatting", () => {
  assert.equal(share(1, 0), 0);
  assert.equal(fmtPct(0.366), "36.6%");
  assert.equal(fmtBytes(9.63e9), "9.63 GB");
  assert.equal(fmtBytes(512), "512 B");
  assert.equal(fmtMbps(9.63e9, 10800), "7.1 Mbit/s");
  assert.equal(fmtRate(18.32), "18 r/s");
  assert.equal(fmtRate(1.25), "1.3 r/s");
});

test("summary: titan's bots took ~73% of the origin time on ~45% of the requests", () => {
  const s = summary(MIX);
  assert.equal(fmtPct(s.botOriginShare), "72.7%");
  assert.equal(fmtPct(s.botRequestShare), "45.3%");
  assert.equal(s.topClient.client, CHROME152);
  assert.equal(fmtPct(s.topClientOriginShare), "36.6%");
  assert.ok(s.share5xx > 0);
  // A human population is never the "biggest single client".
  const h = summary({ ...MIX, clients: [{ class: "human", client: CHROME152, origin_sec: 999999 }, ...MIX.clients] });
  assert.equal(h.topClient.class, "automation");
});

test("classMap fills missing classes with zeros; segments sum to 1", () => {
  const cm = classMap({ classes: [{ key: "bot", requests: 5 }] });
  assert.equal(cm.human.requests, 0);
  const seg = segments(classMap(MIX), "origin_sec");
  assert.deepEqual(seg.map((x) => x.key), [...CLASS_ORDER]);
  assert.ok(Math.abs(seg.reduce((s, x) => s + x.fraction, 0) - 1) < 1e-9);
  assert.deepEqual(segments(classMap({}), "requests").map((x) => x.fraction), [0, 0, 0, 0]);
});

test("hostBotShare", () => {
  const h = { total: { origin_sec: 100 }, classes: { automation: { origin_sec: 60 }, crawler: { origin_sec: 20 }, human: { origin_sec: 20 } } };
  assert.equal(hostBotShare(h), 0.8);
  assert.equal(hostBotShare({}), 0);
});

test("topIPs: coverage of the picked IPs", () => {
  const r = topIPs(MIX.clients[0], 2);
  assert.deepEqual(r.ips, ["83.212.158.22", "154.43.67.250"]);
  assert.equal(r.coverage, 0.9);
  assert.equal(topIPs({}, 5).ips.length, 0);
});

// The guardrails.
test("a browser UA is never offered a UA rule; humans get nothing", () => {
  const auto = clientActions(MIX.clients[0]).map((a) => a.id);
  assert.deepEqual(auto, ["challenge_ips"], "automation: its IPs only");
  assert.deepEqual(clientActions(MIX.clients[2]), [], "human: nothing");
  assert.equal(uaRuleAllowed(MIX.clients[0]), false);
  assert.equal(uaRuleAllowed(MIX.clients[2]), false);
  assert.equal(uaRuleAllowed({ class: "bot", client: "mozilla" }), false);
  assert.equal(uaRuleAllowed({ class: "bot", client: OTHER_KEY }), false);
  assert.deepEqual(clientActions({ class: "automation", client: CHROME152 }), [], "no IPs known: nothing to act on");
});

test("a UA family gets the box-wide UA rules; a bot with IPs also the per-IP challenge", () => {
  assert.deepEqual(clientActions(MIX.clients[1]).map((a) => a.id), ["ua_throttle", "ua_block"]);
  assert.equal(uaRuleAllowed(MIX.clients[1]), true);
  const bot = { class: "bot", client: "python-requests", top_ips_last_hour: [{ ip: "203.0.113.1", requests: 9 }] };
  assert.deepEqual(clientActions(bot).map((a) => a.id), ["challenge_ips", "ua_throttle", "ua_block"]);
  assert.deepEqual(clientActions({ class: "bot", client: "(no user-agent)" }).map((a) => a.id), []);
  assert.deepEqual(clientActions({ class: "bot", client: OTHER_KEY }), []);
});
