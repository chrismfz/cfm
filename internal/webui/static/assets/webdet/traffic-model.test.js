import { test } from "node:test";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import {
  CLASS_ORDER, CLASS_COLORS, share, fmtPct, fmtBytes, fmtMbps, fmtRate, classMap, summary,
  segments, hostBotShare, topIPs, clientActions, challengeableIPs, OTHER_KEY,
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
  assert.deepEqual(auto, ["challenge_ips", "throttle", "deny"], "automation: on its IPs (the dialog offers no UA target)");
  assert.deepEqual(clientActions(MIX.clients[2]), [], "human: nothing");
  assert.deepEqual(clientActions({ class: "automation", client: CHROME152 }), [], "no IPs known: nothing to act on");
  assert.deepEqual(clientActions({ class: "human", client: CHROME152, top_ips_last_hour: [{ ip: "203.0.113.1", requests: 9 }] }), [], "human with IPs: still nothing");
});

test("a UA family gets deny/throttle; a bot with IPs also the per-IP challenge", () => {
  assert.deepEqual(clientActions(MIX.clients[1]).map((a) => a.id), ["throttle", "deny"]);
  const bot = { class: "bot", client: "python-requests", top_ips_last_hour: [{ ip: "203.0.113.1", requests: 9 }] };
  assert.deepEqual(clientActions(bot).map((a) => a.id), ["challenge_ips", "throttle", "deny"]);
  assert.deepEqual(clientActions({ class: "bot", client: "(no user-agent)" }).map((a) => a.id), ["throttle", "deny"], "no UA: ua_any [\"-\"]");
  assert.deepEqual(clientActions({ class: "bot", client: "mozilla" }), []);
  assert.deepEqual(clientActions({ class: "bot", client: OTHER_KEY }), []);
});

test("challengeableIPs: an IPv6 /64 is not challengeable per IP", () => {
  assert.deepEqual(challengeableIPs(["203.0.113.1", "2001:db8:1:2::/64", "2001:db8::5"]), { ok: ["203.0.113.1", "2001:db8::5"], prefixes: ["2001:db8:1:2::/64"] });
});

test("client sorts map to the API's sort values; rate ranks as requests; anything else is origin", async () => {
  const { CLIENT_SORTS, clientSort } = await import("./traffic-model.js");
  assert.deepEqual(Object.keys(CLIENT_SORTS), ["origin", "requests", "rate", "bytes", "ips"]);
  assert.equal(CLIENT_SORTS.rate.param, "requests");
  assert.deepEqual([...new Set(Object.values(CLIENT_SORTS).map((s) => s.param))].sort(), ["bytes", "ips", "origin", "requests"]);
  assert.equal(clientSort("bytes"), "bytes");
  assert.equal(clientSort("nope"), "origin");
  assert.equal(clientSort(null), "origin");
  assert.equal(clientSort("__proto__"), "origin");
});

test("a browser-UA client the distributed tell flagged gets IP actions; an unflagged one nothing", async () => {
  const { clientActions } = await import("./traffic-model.js");
  const { targetsFor, uaPattern } = await import("./emergency-model.js");
  const ips = [{ ip: "203.0.113.1", requests: 2 }];
  const flagged = { class: "human", client: CHROME152, top_ips_last_hour: ips, distributed: { ips: 460, req_per_ip: 1.4, evidence_share: 0 } };
  assert.deepEqual(clientActions(flagged).map((a) => a.id), ["challenge_ips", "throttle", "deny"]);
  assert.deepEqual(targetsFor(flagged), ["ips"], "its IPs only: the UA is every visitor's too");
  assert.equal(uaPattern(flagged), "");
  assert.deepEqual(clientActions({ class: "human", client: CHROME152, top_ips_last_hour: ips }), [], "unflagged visitors: nothing");
});

// rigel, 2026-11-25: Mac Chrome 142, 767 addresses kept of ~18,300 at 1.02/IP,
// two shops carrying almost all of it.
test("distributedSummary: the pool behind the sample, where it lands, whether per-IP actions reach it", async () => {
  const { distributedSummary, topIPs } = await import("./traffic-model.js");
  const ips = Array.from({ length: 500 }, (_, i) => ({ ip: `198.51.${i >> 8}.${i & 255}`, requests: 1 }));
  const c = {
    class: "human", client: CHROME152, ips_last_hour: 767, top_ips_last_hour: ips,
    distributed: {
      ips: 767, est_ips: 18300, requests: 18650, req_per_ip: 1.02, evidence_share: 0, nets: 441,
      hosts: [{ host: "amabilecreations.com", requests: 12500 }, { host: "vagoneto.gr", requests: 5800 }, { host: OTHER_KEY, requests: 350 }],
    },
  };
  const d = distributedSummary(c);
  assert.equal(d.kept, 767);
  assert.equal(d.est, 18300);
  assert.equal(d.nets, 441);
  assert.equal(d.listed, 500);
  assert.ok(d.reach < 0.03, "500 listed of ~18,300");
  assert.equal(d.onceEach, true);
  assert.deepEqual(d.hosts.map((h) => [h.host, h.other]), [["amabilecreations.com", false], ["vagoneto.gr", false], [OTHER_KEY, true]]);
  assert.ok(Math.abs(d.hosts[0].share - 12500 / 18650) < 1e-9);

  // Restored from a file without vhosts: shares over what the vhosts carry.
  const restored = distributedSummary({ ...c, distributed: { ...c.distributed, hosts: [{ host: "a.gr", requests: 300 }, { host: "b.gr", requests: 100 }] } });
  assert.deepEqual(restored.hosts.map((h) => h.share), [0.75, 0.25]);

  // The dialog's preview reads the pool, not the sample.
  const t = topIPs(c, 500);
  assert.equal(t.total, 18300);
  assert.ok(t.coverage < 0.03, `500 one-request addresses carry ${t.coverage} of the hour, not 100%`);

  // A pool whose addresses come back is reachable; an old node (no est_ips, nets, hosts) still reads.
  const back = distributedSummary({ class: "human", client: CHROME152, distributed: { ips: 300, requests: 700, req_per_ip: 2.3, evidence_share: 0.01 } });
  assert.equal(back.est, 300);
  assert.equal(back.onceEach, false);
  assert.deepEqual(back.hosts, []);
  assert.equal(distributedSummary({ class: "human", client: CHROME152 }), null);

  // An unflagged client's preview is unchanged: over what is listed.
  const plain = topIPs({ class: "automation", ips_last_hour: 2, top_ips_last_hour: [{ ip: "a", requests: 3 }, { ip: "b", requests: 1 }] }, 1);
  assert.equal(plain.total, 2);
  assert.equal(plain.coverage, 0.75);
});

test("outcomeSummary: what the edge did, what counts as stopped, the challenge's answers", async () => {
  const { outcomeSummary, OUTCOMES } = await import("./traffic-model.js");
  const o = outcomeSummary({ origin: 1, cached: 1, challenged: 5, blocked: 1, rule_blocked: 0, rate_limited: 1, redirect: 1, other_edge: 0, verify_passed: 1, verify_failed: 3 });
  assert.equal(o.total, 10);
  assert.equal(o.stopped, 7, "challenged + blocked + rule + 429; cache and redirect are not stops");
  assert.equal(o.stoppedShare, 0.7);
  assert.equal(o.passRate, 0.25);
  assert.deepEqual(o.segments.map((x) => x.key), OUTCOMES.map((x) => x.key));
  assert.equal(o.segments.find((x) => x.key === "challenged").fraction, 0.5);
  assert.equal(outcomeSummary(undefined), null, "an older node: absent, not zero");
  assert.equal(outcomeSummary({ origin: 3 }).passRate, null, "no verify answered: no rate");
  for (const x of OUTCOMES) assert.match(x.color, /^var\(--[a-z0-9-]+\)$/, `${x.key} uses a page token`);
});

// The class colours live in two places on purpose: here for the canvas charts
// (ECharts needs values) and as --c-* tokens in style.css for the pages' CSS.
// They must be the same colours in each theme.
test("CLASS_COLORS equal the --c-* tokens in style.css, both themes", () => {
  const css = readFileSync(new URL("../style.css", import.meta.url), "utf8");
  const block = (sel) => {
    const i = css.indexOf(sel);
    assert.ok(i >= 0, sel);
    return css.slice(i, css.indexOf("}", i));
  };
  const blocks = { dark: block(":root {"), light: block(':root[data-theme="light"] {') };
  for (const theme of ["dark", "light"]) {
    for (const k of CLASS_ORDER) {
      const m = blocks[theme].match(new RegExp(`--c-${k}:\\s*(#[0-9a-fA-F]{6})`));
      assert.ok(m, `${theme} --c-${k}`);
      assert.equal(m[1].toLowerCase(), CLASS_COLORS[theme][k].toLowerCase(), `${theme} ${k}`);
    }
  }
});
