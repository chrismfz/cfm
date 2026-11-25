import { test } from "node:test";
import assert from "node:assert/strict";
import {
  TABS, TABLES, tabsFor, pickTab, pickHours, fmtAge, fmtSize, fmtNum, ageBuckets, tablesFor, tableHint,
  tableView, cell, anomalies, tiles, sourceNote, hasData, queueHeadline, trafficHeadline, SHOWN,
} from "./mail-model.js";

test("a scoped viewer has no queue tab, and a link to it opens their first tab", () => {
  assert.deepEqual(tabsFor(false).map((t) => t.key), ["queue", "outbound", "inbound"]);
  assert.deepEqual(tabsFor(true).map((t) => t.key), ["outbound", "inbound"]);
  assert.equal(pickTab("queue", true), "outbound");
  assert.equal(pickTab("queue", false), "queue");
  assert.equal(pickTab("INBOUND", true), "inbound");
  assert.equal(pickTab("", false), "queue");
  assert.equal(pickTab("nonsense", true), "outbound");
});

test("every table sits on a known tab, and every queue table is behind the admin-only tab", () => {
  const tabs = new Set(TABS.map((t) => t.key));
  const keys = new Set();
  for (const t of TABLES) {
    assert.ok(tabs.has(t.tab), t.key);
    assert.ok(!keys.has(t.key), "duplicate " + t.key);
    keys.add(t.key);
    assert.equal(t.src === "queue", t.tab === "queue", t.key);
  }
  assert.deepEqual(tablesFor("queue", true).length, TABLES.filter((t) => t.tab === "queue").length);
  assert.equal(tabsFor(true).some((t) => t.key === "queue"), false);
});

test("a scoped viewer is not shown the server-wide tables", () => {
  const scoped = tablesFor("outbound", true).map((t) => t.key);
  assert.deepEqual(scoped, ["t_out", "t_dom", "t_throttled"]);
  const admin = tablesFor("outbound", false).map((t) => t.key);
  assert.deepEqual(admin, ["t_out", "t_dom", "t_local", "t_throttled", "t_prov", "t_reasons"]);
  const auth = TABLES.find((t) => t.key === "t_auth");
  assert.match(tableHint(auth, false), /under \*/);
  assert.doesNotMatch(tableHint(auth, true), /\*/);
});

test("window: only the offered ones", () => {
  assert.equal(pickHours("6"), 6);
  assert.equal(pickHours("168"), 168);
  assert.equal(pickHours("5"), 24);
  assert.equal(pickHours(undefined), 24);
  assert.equal(pickHours("-1"), 24);
});

test("formats", () => {
  assert.equal(fmtAge(0), "0s");
  assert.equal(fmtAge(45), "45s");
  assert.equal(fmtAge(600), "10m");
  assert.equal(fmtAge(5400), "1.5h");
  assert.equal(fmtAge(172800), "2.0d");
  assert.equal(fmtAge("junk"), "0s");
  assert.equal(fmtSize(512), "512B");
  assert.equal(fmtSize(2048), "2.0K");
  assert.equal(fmtSize(3 * 1048576), "3.0M");
  assert.equal(fmtNum(1234567), "1,234,567");
  assert.equal(fmtNum(null), "0");
});

test("age buckets keep their order and share", () => {
  const b = ageBuckets({ ">1d": 50, "<10m": 50, junk: 9 });
  assert.deepEqual(b.map((x) => x.label), ["<10m", "10m-1h", "1h-6h", "6h-1d", ">1d"]);
  assert.equal(b[0].pct, 50);
  assert.equal(b[4].count, 50);
  assert.equal(ageBuckets(null).every((x) => x.count === 0 && x.pct === 0), true);
});

test("tableView clips, expands, and survives a malformed report", () => {
  const def = TABLES.find((t) => t.key === "t_out");
  const list = Array.from({ length: 25 }, (_, i) => ({ addr: "u" + i + "@example.gr", count: 100 - i }));
  let v = tableView(def, { top_outbound_senders: list }, false);
  assert.equal(v.rows.length, SHOWN);
  assert.equal(v.hidden, 25 - SHOWN);
  assert.equal(v.total, 25);
  assert.deepEqual(v.rows[0], [{ text: "u0@example.gr" }, { text: "100", num: true }]);
  v = tableView(def, { top_outbound_senders: list }, true);
  assert.equal(v.rows.length, 25);
  assert.equal(v.hidden, 0);
  for (const bad of [null, {}, { top_outbound_senders: "x" }, { top_outbound_senders: [null, 3, { addr: "a" }] }]) {
    const w = tableView(def, bad, false);
    assert.ok(w.total <= 1);
    assert.equal(w.hidden, 0);
  }
  const prov = TABLES.find((t) => t.key === "t_prov");
  assert.equal(tableView(prov, { top_outbound_senders: list }, false).total, 0);
  assert.equal(tableView(prov, { deliverability: { by_provider: [{ provider: "", delivered: 3 }] } }, false).rows[0][0].text, "(unknown)");
});

test("cells", () => {
  const oldest = TABLES.find((t) => t.key === "q_oldest");
  const v = tableView(oldest, { oldest: [{ age_sec: 7200, size_bytes: 2048, frozen: true, sender: "", recipients: 3, id: "1abc" }, { frozen: false, sender: "a@b.gr" }] }, false);
  assert.deepEqual(v.rows[0].map((c) => c.text), ["2.0h", "2.0K", "frozen", "<>", "3", "1abc"]);
  assert.equal(v.rows[0][2].flag, true);
  assert.deepEqual(v.rows[1].map((c) => c.text), ["0s", "0B", "", "a@b.gr", "0", ""]);
  assert.deepEqual(cell({ k: "x" }, null), { text: "" });
});

test("anomalies", () => {
  const a = anomalies([{ addr: "x@y.gr", kind: "spike", recent: 1200, baseline_per_hour: 3.5, ratio: 171 }, { addr: "n@y.gr", kind: "new-sender", recent: 80 }, null]);
  assert.deepEqual(a, [
    { addr: "x@y.gr", signal: "spike", recent: "1,200", baseline: "3.5", ratio: "171×" },
    { addr: "n@y.gr", signal: "new sender", recent: "80", baseline: "—", ratio: "—" },
  ]);
  assert.deepEqual(anomalies(undefined), []);
});

test("tiles: a number the page does not have is a dash, never zero", () => {
  const none = tiles({ state: "loading" }, { state: "unavailable" }, false);
  assert.deepEqual(none.map((t) => t.value), Array(8).fill("—"));
  const q = { state: "ok", data: { total: 1500, frozen: 12, deferred: 300 } };
  const tr = { state: "ok", data: { window: "24h", totals: { outbound: 10, inbound: 20, throttled: 1, over_quota: 2, auth_failed: 3, local_submit: 4, rejected: 5 } } };
  const admin = tiles(q, tr, false);
  assert.deepEqual(admin.map((t) => t.key), ["queue", "outbound", "inbound", "local", "rejected", "throttled", "over_quota", "auth_failed"]);
  assert.equal(admin[0].value, "1,500");
  assert.equal(admin[0].sub, "12 frozen · 300 deferred");
  assert.equal(admin[1].sub, "last 24h");
  const scoped = tiles(q, tr, true);
  assert.deepEqual(scoped.map((t) => t.key), ["outbound", "inbound", "throttled", "over_quota", "auth_failed"]);
  // A failed refresh keeps the last numbers; the note says they are old.
  assert.equal(tiles({ state: "error", data: q.data, error: "x" }, tr, false)[0].value, "1,500");
  assert.equal(hasData({ state: "error" }), false);
});

test("source notes", () => {
  assert.equal(sourceNote("queue", { state: "ok", data: {} }).text, "");
  assert.equal(sourceNote("queue", undefined).text, "Loading…");
  assert.match(sourceNote("queue", { state: "unavailable" }).text, /exim_queues/);
  assert.equal(sourceNote("traffic", { state: "unavailable", note: "collector off" }).text, "collector off");
  const e = sourceNote("traffic", { state: "error", error: "HTTP 502" });
  assert.equal(e.bad, true);
  assert.equal(e.text, "Could not load (HTTP 502).");
  assert.match(sourceNote("traffic", { state: "error", error: "HTTP 502", data: {}, at: 1764000000000 }).text, /^Could not refresh \(HTTP 502\)\. Showing the last read, from /);
});

test("headlines", () => {
  assert.equal(queueHeadline(null), "");
  assert.equal(queueHeadline({ mta: "exim", total: 1200, frozen: 3, deferred: 40 }), "exim · 1,200 in queue · 3 frozen · 40 deferred");
  assert.match(queueHeadline({ mta: "exim", total: 9000, truncated: true, parsed: 5000 }), /first 5,000 messages$/);
  assert.equal(trafficHeadline({ window: "6h", scope: "admin" }, false), "last 6h · whole server");
  assert.equal(trafficHeadline({ window: "6h", scope: "scoped" }, false), "last 6h · your domains");
  assert.equal(trafficHeadline({}, true), "your domains");
});
