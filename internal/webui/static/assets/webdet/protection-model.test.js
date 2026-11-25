import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as M from "./protection-model.js";

const NOW = 1_800_000_000;
const row = (o) => ({ ts_unix: NOW - 60, host: "shop.example.gr", ip: "198.51.100.7", uri: "/wp-admin/admin-ajax.php?action=x", method: "post", rule: "WAF_RCE:PHP_BODY", rule_base: "WAF_RCE", waf_rule_id: 402, action: "block", ...o });
const SUMMARY = {
  total_events: 1000, unique_ips: 40, unique_hosts: 3, blocked_events: 250,
  top_rule_bases: [{ key: "WAF_LONG_PATH", count: 600 }, { key: "WAF_RCE", count: 300 }, { key: "WAF_CART_CRAWL", count: 100 }],
  top_ips: [{ key: "198.51.100.7", count: 500, ptr: "host.example.net", country: "Greece", asn: 1241, asn_name: "Example ISP" }, { key: "2001:db8::1", count: 20 }],
  top_hosts: [{ key: "Shop.Example.gr", count: 700 }],
  histogram: [{ ts_unix: NOW - 7200, count: 10, blocked: 4 }, { ts_unix: NOW - 3600, count: 40, blocked: 50 }],
  rows: [
    row({}),
    row({ ts_unix: NOW - 30, action: "challenge", rule: "WAF_RCE:OTHER", waf_rule_id: 0 }),
    row({ rule: "WAF_CART_CRAWL:NO_REFERER", rule_base: "WAF_CART_CRAWL", waf_rule_id: 611, action: "challenge_v2", ip: "2001:db8::1" }),
  ],
};

test("tabs, windows and groupings fall back to their defaults", () => {
  assert.equal(M.tab("events"), "events");
  assert.equal(M.tab("nope"), "waf");
  assert.equal(M.windowOf(6).mix, "6h");
  assert.equal(M.windowOf(168).mix, "", "the traffic mix keeps 24 h");
  assert.equal(M.windowOf(5).hours, 24);
  assert.equal(M.grouping("ip"), "ip");
  assert.equal(M.grouping("__proto__"), "rule");
});

test("wafQuery clamps and carries only the filters set", () => {
  assert.equal(M.wafQuery({ hours: 6, limit: 9999, top: 500, filters: { host: " shop.gr ", rule: "", ip: "198.51.100.7" } }),
    "v1/waf/engine/summary?hours=6&limit=2000&top=100&enrich=1&host=shop.gr&ip=198.51.100.7");
  assert.equal(M.wafQuery(), "v1/waf/engine/summary?hours=24&limit=200&top=50&enrich=1");
});

test("groupRows: exact counts from the node's top list, tier and last hit from the recent requests", () => {
  const g = M.groupRows(SUMMARY, "rule");
  assert.deepEqual(g.map((x) => [x.key, x.count]), [["WAF_LONG_PATH", 600], ["WAF_RCE", 300], ["WAF_CART_CRAWL", 100]]);
  assert.equal(g[0].share, 0.6);
  assert.equal(g[0].width, 1);
  assert.deepEqual(g[0].tiers, [], "no recent request of it: no tier guessed");
  assert.equal(g[0].last, 0);
  assert.deepEqual(g[1].tiers, ["block", "challenge"]);
  assert.equal(g[1].last, NOW - 30);
  assert.equal(g[1].ruleID, 402);
  assert.deepEqual(g[2].tiers, ["challenge v2"]);

  const ips = M.groupRows(SUMMARY, "ip");
  assert.equal(ips[0].who, "Greece · AS1241 Example ISP · host.example.net");
  assert.equal(ips[1].who, "");
  assert.deepEqual(ips[1].tiers, ["challenge v2"]);

  const hosts = M.groupRows(SUMMARY, "host");
  assert.equal(hosts[0].key, "Shop.Example.gr");
  assert.equal(hosts[0].tiers.length, 3, "vhosts match whatever their case");
  assert.deepEqual(M.groupRows(null, "rule"), []);
});

test("groupsNote says when the list is the top N of more", () => {
  assert.equal(M.groupsNote(SUMMARY, "rule", 50), "1,000 hits in 3 rule groups.");
  assert.equal(M.groupsNote(SUMMARY, "rule", 3), "1,000 hits in the top 3 rule groups (more exist: narrow the filters).");
  assert.equal(M.groupsNote(SUMMARY, "host", 50), "1,000 hits in 1 vhost group.");
  assert.equal(M.groupsNote({ total_events: 0 }, "rule", 50), "No WAF hit in this window.");
});

test("tier and its tone", () => {
  assert.equal(M.tier({ action: "BLOCK" }), "block");
  assert.equal(M.tier({ action: "challenge_v2" }), "challenge v2");
  assert.equal(M.tier({ action: "log" }), "logonly");
  assert.equal(M.tier({}), "observed");
  assert.equal(M.tierTone("block"), "danger");
  assert.equal(M.tierTone("logonly"), "");
});

test("excludeOffer is the narrowest exclude: this path, this rule, this vhost", () => {
  const o = M.excludeOffer(row({ host: "Shop.Example.gr" }));
  assert.equal(o.url, "v1/waf/exclude/add?type=path&value=%2Fwp-admin%2Fadmin-ajax.php&rule_ids=402&scope_hosts=shop.example.gr");
  assert.match(o.confirm, /rule 402 on shop\.example\.gr/);
  assert.equal(M.excludeOffer(row({}), { scoped: true }), null, "a scoped caller may only write host excludes");
  assert.equal(M.excludeOffer(row({ waf_rule_id: 0 })), null, "no rule id: nothing to scope it to");
  assert.equal(M.excludeOffer(row({ uri: "/?add-to-cart=1" })), null, "never the whole site");
  assert.equal(M.excludeOffer(row({ uri: "/a/*/b" })), null, "a path that would read as a glob");
  assert.equal(M.excludeOffer(row({ host: "" })), null);
  assert.equal(M.uriPath("/a/b?c=1"), "/a/b");
  assert.equal(M.uriPath(""), "/");
});

test("events: the query, the cursor and the labels", () => {
  assert.equal(M.eventsQuery({ host: "shop.gr", type: "waf_trigger" }), "v1/webdet/history/events?limit=50&enrich=1&host=shop.gr&type=waf_trigger");
  assert.equal(M.eventsQuery({ type: "made_up", cursor: { ts: 100, id: 7 } }), "v1/webdet/history/events?limit=50&enrich=1&before_ts=100&before_id=7");
  assert.equal(M.eventsQuery({ cursor: { ts: 100, id: 0 } }), "v1/webdet/history/events?limit=50&enrich=1", "no id: the first page");
  const page = Array.from({ length: M.EVENT_PAGE }, (_, i) => ({ id: 500 - i, ts_unix: NOW - i }));
  assert.deepEqual(M.nextCursor(page), { ts: NOW - 49, id: 451 });
  assert.equal(M.nextCursor(page.slice(0, 10)), null, "a short page is the last");
  assert.equal(M.nextCursor(page.map((r) => ({ ts_unix: r.ts_unix }))), null, "no ids: no paging");
  assert.equal(M.eventLabel("challenge_v2_reject"), "v2 reject");
  assert.equal(M.eventLabel("challenge_vhost_manual_on"), "challenge vhost manual on");
  assert.equal(M.eventTone("block_trigger"), "danger");
  assert.equal(M.eventTone("challenge_solved"), "ok");
  assert.equal(M.eventDetail({ reason: "WAF_RCE:PHP_BODY", status_code: 403, payload: { method: "post", uri: "/x" } }), "WAF_RCE:PHP_BODY · POST /x · 403");
  assert.equal(M.eventDetail({ reason: "", payload: "not an object" }), "");
});

// The filter chips name history types: each must be one the daemon writes.
test("EVENT_TYPES are event types the daemon records", () => {
  const dir = new URL("../../../../webdetector/", import.meta.url);
  const src = ["engine.go", "challenge_server.go", "history_store.go", "nginx_bridge.go", "challenge_v2.go", "challenge_events.go"]
    .map((f) => { try { return readFileSync(new URL(f, dir), "utf8"); } catch { return ""; } }).join("\n");
  for (const t of M.EVENT_TYPES) {
    if (!t.key) continue;
    assert.ok(src.includes(`"${t.key}"`), `${t.key} is not an event type in internal/webdetector`);
  }
});

test("age, whoLine, tiles, histogram, filters", () => {
  const now = NOW * 1000;
  assert.equal(M.age(NOW - 5, now), "5 s ago");
  assert.equal(M.age(NOW - 200, now), "3 m ago");
  assert.equal(M.age(NOW - 7300, now), "2 h ago");
  assert.equal(M.age(NOW - 200000, now), "2 d ago");
  assert.equal(M.age(NOW + 50, now), "0 s ago", "a clock a little ahead never reads negative");
  assert.equal(M.age(0, now), "");
  assert.equal(M.whoLine({ country_iso: "GR", country: "Greece", asn: 1241 }), "GR · AS1241");
  assert.equal(M.whoLine({ asn_name: "Example ISP" }), "Example ISP");
  assert.equal(M.whoLine(null), "");
  assert.deepEqual(M.wafTiles(SUMMARY).map((t) => [t.value, t.sub]), [["1,000", "40 addresses · 3 vhosts"], ["250", "25% of the hits"]]);
  assert.equal(M.wafTiles(null)[1].sub, "none");
  const h = M.histBars(SUMMARY);
  assert.equal(h[1].height, 1);
  assert.equal(h[0].height, 0.25);
  assert.equal(h[1].blockedHeight, 1, "blocked never taller than its bar");
  assert.deepEqual(M.histBars({}), []);
  assert.deepEqual(M.activeFilters({ host: "a.gr", rule: "", ip: " 198.51.100.7 " }), [{ key: "host", label: "vhost", value: "a.gr" }, { key: "ip", label: "address", value: "198.51.100.7" }]);
});
