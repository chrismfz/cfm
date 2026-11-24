import { test } from "node:test";
import assert from "node:assert/strict";
import { hostSet, chips, entries, attentionCount, without, weight, CHIP_KEYS } from "./vhost-picker-model.js";

// /api/v1/webdet/vhosts rows (webdetVhostControlRow), as the daemon sends them.
const ROWS = [
  { host: "nexon.gr", challenge_enabled: true, waf_enabled: true },
  { host: "myip.gr", challenge_enabled: false, challenge_matched_exclude: "myip.gr", waf_enabled: true, site_cache_static: true },
  { host: "vol2.gr", challenge_enabled: true, waf_enabled: true, challenge_rung: "v2", site_cache_static: true, site_cache_micro: true, rules: 2 },
  { host: "shop.gr", challenge_enabled: true, waf_enabled: false, under_attack: true, challenge_lockdown_until: "2026-11-24T18:00:00Z", http3_enabled: true },
  { host: "files.gr", challenge_enabled: true, waf_enabled: true, clam_enabled: true, clam_mode_inline: true, rules: 1 },
];
const CTX = { challenged: hostSet([{ host: "vol2.gr" }, { host: "shop.gr" }]), suspicious: hostSet(["VOL2.gr"]) };
const texts = (c) => c.map((x) => x.text);

test("chips word each host's state", () => {
  const by = Object.fromEntries(ROWS.map((r) => [r.host, texts(chips(r, CTX))]));
  assert.deepEqual(by["nexon.gr"], []);
  assert.deepEqual(by["myip.gr"], ["challenge excluded", "cache"]);
  assert.deepEqual(by["vol2.gr"], ["challenged v2", "suspicious", "micro cache", "2 rules"]);
  assert.deepEqual(by["shop.gr"], ["under attack", "lockdown", "challenged", "WAF off", "HTTP/3"]);
  assert.deepEqual(by["files.gr"], ["1 rule", "inline scan"]);
  assert.deepEqual(chips(null), []);
});

test("entries: attention first, then by name; the quiet ones alphabetical", () => {
  const { items, total } = entries(ROWS, CTX);
  assert.equal(total, 5);
  assert.deepEqual(items.map((i) => i.host), ["shop.gr", "vol2.gr", "myip.gr", "files.gr", "nexon.gr"]);
});

test("entries: a query narrows by substring, an exact match leads the quiet hosts", () => {
  assert.deepEqual(entries(ROWS, CTX, "Gr").items.length, 5);
  assert.deepEqual(entries(ROWS, CTX, "vol").items.map((i) => i.host), ["vol2.gr"]);
  const rows = [{ host: "a.example.com" }, { host: "example.com" }, { host: "b.example.com" }];
  assert.deepEqual(entries(rows, {}, "example.com").items.map((i) => i.host), ["example.com", "a.example.com", "b.example.com"]);
});

test("entries: duplicates dropped, limit caps what is rendered but not the total", () => {
  const rows = [{ host: "a.gr" }, { host: "A.gr" }, { host: "b.gr" }, { host: "" }, null];
  const r = entries(rows, {}, "", 1);
  assert.equal(r.total, 2);
  assert.deepEqual(r.items.map((i) => i.host), ["a.gr"]);
});

test("attention count", () => {
  assert.equal(attentionCount(ROWS, CTX), 3);
  assert.equal(attentionCount(ROWS, {}), 2); // shop.gr (attack, WAF off), myip.gr (excluded)
});

test("without drops the chips a page shows as columns; weight still counts them all", () => {
  const shop = chips(ROWS[3], CTX);
  const extra = without(shop, ["attack", "lockdown", "waf-off", "challenge-excluded", "h3", "clam"]);
  assert.deepEqual(texts(extra), ["challenged"]);
  assert.ok(weight(shop) > weight(extra));
  for (const r of ROWS) for (const c of chips(r, CTX)) assert.ok(CHIP_KEYS.includes(c.key), c.key);
});

test("an exact match comes first even above a host that needs attention", () => {
  const rows = [{ host: "example.com" }, { host: "www.example.com", under_attack: true }];
  assert.deepEqual(entries(rows, {}, "example.com").items.map((i) => i.host), ["example.com", "www.example.com"]);
  assert.deepEqual(entries(rows, {}, "").items.map((i) => i.host), ["www.example.com", "example.com"]);
});

test("attention count de-duplicates hosts like entries()", () => {
  const rows = [{ host: "a.gr", under_attack: true }, { host: "A.gr", under_attack: true }];
  assert.equal(attentionCount(rows, {}), 1);
});
