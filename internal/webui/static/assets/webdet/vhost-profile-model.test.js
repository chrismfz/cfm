import { test } from "node:test";
import assert from "node:assert/strict";
import {
  PROFILE_SCHEMA, tab, parseTime, postureTiles, challengeTile, wafTile, protoTile, cacheTile, rulesTile, clamTile,
  headPills, ruleRows, excludeRows, matchSummary, actionLabel, relatedHosts, trafficTiles, botClients,
  distributedClients, stackedArea, niceStep, securityTiles, wafRuleRows, editURL,
} from "./vhost-profile-model.js";
import { OTHER_KEY } from "./traffic-model.js";

// A real GET /api/v1/webdet/vhost-profile?host=www.example.com body (from
// VhostProfile in a test engine: an apex WAF rule exclude, a WAF path exclude
// scoped to another host, a scoped challenge path exclude, a *.example.com
// cache policy and two rules), trimmed of timestamps the model never reads.
const PROFILE = {
  schema: "webdet.vhost_profile.v1",
  host: "www.example.com",
  site: "example.com",
  related_hosts: ["example.com", "b2b.example.com", "www.example.com"],
  controls: {
    host: "www.example.com", challenge_enabled: true, waf_enabled: true, http3_enabled: false,
    challenge_toggleable: true, waf_toggleable: true, http3_toggleable: true, under_attack: false,
    under_attack_toggleable: false, clam_enabled: false, clam_toggleable: false, clam_override_present: false,
    clam_mode_inline: false, clam_mode_toggleable: false, clam_mode_override_present: false,
  },
  challenge: {
    auto_active: false, auto_since: "0001-01-01T00:00:00Z", expires_at: "0001-01-01T00:00:00Z", host: "www.example.com",
    lockdown: false, lockdown_until: null, manual_active: false, manual_default_rung: "v2", rung: "", rung_pin: "",
    rung_source: "", rung_trigger: "", solver_farm: false, state: "normal",
  },
  waf_excludes: [
    { type: "host", value: "example.com", rule_ids: [402], scope_takes_host: true },
    { type: "path", value: "/import/", scope_hosts: ["other.example.org"], rule_ids: [402], scope_takes_host: false },
  ],
  challenge_excludes: [{ type: "path", value: "/feed/", scope_hosts: ["example.com"] }],
  site_cache: {
    key: "*.example.com", inherited: true,
    entry: { host: "*.example.com", static: { enabled: true, recipe: "static_lean", ttl: "7d" }, micro: { enabled: true, recipe: "micro_safe", ttl: "10s" } },
  },
  rules: [
    { id: "r_39d3688ad47a8fc0", enabled: true, priority: 100, scope: { vhosts: ["*.example.com"] }, match: { path_any: ["/wp-json/wp/v2/users"] }, action: { type: "block" }, matched_by: "*.example.com", state: "enabled" },
    { id: "r_51dbbb24f8b97336", enabled: false, priority: 100, scope: { vhosts: ["www.example.com"] }, match: { country_in: ["CN"], path_any: ["/checkout"] }, action: { type: "block" }, matched_by: "www.example.com", state: "disabled" },
  ],
};

const tileTexts = (t) => t.pills.map((p) => p.text);

test("schema and tabs", () => {
  assert.equal(PROFILE.schema, PROFILE_SCHEMA);
  assert.equal(tab("security"), "security");
  assert.equal(tab("bogus"), "overview");
  assert.equal(parseTime("0001-01-01T00:00:00Z"), null);
  assert.equal(parseTime(null), null);
});

test("six posture tiles, in the page order, each with an edit link for the host", () => {
  const tiles = postureTiles(PROFILE);
  assert.deepEqual(tiles.map((t) => t.key), ["challenge", "waf", "proto", "cache", "rules", "clam"]);
  for (const t of tiles) assert.ok(t.edit.href.startsWith("/cfm-admin/webdetector/"), t.key);
  assert.equal(postureTiles(null).length, 0);
});

test("challenge tile: off, manual with lockdown, automatic, excluded", () => {
  assert.deepEqual(tileTexts(challengeTile(PROFILE)), ["Off"]);

  const manual = challengeTile({ ...PROFILE, challenge: { ...PROFILE.challenge, manual_active: true, rung: "v2", lockdown: true, expires_at: "2026-11-24T18:00:00Z", lockdown_until: "2026-11-24T18:00:00Z" } });
  assert.deepEqual(tileTexts(manual), ["v2", "manual", "lockdown"]);
  assert.match(manual.why, /Lockdown until/);

  const auto = challengeTile({ ...PROFILE, controls: { ...PROFILE.controls, under_attack: true }, challenge: { ...PROFILE.challenge, auto_active: true, rung: "v2", rung_source: "auto", rung_trigger: "under_attack", auto_since: "2026-11-24T14:02:00Z" } });
  assert.deepEqual(tileTexts(auto), ["v2", "auto", "under attack"]);
  assert.match(auto.why, /^Automatic \(under attack\) since/);

  // An apex exclude decides www: the tile says so and is inherited.
  const ex = challengeTile({ ...PROFILE, controls: { ...PROFILE.controls, challenge_enabled: false, challenge_matched_exclude: "example.com" } });
  assert.deepEqual(tileTexts(ex), ["Excluded"]);
  assert.equal(ex.inherited, true);
  assert.match(ex.why, /example\.com/);
});

test("WAF tile counts the excludes and names the ones the edge applies outside their scope", () => {
  const t = wafTile(PROFILE);
  assert.deepEqual(tileTexts(t), ["On", "2 excludes"]);
  assert.match(t.why, /2 rule-scoped/);
  assert.match(t.why, /1 applied here although scoped to other hosts/);
  assert.equal(t.inherited, true); // the host exclude is the apex's

  const off = wafTile({ ...PROFILE, controls: { ...PROFILE.controls, waf_enabled: false, waf_matched_exclude: "www.example.com" } });
  assert.deepEqual(tileTexts(off), ["Off"]);
  assert.equal(off.inherited, false);
});

test("HTTP/3 tile: the node default is inherited, an opt-in names its pattern", () => {
  assert.equal(protoTile(PROFILE).inherited, true);
  const on = protoTile({ ...PROFILE, controls: { ...PROFILE.controls, http3_enabled: true, http3_matched_optin: "*.example.com" } });
  assert.deepEqual(tileTexts(on), ["HTTP/3 on"]);
  assert.equal(on.inherited, true);
  assert.match(on.why, /\*\.example\.com/);
});

test("cache tile: inherited policy, opt-out, none, and the node switches", () => {
  const t = cacheTile(PROFILE);
  assert.deepEqual(tileTexts(t), ["Static", "Micro 10s"]);
  assert.equal(t.inherited, true);
  assert.ok(t.edit.href.endsWith(encodeURIComponent("*.example.com")), "edits the policy that decides the host");

  const none = cacheTile({ ...PROFILE, site_cache: {} });
  assert.deepEqual(tileTexts(none), ["Off"]);

  const optOut = cacheTile({ ...PROFILE, site_cache: { key: "www.example.com", entry: { static: { enabled: false }, micro: { enabled: false } } } });
  assert.deepEqual(tileTexts(optOut), ["Opted out"]);

  const nodeOff = cacheTile({ ...PROFILE, site_cache: { ...PROFILE.site_cache, switches: { site_cache: false, micro_cache_enforce: true } } });
  assert.equal(nodeOff.pills[0].text, "node off");

  const dry = cacheTile({ ...PROFILE, site_cache: { ...PROFILE.site_cache, switches: { site_cache: true, micro_cache_enforce: false } } });
  assert.ok(tileTexts(dry).includes("micro dry run"));

  const frozen = cacheTile({ ...PROFILE, site_cache: { key: "www.example.com", unloadable: true } });
  assert.deepEqual(tileTexts(frozen), ["Opted out"]);
});

test("rules tile counts by state and names the wider scopes", () => {
  const t = rulesTile(PROFILE);
  assert.deepEqual(tileTexts(t), ["1 enabled", "1 disabled"]);
  assert.match(t.why, /1 through a wider scope \(\*\.example\.com\)/);
  assert.equal(t.inherited, true);
  assert.deepEqual(tileTexts(rulesTile({ ...PROFILE, rules: [] })), ["None"]);
});

test("ClamAV tile: node off, async by default, an inline override", () => {
  assert.deepEqual(tileTexts(clamTile(PROFILE)), ["Off"]);
  const def = clamTile({ ...PROFILE, controls: { ...PROFILE.controls, clam_toggleable: true, clam_enabled: true } });
  assert.deepEqual(tileTexts(def), ["Async scan"]);
  assert.equal(def.inherited, true);
  const inline = clamTile({ ...PROFILE, controls: { ...PROFILE.controls, clam_toggleable: true, clam_enabled: true, clam_mode_inline: true, clam_override_present: true } });
  assert.deepEqual(tileTexts(inline), ["Inline scan"]);
  assert.equal(inline.inherited, false);
});

test("head pills", () => {
  assert.deepEqual(headPills(PROFILE), []);
  const hot = headPills({ ...PROFILE, controls: { ...PROFILE.controls, under_attack: true }, challenge: { ...PROFILE.challenge, lockdown: true, solver_farm: true } });
  assert.deepEqual(hot.map((p) => p.text), ["UNDER ATTACK", "lockdown", "solver farm"]);
});

test("rule rows word the match and action, and mark the inherited scope", () => {
  const rows = ruleRows(PROFILE);
  assert.equal(rows[0].match, "path /wp-json/wp/v2/users");
  assert.equal(rows[0].inherited, true);
  assert.equal(rows[0].actionTone, "danger");
  assert.equal(rows[1].match, "path /checkout · country CN");
  assert.equal(rows[1].state, "disabled");
  assert.equal(matchSummary({}), "any request");
  assert.equal(actionLabel({ type: "throttle", profile: "soft_bot" }), "throttle (soft_bot)");
  assert.equal(actionLabel({ type: "throttle_total", rate_rps: 5, per: "node" }), "throttle 5 r/s per node");
  assert.equal(actionLabel({ type: "challenge_v2" }), "challenge v2");
});

test("exclude rows: WAF first, scope words, outside-scope flag", () => {
  const rows = excludeRows(PROFILE);
  assert.deepEqual(rows.map((r) => r.kind), ["WAF", "WAF", "Challenge"]);
  assert.equal(rows[0].rules, "rules 402");
  assert.equal(rows[0].scope, "every vhost");
  assert.equal(rows[0].exact, false);
  assert.equal(rows[1].outsideScope, true);
  assert.equal(rows[2].scope, "example.com");
  assert.equal(rows[2].outsideScope, false);
});

test("related hosts keep the profile's order and always hold the host", () => {
  assert.deepEqual(relatedHosts(PROFILE), ["example.com", "b2b.example.com", "www.example.com"]);
  assert.deepEqual(relatedHosts({ host: "203.0.113.4", related_hosts: [] }), ["203.0.113.4"]);
});

// One host's traffic mix (traffic-mix?host=): per-vhost classes carry no
// status codes, and the clients may include "everything else".
const MIX = {
  schema: "webdet.traffic_mix.v1",
  window_sec: 3600,
  host: "example.com",
  classes: [
    { key: "automation", requests: 21400, origin_sec: 2310 },
    { key: "crawler", requests: 38900, origin_sec: 1120 },
    { key: "bot", requests: 12800, origin_sec: 640 },
    { key: "human", requests: 111120, origin_sec: 1930 },
  ],
  total: { requests: 184220, origin_sec: 6000, rps_avg: 51.2 },
  series_sec: 300,
  series: [
    { t: 1, requests: { automation: 1000, crawler: 3000, bot: 1000, human: 9000 } },
    { t: 2, requests: { automation: 2000, crawler: 3200, bot: 900, human: 9100 } },
    { t: 3, requests: { automation: 4000, crawler: 3100, bot: 1200, human: 9300 } },
  ],
  clients: [
    { class: "automation", client: "Chrome 152 (no static)", requests: 11900, origin_sec: 1480, ips_last_hour: 214 },
    { class: "human", client: "Chrome 152 / Android", requests: 48200, origin_sec: 610, distributed: { ips: 460, requests: 1100, req_per_ip: 2.4, evidence_share: 0.03 } },
    { class: "crawler", client: "Googlebot", requests: 14200, origin_sec: 310 },
    { class: "bot", client: OTHER_KEY, requests: 9000, origin_sec: 900 },
    { class: "bot", client: "python-requests/2.32", requests: 6100, origin_sec: 420 },
  ],
};

test("traffic tiles: bot shares over the host's totals", () => {
  const t = trafficTiles(MIX);
  assert.equal(t.requests, 184220);
  assert.equal(t.originSec, 6000);
  assert.equal(t.botRequestShare.toFixed(3), ((21400 + 38900 + 12800) / 184220).toFixed(3));
  assert.equal(t.botOriginShare.toFixed(3), ((2310 + 1120 + 640) / 6000).toFixed(3));
  assert.equal(trafficTiles(null).requests, 0);
});

test("bot clients: no humans, no everything-else bucket, by origin time", () => {
  const rows = botClients(MIX);
  assert.deepEqual(rows.map((c) => c.client), ["Chrome 152 (no static)", "python-requests/2.32", "Googlebot"]);
  assert.equal(rows[0].originShare.toFixed(4), (1480 / 6000).toFixed(4));
  assert.equal(botClients(MIX, 1).length, 1);
  assert.deepEqual(distributedClients(MIX).map((c) => c.client), ["Chrome 152 / Android"]);
});

test("stacked area: one polygon per class, ticks on a nice scale, none for too few points", () => {
  const a = stackedArea(MIX);
  assert.equal(a.polygons.length, 4);
  assert.equal(a.polygons[0].key, "human"); // bottom layer
  assert.ok(a.max >= 17600, "max covers the busiest bucket");
  assert.equal(a.ticks.length, 5);
  for (const p of a.polygons) assert.equal(p.points.split(" ").length, 6); // 3 up + 3 down
  assert.equal(stackedArea({ series: [MIX.series[0]] }).polygons.length, 0);
  assert.equal(niceStep(4400), 5000);
  assert.equal(niceStep(1200), 2000);
  assert.equal(niceStep(0), 1);
});

test("security tiles and WAF rule rows from history/vhost-overview", () => {
  const ov = { host: "example.com", hours: 24, challenge_issued: 9420, challenge_solved: 3110, solve_rate_pct: 33.0, waf_hits: 845, top_waf_rule: "rule_sqli", waf_by_rule: [{ rule: "rule_bad_ua", count: 288 }, { rule: "rule_sqli", count: 412 }] };
  const t = securityTiles(ov);
  assert.equal(t.solveRate, 0.33);
  assert.equal(t.wafHits, 845);
  const rows = wafRuleRows(ov);
  assert.deepEqual(rows.map((r) => r.rule), ["rule_sqli", "rule_bad_ua"]);
  assert.equal(rows[0].width, 1);
  assert.equal(securityTiles(null).hours, 24);
});

test("edit links carry the host as each page expects it", () => {
  assert.equal(editURL("rules", "a.com"), "/cfm-admin/webdetector/rules/?vhost=a.com");
  assert.equal(editURL("waf", "a.com"), "/cfm-admin/webdetector/waf/?host=a.com");
  assert.equal(editURL("site-cache", "*.a.com"), "/cfm-admin/webdetector/site-cache/?vhost=*.a.com");
});
