// /cfm-admin/assets/webdet/protection-model.js
//
// Pure model for the Protection page (feature-protection.js): what the edge
// stopped and why, in one place (it replaced the WAF engine and Forensics
// pages). It reads, and never copies, three endpoints:
//
//   GET v1/waf/engine/summary      WAF hits: totals, top rules / IPs / vhosts, rows
//   GET v1/webdet/history/events   every history event, newest first, paged
//   GET v1/webdet/traffic-mix      the edge outcomes (admin only)
//
// The WAF log is GROUPED by default: 200 rows of one rule hide the one hit
// that matters. The groups and their counts are the node's own top lists
// (exact, over the whole window); opening a group asks the node for that
// group's requests, so nothing here is counted from a sample.

import { fmtCount, fmtPct, share } from "./traffic-model.js";

const str = (v) => (v === null || v === undefined ? "" : String(v));
const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

export const TABS = Object.freeze([
  Object.freeze({ key: "waf", label: "WAF log" }),
  Object.freeze({ key: "events", label: "Events" }),
  Object.freeze({ key: "overview", label: "Overview" }),
  // Admin only: the analyze tools and the history store read box-wide data.
  Object.freeze({ key: "tools", label: "Tools", admin: true }),
]);
// tabsFor lists the tabs a session sees.
export function tabsFor({ scoped } = {}) {
  return TABS.filter((t) => !(t.admin && scoped));
}
export const DEFAULT_TAB = "waf";
export function tab(key) {
  return TABS.some((t) => t.key === key) ? key : DEFAULT_TAB;
}

// The page's windows, in hours (the WAF summary takes up to 30 days; the
// traffic mix keeps 24 h, so the outcome tiles show for a day at most).
export const WINDOWS = Object.freeze([
  Object.freeze({ hours: 1, label: "1 hour", mix: "1h" }),
  Object.freeze({ hours: 6, label: "6 hours", mix: "6h" }),
  Object.freeze({ hours: 24, label: "24 hours", mix: "24h" }),
  Object.freeze({ hours: 168, label: "7 days", mix: "" }),
]);
export function windowOf(hours) {
  return WINDOWS.find((w) => w.hours === Number(hours)) || WINDOWS[2];
}

// How the WAF log is grouped: which of the summary's top lists carries the
// groups, which filter of the same endpoint lists one group's requests, and
// how many groups are asked for (`enrich`: the address list shows who each
// one is, which costs a reverse lookup per address, so it is the short one).
// The rule groups are rule FAMILIES (the reason up to its first colon); the
// endpoint's rule= filter matches a substring, so a family whose name is
// inside another's (WAF_BOT in WAF_BOT_UA) lists both when opened.
export const GROUPINGS = Object.freeze({
  rule: Object.freeze({ label: "rule", top: "top_rule_bases", param: "rule", head: "Rule family", n: 50, enrich: false }),
  ip: Object.freeze({ label: "address", top: "top_ips", param: "ip", head: "Address", n: 20, enrich: true }),
  host: Object.freeze({ label: "vhost", top: "top_hosts", param: "host", head: "Vhost", n: 50, enrich: false }),
  // The country comes from the enrichment, so this one asks for it too.
  country: Object.freeze({ label: "country", top: "top_countries", param: "country", head: "Country", n: 20, enrich: true }),
});
export const DEFAULT_GROUPING = "rule";
export function grouping(key) {
  return Object.prototype.hasOwnProperty.call(GROUPINGS, key) ? key : DEFAULT_GROUPING;
}

// tier is what the WAF did with a hit, from the row's action.
export function tier(row) {
  const a = str(row && row.action).toLowerCase();
  if (a === "block") return "block";
  if (a === "challenge_v2") return "challenge v2";
  if (a === "challenge") return "challenge";
  if (a === "logonly" || a === "log") return "logonly";
  return a || "observed";
}
export function tierTone(t) {
  if (t === "block") return "danger";
  if (t === "challenge v2") return "v2";
  if (t === "challenge") return "warn";
  return "";
}

// wafQuery builds the summary request. filters: { host, rule, ip, country }.
// enrich asks for country / ASN on the rows and a PTR for every top address:
// a blocking reverse lookup each (up to a second, one after another), so it
// is asked only where the answer is shown and with a small `top`.
export function wafQuery({ hours, limit, top, filters, enrich } = {}) {
  const q = new URLSearchParams();
  q.set("hours", String(windowOf(hours).hours));
  q.set("limit", String(Math.max(1, Math.min(2000, Number(limit) || 200))));
  q.set("top", String(Math.max(1, Math.min(100, Number(top) || 50))));
  if (enrich) q.set("enrich", "1");
  const f = filters || {};
  for (const k of ["host", "rule", "ip", "country"]) {
    const v = str(f[k]).trim();
    if (v) q.set(k, v);
  }
  return `v1/waf/engine/summary?${q.toString()}`;
}

// groupRows turns the summary into the grouped log: one row per group with
// its exact count (the node's top list) and, from the recent requests the
// same answer carries, what tier it ran at and when it last fired. A group
// with no request among the recent ones shows neither: absent, not guessed.
export function groupRows(summary, by) {
  const g = GROUPINGS[grouping(by)];
  const list = Array.isArray(summary && summary[g.top]) ? summary[g.top] : [];
  const rows = Array.isArray(summary && summary.rows) ? summary.rows : [];
  const total = num(summary && summary.total_events);
  // The node's country key is the name, or the ISO code when it has no name.
  const keyOf = (r) => (g.param === "rule" ? str(r.rule_base)
    : g.param === "ip" ? str(r.ip)
      : g.param === "country" ? (str(r.country).trim() || str(r.country_iso).trim().toUpperCase())
        : str(r.host).toLowerCase());
  const seen = new Map();
  for (const r of rows) {
    const k = keyOf(r);
    if (!k) continue;
    let s = seen.get(k);
    if (!s) { s = { tiers: new Set(), last: 0, ruleIDs: new Set() }; seen.set(k, s); }
    s.tiers.add(tier(r));
    if (num(r.ts_unix) > s.last) s.last = num(r.ts_unix);
    if (num(r.waf_rule_id) > 0) s.ruleIDs.add(num(r.waf_rule_id));
  }
  const max = list.reduce((m, x) => Math.max(m, num(x && x.count)), 0);
  return list.filter((x) => x && str(x.key)).map((x) => {
    const key = str(x.key);
    const s = seen.get(g.param === "host" ? key.toLowerCase() : key);
    return {
      key,
      count: num(x.count),
      share: share(x.count, total),
      width: max > 0 ? num(x.count) / max : 0,
      tiers: s ? [...s.tiers].sort() : [],
      last: s ? s.last : 0,
      // Every rule id seen under this group among the recent requests (a
      // family holds several rules).
      ruleIDs: s ? [...s.ruleIDs].sort((a, b) => a - b) : [],
      // top_ips entries carry who the address is.
      who: g.param === "ip" ? whoLine(x) : "",
    };
  });
}

// listedGroups says how complete the grouped log is: the node sends the top
// N groups, so more may exist when the list is full.
export function groupsNote(summary, by, top) {
  const g = GROUPINGS[grouping(by)];
  const n = Array.isArray(summary && summary[g.top]) ? summary[g.top].length : 0;
  const total = num(summary && summary.total_events);
  if (!total) return "No WAF hit in this window.";
  const full = n >= num(top) && num(top) > 0;
  return `${fmtCount(total)} hits in ${full ? `the top ${fmtCount(n)}` : fmtCount(n)} ${g.label} group${n === 1 ? "" : "s"}${full ? " (more exist: narrow the filters)" : ""}.`;
}

// whoLine is "GR · AS1241 Forthnet · ptr.example" from whatever the node knows.
export function whoLine(x) {
  if (!x) return "";
  const parts = [];
  const cc = str(x.country_iso || x.country).trim();
  if (cc) parts.push(cc);
  const asn = num(x.asn);
  const name = str(x.asn_name).trim();
  if (asn || name) parts.push(`${asn ? `AS${asn}` : ""}${asn && name ? " " : ""}${name}`);
  const ptr = str(x.ptr).trim();
  if (ptr) parts.push(ptr);
  return parts.join(" · ");
}

// uriPath is the request path without its query: what a path exclude takes.
export function uriPath(uri) {
  const p = str(uri).split("?")[0];
  return p || "/";
}

// excludeOffer is the narrowest WAF exclude that would have let one logged
// request through: this path, this rule, this vhost. A scoped (cPanel)
// caller may only write host excludes today, so it gets none here.
// null when the row cannot be excluded that narrowly (no rule id or path).
export function excludeOffer(row, { scoped } = {}) {
  if (scoped || !row) return null;
  const id = num(row.waf_rule_id);
  const path = uriPath(row.uri);
  const host = str(row.host).trim().toLowerCase();
  if (id <= 0 || !host || path === "/" || /[*?\[\]]/.test(path)) return null;
  const q = new URLSearchParams({ type: "path", value: path, rule_ids: String(id), scope_hosts: host });
  return {
    path, host, ruleID: id,
    url: `v1/waf/exclude/add?${q.toString()}`,
    confirm: `Let ${path} through WAF rule ${id} on ${host}?\n\nRequests to that path on that vhost skip this one rule until the exclude is removed (Exceptions page). Every other rule still applies.`,
  };
}

// ── Events ───────────────────────────────────────────────────────────────

// The event kinds offered as filters, most useful first. The history holds
// more types than these: "All" lists every one.
export const EVENT_TYPES = Object.freeze([
  Object.freeze({ key: "", label: "All" }),
  Object.freeze({ key: "waf_trigger", label: "WAF hit" }),
  Object.freeze({ key: "challenge_issued", label: "Challenge served" }),
  Object.freeze({ key: "challenge_solved", label: "Solved" }),
  Object.freeze({ key: "challenge_v2_reject", label: "v2 reject" }),
  Object.freeze({ key: "challenge_expired_unsolved", label: "Not solved" }),
  Object.freeze({ key: "block_trigger", label: "Block" }),
  Object.freeze({ key: "waf_observe", label: "WAF observed" }),
]);
export function eventType(key) {
  return EVENT_TYPES.some((t) => t.key === key) ? key : "";
}
// eventLabel: the filter's wording for a known type, the raw type otherwise.
export function eventLabel(type) {
  const t = EVENT_TYPES.find((x) => x.key && x.key === type);
  return t ? t.label : str(type).replace(/_/g, " ");
}
export function eventTone(type) {
  const t = str(type);
  if (t === "block_trigger" || t === "block") return "danger";
  if (t === "challenge_v2_reject") return "v2";
  if (t === "challenge_solved") return "ok";
  if (t.startsWith("waf_") || t.startsWith("challenge_")) return "warn";
  return "";
}

export const EVENT_PAGE = 50;

// eventsQuery builds one page of the history. cursor is the last row of the
// page shown ({ ts, id }), or null for the newest page.
export function eventsQuery({ host, ip, type, cursor } = {}) {
  const q = new URLSearchParams();
  q.set("limit", String(EVENT_PAGE));
  q.set("enrich", "1");
  for (const [k, v] of [["host", host], ["ip", ip], ["type", eventType(str(type))]]) {
    const s = str(v).trim();
    if (s) q.set(k, s);
  }
  if (cursor && num(cursor.id) > 0) {
    q.set("before_ts", String(num(cursor.ts)));
    q.set("before_id", String(num(cursor.id)));
  }
  return `v1/webdet/history/events?${q.toString()}`;
}

// nextCursor is the cursor for the page after this answer, or null on the
// last page. The node says so itself (`next`): a scoped caller's page can
// come back short of a full one with older events still to read, because the
// node's own fault rows are dropped from it after the query.
export function nextCursor(res) {
  const n = res && res.next;
  if (!n || num(n.before_id) <= 0) return null;
  return { ts: num(n.before_ts), id: num(n.before_id) };
}

// eventDetail is the one-line "what happened" of an event row.
export function eventDetail(ev) {
  if (!ev) return "";
  const p = (ev.payload && typeof ev.payload === "object") ? ev.payload : {};
  const parts = [];
  const reason = str(ev.reason).trim();
  if (reason) parts.push(reason);
  const method = str(p.method).trim();
  const uri = str(p.uri).trim();
  if (uri) parts.push(`${method ? `${method.toUpperCase()} ` : ""}${uri}`);
  const st = num(ev.status_code);
  if (st) parts.push(String(st));
  return parts.join(" · ");
}

// eventsSummaryQuery asks the window's totals for the same vhost and address.
export function eventsSummaryQuery({ hours, host, ip } = {}) {
  const q = new URLSearchParams();
  q.set("hours", String(windowOf(hours).hours));
  for (const [k, v] of [["host", host], ["ip", ip]]) {
    const s = str(v).trim();
    if (s) q.set(k, s);
  }
  return `v1/webdet/history/summary?${q.toString()}`;
}

// eventsSummary is the window's totals as labelled counts, or [] when the
// node sent none (a failed read shows nothing, never zeros).
export function eventsSummary(s) {
  if (!s || typeof s !== "object") return [];
  return [
    ["Challenges served", s.challenge_issued], ["Solved", s.challenge_solved],
    ["Expired unsolved", s.challenge_expired_unsolved], ["Escalated to a block", s.challenge_escalated_block],
    ["Block triggers", s.block_triggers], ["WAF hits", s.waf_observed],
  ].map(([label, v]) => ({ label, value: fmtCount(v) }));
}

// exceptionsURL is the Exceptions page narrowed to one vhost.
export function exceptionsURL(host) {
  const h = str(host).trim().toLowerCase();
  return `/cfm-admin/webdetector/exceptions/${h ? `?host=${encodeURIComponent(h)}` : ""}`;
}

// impossibleUA is the reason a solve's User-Agent contradicts itself, or "".
export function impossibleUA(ev) {
  const p = (ev && ev.payload && typeof ev.payload === "object") ? ev.payload : {};
  return str(p.ua_impossible).trim();
}

// solveTime is the client's real solve latency of a challenge event ("1.3 s",
// "420 ms"), or "" when the event carries none (never a fabricated zero).
export function solveTime(ev) {
  const p = (ev && ev.payload && typeof ev.payload === "object") ? ev.payload : {};
  const ms = Number(p.solve_ms);
  if (!Number.isFinite(ms) || ms <= 0) return "";
  return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`;
}

// eventUA is the event's User-Agent, or "".
export function eventUA(ev) {
  const p = (ev && ev.payload && typeof ev.payload === "object") ? ev.payload : {};
  return str(p.ua).trim();
}

// ── shared ───────────────────────────────────────────────────────────────

// age is "5 s ago" / "3 m ago" / "2 h ago" / "4 d ago" for a unix time.
export function age(tsUnix, nowMs) {
  const ts = num(tsUnix);
  if (ts <= 0) return "";
  const s = Math.max(0, Math.floor(((nowMs === undefined ? Date.now() : nowMs) / 1000) - ts));
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

// wafTiles are the headline numbers of the WAF summary.
export function wafTiles(summary) {
  const s = summary || {};
  const total = num(s.total_events);
  return [
    { key: "hits", title: "WAF hits", value: fmtCount(total), sub: `${fmtCount(s.unique_ips)} addresses · ${fmtCount(s.unique_hosts)} vhosts` },
    { key: "blocked", title: "Blocked", value: fmtCount(s.blocked_events), sub: total ? `${fmtPct(share(s.blocked_events, total), 0)} of the hits` : "none" },
  ];
}

// activeFilters lists the filters in force, for the chips that clear them.
export function activeFilters(filters) {
  const f = filters || {};
  const out = [];
  for (const [k, label] of [["host", "vhost"], ["rule", "rule"], ["ip", "address"], ["country", "country"]]) {
    const v = str(f[k]).trim();
    if (v) out.push({ key: k, label, value: v });
  }
  return out;
}

// histBars turns the summary's per-hour histogram into bar heights (0..1 of
// the busiest hour), oldest first: all hits, and the blocked part of each.
export function histBars(summary) {
  const h = Array.isArray(summary && summary.histogram) ? summary.histogram : [];
  const max = h.reduce((m, b) => Math.max(m, num(b && b.count)), 0);
  return h.map((b) => ({
    ts: num(b.ts_unix),
    count: num(b.count),
    blocked: num(b.blocked),
    height: max > 0 ? num(b.count) / max : 0,
    // The blocked part of its own bar, never more than all of it.
    blockedShare: num(b.count) > 0 ? Math.min(1, num(b.blocked) / num(b.count)) : 0,
  }));
}
