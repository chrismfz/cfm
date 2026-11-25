// /cfm-admin/assets/webdet/traffic-model.js
//
// Pure model for the Web Traffic page (assets/traffic.js): the class
// palette, shares and formatting of GET /api/v1/webdet/traffic-mix
// (internal/webdetector/traffic_mix.go, schema webdet.traffic_mix.v1), and
// WHICH ACTIONS a client is offered. That last part holds the guardrails, so
// it lives here, tested (traffic-model.test.js):
//
//   - A browser UA (classes "automation" and "human") is never offered a
//     UA-keyed throttle or block: every real Chrome 152 on Windows sends the
//     exact same string, so a UA rule would hit customers. A browser-looking
//     scraper is acted on by its IPs (a per-IP challenge), never its UA.
//   - "human" clients are offered nothing, unless the node's distributed tell
//     fired on one (`distributed`: one browser UA from many addresses, a few
//     pages each, almost no static / XHR / POST): then its IPs only, as for
//     automation. A label, never automatic; the UA is still never a target.
//   - A deny or throttle is an expiring traffic rule (emergency-model.js),
//     keyed on a UA FAMILY (crawler / bot classes) or on the client's IPs;
//     never an nft ban here (D1).
//
// The classes are labels (the API's note says so); an action is always the
// operator's click.

import { targetsFor } from "./emergency-model.js";

export const CLASS_ORDER = Object.freeze(["automation", "crawler", "bot", "human"]);

export const CLASS_LABELS = Object.freeze({
  automation: "Browser UA, no static/XHR (automation)",
  crawler: "Known crawlers (by UA)",
  bot: "Other bots and tools",
  human: "Browser UA (likely humans)",
});

// Validated with the dataviz palette checker (OKLab CVD/normal-vision/contrast)
// on each theme's card surface; the tables and direct labels carry identity too.
export const CLASS_COLORS = Object.freeze({
  dark: Object.freeze({ automation: "#d95926", crawler: "#3987e5", bot: "#c98500", human: "#199e70" }),
  light: Object.freeze({ automation: "#eb6834", crawler: "#2a78d6", bot: "#eda100", human: "#1baf7a" }),
});

export const BOT_CLASSES = Object.freeze(["automation", "crawler", "bot"]);

export const OTHER_KEY = "_other";

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

export function share(part, total) {
  const t = num(total);
  return t > 0 ? num(part) / t : 0;
}

export function fmtPct(x, digits = 1) {
  return `${(num(x) * 100).toFixed(digits)}%`;
}

export function fmtCount(n) {
  const v = Math.round(num(n));
  return v.toLocaleString("en-US");
}

export function fmtBytes(b) {
  let v = num(b);
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${i === 0 ? Math.round(v) : v.toFixed(v >= 100 ? 0 : 2)} ${units[i]}`;
}

export function fmtMbps(bytes, seconds) {
  const s = num(seconds);
  if (s <= 0) return "0.0 Mbit/s";
  return `${((num(bytes) * 8) / s / 1e6).toFixed(1)} Mbit/s`;
}

export function fmtRate(rps) {
  const v = num(rps);
  return `${v >= 10 ? v.toFixed(0) : v.toFixed(1)} r/s`;
}

export function fmtSeconds(s) {
  return `${fmtCount(s)} s`;
}

// classMap indexes the response's classes by key (missing keys read as zero).
export function classMap(mix) {
  const out = {};
  for (const k of CLASS_ORDER) out[k] = { key: k, requests: 0, origin_sec: 0, bytes: 0 };
  for (const c of (mix && Array.isArray(mix.classes)) ? mix.classes : []) {
    if (c && out[c.key]) out[c.key] = c;
  }
  return out;
}

// summary is what the top tiles read.
export function summary(mix) {
  const cm = classMap(mix);
  const total = (mix && mix.total) || {};
  const botReq = BOT_CLASSES.reduce((s, k) => s + num(cm[k].requests), 0);
  const botOrigin = BOT_CLASSES.reduce((s, k) => s + num(cm[k].origin_sec), 0);
  const clients = (mix && Array.isArray(mix.clients)) ? mix.clients : [];
  // The biggest BOT client: a "human" row is a population of real visitors
  // sharing a browser UA, never "the culprit".
  const top = clients.find((c) => c && c.client !== OTHER_KEY && BOT_CLASSES.includes(c.class)) || null;
  const s5xx = CLASS_ORDER.reduce((s, k) => s + num(cm[k].status && cm[k].status["5xx"]), 0);
  return {
    requests: num(total.requests),
    originSec: num(total.origin_sec),
    botRequestShare: share(botReq, total.requests),
    botOriginShare: share(botOrigin, total.origin_sec),
    topClient: top,
    topClientOriginShare: top ? share(top.origin_sec, total.origin_sec) : 0,
    rpsAvg: num(total.rps_avg),
    share5xx: share(s5xx, total.requests),
  };
}

// segments turns per-class values into the stacked-bar segments (fractions),
// in CLASS_ORDER; a zero total gives zero widths.
export function segments(values, field) {
  const total = CLASS_ORDER.reduce((s, k) => s + num(values[k] && values[k][field]), 0);
  return CLASS_ORDER.map((k) => ({
    key: k,
    value: num(values[k] && values[k][field]),
    fraction: share(values[k] && values[k][field], total),
  }));
}

// hostBotShare is the bots' share of one vhost's origin time.
export function hostBotShare(host) {
  const cls = (host && host.classes) || {};
  const total = num(host && host.total && host.total.origin_sec);
  const bots = BOT_CLASSES.reduce((s, k) => s + num(cls[k] && cls[k].origin_sec), 0);
  return share(bots, total);
}

// topIPs picks the client's n busiest IPs (last hour) and how much of its
// last-hour requests they carry. For a client the distributed tell flagged,
// the addresses listed are a sample of a bigger pool: coverage is then over
// the hour's requests and total is the pool's estimate (distributed.est_ips),
// not over what is listed (500 listed of rigel's ~18,000 read "100%").
export function topIPs(client, n) {
  const list = (client && Array.isArray(client.top_ips_last_hour)) ? client.top_ips_last_hour : [];
  const d = client && client.distributed;
  const listedReq = list.reduce((s, r) => s + num(r.requests), 0);
  const all = d ? Math.max(num(d.requests), listedReq) : listedReq;
  const picked = list.slice(0, Math.max(0, n | 0));
  const got = picked.reduce((s, r) => s + num(r.requests), 0);
  const total = d ? Math.max(num(d.est_ips), num(d.ips), num(client.ips_last_hour)) : num(client && client.ips_last_hour);
  return { ips: picked.map((r) => r.ip), coverage: share(got, all), known: list.length, total };
}

// DIST_ONCE_PER_IP: under this many requests per address in the hour's
// sample, an address is seen about once: a per-IP challenge, throttle or
// deny on it waits for a return that may not come (rigel 2026-11-25: 1.02
// in the sample, 1.10 in the edge log). The sample's req/IP is a lower bound
// (traffic_mix.go distributedTell), so this is a hint, never a verdict.
export const DIST_ONCE_PER_IP = 1.5;

// distributedSummary reads the distributed tell of one client for the page:
// the pool (kept vs estimated addresses), its networks, where it lands
// (vhost shares, "_other" last), and whether per-IP actions can reach it.
// null when the tell did not fire. A reading, never an action.
export function distributedSummary(client) {
  const d = client && client.distributed;
  if (!d) return null;
  const kept = num(d.ips);
  const est = Math.max(num(d.est_ips), kept);
  const requests = num(d.requests);
  const hosts = (Array.isArray(d.hosts) ? d.hosts : [])
    .filter((h) => h && typeof h.host === "string")
    .map((h) => ({ host: h.host, other: h.host === OTHER_KEY, requests: num(h.requests), share: share(h.requests, requests) }));
  const listed = Array.isArray(client.top_ips_last_hour) ? client.top_ips_last_hour.length : 0;
  const reqPerIP = num(d.req_per_ip);
  return {
    kept, est, requests, reqPerIP, evidence: num(d.evidence_share), nets: num(d.nets), hosts, listed,
    reach: est > 0 ? Math.min(1, listed / est) : 0,
    onceEach: reqPerIP > 0 && reqPerIP < DIST_ONCE_PER_IP,
  };
}

// Client ranking (the clients table's sortable columns). `param` is the
// traffic-mix API's `sort` (TrafficMixSorts in traffic_mix.go): the node
// picks the top N by it. A per-second rate is requests over the same window,
// so "rate" ranks as requests.
export const CLIENT_SORTS = Object.freeze({
  origin: { param: "origin", label: "origin time" },
  requests: { param: "requests", label: "requests" },
  rate: { param: "requests", label: "request rate" },
  bytes: { param: "bytes", label: "traffic" },
  ips: { param: "ips", label: "distinct IPs (last hour)" },
});
export const DEFAULT_CLIENT_SORT = "origin";

export function clientSort(key) {
  return Object.prototype.hasOwnProperty.call(CLIENT_SORTS, key) ? key : DEFAULT_CLIENT_SORT;
}

// clientActions lists what the page offers for one client row. Each action:
// { id, label, kind: "primary"|"quiet"|"danger" }. See the guardrails above;
// which targets a deny/throttle may use is emergency-model.js targetsFor.
export function clientActions(client) {
  if (!client || client.client === OTHER_KEY) return [];
  const cls = client.class;
  const hasIPs = Array.isArray(client.top_ips_last_hour) && client.top_ips_last_hour.length > 0;
  const out = [];
  if ((cls === "automation" || cls === "bot" || (cls === "human" && client.distributed)) && hasIPs) {
    out.push({ id: "challenge_ips", label: "Challenge its IPs…", kind: "primary" });
  }
  if (targetsFor(client).length) {
    out.push({ id: "throttle", label: "Throttle…", kind: "quiet" });
    out.push({ id: "deny", label: "Deny…", kind: "danger" });
  }
  return out;
}

// challengeableIPs splits the client's top IPs for the per-IP challenge,
// which keys on an exact address. The traffic mix lists exact addresses
// (IPv6 included; it groups an IPv6 client by its /64 only for its own
// behaviour count), so `prefixes` is empty in practice: a guard, in case a
// list ever carries a prefix, which a deny or throttle rule takes and the
// per-IP challenge cannot.
export function challengeableIPs(ips) {
  const ok = [];
  const prefixes = [];
  for (const ip of Array.isArray(ips) ? ips : []) (String(ip).includes("/") ? prefixes : ok).push(ip);
  return { ok, prefixes };
}
