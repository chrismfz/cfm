// /cfm-admin/assets/webdet/vhost-picker-model.js
//
// Pure model for the Vhost page's host picker (feature-vhost-picker.js): one
// row per known host with chips for what is going on there, the hosts that
// need attention first. Every fact is the daemon's:
//   - GET v1/webdet/vhosts          the controls row (challenge / WAF excludes,
//     under attack, tier, lockdown, Site Cache tiers, live rule count, HTTP/3,
//     ClamAV); scope-filtered for a scoped (cPanel) caller;
//   - GET v1/challenge/vhosts       the hosts challenged right now;
//   - GET v1/webdet/suspicious      the hosts the long window scores suspicious.
// This file only words and orders them.

const str = (v) => (v === undefined || v === null ? "" : String(v)).trim().toLowerCase();
const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

// hostSet turns a list of rows (or host strings) into a Set of hosts.
export function hostSet(rows) {
  const out = new Set();
  for (const r of Array.isArray(rows) ? rows : []) {
    const h = str(typeof r === "string" ? r : r && r.host);
    if (h) out.add(h);
  }
  return out;
}

// Each chip: { key, text, tone, weight }. weight orders the list: a host with
// any weighted chip sorts above the quiet ones, the heaviest first.
// CHIP_KEYS lists every key; a page that shows some of them as its own
// columns (Vhost controls) leaves those out with without().
export const CHIP_KEYS = Object.freeze(["attack", "lockdown", "challenged", "suspicious", "waf-off", "challenge-excluded", "cache", "rules", "h3", "clam"]);

export function without(chipList, keys) {
  const drop = new Set(keys);
  return chipList.filter((c) => !drop.has(c.key));
}

export function chips(row, ctx = {}) {
  if (!row) return [];
  const host = str(row.host);
  const out = [];
  const add = (key, text, tone, weight = 0) => out.push({ key, text, tone, weight });
  if (row.under_attack) add("attack", "under attack", "attack", 100);
  if (row.challenge_lockdown_until) add("lockdown", "lockdown", "danger", 60);
  if (ctx.challenged && ctx.challenged.has(host)) {
    add("challenged", row.challenge_rung === "v2" ? "challenged v2" : "challenged", "warn", 50);
  }
  if (ctx.suspicious && ctx.suspicious.has(host)) add("suspicious", "suspicious", "warn", 40);
  if (row.waf_enabled === false) add("waf-off", "WAF off", "danger", 30);
  if (row.challenge_enabled === false) add("challenge-excluded", "challenge excluded", "", 10);
  if (row.site_cache_micro) add("cache", "micro cache", "info");
  else if (row.site_cache_static) add("cache", "cache", "ok");
  const rules = num(row.rules);
  if (rules > 0) add("rules", `${rules} rule${rules === 1 ? "" : "s"}`, "info");
  if (row.http3_enabled) add("h3", "HTTP/3", "");
  if (row.clam_enabled && row.clam_mode_inline) add("clam", "inline scan", "");
  return out;
}

export function weight(chipList) {
  return chipList.reduce((s, c) => s + c.weight, 0);
}

// entries builds the picker list: rows filtered by query (a substring of the
// host), each with its chips, the ones that need attention first, then by
// name. limit caps what is rendered (a node can hold hundreds of hosts; the
// query narrows them).
export function entries(rows, ctx = {}, query = "", limit = 200) {
  const q = str(query);
  const list = [];
  const seen = new Set();
  for (const row of Array.isArray(rows) ? rows : []) {
    const host = str(row && row.host);
    if (!host || seen.has(host)) continue;
    seen.add(host);
    if (q && !host.includes(q)) continue;
    const c = chips(row, ctx);
    list.push({ host, chips: c, weight: weight(c) });
  }
  list.sort((a, b) => b.weight - a.weight || exactFirst(a.host, b.host, q) || a.host.localeCompare(b.host));
  return { items: list.slice(0, Math.max(0, limit | 0)), total: list.length };
}

// An exact match of the query sorts above the other quiet hosts.
function exactFirst(a, b, q) {
  if (!q) return 0;
  return (b === q) - (a === q);
}

// attentionCount is how many hosts carry a weighted chip (the picker's
// summary line: "3 need attention").
export function attentionCount(rows, ctx = {}) {
  let n = 0;
  for (const row of Array.isArray(rows) ? rows : []) if (weight(chips(row, ctx)) > 0) n++;
  return n;
}
