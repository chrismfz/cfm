// /cfm-admin/assets/webdet/vhost-profile-model.js
//
// Pure model for the Vhost page's profile tabs (feature-vhost-profile.js):
// it turns GET /api/v1/webdet/vhost-profile (vhost_profile.go, schema
// webdet.vhost_profile.v1) into the posture tiles and the "what applies"
// tables, and the per-host traffic mix (traffic-mix?host=) and security
// summary (history/vhost-overview?host=) into tiles and a chart.
//
// It decides NOTHING about enforcement: every verdict (is the challenge on,
// which policy caches this host, does a rule take it) is the daemon's, read
// from the profile. This file only words it. The bot classes, palette and the
// per-client action guardrails are traffic-model.js's, and a rule's wording
// is rules-model.js's (describeMatch / describeAction): reused, never copied.

import { CLASS_ORDER, BOT_CLASSES, OTHER_KEY, classMap, share } from "./traffic-model.js";
import { describeMatch, describeAction } from "./rules-model.js";

export const PROFILE_SCHEMA = "webdet.vhost_profile.v1";

export const TABS = Object.freeze(["overview", "traffic", "security", "config", "live"]);
export const DEFAULT_TAB = "overview";

export function tab(key) {
  return TABS.includes(key) ? key : DEFAULT_TAB;
}

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
const str = (v) => (v === undefined || v === null ? "" : String(v));
const arr = (v) => (Array.isArray(v) ? v : []);

// A Go zero time ("0001-01-01T00:00:00Z") or an empty value is "no time".
export function parseTime(v) {
  const s = str(v);
  if (!s || s.startsWith("0001-")) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? new Date(t) : null;
}

export function fmtWhen(v, now = new Date()) {
  const d = v instanceof Date ? v : parseTime(v);
  if (!d) return "";
  const sameDay = d.toDateString() === now.toDateString();
  const hm = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return sameDay ? hm : `${d.toLocaleDateString()} ${hm}`;
}

const TRIGGER_LABELS = Object.freeze({
  suspicious_vhost: "suspicious traffic",
  uniqpaths_short: "many unique paths",
  vhost_config: "node config",
  under_attack: "under attack",
});

export function triggerLabel(t) {
  return TRIGGER_LABELS[str(t)] || str(t);
}

// Deep links into the pages that edit each setting. Every one of them takes
// ?vhost= (Vhost controls, Traffic rules, Site cache and ClamAV filter on it);
// the Protection page takes ?host=.
export function editURL(page, host) {
  const h = encodeURIComponent(str(host));
  switch (page) {
    case "controls": return `/cfm-admin/webdetector/controls/?vhost=${h}`;
    case "rules": return `/cfm-admin/webdetector/rules/?vhost=${h}`;
    case "site-cache": return `/cfm-admin/webdetector/site-cache/?vhost=${h}`;
    case "clam": return `/cfm-admin/webdetector/clam/?vhost=${h}`;
    case "waf": return `/cfm-admin/webdetector/protection/?tab=waf&host=${h}`;
    case "traffic": return "/cfm-admin/webdetector/traffic/";
  }
  return "";
}

const pill = (text, tone = "") => ({ text, tone });

// ── Posture tiles ─────────────────────────────────────────────────────────
//
// One tile per setting: { key, title, pills: [{text, tone}], why: string,
// inherited: bool, edit: {label, href} }. tone is a .pill class ("ok",
// "warn", "danger", "info", "attack" or "" for neutral). inherited means a
// broader entry decides the host (an apex exclude, a *.suffix policy, the
// node default): the tile is drawn dashed.

export function challengeTile(p, now = new Date()) {
  const c = (p && p.controls) || {};
  const s = (p && p.challenge) || {};
  const host = str(p && p.host);
  const tier = str(s.rung) === "v2" ? "v2" : "v1";
  const out = { key: "challenge", title: "Challenge", pills: [], why: "", inherited: false, edit: { label: "Vhost controls", href: editURL("controls", host) } };

  if (c.challenge_enabled === false) {
    const ex = str(c.challenge_matched_exclude);
    out.pills.push(pill("Excluded", "warn"));
    if (c.under_attack) out.pills.push(pill("under attack", "attack"));
    out.why = ex ? `Exclude ${ex} takes this host: no vhost challenge here.` : "An exclude takes this host: no vhost challenge here.";
    out.inherited = ex !== "" && ex !== host;
    return out;
  }
  if (s.manual_active) {
    out.pills.push(pill(tier, tier === "v2" ? "danger" : "warn"), pill("manual", "info"));
    if (s.lockdown) out.pills.push(pill("lockdown", "danger"));
    const until = fmtWhen(s.expires_at, now);
    const parts = [until ? `Manual challenge until ${until}.` : "Manual challenge."];
    if (s.lockdown) {
      const lu = fmtWhen(s.lockdown_until, now);
      parts.push(lu ? `Lockdown until ${lu}: no client exemption, crawlers held too.` : "Lockdown: no client exemption, crawlers held too.");
    }
    out.why = parts.join(" ");
  } else if (s.auto_active) {
    out.pills.push(pill(tier, tier === "v2" ? "danger" : "warn"), pill("auto", "info"));
    const since = fmtWhen(s.auto_since, now);
    const why = triggerLabel(s.rung_trigger);
    out.why = `Automatic${why ? ` (${why})` : ""}${since ? ` since ${since}` : ""}.`;
  } else {
    out.pills.push(pill("Off"));
    out.why = "No vhost challenge armed. Per-IP decisions and the WAF still challenge clients.";
  }
  if (str(s.rung_source) === "pin" && str(s.rung_pin)) {
    out.why += ` Tier pinned to ${str(s.rung_pin)}.`;
  }
  if (c.under_attack) out.pills.push(pill("under attack", "attack"));
  return out;
}

export function wafTile(p) {
  const c = (p && p.controls) || {};
  const host = str(p && p.host);
  const ex = arr(p && p.waf_excludes);
  const out = { key: "waf", title: "WAF", pills: [], why: "", inherited: false, edit: { label: "WAF log", href: editURL("waf", host) } };
  if (c.waf_enabled === false) {
    const v = str(c.waf_matched_exclude);
    out.pills.push(pill("Off", "danger"));
    out.why = v ? `Whole-WAF exclude ${v} takes this host.` : "A whole-WAF exclude takes this host.";
    out.inherited = v !== "" && v !== host;
    return out;
  }
  out.pills.push(pill("On", "ok"));
  const ruleScoped = ex.filter((e) => arr(e.rule_ids).length > 0);
  const whole = ex.filter((e) => arr(e.rule_ids).length === 0);
  if (ex.length) out.pills.push(pill(`${ex.length} exclude${ex.length === 1 ? "" : "s"}`, "warn"));
  const parts = [];
  if (ruleScoped.length) parts.push(`${ruleScoped.length} rule-scoped`);
  if (whole.length) parts.push(`${whole.length} whole-WAF on a path`);
  out.why = parts.length ? `${parts.join(", ")}. See What applies.` : "No exclude applies to this host.";
  out.inherited = ex.some((e) => e.type === "host" && str(e.value) !== host);
  return out;
}

export function protoTile(p) {
  const c = (p && p.controls) || {};
  const host = str(p && p.host);
  const pat = str(c.http3_matched_optin);
  const out = { key: "proto", title: "HTTP/3", pills: [], why: "", inherited: false, edit: { label: "Vhost controls", href: editURL("controls", host) } };
  if (c.http3_enabled) {
    out.pills.push(pill("HTTP/3 on", "ok"));
    out.why = pat && pat !== host ? `Opted in by ${pat}.` : "Opted in for this host.";
    out.inherited = pat !== "" && pat !== host;
  } else {
    out.pills.push(pill("HTTP/3 off"));
    out.why = "Not opted in (the node default is off).";
    out.inherited = true;
  }
  return out;
}

function tierText(t, name) {
  if (!t || !t.enabled) return `${name} off`;
  return t.ttl ? `${name} ${t.ttl}` : `${name} on`;
}

export function cacheTile(p) {
  const sc = (p && p.site_cache) || {};
  const host = str(p && p.host);
  const sw = sc.switches || null;
  const out = { key: "cache", title: "Site cache", pills: [], why: "", inherited: !!sc.inherited, edit: { label: "Site cache", href: editURL("site-cache", sc.key || host) } };
  if (sc.unloadable) {
    out.pills.push(pill("Opted out", "warn"));
    out.why = `Policy ${str(sc.key)} cannot be loaded by this build: never cached.`;
    return out;
  }
  const e = sc.entry || null;
  if (!sc.key || !e) {
    out.pills.push(pill("Off"));
    out.why = "No policy covers this host: nothing is cached.";
  } else if (!e.static?.enabled && !e.micro?.enabled) {
    out.pills.push(pill("Opted out"));
    out.why = `${sc.key === host ? "This host's" : `${sc.key}'s`} policy has both tiers off.`;
  } else {
    if (e.static?.enabled) out.pills.push(pill("Static", "ok"));
    out.pills.push(pill(tierText(e.micro, "Micro"), e.micro?.enabled ? "warn" : ""));
    out.why = sc.inherited ? `Policy ${sc.key} covers this host.` : "This host's own policy.";
    if (e.static?.enabled) out.why += " Static files follow the origin's Cache-Control (1 h fallback).";
  }
  if (sw && sw.site_cache === false) {
    out.pills.unshift(pill("node off", "danger"));
    out.why += " SITE_CACHE = 0 on this node: nothing is cached.";
  } else if (sw && sw.micro_cache_enforce === false && e?.micro?.enabled) {
    out.pills.push(pill("micro dry run", "warn"));
    out.why += " MICRO_CACHE_ENFORCE = 0: the micro tier stores nothing.";
  }
  return out;
}

export function rulesTile(p) {
  const host = str(p && p.host);
  const rules = arr(p && p.rules);
  const by = (st) => rules.filter((r) => r.state === st).length;
  const enabled = by("enabled");
  const disabled = by("disabled");
  const expired = by("expired");
  const out = { key: "rules", title: "Traffic rules", pills: [], why: "", inherited: false, edit: { label: "Traffic rules", href: editURL("rules", host) } };
  if (!rules.length) {
    out.pills.push(pill("None"));
    out.why = "No traffic rule's scope takes this host.";
    return out;
  }
  out.pills.push(pill(`${enabled} enabled`, enabled ? "info" : ""));
  if (disabled) out.pills.push(pill(`${disabled} disabled`));
  const parts = [];
  const viaPattern = rules.filter((r) => str(r.matched_by) !== host);
  if (viaPattern.length) parts.push(`${viaPattern.length} through a wider scope (${[...new Set(viaPattern.map((r) => r.matched_by))].join(", ")})`);
  if (expired) parts.push(`${expired} expired`);
  const expiring = rules.filter((r) => r.state === "enabled" && str(r.match?.until));
  if (expiring.length) parts.push(`${expiring.length} expiring`);
  out.why = parts.length ? `${parts.join("; ")}.` : "Every rule names this host.";
  out.inherited = viaPattern.length > 0;
  return out;
}

export function clamTile(p) {
  const c = (p && p.controls) || {};
  const host = str(p && p.host);
  const out = { key: "clam", title: "ClamAV", pills: [], why: "", inherited: !c.clam_override_present, edit: { label: "ClamAV", href: editURL("clam", host) } };
  if (!c.clam_toggleable && !c.clam_enabled) {
    out.pills.push(pill("Off"));
    out.why = "ClamAV upload scanning is off on this node.";
    return out;
  }
  if (!c.clam_enabled) {
    out.pills.push(pill("Not scanned"));
  } else if (c.clam_mode_inline) {
    out.pills.push(pill("Inline scan", "warn"));
  } else {
    out.pills.push(pill("Async scan", "ok"));
  }
  out.why = c.clam_override_present
    ? "A per-vhost override flips this host from the node default."
    : "Node default.";
  if (c.clam_enabled && c.clam_mode_inline) out.why += " An upload waits for its scan.";
  return out;
}

export function postureTiles(p, now = new Date()) {
  if (!p) return [];
  return [challengeTile(p, now), wafTile(p), protoTile(p), cacheTile(p), rulesTile(p), clamTile(p)];
}

// headPills are the domain header's state chips.
export function headPills(p) {
  if (!p) return [];
  const out = [];
  const c = p.controls || {};
  const s = p.challenge || {};
  if (c.under_attack) out.push(pill("UNDER ATTACK", "attack"));
  if (s.lockdown) out.push(pill("lockdown", "danger"));
  if (s.solver_farm) out.push(pill("solver farm", "danger"));
  return out;
}

// ── What applies ─────────────────────────────────────────────────────────

export function actionTone(a) {
  const t = str(a && a.type);
  if (t === "block") return "danger";
  if (t === "allow") return "ok";
  if (t.startsWith("challenge") || t.startsWith("throttle")) return "warn";
  return "";
}

const STATE_TONES = Object.freeze({ enabled: "ok", disabled: "", expired: "", unsupported: "warn" });

export function ruleRows(p, now = new Date()) {
  const host = str(p && p.host);
  return arr(p && p.rules).map((r) => ({
    id: str(r.id),
    priority: num(r.priority),
    note: str(r.note),
    match: describeMatch(r.match),
    matchedBy: str(r.matched_by),
    inherited: str(r.matched_by) !== host,
    action: describeAction(r.action),
    actionTone: actionTone(r.action),
    state: str(r.state),
    stateTone: STATE_TONES[str(r.state)] ?? "",
    until: r.match?.until ? fmtWhen(r.match.until, now) : "",
  }));
}

// excludeRows lists the WAF and challenge excludes the profile reports. Each
// one's scope takes this host: the profile lists no other (the edge and the
// Go matcher both honour an exclude's scope_hosts).
export function excludeRows(p) {
  const host = str(p && p.host);
  const row = (kind, e) => ({
    kind,
    type: str(e.type),
    value: str(e.value),
    rules: arr(e.rule_ids).length ? `rules ${arr(e.rule_ids).join(", ")}` : (kind === "WAF" ? "whole WAF" : "challenge"),
    scope: arr(e.scope_hosts).length ? arr(e.scope_hosts).join(", ") : "every vhost",
    exact: e.type === "host" && str(e.value) === host,
  });
  return [
    ...arr(p && p.waf_excludes).map((e) => row("WAF", e)),
    ...arr(p && p.challenge_excludes).map((e) => row("Challenge", e)),
  ];
}

// relatedHosts orders the domain chips: the profile's own list (site first).
export function relatedHosts(p) {
  const out = arr(p && p.related_hosts).map(str).filter(Boolean);
  const host = str(p && p.host);
  if (host && !out.includes(host)) out.unshift(host);
  return out;
}

// ── Traffic (traffic-mix?host=) ──────────────────────────────────────────

// trafficTiles are the four headline numbers of one host's mix.
export function trafficTiles(mix) {
  const cm = classMap(mix);
  const total = (mix && mix.total) || {};
  const req = num(total.requests);
  const origin = num(total.origin_sec);
  const botReq = BOT_CLASSES.reduce((s, k) => s + num(cm[k].requests), 0);
  const botOrigin = BOT_CLASSES.reduce((s, k) => s + num(cm[k].origin_sec), 0);
  return { requests: req, originSec: origin, rpsAvg: num(total.rps_avg), botRequestShare: share(botReq, req), botOriginShare: share(botOrigin, origin) };
}

// botClients are the host's bot clients (never a likely-human row, never
// the "everything else" bucket), by origin time, with their share of it.
export function botClients(mix, n = 10) {
  const origin = num(mix && mix.total && mix.total.origin_sec);
  return arr(mix && mix.clients)
    .filter((c) => c && c.client !== OTHER_KEY && BOT_CLASSES.includes(c.class))
    .sort((a, b) => num(b.origin_sec) - num(a.origin_sec))
    .slice(0, Math.max(0, n | 0))
    .map((c) => ({ ...c, originShare: share(c.origin_sec, origin) }));
}

// distributedClients are the browser-UA populations the node labelled
// distributed (traffic_mix.go distributedTell): a label, never an action.
export function distributedClients(mix) {
  return arr(mix && mix.clients).filter((c) => c && c.class === "human" && c.distributed);
}

// stackedArea lays the mix's series out as one polygon per class (bottom to
// top in CLASS_ORDER reversed, so automation sits on top as on Web Traffic),
// in a w×h box with padL/padB reserved for the axis labels.
export function stackedArea(mix, w = 900, h = 170, padL = 34, padB = 18) {
  const series = arr(mix && mix.series);
  if (series.length < 2) return { polygons: [], ticks: [], max: 0 };
  const totals = series.map((pt) => CLASS_ORDER.reduce((s, k) => s + num(pt.requests && pt.requests[k]), 0));
  const peak = Math.max(...totals);
  const step = niceStep(peak / 4);
  const max = Math.max(step * 4, 1);
  const x = (i) => padL + (i / (series.length - 1)) * (w - padL - 6);
  const y = (v) => h - padB - (v / max) * (h - padB - 8);
  const base = series.map(() => 0);
  const polygons = [];
  for (const k of [...CLASS_ORDER].reverse()) {
    const top = series.map((pt, i) => base[i] + num(pt.requests && pt.requests[k]));
    const up = top.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`);
    const down = base.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).reverse();
    polygons.push({ key: k, points: [...up, ...down].join(" ") });
    top.forEach((v, i) => { base[i] = v; });
  }
  const ticks = [0, 1, 2, 3, 4].map((g) => ({ value: step * g, y: y(step * g) }));
  return { polygons, ticks, max };
}

// niceStep rounds a raw step up to 1, 2 or 5 times a power of ten.
export function niceStep(raw) {
  const v = num(raw);
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

// ── Security (history/vhost-overview?host=) ──────────────────────────────

export function securityTiles(ov) {
  const o = ov || {};
  return {
    wafHits: num(o.waf_hits),
    topRule: str(o.top_waf_rule),
    issued: num(o.challenge_issued),
    solved: num(o.challenge_solved),
    solveRate: num(o.solve_rate_pct) / 100,
    hours: num(o.hours) || 24,
  };
}

// wafRuleRows sorts the per-rule hit counts and gives each its bar width.
export function wafRuleRows(ov) {
  const rows = arr(ov && ov.waf_by_rule).map((r) => ({ rule: str(r.rule), count: num(r.count) }));
  rows.sort((a, b) => b.count - a.count || a.rule.localeCompare(b.rule));
  const max = rows.length ? rows[0].count : 0;
  return rows.map((r) => ({ ...r, width: max > 0 ? r.count / max : 0 }));
}
