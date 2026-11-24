// /cfm-admin/assets/webdet/emergency-model.js
//
// Pure model for the Web Traffic page's emergency actions: a temporary deny
// (403) or throttle on ONE client of the traffic mix, built as an ordinary
// traffic rule (internal/webdetector/traffic_rules.go) that expires by itself
// (match.until) and is listed, extended or ended from the page. Tested in
// emergency-model.test.js; rule validation itself is rules-model.js's
// (validateRuleForm), the same the Traffic Rules editor runs.
//
// Guardrails (the same doctrine as traffic-model.js clientActions):
//   - A browser UA (classes "automation" and "human") is never a UA target:
//     every real Chrome of that version sends the same string. A browser-
//     looking scraper is targeted by its IPs (ip_any, IPv6 as /64 prefixes,
//     as the traffic mix counts them); "human" clients are offered nothing.
//   - A UA target is the traffic mix's UA family (NormalizeUA, a lower-case
//     token of the raw UA), matched as the substring glob `*<family>*`; a
//     client with no User-Agent is ua_any ["-"].
//   - Every emergency rule has an expiry (1 h default, 7 d at most), a note
//     tagged EMERGENCY_TAG, and a priority in EMERGENCY_BAND, so it runs
//     before the operator's own allows (verified-crawler allows sit at 10+).
//   - Nothing here acts: each rule is the operator's click.

import { LIMITS, THROTTLE_PROFILES, untilIn, vhostPatternsOverlap, ruleExpired, byteLen } from "./rules-model.js";

export const EMERGENCY_TAG = "emergency:";
export const EMERGENCY_BAND = Object.freeze({ from: 1, to: 9 });

export const EMERGENCY_DURATIONS = Object.freeze([
  { sec: 900, label: "15 minutes" },
  { sec: 3600, label: "1 hour" },
  { sec: 21600, label: "6 hours" },
  { sec: 86400, label: "24 hours" },
  { sec: 604800, label: "7 days" },
]);
export const EMERGENCY_MAX_SEC = 604800;
export const EMERGENCY_DEFAULT_SEC = 3600;

const UA_TARGET_CLASSES = Object.freeze(["crawler", "bot"]);
const IP_TARGET_CLASSES = Object.freeze(["automation", "bot", "crawler"]);

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

// uaPattern is the ua_any value that matches a UA family, or "" when the
// client cannot be a UA target. A family carrying a glob character, or too
// short to be specific, is refused rather than widened.
export function uaPattern(client) {
  if (!client || !UA_TARGET_CLASSES.includes(client.class)) return "";
  const fam = String(client.client || "").trim().toLowerCase();
  if (fam === "(no user-agent)") return "-";
  if (!fam || fam === "_other" || fam === "mozilla" || fam === "-") return "";
  if (/[*?\s]/.test(fam) || fam.length < 3) return "";
  return `*${fam}*`;
}

// ipTargets is the client's busiest addresses (last hour), at most n: IPv4
// addresses and IPv6 /64s, as the traffic mix counts them.
export function ipTargets(client, n) {
  if (!client || !IP_TARGET_CLASSES.includes(client.class)) return [];
  const list = Array.isArray(client.top_ips_last_hour) ? client.top_ips_last_hour : [];
  const cap = Math.min(Math.max(0, n | 0), LIMITS.ipsPerRule);
  return list.slice(0, cap).map((r) => String(r.ip || "").trim()).filter(Boolean);
}

// targetsFor lists what an emergency action on this client may key on.
export function targetsFor(client) {
  const out = [];
  if (uaPattern(client)) out.push("ua");
  if (ipTargets(client, 1).length) out.push("ips");
  return out;
}

// currentRate is the client's average request rate over the window.
export function currentRate(client, windowSec) {
  const s = num(windowSec);
  return s > 0 ? num(client && client.requests) / s : 0;
}

// suggestTotalRate proposes a total cap: a quarter of what the client does now
// (a 75% cut), rounded to a readable number, never under 0.5 r/s.
export function suggestTotalRate(rps) {
  const target = num(rps) / 4;
  if (target <= 0.5) return 0.5;
  if (target < 10) return Math.round(target * 2) / 2;
  if (target < 100) return Math.round(target);
  return Math.round(target / 10) * 10;
}

// throttleCut is the share of the client's requests a total cap would refuse
// at its current average rate (bursts make the real share higher).
export function throttleCut(rps, cap) {
  const r = num(rps);
  const c = num(cap);
  if (r <= 0 || c <= 0) return 0;
  return Math.max(0, 1 - c / r);
}

export function isEmergencyRule(rule) {
  return String(rule?.note || "").startsWith(EMERGENCY_TAG);
}

// emergencyPriority is the first priority in EMERGENCY_BAND that no rule on an
// overlapping vhost uses (a tie runs in id order, which nobody can predict),
// or 0 when the band is full there.
export function emergencyPriority(vhosts, rules = []) {
  const taken = new Set(
    (rules || [])
      .filter((r) => (r?.scope?.vhosts || []).some((a) => (vhosts || []).some((b) => vhostPatternsOverlap(a, b))))
      .map((r) => Number(r.priority)),
  );
  for (let p = EMERGENCY_BAND.from; p <= EMERGENCY_BAND.to; p++) if (!taken.has(p)) return p;
  return 0;
}

// clampNote keeps the note within the daemon's byte limit.
function clampNote(s) {
  let v = String(s);
  while (byteLen(v) > LIMITS.noteLen) v = v.slice(0, -1);
  return v;
}

// buildEmergencyRule turns the dialog's choices into a rule payload for
// POST /api/v1/webdet/rules/add. It returns { rule, error }; error is a
// sentence for the operator when the choices cannot make a rule.
//
// opts: { client, target: "ua"|"ips", ipCount, action: "block"|"throttle_total"|"throttle",
//         rate, per: "vhost"|"node", profile, durationSec, vhosts: [..], reason, rules, now }
export function buildEmergencyRule(opts) {
  const o = opts || {};
  const c = o.client;
  if (!c) return { error: "No client." };
  const match = {};
  if (o.target === "ua") {
    const p = uaPattern(c);
    if (!p) return { error: "This client cannot be targeted by its User-Agent (a browser UA is shared by real visitors): use its IPs." };
    match.ua_any = [p];
  } else if (o.target === "ips") {
    const ips = ipTargets(c, o.ipCount);
    if (!ips.length) return { error: "No IPs for this client in the last hour." };
    match.ip_any = ips;
  } else {
    return { error: "Choose the User-Agent or the IPs." };
  }

  const sec = Math.floor(num(o.durationSec));
  if (sec <= 0 || sec > EMERGENCY_MAX_SEC) return { error: "Choose a duration (up to 7 days)." };
  match.until = untilIn(sec, o.now == null ? Date.now() : o.now);

  const vhosts = (Array.isArray(o.vhosts) ? o.vhosts : []).map((h) => String(h).trim().toLowerCase()).filter(Boolean);
  if (!vhosts.length) return { error: "Choose where: all vhosts or a list." };
  if (vhosts.length > LIMITS.vhostsPerRule) return { error: `At most ${LIMITS.vhostsPerRule} vhosts.` };

  let action;
  if (o.action === "block") action = { type: "block" };
  else if (o.action === "throttle_total") {
    const rate = num(o.rate);
    if (rate < LIMITS.throttleTotalMin || rate > LIMITS.throttleTotalMax) {
      return { error: `The total rate must be between ${LIMITS.throttleTotalMin} and ${LIMITS.throttleTotalMax} r/s.` };
    }
    const per = o.per === "node" ? "node" : o.per === "vhost" ? "vhost" : "";
    if (!per) return { error: "Choose per vhost or whole node." };
    action = { type: "throttle_total", rate_rps: rate, per };
  } else if (o.action === "throttle") {
    if (!THROTTLE_PROFILES.some((p) => p.key === o.profile)) return { error: "Choose a per-client profile." };
    action = { type: "throttle", profile: o.profile };
  } else {
    return { error: "Choose deny or throttle." };
  }

  const priority = emergencyPriority(vhosts, o.rules);
  if (!priority) return { error: `Every emergency slot (priority ${EMERGENCY_BAND.from}–${EMERGENCY_BAND.to}) is taken on these vhosts: end one first.` };

  const why = String(o.reason || "").trim() || `web traffic: ${c.client}`;
  return {
    rule: {
      enabled: true,
      priority,
      scope: { vhosts },
      match,
      action,
      note: clampNote(`${EMERGENCY_TAG} ${why}`),
    },
  };
}

// extendedUntil is the rule's until pushed out by sec from the later of now
// and its current until, capped at EMERGENCY_MAX_SEC from now.
export function extendedUntil(rule, sec, now = Date.now()) {
  const cur = Date.parse(rule?.match?.until || "");
  const from = Number.isFinite(cur) && cur > now ? cur : now;
  const target = Math.min(from + num(sec) * 1000, now + EMERGENCY_MAX_SEC * 1000);
  return untilIn(Math.round((target - now) / 1000), now);
}

// activeEmergencyRules is the page's list: emergency rules not yet expired,
// soonest to end first.
export function activeEmergencyRules(rules, now = Date.now()) {
  return (Array.isArray(rules) ? rules : [])
    .filter((r) => isEmergencyRule(r) && !r.unsupported && r.match?.until && !ruleExpired(r, now))
    .sort((a, b) => Date.parse(a.match.until) - Date.parse(b.match.until));
}

// describeEmergency is the list's "what" and "how" columns.
export function describeEmergency(rule) {
  const m = rule?.match || {};
  const a = rule?.action || {};
  let what = "";
  if (Array.isArray(m.ua_any) && m.ua_any.length) what = m.ua_any[0] === "-" ? "no User-Agent" : `UA ${m.ua_any.join(", ")}`;
  else if (Array.isArray(m.ip_any) && m.ip_any.length) what = `${m.ip_any.length} IP${m.ip_any.length === 1 ? "" : "s"}`;
  else what = "(other)";
  let how = a.type || "?";
  if (a.type === "block") how = "deny (403)";
  else if (a.type === "throttle_total") how = `throttle ${a.rate_rps} r/s total ${a.per === "node" ? "for the node" : "per vhost"}`;
  else if (a.type === "throttle") how = `throttle per client (${a.profile})`;
  return { what, how };
}
