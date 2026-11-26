// /cfm-admin/assets/webdet/challenges-model.js
//
// Pure model for the Protection page's Challenges tab (feature-protection.js):
// what the edge did with the requests, how the challenge pages were answered,
// and the WAF's share. Two replies feed it:
//
//   GET v1/webdet/edge-outcomes?hours=&host=   internal/webdetector/traffic_outcomes.go
//   GET v1/waf/hit-rates?hours=&host=          the WAF's hits per inspected request
//
// A challenged visit is up to three challenge requests (the 303 to the page,
// the page, the verify), all counted as "challenged" by the edge. The tab
// counts the page loads (challenge_pages) and the verify answers apart, so a
// share is of the visitors' own requests and the pass rate is of the pages
// served. A number the node did not send is null and shows as a dash, never 0.

export const WINDOWS = Object.freeze([1, 6, 24]);

// chHours: the window this tab reads. The edge keeps 24 hours: a longer page
// window reads the last 24 (capped: true, the tab says so).
export function chHours(hours) {
  const h = Number(hours);
  if (WINDOWS.includes(h)) return { hours: h, capped: false };
  return { hours: 24, capped: h > 24 };
}

export function query(hours, host) {
  const q = new URLSearchParams({ hours: String(chHours(hours).hours) });
  if (host) q.set("host", host);
  return { outcomes: `v1/webdet/edge-outcomes?${q}`, waf: `v1/waf/hit-rates?${q}` };
}

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

export function pct(part, whole, digits = 1) {
  if (!(whole > 0)) return "–";
  return ((part / whole) * 100).toFixed(digits) + "%";
}

export function count(v) {
  return v == null ? "–" : Math.round(Number(v) || 0).toLocaleString("en-US");
}

// The parts a request ends in, in a fixed order with fixed colors (the same
// entity keeps its color on every chart of the tab).
export const PARTS = Object.freeze([
  Object.freeze({ key: "reached", label: "Reached the site", color: "var(--ch-1)" }),
  Object.freeze({ key: "sent", label: "Sent to the check", color: "var(--ch-2)" }),
  Object.freeze({ key: "blocked", label: "Blocked (WAF, ban, policy)", color: "var(--ch-3)" }),
  Object.freeze({ key: "limited", label: "Traffic rule or rate limit", color: "var(--ch-4)" }),
  Object.freeze({ key: "other", label: "Other edge answer", color: "var(--border)" }),
]);

// breakdown reads one `outcomes` object and its request count. null when the
// node sent none.
export function breakdown(outcomes, requests) {
  if (!outcomes || typeof outcomes !== "object") return null;
  const o = outcomes;
  const challenged = num(o.challenged);
  const machinery = Math.min(challenged, num(o.challenge_pages) + num(o.verify_sent_on) + num(o.verify_refused));
  const total = Math.max(0, num(requests) - machinery);
  const v = {
    reached: num(o.origin) + num(o.cached),
    sent: Math.max(0, challenged - machinery),
    blocked: num(o.blocked),
    limited: num(o.rule_blocked) + num(o.rate_limited),
    other: num(o.redirect) + num(o.other_edge),
  };
  return {
    total,
    values: v,
    parts: PARTS.map((p) => ({ ...p, value: v[p.key], share: total > 0 ? v[p.key] / total : 0, pct: pct(v[p.key], total) })),
  };
}

// funnel: the challenge pages served and what became of them.
export function funnel(outcomes) {
  if (!outcomes || typeof outcomes !== "object") return null;
  const pages = num(outcomes.challenge_pages);
  const passed = num(outcomes.verify_sent_on);
  const refused = num(outcomes.verify_refused);
  const unanswered = Math.max(0, pages - passed - refused);
  return {
    pages, passed, refused, unanswered,
    rate: pages > 0 ? Math.min(1, passed / pages) : null,
    // Answers without pages: hours a build before the page count counted.
    noPages: pages === 0 && passed + refused > 0,
    rows: [
      { key: "pages", label: "Pages served", value: pages, share: pages > 0 ? 1 : 0, strong: true },
      { key: "passed", label: "Passed", value: passed, share: pages > 0 ? Math.min(1, passed / pages) : 0, strong: true },
      { key: "unanswered", label: "Never answered", value: unanswered, share: pages > 0 ? unanswered / pages : 0, strong: false },
      { key: "refused", label: "Refused", value: refused, share: pages > 0 ? Math.min(1, refused / pages) : 0, strong: false },
    ],
  };
}

// wafSummary: the WAF's hits over the requests it inspected, and its rules
// with hits, busiest first. null without a reply.
export function wafSummary(hitRates, limit = 8) {
  if (!hitRates || typeof hitRates !== "object") return null;
  const inspected = num(hitRates.inspected_total);
  const rules = (Array.isArray(hitRates.rules) ? hitRates.rules : [])
    .filter((r) => r && num(r.hits) > 0)
    .map((r) => ({ id: Number(r.id) || 0, family: String(r.reason_family || ""), hits: num(r.hits), mode: String(r.default_mode || "") }))
    .sort((a, b) => b.hits - a.hits || a.id - b.id);
  const hits = rules.reduce((s, r) => s + r.hits, 0);
  return {
    inspected, hits,
    rate: inspected > 0 ? hits / inspected : null,
    rules: rules.slice(0, limit).map((r) => ({ ...r, pct: pct(r.hits, inspected, 2), mode: r.mode.replace("_", " ") })),
  };
}

// tiles: the numbers on top of the tab.
export function tiles(edge, waf) {
  const b = edge ? breakdown(edge.outcomes, edge.requests) : null;
  const f = edge ? funnel(edge.outcomes) : null;
  const t = (key, label, value, sub) => ({ key, label, value, sub });
  return [
    t("requests", "Requests", b ? count(b.total) : "–", "the visitors' own"),
    t("reached", "Reached the site", b ? pct(b.values.reached, b.total) : "–", b ? count(b.values.reached) + " requests" : ""),
    t("sent", "Sent to the check", b ? pct(b.values.sent, b.total) : "–", b ? count(b.values.sent) + " requests" : ""),
    t("passed", "Checks passed", f && f.rate != null ? pct(f.passed, f.pages, 0) : "–", f && f.pages ? count(f.passed) + " of " + count(f.pages) + " pages" : "no page served"),
    t("blocked", "Blocked", b ? pct(b.values.blocked, b.total) : "–", "WAF, bans and policies"),
    t("waf", "WAF hit rate", waf && waf.rate != null ? pct(waf.hits, waf.inspected, 2) : "–", waf && waf.inspected ? "of " + count(waf.inspected) + " inspected" : "nothing inspected"),
  ];
}

function hhmm(t) {
  const d = new Date(t * 1000);
  return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
}

// stack: per step, the requests sent to the check, blocked and limited (the
// sites' own traffic would flatten them), each as a share of the busiest step.
export function stack(edge) {
  const series = edge && Array.isArray(edge.series) ? edge.series : [];
  const pts = series.map((p) => {
    const b = breakdown(p && p.outcomes, p && p.requests);
    const v = b ? b.values : { sent: 0, blocked: 0, limited: 0 };
    return { t: Number(p && p.t) || 0, sent: v.sent, blocked: v.blocked, limited: v.limited, sum: v.sent + v.blocked + v.limited };
  });
  const max = pts.reduce((m, p) => Math.max(m, p.sum), 0);
  return {
    max,
    points: pts.map((p) => ({
      ...p,
      h: { sent: max ? p.sent / max : 0, blocked: max ? p.blocked / max : 0, limited: max ? p.limited / max : 0 },
      tip: `${hhmm(p.t)}\nSent to the check ${count(p.sent)}\nBlocked ${count(p.blocked)}\nTraffic rule or rate limit ${count(p.limited)}`,
    })),
  };
}

// passRate: per step, the share of the pages served that were passed. A step
// with no page served has no rate (an empty column, not a zero).
export function passRate(edge) {
  const series = edge && Array.isArray(edge.series) ? edge.series : [];
  return series.map((p) => {
    const f = funnel(p && p.outcomes);
    const t = Number(p && p.t) || 0;
    if (!f || f.rate == null) return { t, rate: null, h: 0, tip: `${hhmm(t)}\nno challenge page served` };
    return { t, rate: f.rate, h: f.rate, tip: `${hhmm(t)}\n${pct(f.passed, f.pages, 0)} passed of ${count(f.pages)} pages` };
  });
}

// axis: five evenly spaced time labels for a series.
export function axis(points) {
  const n = Array.isArray(points) ? points.length : 0;
  if (!n) return [];
  return [0, 0.25, 0.5, 0.75, 1].map((f) => hhmm(points[Math.min(n - 1, Math.round(f * (n - 1)))].t));
}

// hostRows: the node view's most-challenged vhosts.
export function hostRows(hosts) {
  return (Array.isArray(hosts) ? hosts : []).filter((h) => h && h.host).map((h) => {
    const b = breakdown(h.outcomes, h.requests);
    const f = funnel(h.outcomes);
    return {
      host: String(h.host),
      requests: count(b ? b.total : 0),
      sent: b ? pct(b.values.sent, b.total) : "–",
      passed: f && f.rate != null ? pct(f.passed, f.pages, 0) : "–",
      blocked: b ? pct(b.values.blocked, b.total) : "–",
      parts: b ? b.parts : [],
    };
  });
}

// reasonRows: the per-address challenge decisions by reason (admin only).
export function reasonRows(reasons) {
  return (Array.isArray(reasons) ? reasons : []).filter((r) => r && r.reason).map((r) => {
    const reason = String(r.reason);
    const fam = reason.split(":")[0];
    let kind = "a detector";
    if (fam.startsWith("WAF_")) kind = "a WAF rule at challenge level";
    else if (/PATH|MALPATH/.test(fam)) kind = "odd paths";
    else if (/RULE/.test(fam)) kind = "a traffic rule";
    return { reason, kind, decisions: count(r.decisions), addresses: count(r.addresses) };
  });
}
