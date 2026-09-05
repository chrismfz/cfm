// rules-model.js — the pure (DOM-free, Vue-free) half of the Traffic Rules page.
//
// Everything here mirrors the daemon's rule model in
// internal/webdetector/traffic_rules.go (normalizeTrafficRule / ruleMatchFilters)
// and the edge application in configs/lua/cfm.lua Step 3, so the UI can
// explain a rule in plain language and reject an invalid one BEFORE the save
// round-trip. When the Go model changes, change this file in the same PR —
// it is the only client-side copy (CLAUDE.md §5: never keep two lists that
// can drift). Unit-tested with node:test in rules-model.test.js.

// ── Server limits (traffic_rules.go consts) ────────────────────────────────
export const LIMITS = Object.freeze({
  vhostsPerRule: 32,
  countriesPerRule: 20,
  patternsPerField: 20,
  noteLen: 256,
  priorityMin: 1,
  priorityMax: 100000,
});

// ── Actions: what a matching rule does, in the operator's words ───────────
// `caveat` is the fact the old UI hid and that produced wrong rules. Keep it
// short and true to cfm.lua: block/challenge are OR'd across ip/vhost/rule
// action; `allow` is never consulted by the edge, it only ends rule evaluation.
export const ACTIONS = Object.freeze([
  {
    key: "allow",
    label: "Allow",
    tone: "ok",
    summary: "Stop evaluating traffic rules for matching requests (the rules below this one are skipped).",
    caveat: "Does NOT bypass the WAF, a vhost-wide challenge or an IP block. To exempt an endpoint from the challenge use Challenge excludes instead.",
  },
  {
    key: "block",
    label: "Block",
    tone: "danger",
    summary: "Return 403 at the edge.",
    caveat: "Browsers holding a valid clearance cookie keep access until it expires; verified good bots are NOT exempt — allow them first.",
  },
  {
    key: "challenge",
    label: "Challenge",
    tone: "warn",
    summary: "Serve the interactive challenge; humans in a browser pass, bots do not.",
    caveat: "Non-browser clients (APIs, webhooks, mobile apps, crawlers) cannot pass it.",
  },
  {
    key: "throttle",
    label: "Throttle",
    tone: "info",
    summary: "Rate-limit matching clients per IP; requests over the limit get 429 + Retry-After.",
    caveat: "",
  },
]);

export function actionInfo(key) {
  return ACTIONS.find((a) => a.key === String(key || "").toLowerCase()) || null;
}

// ── Throttle profiles (configs/lua/cfm_rules.lua PROFILES) ─────────────────
// An unknown profile name silently falls back to soft_bot at the edge
// (`PROFILES[k] or PROFILES.soft_bot`), so the UI only offers these.
export const THROTTLE_PROFILES = Object.freeze([
  { key: "soft_bot", rate: 2, burst: 20, label: "soft_bot — 2 req/s, burst 20" },
  { key: "medium_bot", rate: 1, burst: 10, label: "medium_bot — 1 req/s, burst 10" },
  { key: "hard_bot", rate: 0.5, burst: 5, label: "hard_bot — 0.5 req/s, burst 5" },
]);

export function throttleProfile(key) {
  return THROTTLE_PROFILES.find((p) => p.key === String(key || "").trim()) || null;
}

export const KNOWN_METHODS = Object.freeze(["GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"]);

// Crawlers a `verified_bot` rule can match: the daemon's FCrDNS registry
// (goodBotPTRSuffixes in internal/webdetector/abuse_shadow.go) minus the
// generic "google" verdict, which covers Google's user-driven fetchers
// (Translate proxy, AMP cache) and is deliberately excluded for rules.
// TestVerifiedBotNamesListedInRulesModel asserts this list equals that set.
// Matching is by reverse DNS that forward-confirms to the IP — never by
// User-Agent string.
export const VERIFIED_BOT_NAMES = Object.freeze(["googlebot", "bingbot", "yahoo", "applebot", "yandex", "meta"]);
const VERIFIED_BOT_DISPLAY = Object.freeze({
  googlebot: "Googlebot", bingbot: "Bingbot", yahoo: "Yahoo Slurp", applebot: "Applebot", yandex: "YandexBot", meta: "Meta (facebookexternalhit / meta-externalagent)",
});
export const VERIFIED_BOT_LABEL = VERIFIED_BOT_NAMES.map((n) => VERIFIED_BOT_DISPLAY[n] || n).join(", ");

// The User-Agent globs each VERIFIABLE crawler announces itself with (keyed by
// VERIFIED_BOT_NAMES, so it cannot drift from the registry: the test asserts
// the keys match). Everything else in the search/social bot groups is a bot the
// daemon CANNOT verify by reverse DNS; recipes that allow verified crawlers add
// a second, explicitly weaker UA-based allow for those so link previews and
// indexing keep working — forgeable, and said so in the warning.
export const VERIFIED_BOT_UA_GLOBS = Object.freeze({
  googlebot: ["*Googlebot*"],
  bingbot: ["*bingbot*"],
  yahoo: ["*Slurp*"],
  applebot: ["*Applebot*"],
  yandex: ["*YandexBot*"],
  meta: ["*facebookexternalhit*", "*meta-externalagent*"],
});
const VERIFIABLE_UA_GLOBS = new Set(Object.values(VERIFIED_BOT_UA_GLOBS).flat());
const VERIFIABLE_UA_GLOBS_LC = new Set([...VERIFIABLE_UA_GLOBS].map((u) => u.toLowerCase()));


// ── Priority bands ────────────────────────────────────────────────────────
// First match wins, lower priority number runs first. The bands only seed the
// default so that allows land before throttles before challenges before
// blocks — the operator can always override. `default` is the first free slot
// suggestPriority() tries.
export const PRIORITY_BANDS = Object.freeze({
  allow: { from: 10, to: 99, default: 50 },
  throttle: { from: 100, to: 199, default: 150 },
  challenge: { from: 200, to: 299, default: 250 },
  block: { from: 300, to: 899, default: 350 },
});

// suggestPriority returns the band default for the action, bumped past any
// priority already used by an existing rule on an overlapping vhost so two
// rules never tie (ties fall back to id order, which nobody can predict).
export function suggestPriority(actionType, rules = [], vhosts = []) {
  const band = PRIORITY_BANDS[String(actionType || "").toLowerCase()];
  if (!band) return 100;
  const taken = new Set(
    (rules || [])
      .filter((r) => rulesOverlapVhosts(r?.scope?.vhosts || [], vhosts))
      .map((r) => Number(r?.priority))
      .filter((n) => Number.isFinite(n)),
  );
  let p = band.default;
  while (taken.has(p) && p < band.to) p += 1;
  return p;
}

// hostPatternMatch mirrors Go ruleHostMatch: exact host, a filepath.Match-style
// glob (`*` spans any run of characters — hosts never contain "/" — `?` one
// character, `[..]` classes passed through), or a "*.suffix" pattern matching
// any host that ends in ".suffix".
export function hostPatternMatch(pattern, host) {
  const pat = String(pattern || "").toLowerCase().trim();
  const h = String(host || "").toLowerCase().trim();
  if (!pat || !h) return false;
  if (pat === h) return true;
  if (pat.startsWith("*.")) {
    const suf = pat.slice(1);
    if (h.endsWith(suf) && h.length > suf.length) return true;
  }
  if (/[*?[]/.test(pat)) {
    try {
      const rx = new RegExp(`^${pat.replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`);
      return rx.test(h);
    } catch {
      return false; // malformed class — Go's filepath.Match errors too (→ no match)
    }
  }
  return false;
}

// vhostPatternsOverlap: can the two scope entries ever select the same host?
// Two literals: equal. Literal vs pattern: the pattern matches the literal.
// Two "*.suffix" patterns: one suffix ends with the other. Used only for UI
// guidance (priority suggestion, neighbours, tie warnings) — never for
// enforcement, which is the daemon's job.
export function vhostPatternsOverlap(a, b) {
  const pa = String(a || "").toLowerCase().trim();
  const pb = String(b || "").toLowerCase().trim();
  if (!pa || !pb) return false;
  if (pa === pb) return true;
  if (hostPatternMatch(pa, pb) || hostPatternMatch(pb, pa)) return true;
  if (pa.startsWith("*.") && pb.startsWith("*.")) {
    const sa = pa.slice(1);
    const sb = pb.slice(1);
    return sa.endsWith(sb) || sb.endsWith(sa);
  }
  return false;
}

function rulesOverlapVhosts(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || !a.length || !b.length) return true;
  return a.some((x) => b.some((y) => vhostPatternsOverlap(x, y)));
}

// priorityTie returns the first existing rule (other than excludeId) that uses
// the same priority on an overlapping vhost, or null. Shared by the editor
// validation and the recipe preview so both warn identically.
export function priorityTie(priority, vhosts, rules = [], excludeId = "") {
  const p = Number(priority);
  if (!Number.isFinite(p) || p <= 0) return null;
  return (rules || []).find(
    (r) => String(r?.id || "") !== String(excludeId || "") && Number(r?.priority) === p &&
      rulesOverlapVhosts(r?.scope?.vhosts || [], vhosts),
  ) || null;
}

// positionText describes where a priority lands among existing rules for the
// same vhosts: "runs after #20 (allow GR, CY) and before #900 (block …)".
export function positionText(priority, rules = [], { excludeId = "", vhosts = [] } = {}) {
  const p = Number(priority);
  if (!Number.isFinite(p)) return "";
  const rows = (rules || [])
    .filter((r) => String(r?.id || "") !== String(excludeId || ""))
    .filter((r) => rulesOverlapVhosts(r?.scope?.vhosts || [], vhosts))
    .map((r) => ({ p: Number(r?.priority), label: shortLabel(r) }))
    .filter((r) => Number.isFinite(r.p))
    .sort((x, y) => x.p - y.p);
  if (!rows.length) return "This will be the only rule for these vhosts.";
  const before = rows.filter((r) => r.p < p).pop();
  const same = rows.find((r) => r.p === p);
  const after = rows.find((r) => r.p > p);
  const parts = [];
  if (before) parts.push(`runs after #${before.p} (${before.label})`);
  if (after) parts.push(`before #${after.p} (${after.label})`);
  if (!before && !after && !same) parts.push("runs first");
  let text = parts.length ? parts.join(" and ") : "";
  if (same) text += `${text ? "; " : ""}ties with #${same.p} (${same.label}) — pick a different number`;
  return text ? text.charAt(0).toUpperCase() + text.slice(1) + "." : "";
}

function shortLabel(row) {
  const act = String(row?.action?.type || "rule");
  const m = describeMatch(row?.match || {}, { max: 2 });
  return `${act} ${m}`.trim().slice(0, 60);
}

// ── Bot groups (User-agent chip + recipes) ────────────────────────────────
// `phrase` is how describeMatch names the group mid-sentence.
// Globs are case-insensitive at the edge; a pattern without `*`/`?` is a
// substring match, so "*Googlebot*" and "googlebot" are equivalent. Kept as
// globs for readability in the saved rule.
export const BOT_GROUPS = Object.freeze([
  {
    key: "search",
    phrase: "search engines",
    label: "Search engines",
    hint: "Googlebot, bingbot, DuckDuckBot, Applebot, YandexBot, Baiduspider",
    patterns: ["*Googlebot*", "*bingbot*", "*DuckDuckBot*", "*Applebot*", "*YandexBot*", "*Baiduspider*"],
  },
  {
    key: "social",
    phrase: "social preview bots",
    label: "Social previews",
    hint: "facebookexternalhit, meta-externalagent, Twitterbot, LinkedInBot, Slackbot, WhatsApp, TelegramBot",
    patterns: ["*facebookexternalhit*", "*meta-externalagent*", "*Twitterbot*", "*LinkedInBot*", "*Slackbot*", "*WhatsApp*", "*TelegramBot*"],
  },
  {
    key: "ai",
    phrase: "AI crawlers",
    label: "AI crawlers",
    hint: "GPTBot, ChatGPT-User, OAI-SearchBot, ClaudeBot, Claude-User, Claude-SearchBot, anthropic-ai, Bytespider, CCBot, Amazonbot, PerplexityBot, Google-Extended, ReflectionBot, ExaSearchBot",
    // Claude-User is also the User-Agent of the claude.ai MCP connector behind
    // /cfm-admin/mcp, and that is fine: traffic rules never see cfm-admin —
    // `location ^~ /cfm-admin/` is `access_by_lua_block { return; }` in both
    // openresty.conf and angie.conf, so cfm.lua Step 3 is skipped for it (only
    // /cfm-admin/login runs through cfm.lua). A "*"-scoped bot rule carrying
    // Claude-User cannot lock the operator out.
    patterns: ["*GPTBot*", "*ChatGPT-User*", "*OAI-SearchBot*", "*ClaudeBot*", "*Claude-User*", "*Claude-SearchBot*", "*anthropic-ai*", "*Bytespider*", "*CCBot*", "*Amazonbot*", "*PerplexityBot*", "*Google-Extended*", "*ReflectionBot*", "*ExaSearchBot*"],
  },
  {
    key: "seo",
    phrase: "SEO tools",
    label: "SEO tools",
    hint: "AhrefsBot, SemrushBot, MJ12bot, DotBot, BLEXBot, PetalBot, DataForSeoBot",
    patterns: ["*AhrefsBot*", "*SemrushBot*", "*MJ12bot*", "*DotBot*", "*BLEXBot*", "*PetalBot*", "*DataForSeoBot*"],
  },
  {
    key: "scripts",
    phrase: "script tools",
    label: "Script tools",
    hint: "python-requests, python-urllib, Go-http-client, curl, wget, libwww-perl, okhttp",
    patterns: ["*python-requests*", "*python-urllib*", "*Go-http-client*", "*curl*", "*wget*", "*libwww-perl*", "*okhttp*"],
  },
  {
    key: "dataset",
    phrase: "dataset / anonymous crawlers",
    label: "Dataset / anonymous crawlers",
    hint: "the anonymous \"Mozilla/5.0 (compatible; crawler)\", img2dataset / imagebot, eurovl-fetch, *DatasetCrawler, VelenPublicWebCrawler — bulk image/text harvesters with no benefit to the site",
    patterns: ["*(compatible; crawler)*", "*img2dataset*", "*imagebot*", "*eurovl-fetch*", "*DatasetCrawler*", "*VelenPublicWebCrawler*"],
  },
  {
    key: "empty",
    phrase: "no User-Agent at all",
    label: "No User-Agent",
    hint: "a lone dash matches ONLY requests without a User-Agent header (the access-log spelling); it is not a substring match",
    patterns: ["-"],
  },
]);

export function botGroup(key) {
  return BOT_GROUPS.find((g) => g.key === key) || null;
}

export const UNVERIFIABLE_BOT_UAS = Object.freeze(
  [...botGroup("search").patterns, ...botGroup("social").patterns].filter((g) => !VERIFIABLE_UA_GLOBS.has(g)),
);

// Verifiable in principle, but their fetches are ONE-SHOT link previews from a
// huge, rarely-repeating IP fleet: the cache-only verified_bot verdict almost
// never exists in time (first two or three requests from an IP get the fence's
// action), so a fence would break most Facebook / Instagram / Messenger
// previews. Recipes therefore keep these in the UA-based allow as well (same
// forgeable trust as before this field existed) until verdicts are persisted /
// pre-seeded.
export const PREVIEW_ONE_SHOT_UAS = Object.freeze([...VERIFIED_BOT_UA_GLOBS.meta]);
export const UA_ALLOW_ALONGSIDE_VERIFIED = Object.freeze([...UNVERIFIABLE_BOT_UAS, ...PREVIEW_ONE_SHOT_UAS]);

// ── Form ⇄ payload ────────────────────────────────────────────────────────
export function emptyForm(overrides = {}) {
  return {
    enabled: false,
    priority: 0, // 0 → suggestPriority() at save/review time
    vhosts: "",
    countries: "",
    countriesMode: "in", // "in" | "not_in"
    ips: "",
    verifiedBot: false,
    uas: "",
    paths: "",
    methods: "",
    actionType: "",
    throttleProfile: "soft_bot",
    note: "",
    hasQS: false,
    qsNotRx: "",
    ...overrides,
  };
}

export function csvSplit(v) {
  return String(v || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

// buildRulePayload turns the editor form into the JSON the API expects. It
// does NOT validate — call validateRuleForm first and refuse to save on
// errors. Mirrors normalizeTrafficRule's upper-casing so the review sentence
// shows what will actually be stored.
export function buildRulePayload(form) {
  const f = form || {};
  const actionType = String(f.actionType || "").trim().toLowerCase();
  const prio = Number(f.priority);
  return {
    enabled: Boolean(f.enabled),
    priority: Number.isFinite(prio) && prio > 0 ? Math.floor(prio) : 0,
    scope: { vhosts: csvSplit(f.vhosts).map((h) => h.toLowerCase()) },
    match: {
      country_in: f.countriesMode === "not_in" ? [] : csvSplit(f.countries).map((x) => x.toUpperCase()),
      country_not_in: f.countriesMode === "not_in" ? csvSplit(f.countries).map((x) => x.toUpperCase()) : [],
      ip_any: csvSplit(f.ips),
      verified_bot: Boolean(f.verifiedBot),
      ua_any: csvSplit(f.uas),
      path_any: csvSplit(f.paths).map((p) => (p.startsWith("/") ? p : "/" + p)),
      methods: csvSplit(f.methods).map((x) => x.toUpperCase()),
      has_qs: Boolean(f.hasQS),
      // qs_not_rx is applied by the daemon whenever the request HAS a query
      // string, independently of has_qs — never drop it because the checkbox
      // is off, or editing a rule would silently widen it.
      qs_not_rx: String(f.qsNotRx || "").trim() || undefined,
    },
    action: {
      type: actionType,
      profile: actionType === "throttle" ? String(f.throttleProfile || "").trim() : "",
    },
    note: String(f.note || "").trim(),
  };
}

export function formFromRule(row) {
  const r = row || {};
  const list = (v) => (Array.isArray(v) ? v.join(", ") : "");
  return {
    enabled: Boolean(r.enabled),
    priority: Number(r.priority || 0),
    vhosts: list(r?.scope?.vhosts),
    countries: list(r?.match?.country_not_in?.length ? r.match.country_not_in : r?.match?.country_in),
    countriesMode: r?.match?.country_not_in?.length ? "not_in" : "in",
    ips: list(r?.match?.ip_any),
    verifiedBot: Boolean(r?.match?.verified_bot),
    uas: list(r?.match?.ua_any),
    paths: list(r?.match?.path_any),
    methods: list(r?.match?.methods),
    actionType: String(r?.action?.type || ""),
    throttleProfile: String(r?.action?.profile || "soft_bot"),
    note: String(r?.note || ""),
    hasQS: Boolean(r?.match?.has_qs),
    qsNotRx: String(r?.match?.qs_not_rx || ""),
  };
}

// hasAnyMatch: does the rule narrow the request set at all? (Empty fields
// match everything — the #1 way to accidentally block a whole vhost.)
export function hasAnyMatch(match) {
  const m = match || {};
  return Boolean(
    (m.country_in && m.country_in.length) ||
      (m.country_not_in && m.country_not_in.length) ||
      (m.ip_any && m.ip_any.length) ||
      m.verified_bot ||
      (m.ua_any && m.ua_any.length) ||
      (m.path_any && m.path_any.length) ||
      (m.methods && m.methods.length) ||
      m.has_qs,
  );
}

// isIPOrCIDR mirrors normalizeIPList's acceptance: an IPv4/IPv6 address, or
// one with a /prefix within range. Syntax-only — canonicalisation (masking) is
// the daemon's job and is reflected back after save.
export function isIPOrCIDR(v) {
  const s = String(v || "").trim();
  if (!s) return false;
  const [addr, bits, extra] = s.split("/");
  if (extra !== undefined) return false;
  const OCTET = "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
  const V4 = new RegExp(`^${OCTET}(\\.${OCTET}){3}$`);
  let is4 = false;
  let is4in6 = false;
  if (V4.test(addr)) {
    is4 = true;
  } else {
    // IPv6: hex groups with at most one "::"; a dotted quad only as the LAST group.
    if (!/^[0-9a-f:.]+$/i.test(addr) || !addr.includes(":")) return false;
    const parts = addr.split("::");
    if (parts.length > 2) return false;
    const groups = parts.flatMap((part) => (part === "" ? [] : part.split(":")));
    if (!groups.length && parts.length !== 2) return false;
    let width = 0;
    let quadTail = false;
    for (let i = 0; i < groups.length; i += 1) {
      const g = groups[i];
      if (/^[0-9a-f]{1,4}$/i.test(g)) { width += 1; continue; }
      if (i === groups.length - 1 && V4.test(g)) { width += 2; quadTail = true; continue; }
      return false;
    }
    // A dotted quad must be the absolute tail: "1.2.3.4::" is not an address.
    if (quadTail && parts.length === 2 && parts[1] === "") return false;
    if (parts.length === 2 ? width > 7 : width !== 8) return false;
    // Expand to 8 groups to recognise a v4-mapped address in ANY spelling
    // ("::ffff:1.2.3.4", "::ffff:c0a8:1", "0:0:0:0:0:ffff:1.2.3.4").
    const head = parts[0] === "" ? [] : parts[0].split(":");
    const tail = parts.length === 2 && parts[1] !== "" ? parts[1].split(":") : [];
    const expand = (gs) => gs.flatMap((g) => (g.includes(".") ? g.split(".").map(Number).reduce((acc, o, i) => { acc[i >> 1] = ((acc[i >> 1] || 0) << 8) | o; return acc; }, []).map((n) => n.toString(16)) : [g]));
    const eh = expand(head);
    const et = expand(tail);
    const full = parts.length === 2 ? [...eh, ...Array(8 - eh.length - et.length).fill("0"), ...et] : eh;
    is4in6 = full.length === 8 && full.slice(0, 5).every((g) => parseInt(g, 16) === 0) && parseInt(full[5], 16) === 0xffff;
  }
  if (bits === undefined) return true;
  if (!/^(0|[1-9]\d{0,2})$/.test(bits)) return false;
  const n = Number(bits);
  if (n > (is4 ? 32 : 128)) return false;
  // A v4-mapped prefix shorter than /96 is rejected by the daemon (it can never
  // match an Unmap()ed request address).
  if (is4in6 && n < 96) return false;
  return true;
}

// re2Rejects: the constructs Go RE2 definitely refuses — lookahead/lookbehind
// and backreferences. A backreference is an UNESCAPED backslash followed by a
// digit; "a\\1" (escaped backslash, then a literal 1) compiles fine in RE2.
// Shared by the rule form and the recipe vars so the two never drift.
export function re2Rejects(rx) {
  const v = String(rx || "");
  return /\(\?<?[=!]/.test(v) || /(^|[^\\])(\\\\)*\\[1-9]/.test(v);
}

// ── Validation (mirrors normalizeTrafficRule; stricter only where the server
//    would silently do something surprising) ───────────────────────────────
// Returns { errors, warnings, hints }. `errors` block the save; `warnings`
// are shown but allowed; `hints` are facts about what the rule will do.
export function validateRuleForm(form, { rules = [], editId = "" } = {}) {
  const errors = [];
  const warnings = [];
  const hints = [];
  const p = buildRulePayload(form);
  const act = actionInfo(p.action.type);

  if (!p.action.type) errors.push("Choose what should happen (allow / block / challenge / throttle).");
  else if (!act) errors.push(`Unknown action "${p.action.type}".`);

  if (p.action.type === "throttle") {
    if (!p.action.profile) errors.push("Throttle needs a profile.");
    else if (!throttleProfile(p.action.profile)) {
      errors.push(`Unknown throttle profile "${p.action.profile}" — the edge would silently fall back to soft_bot.`);
    }
  }

  if (!p.scope.vhosts.length) errors.push("At least one vhost is required.");
  if (p.scope.vhosts.length > LIMITS.vhostsPerRule) errors.push(`Too many vhosts (max ${LIMITS.vhostsPerRule}).`);
  for (const h of p.scope.vhosts) {
    // The daemon only lowercases/trims vhosts, so stay permissive (IDN,
    // underscores…) and reject only what can never be a Host header.
    if (/[\s/:@]/.test(h)) errors.push(`Vhost "${h}" is not a hostname — use just the host part (no scheme, path or port).`);
  }

  const countries = p.match.country_in.length ? p.match.country_in : p.match.country_not_in;
  if (countries.length > LIMITS.countriesPerRule) errors.push(`Too many countries (max ${LIMITS.countriesPerRule}).`);
  for (const cc of countries) {
    if (!/^[A-Z]{2}$/.test(cc)) errors.push(`"${cc}" is not a 2-letter country code (use ISO codes like GR, CY, US).`);
  }
  if (p.match.ip_any.length > LIMITS.patternsPerField) errors.push(`Too many IPs / ranges (max ${LIMITS.patternsPerField}).`);
  for (const ip of p.match.ip_any) {
    if (!isIPOrCIDR(ip)) errors.push(`"${ip}" is not an IPv4/IPv6 address or CIDR range (e.g. 203.0.113.0/24, 2001:db8::/48).`);
  }
  for (const [name, list] of [["UA patterns", p.match.ua_any], ["Path patterns", p.match.path_any], ["Methods", p.match.methods]]) {
    if (list.length > LIMITS.patternsPerField) errors.push(`${name}: too many values (max ${LIMITS.patternsPerField}).`);
  }
  for (const m of p.match.methods) {
    if (!/^[A-Z]+$/.test(m)) errors.push(`Method "${m}" is not valid.`);
    else if (!KNOWN_METHODS.includes(m)) warnings.push(`Method "${m}" is unusual — did you mean one of ${KNOWN_METHODS.join(", ")}?`);
  }
  for (const ua of p.match.ua_any) {
    if (ua.length < 3 && ua !== "-") warnings.push(`UA pattern "${ua}" is very short and will match a lot (substring match).`);
  }
  if (p.match.qs_not_rx) {
    // The daemon compiles Go RE2 ("(?i)" + rx). JavaScript's dialect differs,
    // so only reject what RE2 definitely rejects (lookaround, backreferences)
    // and treat a JS parse failure as a warning — the server has the final say.
    const rx = p.match.qs_not_rx;
    if (re2Rejects(rx)) {
      errors.push("QS pass-through: lookahead/lookbehind and backreferences are not supported (Go RE2 syntax).");
    } else {
      try {
        new RegExp(rx.replace(/^\(\?[imsU]+\)/, ""), "i");
      } catch (err) {
        warnings.push(`QS pass-through could not be parsed as a JavaScript regex (${err.message}); the daemon validates it as Go RE2 on save.`);
      }
    }
  }
  if (byteLen(p.note) > LIMITS.noteLen) errors.push(`Note too long (max ${LIMITS.noteLen} bytes — the daemon counts UTF-8 bytes, not characters).`);

  if (p.priority && (p.priority < LIMITS.priorityMin || p.priority > LIMITS.priorityMax)) {
    errors.push(`Priority must be between ${LIMITS.priorityMin} and ${LIMITS.priorityMax}.`);
  }
  if (p.priority) {
    const tie = priorityTie(p.priority, p.scope.vhosts, rules, editId);
    if (tie) warnings.push(`Priority ${p.priority} is already used by ${tie.id} — ties are resolved by id order, which is not predictable.`);
  }

  const narrow = hasAnyMatch(p.match);
  if (!narrow && p.action.type && p.action.type !== "allow") {
    (p.enabled ? errors : warnings).push(
      p.enabled
        ? `No match conditions: this ENABLED ${p.action.type} rule would ${p.action.type} EVERY request on ${p.scope.vhosts.join(", ") || "the selected vhosts"}. Add a condition or save it disabled.`
        : `No match conditions: this rule matches EVERY request on the selected vhosts (saved disabled).`,
    );
  }
  if (!narrow && p.action.type === "allow") {
    warnings.push("An allow rule with no conditions makes every rule below it unreachable for these vhosts.");
  }
  if (act?.caveat) hints.push(act.caveat);
  if (p.match.ua_any.length && p.action.type === "allow") {
    hints.push("User-Agent is client-controlled: anyone can send this string. For crawlers use the Verified crawler condition instead (FCrDNS, cannot be forged).");
  }
  if (p.match.verified_bot) {
    hints.push(`Verified crawler = the IP's reverse DNS forward-confirms to ${VERIFIED_BOT_LABEL}. On live traffic the verdict is cache-only: a crawler IP seen for the first time matches from about its third request (never a DNS wait per request), then stays verified across refreshes. Other bots (DuckDuckGo, Baidu, X, LinkedIn…) cannot be verified and need a User-Agent condition.`);
    if (p.match.ua_any.length) warnings.push("Verified crawler already proves who the client is; the User-Agent condition only narrows it further (and can be forged).");
  }
  if (p.match.country_in.length) {
    hints.push("Requests whose IP the geo database cannot resolve have no country and never match a country condition.");
  }
  if (p.match.country_not_in.length) {
    hints.push("Requests whose country is unknown (geo not resolved, or the geo module down) do NOT match — the fence fails open rather than blocking everyone during a geo hiccup.");
  }
  if (p.match.ip_any.length) {
    hints.push("Ranges are stored canonically (a bare address becomes /32 or /128; host bits are masked off). Behind a proxy the edge must see the real client IP for this to match.");
  }

  return { errors, warnings, hints, payload: p };
}

// ── Plain-language descriptions ───────────────────────────────────────────
function joinList(items, max = 3) {
  const arr = (items || []).map(String);
  if (arr.length <= max) return arr.join(", ");
  return `${arr.slice(0, max).join(", ")} +${arr.length - max} more`;
}

// describeMatch turns the match block into the qualifier of a sentence:
// "POST requests from CN, RU to /xmlrpc.php" · "every request".
export function describeMatch(match, { max = 3 } = {}) {
  const m = match || {};
  const parts = [];
  const methods = Array.isArray(m.methods) ? m.methods : [];
  const countries = Array.isArray(m.country_in) ? m.country_in : [];
  const countriesNot = Array.isArray(m.country_not_in) ? m.country_not_in : [];
  const ips = Array.isArray(m.ip_any) ? m.ip_any : [];
  const uas = Array.isArray(m.ua_any) ? m.ua_any : [];
  const paths = Array.isArray(m.path_any) ? m.path_any : [];

  parts.push(methods.length ? `${joinList(methods, max)} requests` : (hasAnyMatch(m) ? "requests" : "every request"));
  if (m.verified_bot) parts.push("from a verified crawler (FCrDNS)");
  if (ips.length) parts.push(`from IP ${joinList(ips, max)}`);
  if (countries.length) parts.push(`from ${joinList(countries, max)}`);
  if (countriesNot.length) parts.push(`from outside ${joinList(countriesNot, max)}`);
  if (uas.length) {
    const groups = BOT_GROUPS.filter((g) => g.patterns.every((p) => uas.includes(p)));
    const covered = new Set(groups.flatMap((g) => g.patterns));
    const rest = uas.filter((u) => !covered.has(u));
    const names = [...groups.map((g) => g.phrase), ...rest.map(uaName)];
    parts.push(`with a User-Agent matching ${joinList(names, max)}`);
  }
  if (paths.length) parts.push(`to ${joinList(paths, max)}`);
  if (m.has_qs) parts.push("that carry a query string");
  if (m.qs_not_rx) parts.push(`(except when the query matches /${m.qs_not_rx}/)`);
  return parts.join(" ");
}

function uaName(glob) {
  if (glob === "-") return "no User-Agent at all";
  const s = String(glob || "").replace(/^\*+|\*+$/g, "");
  return s === "" ? glob : s;
}

// describeAction: "block" · "throttle (soft_bot — 2 req/s, burst 20)".
export function describeAction(action) {
  const t = String(action?.type || "").toLowerCase();
  if (t === "throttle") {
    const prof = throttleProfile(action?.profile);
    return `throttle (${prof ? prof.label : action?.profile || "?"})`;
  }
  return t || "?";
}

// describeRule: full sentence for the review pane and the rule table.
// "On ksilokosmos.gr: allow POST requests to /ws_vtrack/json_v2.php."
export function describeRule(row, { max = 3 } = {}) {
  const r = row || {};
  const hosts = Array.isArray(r?.scope?.vhosts) ? r.scope.vhosts : [];
  const where = hosts.length ? `On ${joinList(hosts, max)}: ` : "";
  return `${where}${describeAction(r.action)} ${describeMatch(r.match, { max })}.`;
}

// recipeOf returns the recipe key a rule was created by (note prefix
// "recipe:<key>"), or "".
export function recipeOf(row) {
  const m = /^recipe:([a-z0-9_]+)/i.exec(String(row?.note || ""));
  return m ? m[1].toLowerCase() : "";
}

// ── Simulator pre-fill ────────────────────────────────────────────────────
// A sample request that the rule SHOULD match, so "Test this rule" is one
// click instead of retyping every field. Wildcards get a plausible concrete
// value; a "/path?k=v" pattern is split into path + qs like the edge does.
export function simulateInputFromRule(row) {
  const r = row || {};
  const host = String((r?.scope?.vhosts || [])[0] || "")
    .replace(/^\*\./, "www.")
    .replace(/[*?]/g, "x");
  const m = r.match || {};
  const firstPath = String((m.path_any || [])[0] || "/");
  let [path, qs = ""] = firstPath.split("?");
  path = path.replace(/\*/g, "x").replace(/\?/g, "x") || "/";
  if (!qs && m.has_qs) qs = "page=2";
  const ua = uaName((m.ua_any || [])[0] || "") || "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0";
  return {
    host,
    ip: sampleIPFromPrefix((m.ip_any || [])[0] || ""),
    // "-" means "no User-Agent": send an empty UA, exactly what the edge sends.
    ua: (m.ua_any || [])[0] === "-" ? "" : ua,
    path,
    method: String((m.methods || [])[0] || "GET"),
    country: (m.country_in || [])[0] || sampleCountryOutside(m.country_not_in || []),
    qs,
    // A verified_bot rule is exercised with the override: the sample IP is not
    // a real crawler, so the daemon's inline FCrDNS check would say "no".
    verifiedBot: m.verified_bot ? "googlebot" : "",
  };
}

// sampleIPFromPrefix: a concrete address inside the first ip_any entry
// ("203.0.113.0/24" → "203.0.113.1", "198.51.100.7/32" → "198.51.100.7",
// "2001:db8::/48" → "2001:db8::1").
function sampleIPFromPrefix(entry) {
  const [addr, bits] = String(entry || "").split("/");
  if (!addr) return "";
  if (bits === undefined) return addr;
  if (addr.includes(":")) {
    if (Number(bits) >= 128) return addr;
    return addr.endsWith("::") ? `${addr}1` : addr;
  }
  if (Number(bits) >= 32) return addr;
  const o = addr.split(".").map(Number);
  if (o.length === 4 && o[3] === 0) o[3] = 1;
  return o.join(".");
}

// sampleCountryOutside: a country code the not_in list does NOT contain, so
// the sample request exercises the rule. "" when the rule has no not_in.
function sampleCountryOutside(list) {
  if (!Array.isArray(list) || !list.length) return "";
  for (const cc of ["US", "DE", "CN", "BR", "IN"]) if (!list.includes(cc)) return cc;
  return "ZZ";
}

// ── Recipes ───────────────────────────────────────────────────────────────
// A recipe is a small, ordered bundle of rules whose relative priorities make
// the composition correct (first match wins). `kind`:
//   "multi"  → preview + "Create N rules" (created via rules/add in order)
//   "single" → loads one prefilled rule into the editor for review
//   "link"   → not a rule at all; points at the right tool
// `vars` are the free variables asked from the operator. `build(vars)` returns
// an ordered array of API payloads; every note starts with "recipe:<key>" so
// the group can be found again (recipeOf).
function note(key, text) {
  return `recipe:${key} — ${text}`;
}
// clampNote keeps a recipe note within LIMITS.noteLen no matter how long the
// operator's lists are (shortList caps the count, this caps the bytes): the
// daemon rejects a longer note and a multi-rule recipe would abort half-applied.
// The daemon measures the note in BYTES (Go len()), and every recipe note
// carries a multi-byte em dash, so the cap is applied to the UTF-8 length.
export function byteLen(s) {
  return new TextEncoder().encode(String(s || "")).length;
}
function clampNote(s) {
  const v = String(s || "");
  if (byteLen(v) <= LIMITS.noteLen) return v;
  const ellipsis = "…";
  const budget = LIMITS.noteLen - byteLen(ellipsis);
  let out = "";
  for (const ch of v) {
    if (byteLen(out + ch) > budget) break;
    out += ch;
  }
  return out + ellipsis;
}
function rule(key, { enabled, priority, vhosts, match = {}, action, text }) {
  return {
    enabled: Boolean(enabled),
    priority,
    scope: { vhosts: vhosts.slice() },
    match: {
      country_in: match.country_in || [],
      country_not_in: match.country_not_in || [],
      ip_any: match.ip_any || [],
      verified_bot: Boolean(match.verified_bot),
      ua_any: match.ua_any || [],
      path_any: match.path_any || [],
      methods: match.methods || [],
      has_qs: Boolean(match.has_qs),
      qs_not_rx: match.qs_not_rx || undefined,
    },
    action,
    note: clampNote(note(key, text)),
  };
}
function vhostsVar(vars) {
  return hostsVar(vars, "vhosts", []);
}
function countriesVar(vars, fallback) {
  const cc = csvSplit(vars?.countries).map((c) => c.toUpperCase());
  return cc.length ? cc : fallback;
}
function ipsVar(vars) {
  return csvSplit(vars?.ips);
}
function pathsVar(vars, fallback) {
  const ps = csvSplit(vars?.paths).map((p) => (p.startsWith("/") ? p : "/" + p));
  return ps.length ? ps : fallback;
}
// groupsVar resolves a "botgroups" var (comma-separated BOT_GROUPS keys) to the
// group objects, in BOT_GROUPS order so the rules a recipe builds get stable,
// predictable priorities whatever order the operator typed the keys in.
function groupsVar(vars, fallback) {
  const keys = new Set(csvSplit(vars?.groups).map((k) => k.toLowerCase()));
  const want = keys.size ? keys : new Set(fallback);
  return BOT_GROUPS.filter((g) => want.has(g.key));
}
// hostsVar: like vhostsVar but for a var of another key (recipes that scope
// two different vhost sets, e.g. DAV vs browser panel subdomains).
function hostsVar(vars, key, fallback) {
  const hs = csvSplit(vars?.[key]).map((h) => h.toLowerCase());
  return hs.length ? hs : fallback.slice();
}
// shortList keeps a recipe note under LIMITS.noteLen when the operator pastes
// a long path list: the first few entries, then a count.
function shortList(items, max = 3) {
  const xs = (items || []).map(String);
  return xs.length > max ? `${xs.slice(0, max).join(", ")} +${xs.length - max} more` : xs.join(", ");
}
// pathPatternMatches mirrors traffic_rules.go for one path_any pattern: the
// part before the first '?' matches the request path (a '*' pattern — '*'
// matches anything INCLUDING '/' — is a full match, a wildcard-free one a
// literal prefix; '?' can never be a path wildcard because it always splits
// off the query part first); the part after it, when present, is
// matched per parameter against the request query ("key" = any value,
// "key=value" = that value, case-insensitive). Used only for UI guidance (the
// /.well-known/ refusal, the simulator sample); enforcement is the daemon.
export function pathPatternMatches(pattern, path, qs = "") {
  const raw = String(pattern || "").trim();
  const qi = raw.indexOf("?");
  const p = (qi < 0 ? raw : raw.slice(0, qi)).trim();
  const pq = qi < 0 ? null : raw.slice(qi + 1).trim();
  const v = String(path || "");
  let pathOK = !p;
  if (!pathOK && p.includes("*")) {
    const rx = new RegExp(`^${p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`);
    pathOK = rx.test(v);
  } else if (!pathOK) {
    pathOK = v.startsWith(p);
  }
  if (!pathOK) return false;
  if (pq === null || pq === "") return true;
  const dec = (x) => {
    try {
      return decodeURIComponent(String(x).replace(/\+/g, " ")).toLowerCase();
    } catch {
      return String(x).toLowerCase();
    }
  };
  const req = String(qs || "")
    .split("&")
    .filter(Boolean)
    .map((kv) => {
      const eq = kv.indexOf("=");
      return eq < 0 ? [dec(kv), ""] : [dec(kv.slice(0, eq)), dec(kv.slice(eq + 1))];
    });
  return pq
    .split("&")
    .map((t) => t.trim())
    .filter(Boolean)
    .every((tok) => {
      const eq = tok.indexOf("=");
      const pk = eq < 0 ? dec(tok) : dec(tok.slice(0, eq));
      const pv = eq < 0 ? null : dec(tok.slice(eq + 1));
      return req.some(([k, val]) => k === pk && (pv === null || val === pv));
    });
}
// shadowingRules lists the EXISTING enabled rules that run before `row` on an
// overlapping vhost, let the client through (allow, or a throttle — both end
// evaluation: Simulate is first-match), cover the row's User-Agents (a
// verified_bot allow for FCrDNS-verifiable UAs, or a shared UA pattern) and
// are not narrower than the row (no path / IP / country condition of their
// own, has_qs only if the row has it, methods a superset). Such a rule means
// the row never runs for those clients: tame_bots / geo_fence / geo_challenge
// put verified + Meta preview allows at 10/11 and AI/SEO GET throttles at
// 110/130, which silently neutralise a later bots_read_only or bots_no_qs
// block for exactly the crawler those recipes exist to stop.
export function shadowingRules(row, rules = []) {
  const uas = (row?.match?.ua_any || []).map((u) => String(u).toLowerCase());
  if (!uas.length || row?.action?.type === "allow") return [];
  const verifiable = uas.some((u) => VERIFIABLE_UA_GLOBS_LC.has(u));
  const rowMethods = (row.match?.methods || []).map((m) => String(m).toUpperCase());
  return (rules || []).filter((r) => {
    const m = r?.match || {};
    if (!r?.enabled || !["allow", "throttle"].includes(r.action?.type) || !(Number(r.priority) < Number(row.priority))) return false;
    if (!(r.scope?.vhosts || []).some((a) => (row.scope?.vhosts || []).some((b) => vhostPatternsOverlap(a, b)))) return false;
    // narrower than the row → only a subset of its clients is shadowed; skip
    if ((m.path_any || []).length || (m.ip_any || []).length || (m.country_in || []).length || (m.country_not_in || []).length) return false;
    if (m.has_qs && !row.match?.has_qs) return false;
    const theirMethods = (m.methods || []).map((x) => String(x).toUpperCase());
    if (theirMethods.length && (!rowMethods.length || !rowMethods.every((x) => theirMethods.includes(x)))) return false;
    if (m.verified_bot && verifiable) return true;
    const theirs = (m.ua_any || []).map((u) => String(u).toLowerCase());
    return theirs.some((u) => uas.includes(u));
  });
}
// ACME / CA DCV validators fetch these; a pattern that the matcher would
// resolve onto either of them must never become a rule target.
const WELL_KNOWN_PROBES = Object.freeze(["/.well-known/acme-challenge/token", "/.well-known/pki-validation/fileauth.txt"]);
function patternHitsWellKnown(p) {
  // Two guards: anything the matcher would resolve onto a real probe path
  // ("/", "/*", "/.we", "/*acme*"), and anything literally inside the
  // namespace ("/.well-known/acme-challenge/A" is a prefix of ~1/64 of the
  // tokens a CA issues, "/.well-known/openid" is not a probe but is not ours).
  const pathPart = String(p || "").split("?")[0].trim().toLowerCase();
  if (pathPart === "/.well-known" || pathPart.startsWith("/.well-known/")) return true;
  return WELL_KNOWN_PROBES.some((probe) => pathPatternMatches(p, probe));
}

const VAR_VHOSTS = { key: "vhosts", label: "Vhosts", type: "vhosts", placeholder: "example.com, *.example.com", required: true };
const VAR_GROUPS = Object.freeze({ key: "groups", label: `Bot groups (${BOT_GROUPS.map((g) => g.key).join(", ")})`, type: "botgroups", default: "social, ai, seo", required: true });
const VAR_IPS_OPTIONAL = Object.freeze({ key: "ips", label: "Always allow these IPs / ranges (office, monitors — optional)", type: "ips", placeholder: "203.0.113.0/24, 2001:db8::/48" });

// Bot-facing rules that create real collateral if enabled blindly: the
// "scripts" group is also what webhooks, IoT posters and integrations announce
// (python-requests, Go-http-client, curl…), and "empty" (no User-Agent) is what
// some uptime monitors send. Recipes create the rules for these groups
// DISABLED and say so.
const GROUPS_WITH_COLLATERAL = Object.freeze(new Set(["scripts", "empty"]));

// PROBE_PATHS: what the /.env / phpinfo / VCS-metadata sweeps seen across the
// fleet actually request. Prefix match unless the pattern has a wildcard, and
// '*' also matches '/' (traffic_rules.go wildcardMatch), so "/*phpinfo.php"
// covers "/wp-admin/phpinfo.php", "/*/.env" the "/bin/.env" variant and
// "/*.php.bak" a leftover anywhere.
// NEVER put /.well-known/ here — ACME/DCV validation lives there (see the
// patternHitsWellKnown guard in validateRecipeVars).
export const PROBE_PATHS = Object.freeze([
  "/.env", "/*/.env", "/.git/", "/.svn/", "/.hg/", "/.aws/", "/.ssh/", "/.htpasswd", "/.DS_Store",
  "/*phpinfo.php", "/*.php.bak", "/*.php.old", "/*.php.save", "/*.php~", "/*.sql",
  "/_profiler/", "/server-status",
]);
// The HTTP methods a crawler has no business sending. GET/HEAD/OPTIONS stay
// open (link previews, robots, CORS preflight).
export const WRITE_METHODS = Object.freeze(["POST", "PUT", "PATCH", "DELETE"]);
// Query parameters a crawler legitimately carries: click ids, campaign tags,
// pagination, feeds/exports. Everything else on a bot request is a facet /
// filter permutation (min_price, filter_color, orderby, ind=…).
// Every parameter must be on the list: qs_not_rx exempts the WHOLE query when
// it matches, so a "one exempt key anywhere" regex would let a facet grid
// through as soon as it carries page=N — which is exactly how crawlers walk a
// grid. An empty parameter (a stray "&") is tolerated.
export const BOT_QS_PASSTHROUGH = "^(?:(?:fbclid|gclid|utm_[a-z]+|page|paged|export|xml|feed|lang)(?:=[^&;]*)?(?:[&;]+|$))+$";

export const RECIPES = Object.freeze([
  {
    key: "geo_fence",
    kind: "multi",
    title: "Allow only these countries",
    description: "Serve the site to visitors from the listed countries, to FCrDNS-verified crawlers and to your own IP ranges; block everyone else with one country_not_in rule.",
    vars: [
      VAR_VHOSTS,
      { key: "countries", label: "Allowed countries", type: "countries", default: "GR, CY", required: true },
      VAR_IPS_OPTIONAL,
    ],
    warnings: [
      "The block rule is created DISABLED. Test with the simulator, then enable it from the table.",
      `Rule #10 allows crawlers by reverse-DNS verification (${VERIFIED_BOT_LABEL}) — cannot be forged. A crawler IP seen for the first time (and every crawler IP right after a cfm restart) is verified in the background and gets the fence's action for its first two or three requests before it passes.`,
      "Rule #11 allows by User-Agent only (forgeable) the search/social bots with no verifiable reverse DNS (DuckDuckGo, Baidu, X/Twitter, LinkedIn, Slack, WhatsApp, Telegram) AND Meta's preview fetchers, whose one-shot requests from an ever-changing fleet rarely have a verdict in time. Delete it if you would rather fence those too.",
      "Visitors whose country cannot be resolved are NOT blocked (the fence fails open, so a geo outage never locks everyone out). Office/monitoring ranges are still worth listing: they skip every rule below.",
      "Browsers that already hold a clearance cookie for the vhost keep access until it expires.",
    ],
    build(vars) {
      const vhosts = vhostsVar(vars);
      const cc = countriesVar(vars, ["GR", "CY"]);
      const ips = ipsVar(vars);
      const k = "geo_fence";
      const out = [
        rule(k, { enabled: true, priority: 10, vhosts, match: { verified_bot: true }, action: { type: "allow" }, text: "verified crawlers (FCrDNS) pass the fence" }),
        rule(k, { enabled: true, priority: 11, vhosts, match: { ua_any: [...UA_ALLOW_ALONGSIDE_VERIFIED] }, action: { type: "allow" }, text: "search/social bots without a verdict in time (unverifiable ones + Meta previews) pass by User-Agent (forgeable)" }),
      ];
      if (ips.length) {
        out.push(rule(k, { enabled: true, priority: 15, vhosts, match: { ip_any: ips }, action: { type: "allow" }, text: "office / monitoring ranges always pass the fence" }));
      }
      out.push(rule(k, { enabled: false, priority: 900, vhosts, match: { country_not_in: cc }, action: { type: "block" }, text: `block everyone outside ${cc.join(", ")} — ENABLE after testing` }));
      return out;
    },
  },
  {
    key: "geo_fence_admin",
    kind: "single",
    title: "Admin area only from these countries",
    description: "One rule: visitors outside the listed countries get the challenge (or a block) on the admin/login paths. The rest of the site is untouched.",
    vars: [
      VAR_VHOSTS,
      { key: "countries", label: "Allowed countries", type: "countries", default: "GR", required: true },
      { key: "paths", label: "Admin paths", type: "paths", default: "/wp-admin/, /wp-login.php" },
      { key: "action", label: "Everyone else gets", type: "select", options: ["challenge", "block"], default: "challenge" },
    ],
    warnings: ["Loaded disabled; enable after a simulator run.", "Challenge cannot be passed by non-browser clients (apps, integrations) hitting these paths.", "Visitors whose country cannot be resolved are not matched (fail-open)."],
    build(vars) {
      const vhosts = vhostsVar(vars);
      const cc = countriesVar(vars, ["GR"]);
      const paths = pathsVar(vars, ["/wp-admin/", "/wp-login.php"]);
      const act = vars?.action === "block" ? "block" : "challenge";
      const k = "geo_fence_admin";
      return [
        rule(k, { enabled: false, priority: act === "block" ? 310 : 250, vhosts, match: { country_not_in: cc, path_any: paths }, action: { type: act }, text: `${act} the admin paths for visitors outside ${cc.join(", ")}` }),
      ];
    },
  },
  {
    key: "allow_office_ips",
    kind: "single",
    title: "Always allow office / monitoring IPs",
    description: "Your own ranges skip every rule below this one (a country block, a UA throttle…). Does not bypass WAF, challenge or IP blocks.",
    vars: [VAR_VHOSTS, { key: "ips", label: "IPs / ranges", type: "ips", placeholder: "203.0.113.0/24, 198.51.100.7, 2001:db8::/48", required: true }],
    build(vars) {
      const ips = ipsVar(vars);
      return [rule("allow_office_ips", { enabled: true, priority: 15, vhosts: vhostsVar(vars), match: { ip_any: ips }, action: { type: "allow" }, text: `office / monitoring ranges (${ips.length}) skip the rules below` })];
    },
  },
  {
    key: "protect_login",
    kind: "multi",
    title: "Protect login endpoints",
    description: "Challenge POSTs to the login page (stops credential stuffing) and block xmlrpc.php POSTs (brute-force amplifier).",
    vars: [VAR_VHOSTS],
    warnings: ["Jetpack and the WordPress mobile app use xmlrpc.php — leave that rule disabled on sites that need it.", "Created DISABLED; enable after a simulator run."],
    build(vars) {
      const vhosts = vhostsVar(vars);
      const k = "protect_login";
      return [
        rule(k, { enabled: false, priority: 210, vhosts, match: { path_any: ["/wp-login.php"], methods: ["POST"] }, action: { type: "challenge" }, text: "challenge login POSTs" }),
        rule(k, { enabled: false, priority: 310, vhosts, match: { path_any: ["/xmlrpc.php"], methods: ["POST"] }, action: { type: "block" }, text: "block xmlrpc.php POSTs" }),
      ];
    },
  },
  {
    key: "tame_bots",
    kind: "multi",
    title: "Tame bots",
    description: "Let verified search/social crawlers through, rate-limit SEO and AI crawlers, block requests without a User-Agent.",
    vars: [VAR_VHOSTS],
    warnings: ["Throttles are enabled (low collateral). The no-User-Agent block is created DISABLED: uptime monitors and health checks sometimes send no UA — check the simulator/logs, then enable.", "Rule #11 allows by User-Agent only (forgeable) the bots with no verifiable reverse DNS plus Meta's one-shot preview fetchers."],
    build(vars) {
      const vhosts = vhostsVar(vars);
      const k = "tame_bots";
      return [
        rule(k, { enabled: true, priority: 10, vhosts, match: { verified_bot: true }, action: { type: "allow" }, text: "verified crawlers (FCrDNS) first" }),
        rule(k, { enabled: true, priority: 11, vhosts, match: { ua_any: [...UA_ALLOW_ALONGSIDE_VERIFIED] }, action: { type: "allow" }, text: "search/social bots without a verdict in time (unverifiable ones + Meta previews) by User-Agent (forgeable)" }),
        rule(k, { enabled: true, priority: 110, vhosts, match: { ua_any: botGroup("ai").patterns, methods: ["GET"] }, action: { type: "throttle", profile: "medium_bot" }, text: "AI crawlers at medium_bot" }),
        rule(k, { enabled: true, priority: 130, vhosts, match: { ua_any: botGroup("seo").patterns, methods: ["GET"] }, action: { type: "throttle", profile: "soft_bot" }, text: "SEO crawlers at soft_bot" }),
        rule(k, { enabled: false, priority: 320, vhosts, match: { ua_any: ["-"] }, action: { type: "block" }, text: "block requests with no User-Agent — ENABLE after checking monitors" }),
      ];
    },
  },
  {
    key: "exempt_integration",
    kind: "link",
    title: "Exempt an API / webhook / integration endpoint",
    description: "An `allow` rule does NOT do this — it only skips later rules. To keep the challenge or WAF off a path, add a Challenge / WAF exclude.",
    href: "/cfm-admin/webdetector/waf/",
    linkLabel: "Open Challenge / WAF excludes",
  },
  // ── single-rule recipes (load into the editor for review) ──
  {
    key: "throttle_meta",
    kind: "single",
    title: "Throttle Meta crawlers",
    description: "facebookexternalhit / meta-externalagent at soft_bot (2 req/s, burst 20).",
    vars: [VAR_VHOSTS],
    build(vars) {
      return [rule("throttle_meta", { enabled: true, priority: 150, vhosts: vhostsVar(vars), match: { ua_any: ["*facebookexternalhit*", "*meta-externalagent*"], methods: ["GET"] }, action: { type: "throttle", profile: "soft_bot" }, text: "Meta crawler soft throttle" })];
    },
  },
  {
    key: "throttle_scripts",
    kind: "single",
    title: "Throttle script scrapers",
    description: "python-requests, curl, wget, Go-http-client… at hard_bot (0.5 req/s, burst 5).",
    vars: [VAR_VHOSTS],
    build(vars) {
      return [rule("throttle_scripts", { enabled: true, priority: 160, vhosts: vhostsVar(vars), match: { ua_any: botGroup("scripts").patterns, methods: ["GET", "POST"] }, action: { type: "throttle", profile: "hard_bot" }, text: "generic script tools at hard_bot" })];
    },
  },
  {
    key: "block_meta_qs",
    kind: "single",
    title: "Block Meta bot query-string loops",
    description: "Block Meta/GoogleOther crawlers hitting pages with unexpected query strings (fbclid/export/xml pass through).",
    vars: [VAR_VHOSTS],
    build(vars) {
      return [rule("block_meta_qs", { enabled: false, priority: 330, vhosts: vhostsVar(vars), match: { ua_any: ["*facebookexternalhit*", "*meta-externalagent*", "*GoogleOther*"], methods: ["GET"], has_qs: true, qs_not_rx: "(?:^|[&;])(?:fbclid|export|xml)(?:=|[&;]|$)" }, action: { type: "block" }, text: "Meta/GoogleOther with unexpected query strings (disabled — validate first)" })];
    },
  },
  {
    key: "block_geedo",
    kind: "single",
    title: "Block the Geedo shop scraper",
    description: "Block the Geedo price-comparison crawler (User-Agent GeedoShopProductFinder), which crawls product/category pages across shops. Allowed by default; created disabled — set your vhost(s) (or * for the whole server, admin only) and enable after a simulator run.",
    vars: [VAR_VHOSTS],
    build(vars) {
      return [rule("block_geedo", { enabled: false, priority: 345, vhosts: vhostsVar(vars), match: { ua_any: ["*GeedoShopProductFinder*"] }, action: { type: "block" }, text: "block the Geedo shop scraper by User-Agent (disabled — validate first)" })];
    },
  },
  // ── recipes distilled from fleet traffic (2026-09, titan/rigel/orion) ──
  {
    key: "block_probe_paths",
    kind: "single",
    title: "Block secret / dev-file probes",
    description: "One block rule for the paths only scanners ask for: /.env*, /.git/, /.svn/, /.aws/, phpinfo.php in any directory, *.php.bak / *.php~ leftovers, *.sql dumps, /_profiler/, /server-status. Stops a sweep at its first request instead of feeding the challenge engine and the detection history.",
    vars: [VAR_VHOSTS, { key: "paths", label: "Extra paths (optional)", type: "paths", placeholder: "/backup/, /old/" }],
    warnings: [
      "Created ENABLED: nothing legitimate lives on these paths. Review the list once — a site that really serves .sql or .bak downloads needs those two patterns removed.",
      "/.well-known/ must never be added here: ACME / CA validation for SSL issuance fetches it (the recipe refuses it).",
      "Scope it to * (admin) to cover every vhost on the server.",
      "Path matching is case-sensitive at the edge: a /.ENV or /PHPINFO.php probe slips past this rule (rare in the wild; the challenge engine still catches the sweep).",
    ],
    build(vars) {
      const extra = pathsVar(vars, []);
      const paths = [...PROBE_PATHS, ...extra.filter((p) => !PROBE_PATHS.includes(p))];
      return [rule("block_probe_paths", { enabled: true, priority: 305, vhosts: vhostsVar(vars), match: { path_any: paths }, action: { type: "block" }, text: "block secret/dev-file probes (.env, .git, phpinfo, *.bak, *.sql…)" })];
    },
  },
  {
    key: "bots_read_only",
    kind: "multi",
    title: "Crawlers are read-only",
    description: "Block POST / PUT / PATCH / DELETE from social, AI and SEO crawlers. Seen fleet-wide: Meta's crawler re-POSTing forms (including a delete-tip=1 URL) and WooCommerce ajax fragments. Search engines are not in the default set: Googlebot POSTs while rendering pages.",
    vars: [VAR_VHOSTS, VAR_GROUPS],
    warnings: [
      "The social / AI / SEO rules are created ENABLED: a preview or index crawler never needs to write. Add \"scripts\" (curl, python-requests, Go-http-client…) only if no webhook, IoT poster or integration on the vhost announces itself that way — that rule is created DISABLED.",
      "No verified-crawler allow is put in front on purpose: Meta's crawler IS a verified crawler (FCrDNS to fbsv.net), and an allow would let exactly the POSTs this recipe exists to stop through. Add \"search\" only if you accept blocking Googlebot's rendering POSTs — that rule is created DISABLED.",
    ],
    build(vars) {
      const vhosts = vhostsVar(vars);
      const k = "bots_read_only";
      return groupsVar(vars, ["social", "ai", "seo"]).map((g, i) => {
        const risky = GROUPS_WITH_COLLATERAL.has(g.key) || g.key === "search";
        return rule(k, { enabled: !risky, priority: 350 + i, vhosts, match: { ua_any: g.patterns.slice(), methods: [...WRITE_METHODS] }, action: { type: "block" }, text: `${g.phrase} never write${risky ? " (disabled — legitimate writers may match)" : ""}` });
      });
    },
  },
  {
    key: "bots_no_qs",
    kind: "multi",
    title: "Bots stay off filter / facet URLs",
    description: "Block (or hard-throttle) social, AI and SEO crawlers on pages with a query string, unless every parameter is a click id, UTM tag, pagination, feed or language switch (a facet grid that also carries page=N is still a facet grid). The generalisation of the Meta-only recipe: seen fleet-wide as a shop's whole ?min_price/filter_color grid crawled by Meta, a sports site's ?lg-min/lv-max permutations by Meta + GPTBot, and a listings site's ?ind=k&ind=n… by SemrushBot.",
    vars: [
      VAR_VHOSTS,
      VAR_GROUPS,
      { key: "action", label: "Action", type: "select", options: ["block", "throttle"], default: "block" },
      { key: "qs_ok", label: "Query params that pass (Go RE2 regex; clear it to block every bot GET with a query string)", type: "regex", default: BOT_QS_PASSTHROUGH },
    ],
    warnings: [
      "Created DISABLED — run the simulator with a real filter URL of the site first, then enable.",
      "Do not add \"search\" unless you accept de-indexing filtered listings: Googlebot crawling ?page= keeps working (pagination passes), ?filter_color= will not.",
    ],
    build(vars) {
      const vhosts = vhostsVar(vars);
      const k = "bots_no_qs";
      const throttle = vars?.action === "throttle";
      // An empty regex means "nothing passes": the rule then matches every bot
      // GET that carries a query string (qs_not_rx omitted, has_qs alone).
      const qsOK = String(vars?.qs_ok ?? "").trim() || undefined;
      return groupsVar(vars, ["social", "ai", "seo"]).map((g, i) =>
        rule(k, {
          enabled: false,
          priority: (throttle ? 170 : 360) + i,
          vhosts,
          match: { ua_any: g.patterns.slice(), methods: ["GET"], has_qs: true, qs_not_rx: qsOK },
          action: throttle ? { type: "throttle", profile: "hard_bot" } : { type: "block" },
          text: `${g.phrase} on filter/facet query strings (disabled — validate first)`,
        }),
      );
    },
  },
  {
    key: "lock_panel_subdomains",
    kind: "multi",
    title: "Lock panel service subdomains to your countries",
    description: "The cPanel proxy subdomains are brute-force and scanner targets (cpcalendars.* at 9 rps of 401s from one IP, webdisk.*, autodiscover.*/autoconfig.* uniq-path sweeps from Google Cloud). DAV / mail-autodiscovery subdomains get a BLOCK for visitors outside the listed countries (those clients cannot solve a challenge); the browser ones (cpanel.*, webmail.*) get the challenge.",
    vars: [
      { key: "svc_vhosts", label: "Service subdomains (block outside)", type: "vhosts", default: "cpcalendars.*, cpcontacts.*, webdisk.*, autodiscover.*, autoconfig.*", required: true },
      { key: "web_vhosts", label: "Browser panel subdomains (challenge outside)", type: "vhosts", default: "cpanel.*, webmail.*" },
      { key: "countries", label: "Allowed countries", type: "countries", default: "GR, CY", required: true },
      VAR_IPS_OPTIONAL,
    ],
    warnings: [
      "Wildcard vhosts (cpanel.*) need an admin session. Both enforcing rules are created DISABLED; enable after a simulator run.",
      "A customer syncing calendars/contacts or using Web Disk from abroad is blocked — list their range in the always-allow IPs, or drop the country they travel to into the allowed list.",
      "autodiscover.* is not always fetched by the customer's own device: Outlook for iOS/Android and Microsoft 365 resolve it through Microsoft's cloud (AutoDetect), so the request arrives from Microsoft ranges abroad even for a customer in Athens. If customers use Outlook mobile, take autodiscover.*/autoconfig.* out of the service list or add Microsoft's ranges to the always-allow IPs.",
      "Visitors whose country cannot be resolved are NOT matched (fail-open).",
    ],
    build(vars) {
      const svc = hostsVar(vars, "svc_vhosts", ["cpcalendars.*", "cpcontacts.*", "webdisk.*", "autodiscover.*", "autoconfig.*"]);
      const web = hostsVar(vars, "web_vhosts", []);
      const cc = countriesVar(vars, ["GR", "CY"]);
      const ips = ipsVar(vars);
      const k = "lock_panel_subdomains";
      const out = [];
      // One allow per scope: the two vhost lists are validated separately
      // against the 32-vhost limit, so their union must never travel in one rule.
      if (ips.length) out.push(rule(k, { enabled: true, priority: 15, vhosts: svc, match: { ip_any: ips }, action: { type: "allow" }, text: "office / monitoring ranges always pass (service subdomains)" }));
      if (ips.length && web.length) out.push(rule(k, { enabled: true, priority: 16, vhosts: web, match: { ip_any: ips }, action: { type: "allow" }, text: "office / monitoring ranges always pass (browser panel subdomains)" }));
      if (web.length) out.push(rule(k, { enabled: false, priority: 252, vhosts: web, match: { country_not_in: cc }, action: { type: "challenge" }, text: `challenge the browser panel subdomains outside ${cc.join(", ")} — ENABLE after testing` }));
      out.push(rule(k, { enabled: false, priority: 312, vhosts: svc, match: { country_not_in: cc }, action: { type: "block" }, text: `block DAV / autodiscover subdomains outside ${cc.join(", ")} — ENABLE after testing` }));
      return out;
    },
  },
  {
    key: "geo_challenge",
    kind: "multi",
    title: "Challenge visitors from (or outside) these countries",
    description: "The softer geo-fence for a shop that cannot block the world: visitors from the listed countries (or everyone outside them) get the challenge, optionally only on catalogue paths. Verified crawlers pass first. Built for the Singapore-datacenter scraper that hit one shop from 130 IPs behind three browser User-Agents.",
    vars: [
      VAR_VHOSTS,
      { key: "mode", label: "Challenge visitors…", type: "select", options: ["from", "outside"], default: "from" },
      { key: "countries", label: "Countries", type: "countries", default: "SG, RU", required: true },
      { key: "paths", label: "Only on these paths (optional; empty = whole site)", type: "paths", placeholder: "/product/, /category/" },
      VAR_IPS_OPTIONAL,
    ],
    warnings: [
      "The challenge rule is created DISABLED. Test with the simulator, then enable it from the table.",
      "Non-browser clients from the matched countries (apps, feeds, payment callbacks) cannot solve a challenge — narrow with paths or list their IPs.",
      `Rule #10 allows crawlers by reverse-DNS verification (${VERIFIED_BOT_LABEL}); rule #11 allows the unverifiable search/social bots and Meta previews by User-Agent (forgeable).`,
      "Visitors whose country cannot be resolved are not matched (fail-open).",
    ],
    build(vars) {
      const vhosts = vhostsVar(vars);
      const cc = countriesVar(vars, ["SG", "RU"]);
      const outside = vars?.mode === "outside";
      const paths = pathsVar(vars, []);
      const ips = ipsVar(vars);
      const k = "geo_challenge";
      const out = [
        rule(k, { enabled: true, priority: 10, vhosts, match: { verified_bot: true }, action: { type: "allow" }, text: "verified crawlers (FCrDNS) pass" }),
        rule(k, { enabled: true, priority: 11, vhosts, match: { ua_any: [...UA_ALLOW_ALONGSIDE_VERIFIED] }, action: { type: "allow" }, text: "unverifiable search/social bots + Meta previews pass by User-Agent (forgeable)" }),
      ];
      if (ips.length) out.push(rule(k, { enabled: true, priority: 15, vhosts, match: { ip_any: ips }, action: { type: "allow" }, text: "office / monitoring ranges always pass" }));
      out.push(rule(k, {
        enabled: false,
        priority: 260,
        vhosts,
        match: outside ? { country_not_in: cc, path_any: paths } : { country_in: cc, path_any: paths },
        action: { type: "challenge" },
        text: `challenge visitors ${outside ? "outside" : "from"} ${cc.join(", ")}${paths.length ? " on " + shortList(paths) : ""} — ENABLE after testing`,
      }));
      return out;
    },
  },
  {
    key: "block_dataset_crawlers",
    kind: "single",
    title: "Block dataset / anonymous crawlers",
    description: "Block the bulk harvesters that bring nothing back: the anonymous \"Mozilla/5.0 (compatible; crawler)\" fleet on residential proxies, img2dataset / imagebot image scrapers, eurovl-fetch, *DatasetCrawler, VelenPublicWebCrawler.",
    vars: [VAR_VHOSTS],
    warnings: ["Created ENABLED: none of these User-Agents is a search engine, a preview fetcher or a monitor. Scope it to * (admin) to cover every vhost."],
    build(vars) {
      return [rule("block_dataset_crawlers", { enabled: true, priority: 335, vhosts: vhostsVar(vars), match: { ua_any: botGroup("dataset").patterns.slice() }, action: { type: "block" }, text: "block dataset / anonymous crawlers by User-Agent" })];
    },
  },
  {
    key: "throttle_hot_path",
    kind: "single",
    title: "Throttle an expensive endpoint for everyone",
    description: "A per-IP rate limit on one or more paths, with no User-Agent condition: admin-ajax.php bursts (20 POST/s from one visitor), WooCommerce ?wc-ajax= fragments, forum attachment downloads. The fix for the \"a few IPs at many times the site's per-IP median\" shape that hides under the vhost score.",
    vars: [
      VAR_VHOSTS,
      { key: "paths", label: "Paths (a /path?param form matches the parameter on any path)", type: "paths", default: "/wp-admin/admin-ajax.php, /?wc-ajax, /forum/download/file.php", required: true },
      { key: "profile", label: "Profile", type: "select", options: THROTTLE_PROFILES.map((p) => p.key), default: "soft_bot" },
    ],
    warnings: [
      "Loaded DISABLED — this throttles humans too. A real WooCommerce page load fires 2-5 ajax POSTs, so soft_bot (2 req/s, burst 20) is the safe start; go harder only from the simulator and the access log.",
      "\"/?wc-ajax\" means: any path, when the query carries wc-ajax (so /en/?wc-ajax=… is covered too).",
    ],
    build(vars) {
      const paths = pathsVar(vars, ["/wp-admin/admin-ajax.php", "/?wc-ajax", "/forum/download/file.php"]);
      const profile = throttleProfile(vars?.profile) ? String(vars.profile) : "soft_bot";
      return [rule("throttle_hot_path", { enabled: false, priority: 180, vhosts: vhostsVar(vars), match: { path_any: paths }, action: { type: "throttle", profile }, text: `throttle ${shortList(paths)} for everyone at ${profile} (disabled — validate first)` })];
    },
  },
  {
    key: "lock_dev_sites",
    kind: "multi",
    title: "Lock dev / staging subdomains",
    description: "Nobody outside your country (and your office ranges) should see a dev site: they are the first stop of phpinfo / .env sweeps and they get indexed by mistake. Everyone outside the listed countries gets the challenge; office ranges pass.",
    vars: [
      { key: "vhosts", label: "Vhosts", type: "vhosts", placeholder: "dev.*, staging.*, test.*, dev.example.com", required: true },
      { key: "countries", label: "Allowed countries", type: "countries", default: "GR", required: true },
      VAR_IPS_OPTIONAL,
    ],
    warnings: [
      "The challenge rule is created DISABLED; enable after a simulator run. Wildcard vhosts (dev.*) need an admin session.",
      "This recipe keys on country so the rule can be enabled from the table: cfm-admin refuses to save an ENABLED rule with no match condition (the daemon itself accepts one via the API). The price is fail-open — a visitor whose country cannot be resolved (some datacenter / proxy ranges) is not challenged. If the dev site must be fail-closed, add a catch-all challenge through the API or CLI on top.",
    ],
    build(vars) {
      const vhosts = vhostsVar(vars);
      const cc = countriesVar(vars, ["GR"]);
      const ips = ipsVar(vars);
      const k = "lock_dev_sites";
      const out = [];
      if (ips.length) out.push(rule(k, { enabled: true, priority: 15, vhosts, match: { ip_any: ips }, action: { type: "allow" }, text: "office / monitoring ranges always pass" }));
      out.push(rule(k, { enabled: false, priority: 255, vhosts, match: { country_not_in: cc }, action: { type: "challenge" }, text: `challenge everyone outside ${cc.join(", ")} on the dev site — ENABLE after testing` }));
      return out;
    },
  },
  {
    key: "xmlrpc_lockdown",
    kind: "multi",
    title: "Lock down xmlrpc.php server-wide",
    description: "Block xmlrpc.php POSTs on every WordPress vhost, with an optional allow for the Jetpack / WordPress.com ranges. Catches the slow brute-forcer (one POST every 25 s behind rotating browser User-Agents) that stays under the WAF's burst threshold.",
    vars: [
      { key: "vhosts", label: "Vhosts", type: "vhosts", default: "*", placeholder: "* (admin) or the WordPress vhosts", required: true },
      { key: "ips", label: "Jetpack / WordPress.com ranges to keep allowed (optional)", type: "ips", placeholder: "the ranges Jetpack publishes on its IP-allowlist support page" },
    ],
    warnings: [
      "Jetpack, the WordPress mobile app and some publishing tools talk to xmlrpc.php. The block is created DISABLED: list the Jetpack ranges (copy them from Jetpack's allowlist page, they are not hard-coded here on purpose) or leave sites that need it out of the scope, then enable.",
      "The per-site \"Protect login endpoints\" recipe is the same block without the fleet-wide scope.",
    ],
    build(vars) {
      const vhosts = vhostsVar(vars);
      const ips = ipsVar(vars);
      const k = "xmlrpc_lockdown";
      const out = [];
      if (ips.length) out.push(rule(k, { enabled: true, priority: 16, vhosts, match: { ip_any: ips, path_any: ["/xmlrpc.php"] }, action: { type: "allow" }, text: "Jetpack / WordPress.com ranges may use xmlrpc.php" }));
      out.push(rule(k, { enabled: false, priority: 315, vhosts, match: { path_any: ["/xmlrpc.php"], methods: ["POST"] }, action: { type: "block" }, text: "block xmlrpc.php POSTs — ENABLE after listing Jetpack ranges" }));
      return out;
    },
  },
  {
    key: "monitoring_probes",
    kind: "link",
    title: "Keep the challenge off your uptime monitor",
    description: "An `allow` rule does NOT stop the challenge: it only ends rule evaluation, and the challenge decision is OR'd in separately. A monitor that gets the challenge page reports the site as up while customers see a puzzle — or as down. Add its IP / User-Agent as a Challenge exclude instead.",
    href: "/cfm-admin/webdetector/waf/",
    linkLabel: "Open Challenge / WAF excludes",
  },
  {
    key: "block_scraper",
    kind: "single",
    title: "Block a scraper by User-Agent",
    description: "Paste the User-Agent fragment(s) from Forensics / IP drilldown; optionally narrow by country.",
    vars: [VAR_VHOSTS, { key: "uas", label: "UA fragments", type: "uas", placeholder: "*SomeScraper*, *another-bot*", required: true }, { key: "countries", label: "Only from countries (optional)", type: "countries", default: "" }],
    build(vars) {
      const uas = csvSplit(vars?.uas);
      return [rule("block_scraper", { enabled: false, priority: 340, vhosts: vhostsVar(vars), match: { ua_any: uas, country_in: countriesVar(vars, []) }, action: { type: "block" }, text: `block ${uas.map(uaName).join(", ") || "scraper"} (disabled — test first)` })];
    },
  },
]);

export function recipe(key) {
  return RECIPES.find((r) => r.key === key) || null;
}

// recipeVarsDefaults returns the initial vars object for a recipe (defaults
// applied, vhosts prefilled from the page context when given).
export function recipeVarsDefaults(rcp, { vhosts = "" } = {}) {
  const out = {};
  // The page context (vhost filter / editor vhost) wins for "vhosts"; a recipe
  // default (e.g. "*" for a server-wide lockdown) applies when there is none.
  for (const v of rcp?.vars || []) out[v.key] = v.key === "vhosts" ? String(vhosts || v.default || "") : String(v.default ?? "");
  return out;
}

// validateRecipeVars: required vars present, countries well-formed.
export function validateRecipeVars(rcp, vars) {
  const errors = [];
  for (const v of rcp?.vars || []) {
    const raw = String(vars?.[v.key] ?? "").trim();
    if (v.required && !raw) errors.push(`${v.label} is required.`);
    if (v.type === "countries") {
      for (const cc of csvSplit(raw)) if (!/^[A-Za-z]{2}$/.test(cc)) errors.push(`"${cc}" is not a 2-letter country code.`);
    }
    if (v.type === "vhosts" && csvSplit(raw).length > LIMITS.vhostsPerRule) errors.push(`Too many vhosts (max ${LIMITS.vhostsPerRule}).`);
    if (v.type === "ips") {
      const ips = csvSplit(raw);
      if (ips.length > LIMITS.patternsPerField) errors.push(`${v.label}: too many entries (max ${LIMITS.patternsPerField}).`);
      for (const ip of ips) if (!isIPOrCIDR(ip)) errors.push(`"${ip}" is not an IPv4/IPv6 address or CIDR range.`);
    }
    if (v.type === "regex" && raw) {
      // Same RE2-vs-JS split as validateRuleForm: reject what RE2 definitely
      // rejects, let the daemon have the final say on the rest.
      if (re2Rejects(raw)) errors.push(`${v.label}: lookahead/lookbehind and backreferences are not supported (Go RE2 syntax).`);
    }
    if (v.type === "botgroups") {
      for (const key of csvSplit(raw)) if (!botGroup(key.toLowerCase())) errors.push(`"${key}" is not a bot group (use ${BOT_GROUPS.map((g) => g.key).join(", ")}).`);
    }
    if (v.type === "paths") {
      const ps = csvSplit(raw).map((p) => (p.startsWith("/") ? p : "/" + p));
      for (const p of ps) if (patternHitsWellKnown(p)) errors.push(`"${p}" would match /.well-known/ — ACME/DCV validation lives there, so it is never a rule target (a bare "/" or "/*" matches everything).`);
      // The daemon counts raw entries (len(in) > max runs before its dedupe).
      // block_probe_paths prepends its fixed list and drops extras it already
      // carries; every other recipe sends the operator's list as typed.
      const probeRecipe = rcp?.key === "block_probe_paths";
      const fixed = probeRecipe ? PROBE_PATHS.length : 0;
      const sent = probeRecipe ? ps.filter((p) => !PROBE_PATHS.includes(p)).length : ps.length;
      if (fixed + sent > LIMITS.patternsPerField) {
        errors.push(`${v.label}: too many paths (the rule may carry ${LIMITS.patternsPerField}${fixed ? `, ${fixed} are built in` : ""}).`);
      }
    }
  }
  return errors;
}
