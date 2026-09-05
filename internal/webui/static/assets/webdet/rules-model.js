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

// hostPatternMatch mirrors Go ruleHostMatch: exact host, a `*`/`?` glob, or a
// "*.suffix" pattern matching any host that ends in ".suffix".
export function hostPatternMatch(pattern, host) {
  const pat = String(pattern || "").toLowerCase().trim();
  const h = String(host || "").toLowerCase().trim();
  if (!pat || !h) return false;
  if (pat === h) return true;
  if (pat.startsWith("*.")) {
    const suf = pat.slice(1);
    if (h.endsWith(suf) && h.length > suf.length) return true;
  }
  if (/[*?]/.test(pat)) {
    const rx = new RegExp(`^${pat.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^.]*").replace(/\?/g, ".")}$`);
    return rx.test(h);
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
    hint: "GPTBot, ChatGPT-User, ClaudeBot, anthropic-ai, Bytespider, CCBot, Amazonbot, PerplexityBot, Google-Extended",
    patterns: ["*GPTBot*", "*ChatGPT-User*", "*ClaudeBot*", "*anthropic-ai*", "*Bytespider*", "*CCBot*", "*Amazonbot*", "*PerplexityBot*", "*Google-Extended*"],
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

// ── Form ⇄ payload ────────────────────────────────────────────────────────
export function emptyForm(overrides = {}) {
  return {
    enabled: false,
    priority: 0, // 0 → suggestPriority() at save/review time
    vhosts: "",
    countries: "",
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
      country_in: csvSplit(f.countries).map((x) => x.toUpperCase()),
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
    countries: list(r?.match?.country_in),
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
      (m.ua_any && m.ua_any.length) ||
      (m.path_any && m.path_any.length) ||
      (m.methods && m.methods.length) ||
      m.has_qs,
  );
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

  if (p.match.country_in.length > LIMITS.countriesPerRule) errors.push(`Too many countries (max ${LIMITS.countriesPerRule}).`);
  for (const cc of p.match.country_in) {
    if (!/^[A-Z]{2}$/.test(cc)) errors.push(`"${cc}" is not a 2-letter country code (use ISO codes like GR, CY, US).`);
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
    if (/\(\?<?[=!]/.test(rx) || /\\[1-9]/.test(rx)) {
      errors.push("QS pass-through: lookahead/lookbehind and backreferences are not supported (Go RE2 syntax).");
    } else {
      try {
        new RegExp(rx.replace(/^\(\?[imsU]+\)/, ""), "i");
      } catch (err) {
        warnings.push(`QS pass-through could not be parsed as a JavaScript regex (${err.message}); the daemon validates it as Go RE2 on save.`);
      }
    }
  }
  if (p.note.length > LIMITS.noteLen) errors.push(`Note too long (max ${LIMITS.noteLen} characters).`);

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
    hints.push("User-Agent is client-controlled: anyone can send this string. Prefer an allow keyed on something the client cannot forge.");
  }
  if (p.match.country_in.length) {
    hints.push("Requests whose IP the geo database cannot resolve have no country and never match a country condition.");
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
  const uas = Array.isArray(m.ua_any) ? m.ua_any : [];
  const paths = Array.isArray(m.path_any) ? m.path_any : [];

  parts.push(methods.length ? `${joinList(methods, max)} requests` : (hasAnyMatch(m) ? "requests" : "every request"));
  if (countries.length) parts.push(`from ${joinList(countries, max)}`);
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
    ip: "",
    // "-" means "no User-Agent": send an empty UA, exactly what the edge sends.
    ua: (m.ua_any || [])[0] === "-" ? "" : ua,
    path,
    method: String((m.methods || [])[0] || "GET"),
    country: String((m.country_in || [])[0] || ""),
    qs,
  };
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
const GOOD_BOT_UAS = [...botGroup("search").patterns, ...botGroup("social").patterns];

function note(key, text) {
  return `recipe:${key} — ${text}`;
}
function rule(key, { enabled, priority, vhosts, match = {}, action, text }) {
  return {
    enabled: Boolean(enabled),
    priority,
    scope: { vhosts: vhosts.slice() },
    match: {
      country_in: match.country_in || [],
      ua_any: match.ua_any || [],
      path_any: match.path_any || [],
      methods: match.methods || [],
      has_qs: Boolean(match.has_qs),
      qs_not_rx: match.qs_not_rx || undefined,
    },
    action,
    note: note(key, text),
  };
}
function vhostsVar(vars) {
  return csvSplit(vars?.vhosts).map((h) => h.toLowerCase());
}
function countriesVar(vars, fallback) {
  const cc = csvSplit(vars?.countries).map((c) => c.toUpperCase());
  return cc.length ? cc : fallback;
}
function pathsVar(vars, fallback) {
  const ps = csvSplit(vars?.paths).map((p) => (p.startsWith("/") ? p : "/" + p));
  return ps.length ? ps : fallback;
}

const VAR_VHOSTS = { key: "vhosts", label: "Vhosts", type: "vhosts", placeholder: "example.com, *.example.com", required: true };

export const RECIPES = Object.freeze([
  {
    key: "geo_fence",
    kind: "multi",
    title: "Allow only these countries",
    description: "Serve the site to visitors from the listed countries and to search/social crawlers; block everyone else.",
    vars: [VAR_VHOSTS, { key: "countries", label: "Allowed countries", type: "countries", default: "GR, CY", required: true }],
    warnings: [
      "The block rule is created DISABLED. Test with the simulator, then enable it from the table.",
      "Crawlers are allowed by User-Agent, which anyone can forge. A verified-bot (FCrDNS) match is a planned follow-up.",
      "Visitors whose IP has no country in the geo database are blocked too (no country never matches an allow). Add an allow for office/monitoring ranges when IP matching lands.",
      "Browsers that already hold a clearance cookie for the vhost keep access until it expires.",
    ],
    build(vars) {
      const vhosts = vhostsVar(vars);
      const cc = countriesVar(vars, ["GR", "CY"]);
      const k = "geo_fence";
      return [
        rule(k, { enabled: true, priority: 10, vhosts, match: { ua_any: GOOD_BOT_UAS }, action: { type: "allow" }, text: "let search/social crawlers through before the fence (UA-based)" }),
        rule(k, { enabled: true, priority: 20, vhosts, match: { country_in: cc }, action: { type: "allow" }, text: `visitors from ${cc.join(", ")} skip the fence` }),
        rule(k, { enabled: false, priority: 900, vhosts, action: { type: "block" }, text: "block everyone else — ENABLE after testing" }),
      ];
    },
  },
  {
    key: "geo_fence_admin",
    kind: "multi",
    title: "Admin area only from these countries",
    description: "Visitors from the listed countries reach the admin/login paths normally; everyone else gets the challenge there. The rest of the site is untouched.",
    vars: [
      VAR_VHOSTS,
      { key: "countries", label: "Allowed countries", type: "countries", default: "GR", required: true },
      { key: "paths", label: "Admin paths", type: "paths", default: "/wp-admin/, /wp-login.php" },
      { key: "action", label: "Everyone else gets", type: "select", options: ["challenge", "block"], default: "challenge" },
    ],
    warnings: ["The enforcing rule is created DISABLED; enable it after a simulator run.", "Challenge cannot be passed by non-browser clients (apps, integrations) hitting these paths."],
    build(vars) {
      const vhosts = vhostsVar(vars);
      const cc = countriesVar(vars, ["GR"]);
      const paths = pathsVar(vars, ["/wp-admin/", "/wp-login.php"]);
      const act = vars?.action === "block" ? "block" : "challenge";
      const k = "geo_fence_admin";
      return [
        rule(k, { enabled: true, priority: 100, vhosts, match: { country_in: cc, path_any: paths }, action: { type: "allow" }, text: `${cc.join(", ")} reach the admin paths normally` }),
        rule(k, { enabled: false, priority: 101, vhosts, match: { path_any: paths }, action: { type: act }, text: `${act} the admin paths for everyone else — ENABLE after testing` }),
      ];
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
    description: "Let search/social crawlers through, rate-limit SEO and AI crawlers, block requests without a User-Agent.",
    vars: [VAR_VHOSTS],
    warnings: ["Throttles are enabled (low collateral). The no-User-Agent block is created DISABLED: uptime monitors and health checks sometimes send no UA — check the simulator/logs, then enable."],
    build(vars) {
      const vhosts = vhostsVar(vars);
      const k = "tame_bots";
      return [
        rule(k, { enabled: true, priority: 10, vhosts, match: { ua_any: GOOD_BOT_UAS }, action: { type: "allow" }, text: "search/social crawlers first" }),
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
  for (const v of rcp?.vars || []) out[v.key] = v.key === "vhosts" ? String(vhosts || "") : String(v.default ?? "");
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
  }
  return errors;
}
