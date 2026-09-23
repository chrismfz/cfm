// Site Cache — pure, DOM-free client model for the cfm-admin Site Cache page.
//
// Mirrors the daemon's store rules (internal/webdetector/site_cache.go: host
// validation, TTL parsing, recipe vocabularies, cookie-name rules, the set
// merge) and the edge's micro TTL snapping (configs/lua/cfm_cache.lua
// micro_bucket_seconds), so the page validates and previews what the node will
// really do. The daemon stays authoritative: every write is re-validated
// server-side. site-cache-model.test.js pins the recipe lists, the limits and
// MICRO_BUCKETS to their Go / Lua sources, so a second copy cannot drift
// (CLAUDE.md §5).
//
// What the settings do at the edge (docs/site-cache-runbook.md §1):
//   * static tier — static assets; follows the origin's Cache-Control /
//     Expires with a 1 h fallback. Its recipe and TTL are LABELS only.
//   * micro tier — anonymous GET/HEAD through the HTTPS `location /`, for the
//     TTL snapped to a bucket; a dry run until MICRO_CACHE_ENFORCE = 1.
//   * both tiers off = an explicit opt-out (never cached, even under an armed
//     wildcard).

import { csvSplit, hostPatternMatch } from "./rules-model.js";

export const STATIC_RECIPES = Object.freeze(["static_lean", "static_aggressive"]);
export const MICRO_RECIPES = Object.freeze(["micro_safe", "micro_aggressive", "micro_custom", "fullpage_advanced"]);
// Recipes the editor offers for a new selection. fullpage_advanced ships
// disabled (design §8): it stays selectable only on an entry that already uses it.
export const MICRO_RECIPES_OFFERED = Object.freeze(["micro_safe", "micro_aggressive", "micro_custom"]);
// The micro TTL buckets, in seconds (cfm_cache.lua MICRO_BUCKETS).
export const MICRO_BUCKETS = Object.freeze([1, 2, 5, 10, 30, 60]);
export const MAX_AUTH_COOKIES = 32;
export const MAX_HOST_LEN = 253;

const RECIPE_LABELS = Object.freeze({
  static_lean: "static lean",
  static_aggressive: "static aggressive",
  micro_safe: "micro safe",
  micro_aggressive: "micro aggressive",
  micro_custom: "micro custom",
  fullpage_advanced: "full-page advanced",
});

export function recipeLabel(recipe) {
  return RECIPE_LABELS[recipe] || String(recipe || "");
}

// asciiLower folds A-Z only, as the daemon and the edge do: a Unicode fold
// would turn a look-alike into a valid name the daemon then rejects.
function asciiLower(s) {
  return String(s).replace(/[A-Z]/g, (c) => c.toLowerCase());
}

// canonHost mirrors siteCacheCanonHost: trim, ASCII-lowercase, cut a :port,
// and strip trailing dots until stable. (The set API rejects a ":" before it
// canonicalises; hostError reports that separately.)
export function canonHost(host) {
  let h = asciiLower(String(host == null ? "" : host).trim());
  const i = h.indexOf(":");
  if (i >= 0) h = h.slice(0, i);
  for (;;) {
    const t = h.replace(/\.+$/, "").trim();
    if (t === h) return h;
    h = t;
  }
}

// hostError mirrors the set API's host checks (Apply + siteCacheHostError) and
// returns "" for a valid host, else the reason.
export function hostError(raw) {
  const s = String(raw == null ? "" : raw);
  if (s.includes(":")) return "no port: the edge keys policies on the bare host";
  const h = canonHost(s);
  if (!h) return "enter a host";
  if (h.length > MAX_HOST_LEN) return `longer than ${MAX_HOST_LEN} characters`;
  let name = h;
  if (h.startsWith("*.")) {
    name = h.slice(2);
    if (!name.includes(".")) return "a wildcard needs at least two labels after \"*.\" (e.g. *.example.com, not *.com)";
  }
  for (const label of name.split(".")) {
    if (!label) return "empty label (\"..\" or a leading dot)";
    if (label.length > 63) return "a label is longer than 63 characters";
    for (const ch of label) {
      if (ch.codePointAt(0) >= 0x80) return "not ASCII: give an internationalized name in its punycode (xn--) form";
      if (!/[a-z0-9_-]/.test(ch)) return `invalid character "${ch}"`;
    }
    if (label.startsWith("-") || label.endsWith("-")) return "a label cannot start or end with \"-\"";
  }
  return "";
}

export function isWildcard(host) {
  return String(host || "").startsWith("*.");
}

// parseTTLSeconds mirrors parseCacheTTL: "<n><unit>", unit s/m/h/d, n a
// positive integer (Go's strconv.Atoi, so an optional sign). NaN when invalid.
export function parseTTLSeconds(v) {
  const s = String(v == null ? "" : v).trim().toLowerCase();
  if (s.length < 2) return NaN;
  const unit = s[s.length - 1];
  const q = s.slice(0, -1);
  if (!/^[+-]?\d+$/.test(q)) return NaN;
  const n = Number(q);
  if (!Number.isSafeInteger(n) || n <= 0) return NaN;
  const mult = { s: 1, m: 60, h: 3600, d: 86400 }[unit];
  return mult ? n * mult : NaN;
}

export function ttlError(v) {
  const s = String(v == null ? "" : v).trim();
  if (!s) return "";
  return Number.isNaN(parseTTLSeconds(s)) ? `invalid TTL "${s}": use a number and a unit s/m/h/d, e.g. 5s` : "";
}

// microBucketSeconds mirrors cfm_cache.lua micro_bucket_seconds: the edge reads
// "[+]<n><unit>" (a bare number or inner spaces too), snaps to the nearest
// bucket with ties going DOWN, clamps above 60 s, and falls back to the
// smallest bucket for empty / unparseable / <= 0.
export function microBucketSeconds(ttl) {
  let n = NaN;
  if (typeof ttl === "number") {
    n = ttl;
  } else if (typeof ttl === "string") {
    const m = /^\s*\+?(\d+)\s*([a-z]?)\s*$/.exec(ttl.toLowerCase());
    const unit = m ? { "": 1, s: 1, m: 60, h: 3600, d: 86400 }[m[2]] : undefined;
    if (m && unit) n = Number(m[1]) * unit;
  }
  if (!(n > 0)) return MICRO_BUCKETS[0];
  let best = MICRO_BUCKETS[0];
  let bestd = Infinity;
  for (const b of MICRO_BUCKETS) {
    const d = Math.abs(b - n);
    if (d < bestd) {
      best = b;
      bestd = d;
    }
  }
  return best;
}

export function isBucketTTL(ttl) {
  return MICRO_BUCKETS.includes(parseTTLSeconds(ttl));
}

// goIsSpaceOrControl: the runes siteCacheCookieNameError refuses as
// whitespace — r <= ' ', DEL, and Go's unicode.IsSpace (U+0085, U+00A0 and the
// Unicode Z categories). JavaScript's \s differs (it has U+FEFF, lacks U+0085),
// so the set is spelled out.
function goIsSpaceOrControl(cp) {
  return cp <= 0x20 || cp === 0x7f || cp === 0x85 || cp === 0xa0 || cp === 0x1680 ||
    (cp >= 0x2000 && cp <= 0x200a) || cp === 0x2028 || cp === 0x2029 || cp === 0x202f ||
    cp === 0x205f || cp === 0x3000;
}

// cookieNameError mirrors siteCacheCookieNameError.
export function cookieNameError(c) {
  if (new TextEncoder().encode(c).length > 256) return "longer than 256 bytes";
  for (const ch of c) {
    if (goIsSpaceOrControl(ch.codePointAt(0)) || ch === "=" || ch === ";") {
      return "a cookie name never holds whitespace, \"=\", \";\" or a control character";
    }
  }
  const l = c.toLowerCase();
  if (l === "__host-" || l === "__secure-") return "only a __Host- / __Secure- prefix (the edge strips it, leaving no name)";
  if (c.startsWith("[")) return "starts with \"[\" (read as an array with no name)";
  return "";
}

// parseAuthCookies splits the comma list, de-duplicates case-insensitively
// (ASCII fold, as the daemon), and reports every name the daemon would refuse.
export function parseAuthCookies(csv) {
  const names = [];
  const errors = [];
  const seen = new Set();
  for (const c of csvSplit(csv)) {
    const why = cookieNameError(c);
    if (why) {
      errors.push(`auth cookie "${c}": ${why}`);
      continue;
    }
    const key = asciiLower(c);
    if (seen.has(key)) continue;
    seen.add(key);
    names.push(c);
  }
  if (names.length > MAX_AUTH_COOKIES) errors.push(`too many auth cookies (${names.length}, max ${MAX_AUTH_COOKIES})`);
  return { names, errors };
}

function tierOf(entry, kind) {
  const t = entry && entry[kind];
  return {
    enabled: Boolean(t && t.enabled),
    recipe: String((t && t.recipe) || ""),
    ttl: String((t && t.ttl) || ""),
  };
}

export function isOptOut(entry) {
  return !tierOf(entry, "static").enabled && !tierOf(entry, "micro").enabled;
}

// ── Editor form ─────────────────────────────────────────────────────────────

export function emptyForm() {
  return {
    host: "",
    staticOn: false,
    staticRecipe: "static_lean",
    microOn: false,
    microRecipe: "micro_safe",
    microTTL: "1s",
    strictCookies: false,
    authCookies: "",
  };
}

export function formFromEntry(entry) {
  const st = tierOf(entry, "static");
  const mi = tierOf(entry, "micro");
  return {
    host: String((entry && entry.host) || ""),
    staticOn: st.enabled,
    staticRecipe: st.recipe || "static_lean",
    microOn: mi.enabled,
    microRecipe: mi.recipe || "micro_safe",
    // No stored TTL runs at 1 s at the edge, so the form shows (and a save
    // sends) exactly that.
    microTTL: mi.ttl || "1s",
    strictCookies: Boolean(entry && entry.strict_cookies),
    authCookies: ((entry && entry.auth_cookies) || []).join(", "),
  };
}

// buildPatch turns the form into a set-API patch. The API MERGES (absent
// fields keep their stored value), so the patch carries only what the form
// decides:
//   * enabled for both tiers, always (both off on a new host is the explicit
//     opt-out the API requires);
//   * a tier's recipe (and the micro TTL) only while that tier is on — a
//     disabled tier keeps its stored recipe, which is how the daemon knows a
//     re-enable must start from an empty cache;
//   * the static TTL never: it is a label the edge does not apply.
export function buildPatch(form) {
  const f = form || emptyForm();
  const patch = { host: canonHost(f.host) };
  patch.static = { enabled: Boolean(f.staticOn) };
  if (f.staticOn) patch.static.recipe = f.staticRecipe;
  patch.micro = { enabled: Boolean(f.microOn) };
  if (f.microOn) {
    patch.micro.recipe = f.microRecipe;
    patch.micro.ttl = String(f.microTTL || "").trim().toLowerCase();
  }
  patch.strict_cookies = Boolean(f.strictCookies);
  patch.auth_cookies = parseAuthCookies(f.authCookies).names;
  return patch;
}

export function offPatch(host) {
  return { host: canonHost(host), static: { enabled: false }, micro: { enabled: false } };
}

// validateForm returns { errors, warnings } for the editor. `original` is the
// stored entry being edited (null for a new policy); `inScope(host)` is the
// page's scope check for a scoped token (always true for an admin).
export function validateForm(form, { original = null, inScope = () => true, existing = [] } = {}) {
  const f = form || emptyForm();
  const errors = [];
  const warnings = [];
  const herr = hostError(f.host);
  if (herr) errors.push(`Host: ${herr}.`);
  const host = canonHost(f.host);
  if (!herr && !inScope(host)) errors.push(`Host: ${host} is not one of your vhosts.`);
  if (f.staticOn && !STATIC_RECIPES.includes(f.staticRecipe)) errors.push("Static tier: pick a recipe.");
  if (f.microOn && !MICRO_RECIPES.includes(f.microRecipe)) errors.push("Micro tier: pick a recipe.");
  if (f.microOn) {
    const terr = ttlError(f.microTTL);
    if (terr) errors.push(`Micro TTL: ${terr}.`);
    else if (!String(f.microTTL || "").trim()) warnings.push("Micro TTL is empty: the edge runs it at 1 s.");
    else if (!isBucketTTL(f.microTTL)) warnings.push(`Micro TTL ${String(f.microTTL).trim()} is not a bucket: the edge snaps it to ${microBucketSeconds(String(f.microTTL))} s.`);
    if (f.microRecipe === "fullpage_advanced") warnings.push("full-page advanced is a label only: the micro tier never caches longer than 60 s.");
  }
  const cookies = parseAuthCookies(f.authCookies);
  errors.push(...cookies.errors.map((e) => `${e[0].toUpperCase()}${e.slice(1)}.`));
  if (!f.microOn && (f.strictCookies || cookies.names.length)) {
    warnings.push("Strict cookies and auth cookies apply to the micro tier only; they do nothing while it is off.");
  }
  if (!f.staticOn && !f.microOn) {
    warnings.push(isWildcard(host)
      ? "Both tiers off: an opt-out. Nothing under this wildcard is cached, unless a more specific policy arms it."
      : "Both tiers off: an opt-out. This host is never cached, even under an armed wildcard.");
  }
  if (original) {
    const st = tierOf(original, "static");
    const mi = tierOf(original, "micro");
    if (!st.enabled && f.staticOn) warnings.push("Turning the static tier on starts this vhost from an empty cache (a new generation) for both tiers.");
    if (!mi.enabled && f.microOn && mi.recipe) warnings.push("Re-enabling the micro tier starts this vhost from an empty cache (a new generation) for both tiers.");
  } else if (!herr && existing.some((e) => canonHost(e.host) === host)) {
    warnings.push(`${host} already has a policy: saving updates it (fields you leave out keep their stored value).`);
  } else if (!herr) {
    const cover = coveringWildcard(host, existing);
    if (cover) warnings.push(`${host} is covered by ${cover}: a policy of its own replaces the wildcard's for this host.`);
  }
  return { errors, warnings };
}

// coveringWildcard: the stored "*.suffix" policy the edge would apply to host
// without a policy of its own — the most specific (longest) match, as
// cfm_cache.lua orders them. "" when none covers it.
export function coveringWildcard(host, entries) {
  const h = canonHost(host);
  let best = "";
  for (const e of entries || []) {
    const pat = canonHost(e && e.host);
    if (!isWildcard(pat) || pat === h) continue;
    if (hostPatternMatch(pat, h) && pat.length > best.length) best = pat;
  }
  return best;
}

// ── List rows ───────────────────────────────────────────────────────────────

// rowView flattens an entry (+ its stats row, when the edge reported one) for
// the table.
export function rowView(entry, stats) {
  const st = tierOf(entry, "static");
  const mi = tierOf(entry, "micro");
  const updated = Date.parse((entry && entry.updated_at) || "");
  const s = stats || null;
  return {
    host: String((entry && entry.host) || ""),
    wildcard: isWildcard(entry && entry.host),
    staticOn: st.enabled,
    staticRecipe: st.recipe,
    staticTTL: st.ttl,
    microOn: mi.enabled,
    microRecipe: mi.recipe,
    microTTL: mi.ttl,
    microBucket: microBucketSeconds(mi.ttl),
    optOut: !st.enabled && !mi.enabled,
    strictCookies: Boolean(entry && entry.strict_cookies),
    authCookies: (entry && entry.auth_cookies) || [],
    generation: Number((entry && entry.generation) || 0),
    updatedMs: Number.isNaN(updated) ? 0 : updated,
    stats: s,
    hitPct: s && s.cacheable_total > 0 ? Number(s.hit_ratio_pct) : null,
    entry,
  };
}

// generationSinceMs: a policy's generation is the wall-clock ms of its last
// purge or re-enable (nextGenerationLocked). A store written before that
// counted generations from 1, so a small value is a counter, not a time: null.
export function generationSinceMs(gen, nowMs = Date.now()) {
  const g = Number(gen || 0);
  if (!(g > 1e11) || g > nowMs + 86400000) return null;
  return g;
}

export function buildRows(entries, statsRows) {
  const byHost = new Map();
  for (const r of statsRows || []) if (r && r.host) byHost.set(r.host, r);
  return (entries || []).map((e) => rowView(e, byHost.get(e && e.host)));
}

export function tierCounts(rows) {
  const out = { all: 0, static: 0, micro: 0, optout: 0 };
  for (const r of rows || []) {
    out.all += 1;
    if (r.staticOn) out.static += 1;
    if (r.microOn) out.micro += 1;
    if (r.optOut) out.optout += 1;
  }
  return out;
}

// filterRows: quick filter (static / micro / optout), a vhost (an exact policy
// or a wildcard covering it), and a free-text search.
export function filterRows(rows, { quick = "", vhost = "", search = "" } = {}) {
  const vf = canonHost(vhost);
  const q = String(search || "").trim().toLowerCase();
  return (rows || []).filter((r) => {
    if (quick === "static" && !r.staticOn) return false;
    if (quick === "micro" && !r.microOn) return false;
    if (quick === "optout" && !r.optOut) return false;
    if (vf && !(r.host === vf || hostPatternMatch(r.host, vf))) return false;
    if (!q) return true;
    const hay = [r.host, r.staticRecipe, r.microRecipe, r.microTTL, r.authCookies.join(",")].join(" ").toLowerCase();
    return hay.includes(q);
  });
}

export const SORT_KEYS = Object.freeze(["host", "tiers", "recipe", "ttl", "gen", "updated", "hit"]);

function sortValue(r, key) {
  switch (key) {
    case "tiers": return (r.staticOn ? 2 : 0) + (r.microOn ? 1 : 0);
    case "recipe": return `${r.staticOn ? r.staticRecipe : ""}|${r.microOn ? r.microRecipe : ""}`;
    case "ttl": return r.microOn ? r.microBucket : -1;
    case "gen": return r.generation;
    case "updated": return r.updatedMs;
    case "hit": return r.hitPct == null ? -1 : r.hitPct;
    default: return r.host;
  }
}

// sortRows sorts a copy; the host breaks ties, so the order is stable across
// refreshes.
export function sortRows(rows, key = "host", dir = "asc") {
  const k = SORT_KEYS.includes(key) ? key : "host";
  const sign = dir === "desc" ? -1 : 1;
  const byHost = (a, b) => a.host.localeCompare(b.host, undefined, { sensitivity: "base" });
  return [...(rows || [])].sort((a, b) => {
    const va = sortValue(a, k);
    const vb = sortValue(b, k);
    let cmp = 0;
    if (typeof va === "number" && typeof vb === "number") cmp = va - vb;
    else cmp = String(va).localeCompare(String(vb), undefined, { sensitivity: "base" });
    return cmp !== 0 ? cmp * sign : byHost(a, b);
  });
}

// ── Node switches ───────────────────────────────────────────────────────────

// kvBool mirrors the daemon's detectors.conf boolean reader: an inline ; / #
// comment and surrounding quotes are stripped; anything unrecognised is the
// default.
function kvBool(v, def) {
  if (v == null) return def;
  let s = String(v);
  const i = s.search(/[;#]/);
  if (i >= 0) s = s.slice(0, i);
  s = s.trim().replace(/^["']+|["']+$/g, "").toLowerCase();
  if (["1", "true", "yes", "on"].includes(s)) return true;
  if (["0", "false", "no", "off"].includes(s)) return false;
  return def;
}

// nodeSwitches reads SITE_CACHE / MICRO_CACHE_ENFORCE from a
// GET /api/v1/detectors/config?view=merged payload (admin only). null when the
// payload has no [webdetector] section to read.
export function nodeSwitches(payload) {
  const cfg = payload && payload.config;
  if (!cfg) return null;
  const sections = [...(cfg.core || []), ...(cfg.leniency || []), ...(cfg.advanced || [])];
  const wd = sections.find((s) => s && String(s.name).toLowerCase() === "webdetector");
  if (!wd) return null;
  const keys = {};
  for (const [k, v] of Object.entries(wd.keys || {})) keys[k.toUpperCase()] = v;
  return {
    siteCache: kvBool(keys.SITE_CACHE, true),
    microEnforce: kvBool(keys.MICRO_CACHE_ENFORCE, false),
  };
}

// ── Checking one URL ────────────────────────────────────────────────────────

// debugCurl builds the runbook §4 debug-stamp request for a host: run on the
// box itself, against the edge's HTTPS listener. A wildcard gets an example
// sub-host. "" for an invalid host (the command is meant to be pasted into a
// shell, so only a validated host goes into it).
export function debugCurl(host, path = "/") {
  if (hostError(host)) return "";
  const h = canonHost(host).replace(/^\*\./, "www.");
  let p = String(path || "/").trim() || "/";
  if (!p.startsWith("/")) p = `/${p}`;
  p = p.replace(/'/g, "%27").replace(/\s/g, (c) => encodeURIComponent(c));
  return `curl -sk -o /dev/null -D - -H 'X-CFM-Cache-Debug: 1' --resolve ${h}:9043:<vhost-ip> 'https://${h}:9043${p}'`;
}
