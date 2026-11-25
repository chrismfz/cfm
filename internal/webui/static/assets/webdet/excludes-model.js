// Pure helpers for the Dynamic excludes card (feature-excludes.js), kept out
// of the Vue mixin so `make test-js` can pin them. The daemon is authoritative
// (exclude_api_handlers.go: challengePathExcludeScope); these only stop a form
// the server would refuse and say why in the card.

// Split a comma / space separated host list, lower-cased, de-duplicated.
export function parseScopeHosts(raw) {
  const out = [];
  for (const part of String(raw ?? "").split(/[\s,]+/)) {
    const h = part.trim().toLowerCase().replace(/\.$/, "");
    if (h && !out.includes(h)) out.push(h);
  }
  return out;
}

const GLOB = /[*?[\]]/;

// The token's literal (non-glob) vhosts, sorted: what a tenant may scope a
// challenge path exclude to (the server never takes a glob from a tenant).
export function literalVhosts(allowedVhosts = []) {
  return [...new Set(allowedVhosts.map((h) => String(h).trim().toLowerCase()).filter((h) => h && !GLOB.test(h)))].sort();
}

// Which exclude kinds may take type=path for this session. A scoped token may
// write PATH excludes on its own literal vhosts: a challenge one (the malpath
// carve-out), and a WAF one for ONE rule with an expiry (scopedWAFAddError
// below; the server refuses a wider one). The UI ships inside the daemon
// binary, so this always matches its API.
export function pathTypeAllowed(kind, { isScoped, scopedExcludeManagementAllowed, allowedVhosts = [] }) {
  if (!isScoped) return true;
  return (kind === "challenge" || kind === "waf") && Boolean(scopedExcludeManagementAllowed) && literalVhosts(allowedVhosts).length > 0;
}

// ── What a site owner (scoped token) may do to the WAF ───────────────────
// The daemon enforces all of it (internal/webdetector/waf_exclude_tenant.go);
// these copies keep the page from offering what will be refused.

// The WAF reason families a site owner can neither exclude by rule nor switch
// off: they keep running when the owner turns the site's WAF off. A copy of
// wafTenantKeptFamilies (Go) and WAF_TENANT_KEPT_REASONS (Lua), kept equal by
// TestWAFTenantKeptFamilies_LuaParity, which reads this line.
export const TENANT_KEPT_FAMILIES = Object.freeze(["WAF_CVE", "WAF_WEBSHELL"]);
export const TENANT_KEPT_NOTE = "CVE and webshell rules stay on";

export function tenantKeptFamily(reason) {
  return TENANT_KEPT_FAMILIES.includes(String(reason || "").split(":")[0].trim());
}

// How long a site owner's rule exclude may last. The first is the default.
export const EXCLUDE_TTLS = Object.freeze([
  Object.freeze({ key: "24h", label: "24 hours" }),
  Object.freeze({ key: "7d", label: "7 days" }),
]);

// scopedWAFAddError: why a site owner's WAF exclude would be refused, or "".
// No rule = the switch (a host only). A rule exclude is one rule id (no list,
// range or group), with an expiry.
export function scopedWAFAddError({ type, rules, ttl }) {
  const r = String(rules || "").trim();
  if (!r) return type === "path" ? "name the one rule to let this path through" : "";
  if (!/^\d{3}$/.test(r)) return "name one rule (for example 402), not a list or a range";
  if (!EXCLUDE_TTLS.some((t) => t.key === ttl)) return "choose how long: 24 hours or 7 days";
  return "";
}

// The problem with a challenge PATH exclude's scope field, or "" when it may be
// sent. A pre-check only, deliberately small so it cannot drift from the
// daemon (challengePathExcludeScope / wideScopeHost decide, and their error is
// shown as is): a scope is required, and a tenant may name only its own
// literal vhosts. Admin globs are left to the server.
export function challengePathScopeError(hosts, { isScoped, allowedVhosts = [] }) {
  if (!hosts.length) {
    return isScoped
      ? "pick at least one of your sites"
      : "a path exclude needs at least one scope host (it would otherwise apply to every site)";
  }
  if (!isScoped) return "";
  const own = new Set(literalVhosts(allowedVhosts));
  const outside = hosts.filter((h) => !own.has(h));
  return outside.length ? `outside your sites: ${outside.join(", ")}` : "";
}

// A challenge path value must be a path: a value without a slash is most
// likely the host prefill left over from type=host.
export function looksLikeHostValue(value) {
  const v = String(value ?? "").trim();
  return v !== "" && !v.includes("/");
}

// Scope column for a challenge exclude row. An unscoped path entry (an older
// version wrote one) matches nothing: never render it as "*" (every site).
export function formatChallengeExcludeScope(row) {
  const hosts = Array.isArray(row?.scope_hosts) ? row.scope_hosts : [];
  if (row?.type === "path" && !hosts.length) return "none (inert: remove it)";
  return hosts.length ? hosts.join(", ") : "*";
}

// ── Exceptions page (partial-exceptions.js) ──────────────────────────────

export const EXCEPTION_TABS = Object.freeze([
  Object.freeze({ key: "waf", label: "WAF" }),
  Object.freeze({ key: "challenge", label: "Challenge" }),
  Object.freeze({ key: "trusted", label: "Trusted clients" }),
]);
export function exceptionTab(key) {
  return EXCEPTION_TABS.some((t) => t.key === key) ? key : "waf";
}

// wafExcludeSkips says what a WAF exclude lets through: "the whole WAF" for
// an entry without rule ids, "rule 402" / "rules 401, 431" otherwise.
export function wafExcludeSkips(row) {
  const ids = Array.isArray(row && row.rule_ids) ? row.rule_ids : [];
  // keep_critical: a site owner's switch. The named-CVE and webshell rules keep running.
  if (!ids.length && row && row.keep_critical === true) return { text: "the WAF (" + TENANT_KEPT_NOTE + ")", whole: true };
  if (!ids.length) return { text: "the whole WAF", whole: true };
  return { text: `rule${ids.length === 1 ? "" : "s"} ${ids.join(", ")}`, whole: false };
}

// excludeWhere says where an exclude applies: its scope hosts, or every vhost
// (for a host entry, the host itself is the where).
export function excludeWhere(row) {
  const hosts = Array.isArray(row && row.scope_hosts) ? row.scope_hosts : [];
  if (hosts.length) return hosts.join(", ");
  return row && row.type === "host" ? "this host" : "every vhost";
}

// filterExcludes keeps the rows whose value or scope holds the text typed.
export function filterExcludes(rows, text) {
  const list = Array.isArray(rows) ? rows : [];
  const q = String(text || "").trim().toLowerCase();
  if (!q) return list;
  return list.filter((r) => r && (String(r.value || "").toLowerCase().includes(q)
    || (Array.isArray(r.scope_hosts) ? r.scope_hosts : []).some((h) => String(h).toLowerCase().includes(q))));
}

// sortExcludes puts the widest entries first (they are the ones to look at):
// a whole-WAF entry before a rule-scoped one, an every-vhost entry before a
// scoped one, then newest first. A new list; the input is not changed.
export function sortExcludes(rows) {
  const w = (r) => ((Array.isArray(r.rule_ids) && r.rule_ids.length) ? 0 : 2) + ((Array.isArray(r.scope_hosts) && r.scope_hosts.length) || r.type === "host" ? 0 : 1);
  return (Array.isArray(rows) ? rows.filter(Boolean) : []).slice().sort((a, b) => (w(b) - w(a)) || String(b.created_at || "").localeCompare(String(a.created_at || "")));
}

// excludeWhen is the entry's creation time as a short local date, or "".
// excludeBy: who wrote the entry, when it was not the operator.
export function excludeBy(row) {
  return row && row.by === "scoped" ? "site owner" : "";
}

// excludeExpires: when an entry stops applying. {text, soon}; text is "" for
// an entry without an expiry. `soon` = within a day.
export function excludeExpires(row, nowMs = Date.now()) {
  const at = Number(row && row.expires_unix);
  if (!Number.isFinite(at) || at <= 0) return { text: "", soon: false };
  const left = at - Math.floor(nowMs / 1000);
  if (left <= 0) return { text: "expired", soon: true };
  if (left < 3600) return { text: "in " + Math.max(1, Math.round(left / 60)) + " min", soon: true };
  if (left < 86400) return { text: "in " + Math.round(left / 3600) + " h", soon: true };
  return { text: "in " + Math.round(left / 86400) + " d", soon: false };
}

export function excludeWhen(row) {
  const d = new Date(String((row && row.created_at) || ""));
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}
