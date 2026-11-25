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
// write challenge PATH excludes on its own literal vhosts (the malpath
// carve-out); WAF path excludes stay admin-only (the server refuses them for
// a scoped token). The UI ships inside the daemon binary, so this always
// matches its API.
export function pathTypeAllowed(kind, { isScoped, scopedExcludeManagementAllowed, allowedVhosts = [] }) {
  if (!isScoped) return true;
  return kind === "challenge" && Boolean(scopedExcludeManagementAllowed) && literalVhosts(allowedVhosts).length > 0;
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
export function excludeWhen(row) {
  const d = new Date(String((row && row.created_at) || ""));
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}
