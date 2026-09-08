// Challenge Access-Control — pure, DOM-free client model.
//
// Mirrors internal/webdetector/challenge_access.go (the entry shape, the match
// grammar it shares with traffic rules, and the challenge-only asn_in field) so
// the cfm-admin builder validates and previews exactly what the daemon
// enforces. Reuses the traffic-rule helpers (csvSplit, BOT_GROUPS,
// VERIFIED_BOT_LABEL) — one grammar, not a second copy (CLAUDE.md §5).
//
// An entry EXEMPTS matching requests from the interactive challenge
// (challenge→allow only): it never softens the WAF or an IP block, and an
// unknown country/ASN fails open (never matches).

import { csvSplit, BOT_GROUPS, VERIFIED_BOT_LABEL } from "./rules-model.js";

export { BOT_GROUPS, VERIFIED_BOT_LABEL };

export const CA_METHODS = Object.freeze(["GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"]);

// The match dimensions the builder exposes, in display order. Each is a chip in
// the editor and a clause in the plain-language summary.
export const CA_DIMENSIONS = Object.freeze(["paths", "uas", "countries", "ips", "asns", "methods", "vbot"]);

export function emptyCAForm() {
  return {
    enabled: true,
    vhosts: "",
    paths: "",
    uas: "",
    countries: "",
    countriesMode: "in", // "in" | "not_in"
    ips: "",
    asns: "",
    methods: "",
    verifiedBot: false,
    note: "",
  };
}

// parseASNs turns "AS15169, 64500" into [15169, 64500]. A leading "as"/"AS" is
// optional (matches the daemon's asn normalizer). Non-numeric / zero tokens are
// dropped here and reported by validateCAForm.
export function parseASNs(v) {
  return csvSplit(v)
    .map((tok) => Number(String(tok).trim().replace(/^as/i, "")))
    .filter((n) => Number.isInteger(n) && n > 0);
}

// invalidASNTokens returns the raw tokens that are NOT a positive integer ASN,
// so the editor can point at the exact typo.
export function invalidASNTokens(v) {
  return csvSplit(v).filter((tok) => {
    const n = Number(String(tok).trim().replace(/^as/i, ""));
    return !(Number.isInteger(n) && n > 0);
  });
}

// buildCAPayload turns the editor form into the /api/v1/challenge/access/add
// body. Only non-empty dimensions are included, so an "exempt this whole vhost"
// entry sends an empty match object (equivalent to a host challenge-exclude).
export function buildCAPayload(form) {
  const match = {};
  const codes = csvSplit(form.countries).map((c) => c.toUpperCase());
  if (codes.length) {
    if (form.countriesMode === "not_in") match.country_not_in = codes;
    else match.country_in = codes;
  }
  const ips = csvSplit(form.ips);
  if (ips.length) match.ip_any = ips;
  const asns = parseASNs(form.asns);
  if (asns.length) match.asn_in = asns;
  const uas = csvSplit(form.uas);
  if (uas.length) match.ua_any = uas;
  const paths = csvSplit(form.paths);
  if (paths.length) match.path_any = paths;
  const methods = csvSplit(form.methods).map((m) => m.toUpperCase());
  if (methods.length) match.methods = methods;
  if (form.verifiedBot) match.verified_bot = true;

  return {
    enabled: Boolean(form.enabled),
    scope: { vhosts: csvSplit(form.vhosts) },
    match,
    note: String(form.note || "").trim(),
  };
}

// caFormFromEntry hydrates the editor from a stored entry (the inverse of
// buildCAPayload), for Edit / Duplicate.
export function caFormFromEntry(entry) {
  const m = (entry && entry.match) || {};
  const notIn = Array.isArray(m.country_not_in) && m.country_not_in.length > 0;
  return {
    enabled: entry ? Boolean(entry.enabled) : true,
    vhosts: joinList(entry && entry.scope && entry.scope.vhosts),
    paths: joinList(m.path_any),
    uas: joinList(m.ua_any),
    countries: joinList(notIn ? m.country_not_in : m.country_in),
    countriesMode: notIn ? "not_in" : "in",
    ips: joinList(m.ip_any),
    asns: joinList(m.asn_in),
    methods: joinList(m.methods),
    verifiedBot: Boolean(m.verified_bot),
    note: String((entry && entry.note) || ""),
  };
}

// dimensionsPresent reports which chips to open when editing an entry.
export function dimensionsPresent(entry) {
  const m = (entry && entry.match) || {};
  return {
    paths: nonEmpty(m.path_any),
    uas: nonEmpty(m.ua_any),
    countries: nonEmpty(m.country_in) || nonEmpty(m.country_not_in),
    ips: nonEmpty(m.ip_any),
    asns: nonEmpty(m.asn_in),
    methods: nonEmpty(m.methods),
    vbot: Boolean(m.verified_bot),
  };
}

// describeCAMatch renders a stored entry's match as one plain-language phrase
// for the table's "Exempts" column and the editor review sentence.
export function describeCAMatch(match) {
  const m = match || {};
  const parts = [];
  if (nonEmpty(m.country_in)) parts.push(`country ∈ ${m.country_in.join(", ")}`);
  if (nonEmpty(m.country_not_in)) parts.push(`country ∉ ${m.country_not_in.join(", ")}`);
  if (nonEmpty(m.asn_in)) parts.push(`ASN ${m.asn_in.map((a) => "AS" + a).join(", ")}`);
  if (nonEmpty(m.ip_any)) parts.push(`IP ${m.ip_any.join(", ")}`);
  if (m.verified_bot) parts.push("verified crawler");
  if (nonEmpty(m.ua_any)) parts.push(`UA ${m.ua_any.join(", ")}`);
  if (nonEmpty(m.path_any)) parts.push(`path ${m.path_any.join(", ")}`);
  if (nonEmpty(m.methods)) parts.push(`method ${m.methods.join(", ")}`);
  if (!parts.length) return "any request (whole vhost)";
  return parts.join(" AND ");
}

// validateCAForm returns { errors, warnings } for the editor — a client-side
// preview of the daemon's normalizer; the server re-validates on save.
export function validateCAForm(form) {
  const errors = [];
  const warnings = [];
  if (!csvSplit(form.vhosts).length) errors.push("At least one vhost is required.");

  const codes = csvSplit(form.countries);
  const badCodes = codes.filter((c) => c.trim().length !== 2);
  if (badCodes.length) errors.push(`Country codes must be 2 letters: ${badCodes.join(", ")}`);

  const badASN = invalidASNTokens(form.asns);
  if (badASN.length) errors.push(`ASN must be a positive number (e.g. AS15169): ${badASN.join(", ")}`);

  const payload = buildCAPayload(form);
  if (!Object.keys(payload.match).length) {
    warnings.push("No conditions — this exempts EVERY request on the selected vhosts from the challenge (like turning the challenge off for the whole vhost).");
  }
  const onlyAsn = Object.keys(payload.match).length === 1 && Array.isArray(payload.match.asn_in);
  if (onlyAsn) {
    warnings.push("ASN alone is broad (clouds host attackers too). Pair it with a path or the verified-crawler condition.");
  }
  return { errors, warnings };
}

// caScopeLabel renders an entry's vhost scope for the list: "Global" when it is
// wildcard-all, else the joined host list.
export function caScopeLabel(vhosts) {
  const a = Array.isArray(vhosts) ? vhosts : [];
  if (!a.length) return "Global";
  if (a.length === 1 && a[0] === "*") return "Global";
  return a.join(", ");
}

function joinList(v) {
  return Array.isArray(v) ? v.join(", ") : "";
}
function nonEmpty(v) {
  return Array.isArray(v) && v.length > 0;
}
