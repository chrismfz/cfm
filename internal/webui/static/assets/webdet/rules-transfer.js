// Traffic rules export / import (moving a site's rules between nodes).
//
// Pure helpers for feature-rules.js. The daemon owns every rule decision
// (validation, duplicates, scope, the all-or-nothing write —
// traffic_rules_transfer.go); this module only names the download, reads the
// chosen file and summarises the daemon's import plan for the page.

export const EXPORT_FORMAT = "cfm-traffic-rules";

// exportFileName → cfm-rules-<vhost|all>-<YYYY-MM-DD>.json (UTC date).
export function exportFileName(vhost, now = new Date()) {
  const raw = String(vhost || "").trim().toLowerCase();
  const slug = raw ? raw.replace(/[^a-z0-9.-]+/g, "_").replace(/^[._-]+|[._-]+$/g, "") : "";
  return `cfm-rules-${slug || "all"}-${now.toISOString().slice(0, 10)}.json`;
}

// exportPath builds the export URL for the vhost filter ("" = every rule the
// caller can list).
export function exportPath(vhost) {
  const v = String(vhost || "").trim();
  return v ? `v1/webdet/rules/export?vhost=${encodeURIComponent(v)}` : "v1/webdet/rules/export";
}

// importPath builds the import URL.
export function importPath({ dryRun = false, disabled = false } = {}) {
  const q = [];
  if (dryRun) q.push("dry_run=1");
  if (disabled) q.push("disabled=1");
  return q.length ? `v1/webdet/rules/import?${q.join("&")}` : "v1/webdet/rules/import";
}

// parseExportFile reads the text of a chosen file. It only catches what the
// page can say better than the daemon (not JSON, not an export at all); the
// daemon validates the rest. Returns { doc, error }.
export function parseExportFile(text) {
  let doc;
  try {
    doc = JSON.parse(String(text || ""));
  } catch (err) {
    return { doc: null, error: `Not a JSON file: ${err.message}` };
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    return { doc: null, error: "Not a traffic rules export (expected a JSON object)." };
  }
  if (doc.format !== EXPORT_FORMAT) {
    return { doc: null, error: `Not a traffic rules export (format "${doc.format ?? ""}", expected "${EXPORT_FORMAT}"). Export it from Traffic Rules → Export / Import or with "cfm webtop rules export".` };
  }
  if (!Array.isArray(doc.rules) || doc.rules.length === 0) {
    return { doc: null, error: "The export contains no rules." };
  }
  return { doc, error: "" };
}

// docVhosts lists the vhosts the document's rules are scoped to.
export function docVhosts(doc) {
  const out = new Set();
  for (const r of doc?.rules || []) for (const v of r?.scope?.vhosts || []) out.add(String(v));
  return [...out].sort();
}

// planSummary turns the daemon's plan into the page's one-line verdict.
// canImport is true only for a clean plan with something to add.
export function planSummary(plan) {
  if (!plan) return { text: "", tone: "", canImport: false };
  const add = Number(plan.add) || 0;
  const dup = Number(plan.duplicates) || 0;
  const bad = Number(plan.invalid) || 0;
  const warn = (plan.items || []).filter((it) => (it.warnings || []).length).length;
  if (plan.error) {
    return { text: plan.error, tone: "danger", canImport: false };
  }
  if (bad) {
    return { text: `${bad} rule(s) are invalid; nothing can be imported.`, tone: "danger", canImport: false };
  }
  if (!add) {
    if (!dup) return { text: "Nothing to import.", tone: "", canImport: false };
    const differ = warn ? ` ${warn} of them differ here (disabled or another priority): see the warnings.` : "";
    return { text: `All ${dup} rule(s) already exist on this node; nothing to import.${differ}`, tone: warn ? "warn" : "", canImport: false };
  }
  const parts = [`${add} rule(s) will be added`];
  if (dup) parts.push(`${dup} duplicate(s) skipped`);
  if (warn) parts.push(`${warn} with a warning`);
  return { text: `${parts.join(", ")}.`, tone: warn ? "warn" : "ok", canImport: true };
}

export function itemTone(status) {
  if (status === "add") return "ok";
  if (status === "invalid") return "danger";
  return "";
}
