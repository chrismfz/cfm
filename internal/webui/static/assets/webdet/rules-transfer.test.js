// node --test internal/webui/static/assets/webdet/rules-transfer.test.js
import test from "node:test";
import assert from "node:assert/strict";
import {
  EXPORT_FORMAT,
  docVhosts,
  exportFileName,
  exportPath,
  importPath,
  itemTone,
  parseExportFile,
  planSummary,
} from "./rules-transfer.js";

const day = new Date("2026-10-14T23:30:00Z");

test("export file name carries the vhost and the UTC date", () => {
  assert.equal(exportFileName("GoKids.gr", day), "cfm-rules-gokids.gr-2026-10-14.json");
  assert.equal(exportFileName("", day), "cfm-rules-all-2026-10-14.json");
  assert.equal(exportFileName("*.example.com", day), "cfm-rules-example.com-2026-10-14.json");
  assert.equal(exportFileName("../../x", day), "cfm-rules-x-2026-10-14.json");
});

test("paths", () => {
  assert.equal(exportPath(""), "v1/webdet/rules/export");
  assert.equal(exportPath(" gokids.gr "), "v1/webdet/rules/export?vhost=gokids.gr");
  assert.equal(exportPath("a b&c"), "v1/webdet/rules/export?vhost=a%20b%26c");
  assert.equal(importPath(), "v1/webdet/rules/import");
  assert.equal(importPath({ dryRun: true }), "v1/webdet/rules/import?dry_run=1");
  assert.equal(importPath({ dryRun: true, disabled: true }), "v1/webdet/rules/import?dry_run=1&disabled=1");
  assert.equal(importPath({ disabled: true }), "v1/webdet/rules/import?disabled=1");
});

test("parseExportFile accepts an export and refuses anything else", () => {
  const good = { format: EXPORT_FORMAT, version: 1, rules: [{ scope: { vhosts: ["b.gr", "a.gr"] } }, { scope: { vhosts: ["a.gr"] } }] };
  const ok = parseExportFile(JSON.stringify(good));
  assert.equal(ok.error, "");
  assert.deepEqual(docVhosts(ok.doc), ["a.gr", "b.gr"]);
  assert.match(parseExportFile("{nope").error, /Not a JSON file/);
  assert.match(parseExportFile("[]").error, /expected a JSON object/);
  assert.match(parseExportFile("null").error, /expected a JSON object/);
  // A single rule as `cfm webtop rules get` prints it is not an export.
  assert.match(parseExportFile(JSON.stringify({ rule: { id: "r_1" } })).error, /format ""/);
  assert.match(parseExportFile(JSON.stringify({ format: EXPORT_FORMAT, version: 1, rules: [] })).error, /no rules/);
});

test("planSummary only allows a clean plan with something to add", () => {
  assert.equal(planSummary(null).canImport, false);
  const clean = planSummary({ add: 3, duplicates: 0, invalid: 0, items: [] });
  assert.equal(clean.canImport, true);
  assert.equal(clean.tone, "ok");
  const warn = planSummary({ add: 2, duplicates: 1, invalid: 0, items: [{ warnings: ["priority 100 …"] }, {}] });
  assert.equal(warn.canImport, true);
  assert.equal(warn.tone, "warn");
  assert.match(warn.text, /2 rule\(s\) will be added, 1 duplicate\(s\) skipped, 1 with a priority warning/);
  const dupOnly = planSummary({ add: 0, duplicates: 5, invalid: 0, items: [] });
  assert.equal(dupOnly.canImport, false);
  assert.match(dupOnly.text, /All 5 rule\(s\) already exist/);
  const bad = planSummary({ add: 4, duplicates: 0, invalid: 1, error: "1 rule(s) are invalid; nothing was imported", items: [] });
  assert.equal(bad.canImport, false);
  assert.equal(bad.tone, "danger");
  assert.equal(planSummary({ add: 0, error: "not a traffic rules export" }).canImport, false);
});

test("itemTone", () => {
  assert.equal(itemTone("add"), "ok");
  assert.equal(itemTone("invalid"), "danger");
  assert.equal(itemTone("duplicate"), "");
});
