// node --test internal/webui/static/assets/webdet/challenge-access-model.test.js
//
// Mirrors internal/webdetector/challenge_access.go: the payload the builder
// sends must match the entry shape the daemon normalizes/enforces.
import test from "node:test";
import assert from "node:assert/strict";
import {
  emptyCAForm,
  parseASNs,
  invalidASNTokens,
  buildCAPayload,
  caFormFromEntry,
  dimensionsPresent,
  describeCAMatch,
  validateCAForm,
  caScopeLabel,
} from "./challenge-access-model.js";

test("parseASNs strips AS prefix and drops junk", () => {
  assert.deepEqual(parseASNs("AS15169, 8075, as714"), [15169, 8075, 714]);
  assert.deepEqual(parseASNs("AS0, -1, foo, "), []);
  assert.deepEqual(invalidASNTokens("AS15169, foo, 0"), ["foo", "0"]);
});

test("buildCAPayload maps dimensions and omits empties", () => {
  const f = emptyCAForm();
  f.vhosts = "shop.gr, www.shop.gr";
  f.paths = "*/google.xml";
  f.asns = "AS15169";
  f.enabled = true;
  const p = buildCAPayload(f);
  assert.deepEqual(p.scope.vhosts, ["shop.gr", "www.shop.gr"]);
  assert.deepEqual(p.match.path_any, ["*/google.xml"]);
  assert.deepEqual(p.match.asn_in, [15169]);
  assert.equal(p.enabled, true);
  // Untouched dimensions are absent, not empty arrays.
  assert.ok(!("country_in" in p.match));
  assert.ok(!("ip_any" in p.match));
  assert.ok(!("verified_bot" in p.match));
});

test("buildCAPayload country mode is mutually exclusive", () => {
  const f = emptyCAForm();
  f.vhosts = "a.gr";
  f.countries = "GR, CY";
  f.countriesMode = "not_in";
  const p = buildCAPayload(f);
  assert.deepEqual(p.match.country_not_in, ["GR", "CY"]);
  assert.ok(!("country_in" in p.match));
});

test("verified_bot only when checked", () => {
  const f = emptyCAForm();
  f.vhosts = "a.gr";
  f.verifiedBot = true;
  assert.equal(buildCAPayload(f).match.verified_bot, true);
  f.verifiedBot = false;
  assert.ok(!("verified_bot" in buildCAPayload(f).match));
});

test("empty match = whole-vhost exemption (no match keys)", () => {
  const f = emptyCAForm();
  f.vhosts = "a.gr";
  assert.deepEqual(buildCAPayload(f).match, {});
});

test("caFormFromEntry round-trips an entry", () => {
  const entry = {
    id: "ca_1",
    enabled: false,
    scope: { vhosts: ["shop.gr"] },
    match: { asn_in: [15169], path_any: ["/*/google.xml"], country_not_in: ["RU"] },
    note: "feed",
  };
  const f = caFormFromEntry(entry);
  assert.equal(f.enabled, false);
  assert.equal(f.vhosts, "shop.gr");
  assert.equal(f.asns, "15169");
  assert.equal(f.paths, "/*/google.xml");
  assert.equal(f.countries, "RU");
  assert.equal(f.countriesMode, "not_in");
  assert.equal(f.note, "feed");
  const present = dimensionsPresent(entry);
  assert.equal(present.asns, true);
  assert.equal(present.paths, true);
  assert.equal(present.countries, true);
  assert.equal(present.ips, false);
});

test("describeCAMatch renders conditions or whole-vhost", () => {
  assert.equal(describeCAMatch({}), "any request (whole vhost)");
  const s = describeCAMatch({ asn_in: [15169], path_any: ["*/google.xml"] });
  assert.ok(s.includes("AS15169"));
  assert.ok(s.includes("AND"));
});

test("validateCAForm flags missing vhost, bad codes, bad ASN, whole-vhost", () => {
  const bad = emptyCAForm();
  bad.countries = "GRE";
  bad.asns = "foo";
  const v = validateCAForm(bad);
  assert.ok(v.errors.some((e) => /vhost/i.test(e)));
  assert.ok(v.errors.some((e) => /2 letters/i.test(e)));
  assert.ok(v.errors.some((e) => /ASN/i.test(e)));

  const whole = emptyCAForm();
  whole.vhosts = "a.gr";
  const vw = validateCAForm(whole);
  assert.equal(vw.errors.length, 0);
  assert.ok(vw.warnings.some((w) => /EVERY request/i.test(w)));
});

test("buildCAPayload lowercases vhosts", () => {
  const f = emptyCAForm();
  f.vhosts = "Shop.GR, WWW.Shop.GR";
  assert.deepEqual(buildCAPayload(f).scope.vhosts, ["shop.gr", "www.shop.gr"]);
});

test("round-trip preserves unmodeled match keys (no silent broadening)", () => {
  const entry = {
    id: "ca_qs",
    enabled: true,
    scope: { vhosts: ["shop.gr"] },
    match: { path_any: ["/x"], qs_not_rx: "(?:fbclid)(?:=|$)", has_qs: true },
  };
  const form = caFormFromEntry(entry);
  // The form does not model qs — but a toggle/edit must not drop it.
  const rebuilt = buildCAPayload(form);
  assert.equal(rebuilt.match.qs_not_rx, "(?:fbclid)(?:=|$)");
  assert.equal(rebuilt.match.has_qs, true);
  assert.deepEqual(rebuilt.match.path_any, ["/x"]);
});

test("validateCAForm rejects non-letter country codes", () => {
  const f = emptyCAForm();
  f.vhosts = "a.gr";
  f.countries = "G1, 12";
  assert.ok(validateCAForm(f).errors.some((e) => /2 letters/i.test(e)));
});

test("caScopeLabel shows Global for wildcard-all", () => {
  assert.equal(caScopeLabel([]), "Global");
  assert.equal(caScopeLabel(["*"]), "Global");
  assert.equal(caScopeLabel(["shop.gr"]), "shop.gr");
});
