// node --test internal/webui/static/assets/webdet/challenge-access-recipes.test.js
import test from "node:test";
import assert from "node:assert/strict";
import {
  CA_RECIPES,
  caRecipe,
  caRecipeVarsDefaults,
  caRecipeErrors,
  caRecipeBuild,
  recipeOfEntry,
} from "./challenge-access-recipes.js";

test("recipe keys are unique and non-empty", () => {
  const keys = CA_RECIPES.map((r) => r.key);
  assert.equal(new Set(keys).size, keys.length);
  assert.ok(keys.every((k) => /^[a-z0-9_]+$/.test(k)));
});

test("caRecipeVarsDefaults seeds defaults and vhosts from context", () => {
  const feed = caRecipe("allow_feed_fetchers");
  const v = caRecipeVarsDefaults(feed, { vhosts: "shop.gr" });
  assert.equal(v.vhosts, "shop.gr");
  assert.equal(v.paths, "*/google.xml, */*feed*.xml");
  // A static default (verified crawlers vhosts "*") is not overridden by context.
  const vc = caRecipeVarsDefaults(caRecipe("allow_verified_crawlers"), { vhosts: "shop.gr" });
  assert.equal(vc.vhosts, "*");
});

test("allow_feed_fetchers builds the google-xrawler exemption", () => {
  const rcp = caRecipe("allow_feed_fetchers");
  const out = caRecipeBuild(rcp, { vhosts: "Shop.GR", paths: "*/google.xml" });
  assert.equal(out.length, 1);
  assert.deepEqual(out[0].scope.vhosts, ["shop.gr"]); // lowercased
  assert.deepEqual(out[0].match.asn_in, [15169]);
  assert.deepEqual(out[0].match.path_any, ["*/google.xml"]);
  assert.ok(out[0].note.startsWith("recipe:allow_feed_fetchers"));
  assert.equal(out[0].enabled, true);
});

test("required vars gate the build", () => {
  const rcp = caRecipe("allow_monitor");
  assert.deepEqual(caRecipeErrors(rcp, { vhosts: "a.gr", ips: "" }).length ? "err" : "ok", "err");
  assert.deepEqual(caRecipeBuild(rcp, { vhosts: "a.gr", ips: "" }), []); // no build while invalid
  const ok = caRecipeBuild(rcp, { vhosts: "a.gr", ips: "203.0.113.0/24" });
  assert.deepEqual(ok[0].match.ip_any, ["203.0.113.0/24"]);
});

test("allow_office requires an ASN or a country", () => {
  const rcp = caRecipe("allow_office");
  const errs = caRecipeErrors(rcp, { vhosts: "a.gr" });
  assert.ok(errs.some((e) => /ASN or a country/i.test(e)));
  const out = caRecipeBuild(rcp, { vhosts: "a.gr", asns: "AS64500", paths: "/portal" });
  assert.deepEqual(out[0].match.asn_in, [64500]);
  assert.deepEqual(out[0].match.path_any, ["/portal"]);
});

test("allow_integration_path adds methods only when given", () => {
  const rcp = caRecipe("allow_integration_path");
  const noM = caRecipeBuild(rcp, { vhosts: "a.gr", paths: "/webhook", methods: "" });
  assert.ok(!("methods" in noM[0].match));
  const withM = caRecipeBuild(rcp, { vhosts: "a.gr", paths: "/webhook", methods: "post" });
  assert.deepEqual(withM[0].match.methods, ["POST"]);
});

test("recipeOfEntry recovers the key from the note tag", () => {
  assert.equal(recipeOfEntry({ note: "recipe:allow_monitor — uptime" }), "allow_monitor");
  assert.equal(recipeOfEntry({ note: "manual entry" }), "");
});
