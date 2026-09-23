// node --test internal/webui/static/assets/webdet/site-cache-recipes.test.js
import test from "node:test";
import assert from "node:assert/strict";
import {
  SC_RECIPES,
  scRecipe,
  scRecipeVarsDefaults,
  scRecipeErrors,
  scRecipeBuild,
} from "./site-cache-recipes.js";
import { STATIC_RECIPES, MICRO_RECIPES_OFFERED, isBucketTTL, hostError } from "./site-cache-model.js";

test("recipe keys are unique and non-empty", () => {
  const keys = SC_RECIPES.map((r) => r.key);
  assert.equal(new Set(keys).size, keys.length);
  assert.ok(keys.every((k) => /^[a-z0-9_]+$/.test(k)));
});

test("every recipe builds valid set patches", () => {
  for (const rcp of SC_RECIPES) {
    const vars = scRecipeVarsDefaults(rcp, { vhosts: "Shop.Example.com, *.example.com" });
    assert.deepEqual(scRecipeErrors(rcp, vars), [], rcp.key);
    const patches = scRecipeBuild(rcp, vars);
    assert.deepEqual(patches.map((p) => p.host), ["shop.example.com", "*.example.com"], rcp.key);
    for (const p of patches) {
      assert.equal(hostError(p.host), "", `${rcp.key}: ${p.host}`);
      assert.ok(p.static || p.micro, `${rcp.key}: names a tier`);
      if (p.static && p.static.enabled) assert.ok(STATIC_RECIPES.includes(p.static.recipe), rcp.key);
      if (p.micro && p.micro.enabled) {
        assert.ok(MICRO_RECIPES_OFFERED.includes(p.micro.recipe), rcp.key);
        // A micro recipe always sends its TTL: without one the edge runs 1 s.
        assert.ok(isBucketTTL(p.micro.ttl), `${rcp.key}: ttl ${p.micro.ttl}`);
      }
      // A disabled tier sends no recipe (the stored one is kept for a re-enable).
      for (const t of [p.static, p.micro]) if (t && !t.enabled) assert.deepEqual(t, { enabled: false }, rcp.key);
    }
  }
});

test("a recipe names only its own tier (the set API merges)", () => {
  const burst = scRecipeBuild(scRecipe("burst_shield"), { vhosts: "a.com" });
  assert.deepEqual(burst, [{ host: "a.com", micro: { enabled: true, recipe: "micro_safe", ttl: "1s" } }]);
  const stat = scRecipeBuild(scRecipe("static_assets"), { vhosts: "a.com" });
  assert.deepEqual(stat, [{ host: "a.com", static: { enabled: true, recipe: "static_lean" } }]);
});

test("near_static carries the chosen bucket", () => {
  const rcp = scRecipe("near_static");
  const vars = scRecipeVarsDefaults(rcp, { vhosts: "news.example.com" });
  assert.equal(vars.ttl, "10s");
  assert.equal(scRecipeBuild(rcp, { ...vars, ttl: "30s" })[0].micro.ttl, "30s");
  assert.match(scRecipeErrors(rcp, { ...vars, ttl: "45s" }).join(" "), /pick one of 10s, 30s/);
});

test("errors: required vhosts, an invalid host, a host out of scope", () => {
  const rcp = scRecipe("static_assets");
  assert.match(scRecipeErrors(rcp, { vhosts: "" }).join(" "), /Vhosts is required/);
  assert.match(scRecipeErrors(rcp, { vhosts: "ok.com, *.com" }).join(" "), /\*\.com: a wildcard needs/);
  const scoped = scRecipeErrors(rcp, { vhosts: "mine.com, theirs.com" }, { inScope: (h) => h === "mine.com" });
  assert.deepEqual(scoped, ["theirs.com is not one of your vhosts."]);
  assert.deepEqual(scRecipeBuild(rcp, { vhosts: "*.com" }), [], "an error builds nothing");
});

test("a host listed twice is one write", () => {
  const patches = scRecipeBuild(scRecipe("opt_out"), { vhosts: "api.example.com, API.example.com." });
  assert.deepEqual(patches, [{ host: "api.example.com", static: { enabled: false }, micro: { enabled: false } }]);
});

test("scRecipeVarsDefaults seeds vhosts from context without overriding a default", () => {
  const v = scRecipeVarsDefaults(scRecipe("near_static"), { vhosts: "shop.gr" });
  assert.deepEqual(v, { vhosts: "shop.gr", ttl: "10s" });
  assert.deepEqual(scRecipeVarsDefaults(null), {});
});
