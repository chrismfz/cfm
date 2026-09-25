// Site Cache recipes — pre-canned per-vhost policies, the same front-end-only
// pattern as the Challenge Access recipes: a catalog whose build(vars) emits
// ordinary /api/v1/site-cache/set patches, one per vhost. The set API MERGES,
// so a recipe changes only the tier it names: "Burst shield" on a vhost that
// already caches static assets keeps its static tier.
//
// The recipe name stored with a tier is a label (docs/site-cache-design.md §8):
// what the edge applies is the tier on/off and, for the micro tier, the TTL
// bucket — which is why every micro recipe here sends its TTL explicitly.

import { csvSplit } from "./rules-model.js";
import { canonHost, hostError, MICRO_BUCKETS } from "./site-cache-model.js";

const BUCKET_OPTIONS = Object.freeze(MICRO_BUCKETS.map((b) => `${b}s`));

function hostsOf(v) {
  return csvSplit(v).map((h) => canonHost(h));
}

export const SC_RECIPES = Object.freeze([
  {
    key: "static_assets",
    title: "Cache static assets",
    description:
      "Tier A for css / js / fonts / images: the origin's Cache-Control / Expires decide how long, with a 1 h fallback. The lowest-risk tier and the usual first step.",
    vars: [
      { key: "vhosts", label: "Vhosts", type: "vhosts", required: true, placeholder: "shop.example.com, *.example.com" },
    ],
    warnings: [
      "The static tier does not read request cookies: an origin that serves a per-user .css / .js / image must mark it private or set a cookie on it.",
    ],
    build: (v) => hostsOf(v.vhosts).map((host) => ({ host, static: { enabled: true, recipe: "static_lean" } })),
  },
  {
    key: "burst_shield",
    title: "Burst shield (micro-cache 1 s)",
    description:
      "Tier B at 1 s: absorbs a burst on heavy pages while every visitor still sees a page at most a second old. Anonymous GET/HEAD over HTTPS only; logged-in, cart and admin traffic is never micro-cached.",
    vars: [
      { key: "vhosts", label: "Vhosts", type: "vhosts", required: true, placeholder: "shop.example.com" },
    ],
    warnings: [
      "Where this node has MICRO_CACHE_ENFORCE = 1, pages are served from cache at once; at 0 it is a dry run and the debug stamp only reports what would be cached.",
      "Check that the app's session cookie is on the auth list (built in, or add it in the editor) before enforcing.",
    ],
    build: (v) => hostsOf(v.vhosts).map((host) => ({ host, micro: { enabled: true, recipe: "micro_safe", ttl: "1s" } })),
  },
  {
    key: "near_static",
    title: "Near-static pages (micro-cache 10–60 s)",
    description:
      "Tier B with a longer bucket for pages that rarely change (a landing page, a news front page). Visitors can see a page up to the TTL old; purge after an edit to show it at once.",
    vars: [
      { key: "vhosts", label: "Vhosts", type: "vhosts", required: true, placeholder: "news.example.com" },
      { key: "ttl", label: "TTL", type: "select", required: true, default: "10s", options: ["10s", "30s", "60s"] },
    ],
    warnings: [
      "Where this node has MICRO_CACHE_ENFORCE = 1, pages are served from cache at once; at 0 it is a dry run.",
      "Anything that must change at once (stock, prices, a breaking-news edit) needs a purge, or a shorter bucket.",
    ],
    build: (v) => hostsOf(v.vhosts).map((host) => ({ host, micro: { enabled: true, recipe: "micro_aggressive", ttl: v.ttl } })),
  },
  {
    key: "static_and_burst",
    title: "Static assets + burst shield",
    description: "Both tiers: static assets by the origin's headers, and anonymous pages micro-cached at 1 s.",
    vars: [
      { key: "vhosts", label: "Vhosts", type: "vhosts", required: true, placeholder: "shop.example.com" },
    ],
    warnings: ["Where this node has MICRO_CACHE_ENFORCE = 1, the micro tier serves pages from cache at once; at 0 it is a dry run."],
    build: (v) => hostsOf(v.vhosts).map((host) => ({
      host,
      static: { enabled: true, recipe: "static_lean" },
      micro: { enabled: true, recipe: "micro_safe", ttl: "1s" },
    })),
  },
  {
    key: "opt_out",
    title: "Never cache this host (opt-out)",
    description:
      "Both tiers off, stored as a policy: the host is never cached, even when a wildcard such as *.example.com is armed. Use it for a sub-host that must stay live (an API, a staging site).",
    vars: [
      { key: "vhosts", label: "Vhosts", type: "vhosts", required: true, placeholder: "api.example.com" },
    ],
    warnings: ["While it is off nothing is served from its cache, and turning it on again starts from an empty cache. What a covering wildcard cached for this host is dropped by purging the wildcard."],
    build: (v) => hostsOf(v.vhosts).map((host) => ({ host, static: { enabled: false }, micro: { enabled: false } })),
  },
]);

export function scRecipe(key) {
  return SC_RECIPES.find((r) => r.key === key) || null;
}

// Seed the vars form: each var's default (else ""); vhosts is prefilled from the
// caller's context (the current vhost filter, or a scoped token's vhosts).
export function scRecipeVarsDefaults(rcp, ctx = {}) {
  const out = {};
  for (const v of (rcp && rcp.vars) || []) out[v.key] = v.default != null ? v.default : "";
  if ("vhosts" in out && !out.vhosts && ctx.vhosts) out.vhosts = ctx.vhosts;
  return out;
}

// scRecipeErrors: required vars, every vhost valid (and in scope for a scoped
// token), and a select var holding one of its options.
export function scRecipeErrors(rcp, vars, { inScope = () => true } = {}) {
  const errors = [];
  if (!rcp) return errors;
  const vv = vars || {};
  for (const v of rcp.vars) {
    const raw = vv[v.key] == null ? "" : String(vv[v.key]);
    if (v.required && !csvSplit(raw).length) {
      errors.push(`${v.label} is required.`);
      continue;
    }
    if (v.type === "vhosts") {
      for (const h of csvSplit(raw)) {
        const why = hostError(h);
        if (why) errors.push(`${h}: ${why}.`);
        else if (!inScope(canonHost(h))) errors.push(`${canonHost(h)} is not one of your vhosts.`);
      }
    }
    if (v.type === "select" && raw && !(v.options || []).includes(raw)) errors.push(`${v.label}: pick one of ${(v.options || []).join(", ")}.`);
  }
  return errors;
}

export function scRecipeBuild(rcp, vars, opts) {
  if (!rcp || scRecipeErrors(rcp, vars, opts).length) return [];
  // One patch per distinct host (a vhost listed twice is one write).
  const seen = new Set();
  return rcp.build(vars).filter((p) => (seen.has(p.host) ? false : (seen.add(p.host), true)));
}

export { BUCKET_OPTIONS };
