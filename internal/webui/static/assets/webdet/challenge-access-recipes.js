// Challenge-Recipes — pre-canned Challenge Access-Control exemptions, the same
// front-end-only pattern as the traffic-rules RECIPES (rules-model.js): a
// catalog whose build(vars) emits ordinary /api/v1/challenge/access/add
// payloads. Each recipe creates ONE exemption entry (a flat allow-list needs no
// multi-rule ordering), tagged in the note as `recipe:<key>` so it groups in the
// list. Motivating cases come from docs/challenge-access-control.md §5.

import { parseASNs } from "./challenge-access-model.js";
import { csvSplit } from "./rules-model.js";

function vhosts(v) {
  return csvSplit(v).map((h) => h.toLowerCase());
}

export const CA_RECIPES = Object.freeze([
  {
    key: "allow_feed_fetchers",
    title: "Let product-feed fetchers reach feeds",
    description:
      "Exempt Google's feed crawler (google-xrawler, AS15169) on your product-feed paths, so an auto-challenged shop's Merchant feed keeps updating. Pairs the ASN with the feed path so only feed requests are exempted.",
    vars: [
      { key: "vhosts", label: "Vhosts", type: "vhosts", required: true, placeholder: "shop.example.com" },
      { key: "paths", label: "Feed paths", type: "paths", required: true, default: "*/google.xml, */*feed*.xml" },
    ],
    warnings: ["ASN alone is broad; this recipe pairs it with the feed path so only the feed is exempted."],
    build: (v) => [{
      enabled: true,
      scope: { vhosts: vhosts(v.vhosts) },
      match: { asn_in: [15169], path_any: csvSplit(v.paths) },
      note: "recipe:allow_feed_fetchers — Google feed fetcher → product feed",
    }],
  },
  {
    key: "allow_verified_crawlers",
    title: "Let verified search / social crawlers through",
    description:
      "Exempt FCrDNS-verified Googlebot / Bing / Meta crawlers — spoof-proof (what the IP reverse-DNS confirms, not the User-Agent). Non-verifiable bots (DuckDuckGo, Baidu) need a UA or ASN condition instead.",
    vars: [
      { key: "vhosts", label: "Vhosts", type: "vhosts", required: true, default: "*", placeholder: "* (all vhosts)" },
    ],
    warnings: ["Covers only FCrDNS-verifiable crawlers. It also keeps Google's Translate/AMP proxies out of the challenge (they cannot solve one)."],
    build: (v) => [{
      enabled: true,
      scope: { vhosts: vhosts(v.vhosts) },
      match: { verified_bot: true },
      note: "recipe:allow_verified_crawlers — FCrDNS search/social crawlers",
    }],
  },
  {
    key: "allow_monitor",
    title: "Exempt an uptime monitor",
    description:
      "Stop serving the challenge page to your uptime monitor's IP ranges — it cannot solve a JS challenge, so it just loops. Works in DNAT mode too (IP-based).",
    vars: [
      { key: "vhosts", label: "Vhosts", type: "vhosts", required: true, default: "*" },
      { key: "ips", label: "Monitor IPs / ranges", type: "ips", required: true, placeholder: "203.0.113.0/24, 198.51.100.7" },
    ],
    warnings: [],
    build: (v) => [{
      enabled: true,
      scope: { vhosts: vhosts(v.vhosts) },
      match: { ip_any: csvSplit(v.ips) },
      note: "recipe:allow_monitor — uptime / monitoring probe",
    }],
  },
  {
    key: "allow_integration_path",
    title: "Exempt a machine / integration endpoint",
    description:
      "Exempt a webhook or API path a non-browser client hits (it cannot solve a challenge). Add methods to narrow it (e.g. POST only). The WAF stays armed on these paths.",
    vars: [
      { key: "vhosts", label: "Vhosts", type: "vhosts", required: true },
      { key: "paths", label: "Paths", type: "paths", required: true, placeholder: "/wp-json/wc/*, /webhook" },
      { key: "methods", label: "Methods (optional)", type: "methods", required: false, placeholder: "POST" },
    ],
    warnings: ["This only skips the challenge — the WAF rule engine still inspects these paths."],
    build: (v) => {
      const match = { path_any: csvSplit(v.paths) };
      const methods = csvSplit(v.methods).map((m) => m.toUpperCase());
      if (methods.length) match.methods = methods;
      return [{
        enabled: true,
        scope: { vhosts: vhosts(v.vhosts) },
        match,
        note: "recipe:allow_integration_path — machine/integration endpoint",
      }];
    },
  },
  {
    key: "allow_office",
    title: "Exempt an office ASN / country",
    description:
      "Trust a partner network (by ASN) or a country for a scoped set of paths. Provide at least an ASN or a country; add paths to narrow it.",
    vars: [
      { key: "vhosts", label: "Vhosts", type: "vhosts", required: true },
      { key: "asns", label: "ASNs (optional)", type: "asns", required: false, placeholder: "AS64500" },
      { key: "countries", label: "Countries (optional)", type: "countries", required: false, placeholder: "GR, CY" },
      { key: "paths", label: "Paths (optional)", type: "paths", required: false },
    ],
    warnings: ["ASN or country alone is broad; add paths to narrow it. Unknown country/ASN never matches (fail-open)."],
    build: (v) => {
      const match = {};
      const asns = parseASNs(v.asns);
      if (asns.length) match.asn_in = asns;
      const codes = csvSplit(v.countries).map((c) => c.toUpperCase());
      if (codes.length) match.country_in = codes;
      const paths = csvSplit(v.paths);
      if (paths.length) match.path_any = paths;
      return [{
        enabled: true,
        scope: { vhosts: vhosts(v.vhosts) },
        match,
        note: "recipe:allow_office — trusted office/partner network",
      }];
    },
  },
]);

export function caRecipe(key) {
  return CA_RECIPES.find((r) => r.key === key) || null;
}

// Seed the vars form: each var's default (else ""); vhosts is prefilled from the
// caller's context (current vhost filter) when it has no static default.
export function caRecipeVarsDefaults(rcp, ctx = {}) {
  const out = {};
  for (const v of (rcp && rcp.vars) || []) {
    out[v.key] = v.default != null ? v.default : "";
  }
  if ("vhosts" in out && !out.vhosts && ctx.vhosts) out.vhosts = ctx.vhosts;
  return out;
}

export function caRecipeErrors(rcp, vars) {
  const errors = [];
  if (!rcp) return errors;
  for (const v of rcp.vars) {
    if (v.required && !csvSplit((vars && vars[v.key]) || "").length) errors.push(`${v.label} is required.`);
  }
  if (rcp.key === "allow_office") {
    const hasAsn = parseASNs((vars && vars.asns) || "").length > 0;
    const hasCountry = csvSplit((vars && vars.countries) || "").length > 0;
    if (!hasAsn && !hasCountry) errors.push("Provide at least an ASN or a country.");
  }
  return errors;
}

export function caRecipeBuild(rcp, vars) {
  if (!rcp || caRecipeErrors(rcp, vars).length) return [];
  return rcp.build(vars);
}

// recipeOfEntry recovers the recipe key from a stored entry's note tag.
export function recipeOfEntry(entry) {
  const m = /(?:^|\s)recipe:([a-z0-9_]+)/i.exec((entry && entry.note) || "");
  return m ? m[1] : "";
}
