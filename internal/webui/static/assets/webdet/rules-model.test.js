// node --test internal/webui/static/assets/webdet/rules-model.test.js
import test from "node:test";
import assert from "node:assert/strict";
import {
  ACTIONS,
  BOT_GROUPS,
  PRIORITY_BANDS,
  LIMITS,
  RECIPES,
  PROBE_PATHS,
  WRITE_METHODS,
  BOT_QS_PASSTHROUGH,
  THROTTLE_PROFILES,
  UA_ALLOW_ALONGSIDE_VERIFIED,
  UNVERIFIABLE_BOT_UAS,
  VERIFIED_BOT_LABEL,
  VERIFIED_BOT_NAMES,
  VERIFIED_BOT_UA_GLOBS,
  botGroup,
  buildRulePayload,
  byteLen,
  describeMatch,
  describeRule,
  emptyForm,
  formFromRule,
  hostPatternMatch,
  isIPOrCIDR,
  pathPatternMatches,
  positionText,
  priorityTie,
  recipe,
  re2Rejects,
  recipeOf,
  recipeVarsDefaults,
  shadowingRules,
  simulateInputFromRule,
  suggestPriority,
  validateRecipeVars,
  validateRuleForm,
  vhostPatternsOverlap,
} from "./rules-model.js";

const baseRules = [
  { id: "r_a", priority: 10, scope: { vhosts: ["example.com"] }, match: { ua_any: ["*Googlebot*"] }, action: { type: "allow" }, note: "recipe:geo_fence — bots" },
  { id: "r_b", priority: 20, scope: { vhosts: ["example.com"] }, match: { country_in: ["GR", "CY"] }, action: { type: "allow" } },
  { id: "r_c", priority: 900, scope: { vhosts: ["example.com"] }, match: {}, action: { type: "block" }, enabled: false },
];

test("buildRulePayload mirrors server normalisation (upper-case, leading slash, profile only for throttle)", () => {
  const p = buildRulePayload(emptyForm({
    actionType: "Block", vhosts: "Example.com, *.example.com", countries: "gr, cy", methods: "post", paths: "xmlrpc.php, /wp-login.php",
    throttleProfile: "hard_bot", hasQS: false, qsNotRx: "fbclid", priority: 42.7, enabled: true,
  }));
  assert.deepEqual(p.scope.vhosts, ["example.com", "*.example.com"]);
  assert.deepEqual(p.match.country_in, ["GR", "CY"]);
  assert.deepEqual(p.match.methods, ["POST"]);
  assert.deepEqual(p.match.path_any, ["/xmlrpc.php", "/wp-login.php"]);
  assert.equal(p.match.qs_not_rx, "fbclid", "pass-through is kept even without has_qs (the daemon applies it independently)");
  assert.equal(p.match.has_qs, false);
  assert.equal(p.action.type, "block");
  assert.equal(p.action.profile, "");
  assert.equal(p.priority, 42);
  assert.equal(p.enabled, true);
});

test("formFromRule → buildRulePayload round-trips a stored rule", () => {
  const row = {
    id: "r_x", enabled: true, priority: 120, scope: { vhosts: ["shop.example.com"] },
    match: { country_in: ["US"], ua_any: ["*curl*"], path_any: ["/api/"], methods: ["GET"], has_qs: true, qs_not_rx: "fbclid" },
    action: { type: "throttle", profile: "medium_bot" }, note: "n",
  };
  const p = buildRulePayload(formFromRule(row));
  assert.deepEqual(p.scope, row.scope);
  assert.deepEqual(p.match, { ...row.match, country_not_in: [], ip_any: [], verified_bot: false });
  assert.deepEqual(p.action, row.action);
  assert.equal(p.note, "n");
  assert.equal(p.priority, 120);
});

test("validateRuleForm: vhost check stays permissive (IDN / underscore ok) but rejects URLs", () => {
  const ok = validateRuleForm(emptyForm({ actionType: "block", vhosts: "my_site.local, ξύλο.gr, *.example.com", uas: "*x*" }));
  assert.equal(ok.errors.length, 0, ok.errors.join(" | "));
  const bad = validateRuleForm(emptyForm({ actionType: "block", vhosts: "https://a.com/", uas: "*x*" }));
  assert.ok(bad.errors.some((e) => /is not a hostname/.test(e)));
});

test("validateRuleForm: missing action / vhost / bad country / unknown profile are errors", () => {
  const v = validateRuleForm(emptyForm({ countries: "GRE, C", methods: "GET" }));
  assert.ok(v.errors.some((e) => /Choose what should happen/.test(e)));
  assert.ok(v.errors.some((e) => /At least one vhost/.test(e)));
  assert.ok(v.errors.some((e) => /"GRE" is not a 2-letter/.test(e)));
  assert.ok(v.errors.some((e) => /"C" is not a 2-letter/.test(e)));

  const t = validateRuleForm(emptyForm({ actionType: "throttle", throttleProfile: "turbo", vhosts: "a.com", uas: "*x*" }));
  assert.ok(t.errors.some((e) => /Unknown throttle profile "turbo"/.test(e)));
});

test("validateRuleForm: an ENABLED block with no conditions is an error, a disabled one a warning", () => {
  const on = validateRuleForm(emptyForm({ actionType: "block", vhosts: "a.com", enabled: true }));
  assert.ok(on.errors.some((e) => /EVERY request on a.com/.test(e)));
  const off = validateRuleForm(emptyForm({ actionType: "block", vhosts: "a.com", enabled: false }));
  assert.equal(off.errors.length, 0);
  assert.ok(off.warnings.some((w) => /matches EVERY request/.test(w)));
});

test("validateRuleForm: allow carries the 'does not bypass' caveat; UA-based allow warns about spoofing", () => {
  const v = validateRuleForm(emptyForm({ actionType: "allow", vhosts: "a.com", uas: "*Googlebot*", methods: "GET" }));
  assert.equal(v.errors.length, 0);
  assert.ok(v.hints.some((h) => /Does NOT bypass the WAF/.test(h)));
  assert.ok(v.hints.some((h) => /client-controlled/.test(h)));
});

test("validateRuleForm: priority tie with an existing rule on the same vhost warns; invalid regex errors", () => {
  const tie = validateRuleForm(emptyForm({ actionType: "challenge", vhosts: "example.com", paths: "/x", priority: 20 }), { rules: baseRules });
  assert.ok(tie.warnings.some((w) => /Priority 20 is already used by r_b/.test(w)));
  const rx = validateRuleForm(emptyForm({ actionType: "block", vhosts: "a.com", hasQS: true, qsNotRx: "(" }));
  assert.ok(rx.warnings.some((w) => /could not be parsed/.test(w)), "JS parse failure is a warning: the daemon validates as Go RE2");
  const rxLimit = validateRuleForm(emptyForm({ actionType: "block", vhosts: "a.com", uas: Array.from({ length: LIMITS.patternsPerField + 1 }, (_, i) => `*bot${i}*`).join(",") }));
  assert.ok(rxLimit.errors.some((e) => /UA patterns: too many/.test(e)));
});

test("suggestPriority uses the action band and skips taken slots on overlapping vhosts", () => {
  assert.equal(suggestPriority("allow", [], ["a.com"]), 50);
  const rules = [{ priority: 50, scope: { vhosts: ["a.com"] } }, { priority: 51, scope: { vhosts: ["a.com"] } }, { priority: 52, scope: { vhosts: ["other.com"] } }];
  assert.equal(suggestPriority("allow", rules, ["a.com"]), 52); // other.com does not overlap
  assert.equal(suggestPriority("block", rules, ["a.com"]), 350);
  assert.equal(suggestPriority("nonsense"), 100);
});

test("positionText names the neighbours and flags a tie", () => {
  assert.match(positionText(15, baseRules, { vhosts: ["example.com"] }), /^Runs after #10 \(allow .*\) and before #20/);
  assert.match(positionText(20, baseRules, { vhosts: ["example.com"] }), /ties with #20/);
  assert.match(positionText(5, baseRules, { vhosts: ["example.com"] }), /^Before #10/);
  assert.equal(positionText(5, [], { vhosts: ["example.com"] }), "This will be the only rule for these vhosts.");
  // excludeId: editing r_b itself must not tie with itself
  assert.doesNotMatch(positionText(20, baseRules, { vhosts: ["example.com"], excludeId: "r_b" }), /ties/);
});

test("describeMatch / describeRule read like English and collapse bot groups", () => {
  assert.equal(describeMatch({}), "every request");
  assert.equal(describeMatch({ methods: ["POST"], path_any: ["/xmlrpc.php"] }), "POST requests to /xmlrpc.php");
  assert.equal(describeMatch({ country_in: ["CN", "RU"] }), "requests from CN, RU");
  const search = BOT_GROUPS.find((g) => g.key === "search").patterns;
  assert.equal(describeMatch({ ua_any: [...search, "*Foo*"] }), "requests with a User-Agent matching search engines, Foo");
  assert.equal(describeMatch({ ua_any: ["-"] }), "requests with a User-Agent matching no User-Agent at all");
  assert.equal(describeMatch({ has_qs: true, qs_not_rx: "fbclid" }), "requests that carry a query string (except when the query matches /fbclid/)");
  assert.equal(
    describeRule({ scope: { vhosts: ["ksilokosmos.gr"] }, match: { methods: ["POST"], path_any: ["/ws_vtrack/json_v2.php"] }, action: { type: "allow" } }),
    "On ksilokosmos.gr: allow POST requests to /ws_vtrack/json_v2.php.",
  );
  assert.equal(
    describeRule({ scope: { vhosts: ["a.com"] }, match: { ua_any: ["*curl*"] }, action: { type: "throttle", profile: "hard_bot" } }),
    "On a.com: throttle (hard_bot — 0.5 req/s, burst 5) requests with a User-Agent matching curl.",
  );
  assert.equal(describeMatch({ country_in: ["A", "B", "C", "D", "E"] }), "requests from A, B, C +2 more");
});

test("simulateInputFromRule builds a request the rule matches (glob → concrete, /p?q split)", () => {
  const s = simulateInputFromRule({
    scope: { vhosts: ["*.example.com"] },
    match: { path_any: ["/forum/ucp.php?mode=register"], methods: ["POST"], country_in: ["US"], ua_any: ["*GPTBot*"] },
  });
  assert.deepEqual(s, { host: "www.example.com", ip: "", ua: "GPTBot", path: "/forum/ucp.php", method: "POST", country: "US", qs: "mode=register", verifiedBot: "" });
  const e = simulateInputFromRule({ scope: { vhosts: ["a.com"] }, match: { ua_any: ["-"], has_qs: true } });
  assert.equal(e.ua, "", "a '-' rule is tested with an EMPTY UA, which is what the edge sends");
  assert.equal(e.qs, "page=2");
  assert.equal(e.path, "/");
});

test("recipes: every multi recipe is ordered by priority, tagged, and only enables low-collateral rules", () => {
  for (const rcp of RECIPES.filter((r) => r.kind !== "link")) {
    const vars = recipeVarsDefaults(rcp, { vhosts: "a.com" });
    if (rcp.key === "block_scraper") vars.uas = "*Evil*";
    if (rcp.key === "allow_office_ips") vars.ips = "203.0.113.0/24";
    assert.equal(validateRecipeVars(rcp, vars).length, 0, `${rcp.key} defaults validate`);
    const rules = rcp.build(vars);
    assert.ok(rules.length >= 1, rcp.key);
    for (let i = 1; i < rules.length; i += 1) assert.ok(rules[i - 1].priority < rules[i].priority, `${rcp.key} ordered`);
    const scopesOwnVhosts = rcp.vars.some((v) => v.key === "vhosts");
    for (const r of rules) {
      assert.equal(recipeOf(r), rcp.key);
      if (scopesOwnVhosts) assert.deepEqual(r.scope.vhosts, ["a.com"]);
      else assert.ok(r.scope.vhosts.length >= 1, `${rcp.key}: every rule is scoped`);
      assert.ok(byteLen(r.note) <= LIMITS.noteLen, `${rcp.key}: note fits (bytes, like the daemon)`);
      // every built rule passes the same validation the editor applies
      const v = validateRuleForm(formFromRule(r));
      assert.deepEqual(v.errors, [], `${rcp.key}: ${v.errors.join(" | ")}`);
      // An enabled block must be keyed on something a bystander never sends:
      // a User-Agent pattern or a probe path. Country / catch-all blocks and
      // challenges start disabled ("validate first").
      const keyed = r.match.ua_any.length || r.match.path_any.length;
      if (r.action.type === "block" && !keyed) assert.equal(r.enabled, false, `${rcp.key}: catch-all block must start disabled`);
      if (r.action.type === "block" && (r.match.country_in.length || r.match.country_not_in.length)) assert.equal(r.enabled, false, `${rcp.key}: geo block must start disabled`);
      if (r.action.type === "challenge") assert.equal(r.enabled, false, `${rcp.key}: challenge must start disabled`);
      if (r.action.type === "block" && r.match.ua_any.includes("-")) assert.equal(r.enabled, false, `${rcp.key}: no-UA block must start disabled (monitors)`);
    }
  }
});

test("geo_fence: verified crawlers → (office IPs) → disabled block of everyone outside", () => {
  const rcp = recipe("geo_fence");
  const rules = rcp.build({ vhosts: "shop.gr, www.shop.gr", countries: "gr, cy", ips: "" });
  assert.equal(rules.length, 3);
  assert.equal(rules[0].action.type, "allow");
  assert.equal(rules[0].match.verified_bot, true, "crawlers are allowed by FCrDNS, not by UA");
  assert.deepEqual(rules[0].match.ua_any, []);
  // the bots FCrDNS cannot verify keep a (weaker, UA-based) allow of their own
  assert.equal(rules[1].action.type, "allow");
  assert.deepEqual(rules[1].match.ua_any, [...UA_ALLOW_ALONGSIDE_VERIFIED]);
  assert.ok(UNVERIFIABLE_BOT_UAS.includes("*Twitterbot*") && UNVERIFIABLE_BOT_UAS.includes("*DuckDuckBot*"));
  assert.ok(!UNVERIFIABLE_BOT_UAS.includes("*Googlebot*") && !UNVERIFIABLE_BOT_UAS.includes("*facebookexternalhit*"));
  // Meta previews are one-shot from a huge fleet: kept in the UA allow on purpose; Googlebot is not.
  assert.ok(UA_ALLOW_ALONGSIDE_VERIFIED.includes("*facebookexternalhit*") && UA_ALLOW_ALONGSIDE_VERIFIED.includes("*meta-externalagent*"));
  assert.ok(!UA_ALLOW_ALONGSIDE_VERIFIED.includes("*Googlebot*") && !UA_ALLOW_ALONGSIDE_VERIFIED.includes("*bingbot*"));
  assert.equal(rules[2].action.type, "block");
  assert.deepEqual(rules[2].match.country_not_in, ["GR", "CY"]);
  assert.deepEqual(rules[2].match.country_in, []);
  assert.equal(rules[2].enabled, false);
  assert.deepEqual(rules[2].scope.vhosts, ["shop.gr", "www.shop.gr"]);

  const withIPs = rcp.build({ vhosts: "shop.gr", countries: "GR", ips: "203.0.113.0/24, 2001:db8::/48" });
  assert.equal(withIPs.length, 4);
  assert.equal(withIPs[2].action.type, "allow");
  assert.deepEqual(withIPs[2].match.ip_any, ["203.0.113.0/24", "2001:db8::/48"]);
  for (let i = 1; i < withIPs.length; i += 1) assert.ok(withIPs[i - 1].priority < withIPs[i].priority);
});

test("geo_fence_admin is one country_not_in rule honouring action and paths", () => {
  const rules = recipe("geo_fence_admin").build({ vhosts: "a.com", countries: "GR", paths: "admin/", action: "block" });
  assert.equal(rules.length, 1);
  assert.deepEqual(rules[0].match.path_any, ["/admin/"]);
  assert.deepEqual(rules[0].match.country_not_in, ["GR"]);
  assert.equal(rules[0].action.type, "block");
  assert.equal(rules[0].enabled, false);
  const ch = recipe("geo_fence_admin").build({ vhosts: "a.com", countries: "GR" });
  assert.equal(ch[0].action.type, "challenge");
  assert.ok(ch[0].priority < rules[0].priority, "challenge band precedes block band");
});

test("block_geedo blocks the Geedo shop scraper by UA, created disabled", () => {
  const rules = recipe("block_geedo").build({ vhosts: "shop.gr" });
  assert.equal(rules.length, 1);
  assert.equal(rules[0].action.type, "block");
  assert.deepEqual(rules[0].match.ua_any, ["*GeedoShopProductFinder*"]);
  assert.equal(rules[0].enabled, false, "block starts disabled — validate first");
  assert.deepEqual(rules[0].scope.vhosts, ["shop.gr"]);
});

test("country mode + ip_any: payload, round-trip, description, sample request", () => {
  const p = buildRulePayload(emptyForm({ actionType: "block", vhosts: "a.com", countries: "gr, cy", countriesMode: "not_in", ips: "203.0.113.0/24, 2001:db8::/48" }));
  assert.deepEqual(p.match.country_in, []);
  assert.deepEqual(p.match.country_not_in, ["GR", "CY"]);
  assert.deepEqual(p.match.ip_any, ["203.0.113.0/24", "2001:db8::/48"]);
  const f = formFromRule({ match: { country_not_in: ["GR"], ip_any: ["198.51.100.7/32"] }, scope: { vhosts: ["a.com"] }, action: { type: "allow" } });
  assert.equal(f.countriesMode, "not_in");
  assert.equal(f.countries, "GR");
  assert.equal(f.ips, "198.51.100.7/32");
  assert.equal(describeMatch({ country_not_in: ["GR", "CY"] }), "requests from outside GR, CY");
  assert.equal(describeMatch({ ip_any: ["203.0.113.0/24"], methods: ["GET"] }), "GET requests from IP 203.0.113.0/24");
  const sim = simulateInputFromRule({ scope: { vhosts: ["a.com"] }, match: { country_not_in: ["US", "DE"], ip_any: ["203.0.113.0/24"] } });
  assert.equal(sim.ip, "203.0.113.1");
  assert.equal(sim.country, "CN");
  assert.equal(simulateInputFromRule({ scope: { vhosts: ["a.com"] }, match: { ip_any: ["2001:db8::/48"] } }).ip, "2001:db8::1");
  assert.equal(simulateInputFromRule({ scope: { vhosts: ["a.com"] }, match: { ip_any: ["198.51.100.7/32"] } }).ip, "198.51.100.7");
  const v = validateRuleForm(emptyForm({ actionType: "block", vhosts: "a.com", countries: "GR", countriesMode: "not_in" }));
  assert.equal(v.errors.length, 0);
  assert.ok(v.hints.some((h) => /do NOT match/.test(h)), "unknown country is fail-open");
  const bad = validateRuleForm(emptyForm({ actionType: "allow", vhosts: "a.com", ips: "203.0.113.0/33, example.com" }));
  assert.equal(bad.errors.filter((e) => /not an IPv4\/IPv6/.test(e)).length, 2);
});

test("isIPOrCIDR accepts what normalizeIPList accepts", () => {
  for (const ok of ["203.0.113.0/24", "198.51.100.7", "0.0.0.0/0", "2001:db8::/48", "2001:db8::1", "::1", "::", "::ffff:203.0.113.9", "::ffff:203.0.113.0/120", "::ffff:c0a8:1/96", "0:0:0:0:0:ffff:1.2.3.4/120", "fe80::1/128", "1:2:3:4:5:6:7:8", "::1.2.3.4", "::1.2.3.4/64"]) {
    assert.equal(isIPOrCIDR(ok), true, ok);
  }
  for (const bad of ["203.0.113.0/33", "256.1.1.1", "1.2.3", "2001:db8::/129", "2001:db8:::1", "1:2:3:4:5:6:7:8:9", "example.com", "", "1.2.3.4/24/1", "gggg::1",
    "01.2.3.4", "1.2.3.4/024", "1.2.3.4::1", "1.2.3.4::", "a:b:1.2.3.4::", "::ffff:1.2.3.4/64", "::ffff:c0a8:1/64", "0:0:0:0:0:ffff:1.2.3.4/64"]) {
    assert.equal(isIPOrCIDR(bad), false, bad);
  }
});

test("validateRecipeVars: required + country shape", () => {
  const rcp = recipe("geo_fence");
  assert.ok(validateRecipeVars(rcp, { vhosts: "", countries: "GR" }).some((e) => /Vhosts is required/.test(e)));
  assert.ok(validateRecipeVars(rcp, { vhosts: "a.com", countries: "Greece" }).some((e) => /not a 2-letter/.test(e)));
  const many = Array.from({ length: LIMITS.patternsPerField + 1 }, (_, i) => `203.0.${i}.0/24`).join(", ");
  assert.ok(validateRecipeVars(rcp, { vhosts: "a.com", countries: "GR", ips: many }).some((e) => /too many entries/.test(e)));
});

test("static tables are consistent", () => {
  assert.deepEqual(ACTIONS.map((a) => a.key), ["allow", "block", "challenge", "throttle"]);
  assert.deepEqual(THROTTLE_PROFILES.map((p) => p.key), ["soft_bot", "medium_bot", "hard_bot"]);
  assert.ok(RECIPES.some((r) => r.kind === "link" && /exclude/i.test(r.title + r.description)));
  assert.equal(recipeOf({ note: "hand-written" }), "");
  assert.equal(recipeOf({ note: "recipe:tame_bots — x" }), "tame_bots");
});

test("qs_not_rx validation follows Go RE2, not JavaScript", () => {
  const goFlags = validateRuleForm(emptyForm({ actionType: "block", vhosts: "a.com", hasQS: true, qsNotRx: "(?i)fbclid" }));
  assert.equal(goFlags.errors.length, 0, "a leading Go inline-flag group is valid");
  const look = validateRuleForm(emptyForm({ actionType: "block", vhosts: "a.com", hasQS: true, qsNotRx: "(?=fbclid)" }));
  assert.ok(look.errors.some((e) => /lookahead/.test(e)));
  const backref = validateRuleForm(emptyForm({ actionType: "block", vhosts: "a.com", hasQS: true, qsNotRx: "(a)\\1" }));
  assert.ok(backref.errors.some((e) => /backreferences/.test(e)));
  const escaped = validateRuleForm(emptyForm({ actionType: "block", vhosts: "a.com", hasQS: true, qsNotRx: "a\\\\1" }));
  assert.equal(escaped.errors.length, 0, "an escaped backslash followed by a digit is not a backreference");
  const broken = validateRuleForm(emptyForm({ actionType: "block", vhosts: "a.com", hasQS: true, qsNotRx: "(" }));
  assert.equal(broken.errors.length, 0);
  assert.ok(broken.warnings.some((w) => /could not be parsed/.test(w)));
});

test("vhost overlap mirrors ruleHostMatch: *.suffix only overlaps its own domain", () => {
  assert.equal(hostPatternMatch("*.shop-a.gr", "www.shop-a.gr"), true);
  assert.equal(hostPatternMatch("*.shop-a.gr", "shop-a.gr"), false);
  assert.equal(hostPatternMatch("*.shop-a.gr", "blog-b.com"), false);
  assert.equal(hostPatternMatch("a.com", "a.com"), true);
  // filepath.Match semantics: `*` crosses dots, `?` is one char, classes work
  assert.equal(hostPatternMatch("*example.com", "www.example.com"), true);
  assert.equal(hostPatternMatch("shop*.gr", "shop.foo.gr"), true);
  assert.equal(hostPatternMatch("[ab].example.com", "a.example.com"), true);
  assert.equal(hostPatternMatch("[ab].example.com", "c.example.com"), false);
  assert.equal(hostPatternMatch("w?w.a.com", "www.a.com"), true);
  assert.equal(hostPatternMatch("[x.a.com", "x.a.com"), false);
  const wild = [{ id: "r_g", priority: 50, scope: { vhosts: ["*example.com"] }, action: { type: "allow" }, match: {} }];
  assert.equal(priorityTie(50, ["www.example.com"], wild)?.id, "r_g");
  assert.equal(suggestPriority("allow", wild, ["www.example.com"]), 51);
  assert.equal(vhostPatternsOverlap("*.shop-a.gr", "blog-b.com"), false);
  assert.equal(vhostPatternsOverlap("*.shop-a.gr", "x.shop-a.gr"), true);
  assert.equal(vhostPatternsOverlap("*.shop-a.gr", "*.eu.shop-a.gr"), true);
  assert.equal(vhostPatternsOverlap("*.shop-a.gr", "*.other.gr"), false);
  // guidance for blog-b.com is not driven by a *.shop-a.gr rule
  const rules = [{ id: "r_w", priority: 50, scope: { vhosts: ["*.shop-a.gr"] }, action: { type: "allow" }, match: {} }];
  assert.equal(suggestPriority("allow", rules, ["blog-b.com"]), 50);
  assert.equal(priorityTie(50, ["blog-b.com"], rules), null);
  assert.equal(priorityTie(50, ["www.shop-a.gr"], rules)?.id, "r_w");
  assert.equal(priorityTie(50, ["www.shop-a.gr"], rules, "r_w"), null);
});

test("verified_bot: payload, round-trip, description, sample request, hints", () => {
  const p = buildRulePayload(emptyForm({ actionType: "allow", vhosts: "a.com", verifiedBot: true }));
  assert.equal(p.match.verified_bot, true);
  const f = formFromRule({ match: { verified_bot: true }, scope: { vhosts: ["a.com"] }, action: { type: "allow" } });
  assert.equal(f.verifiedBot, true);
  assert.equal(describeMatch({ verified_bot: true }), "requests from a verified crawler (FCrDNS)");
  assert.equal(describeMatch({ verified_bot: true, methods: ["GET"] }), "GET requests from a verified crawler (FCrDNS)");
  const sim = simulateInputFromRule({ scope: { vhosts: ["a.com"] }, match: { verified_bot: true } });
  assert.equal(sim.verifiedBot, "googlebot", "the sample exercises the crawler path via the override");
  assert.equal(simulateInputFromRule({ scope: { vhosts: ["a.com"] }, match: { methods: ["GET"] } }).verifiedBot, "");
  const v = validateRuleForm(emptyForm({ actionType: "allow", vhosts: "a.com", verifiedBot: true }));
  assert.equal(v.errors.length, 0);
  assert.ok(v.hints.some((h) => /cache-only/.test(h)));
  const both = validateRuleForm(emptyForm({ actionType: "allow", vhosts: "a.com", verifiedBot: true, uas: "*Googlebot*" }));
  assert.ok(both.warnings.some((w) => /already proves/.test(w)));
  // an enabled allow keyed only on verified_bot is a narrowed rule, not a catch-all
  const on = validateRuleForm(emptyForm({ actionType: "block", vhosts: "a.com", verifiedBot: true, enabled: true }));
  assert.equal(on.errors.length, 0);
  assert.ok(VERIFIED_BOT_NAMES.includes("googlebot") && VERIFIED_BOT_NAMES.includes("meta"));
  assert.ok(!VERIFIED_BOT_NAMES.includes("google"), "generic google verdict is excluded for rules");
  assert.deepEqual(Object.keys(VERIFIED_BOT_UA_GLOBS).sort(), [...VERIFIED_BOT_NAMES].sort(), "every verifiable crawler has its UA globs listed (single source for the unverifiable set)");
  for (const globs of Object.values(VERIFIED_BOT_UA_GLOBS)) for (const g of globs) assert.ok(!UNVERIFIABLE_BOT_UAS.includes(g), `${g} is verifiable`);
  for (const n of VERIFIED_BOT_NAMES) assert.ok(VERIFIED_BOT_LABEL.length && !VERIFIED_BOT_LABEL.includes(`, ${n},`), `label uses display names, not raw key ${n}`);
  assert.match(VERIFIED_BOT_LABEL, /Googlebot/);
  // tame_bots allows crawlers by FCrDNS too, plus the unverifiable ones by UA
  const tb = recipe("tame_bots").build({ vhosts: "a.com" });
  assert.equal(tb[0].match.verified_bot, true);
  assert.deepEqual(tb[0].match.ua_any, []);
  assert.deepEqual(tb[1].match.ua_any, [...UA_ALLOW_ALONGSIDE_VERIFIED]);
});

// ── recipes distilled from fleet traffic (2026-09) ───────────────────────

test("bot groups: dataset group exists, AI group grew (incl. Claude-User), every group fits one rule", () => {
  const ds = botGroup("dataset");
  assert.ok(ds && ds.patterns.includes("*(compatible; crawler)*") && ds.patterns.includes("*img2dataset*"));
  for (const ua of ["*OAI-SearchBot*", "*Claude-User*", "*Claude-SearchBot*"]) assert.ok(botGroup("ai").patterns.includes(ua), ua);
  for (const g of BOT_GROUPS) {
    assert.ok(g.patterns.length <= LIMITS.patternsPerField, `${g.key} fits in ua_any`);
    assert.equal(new Set(g.patterns.map((p) => p.toLowerCase())).size, g.patterns.length, `${g.key} has no duplicate patterns`);
  }
  assert.equal(describeMatch({ ua_any: ds.patterns }), "requests with a User-Agent matching dataset / anonymous crawlers");
});

test("block_probe_paths: one ENABLED block on the probe list, extras appended, /.well-known refused", () => {
  const rcp = recipe("block_probe_paths");
  assert.ok(PROBE_PATHS.length <= LIMITS.patternsPerField);
  for (const p of PROBE_PATHS) assert.ok(p.startsWith("/") && !/well-known/.test(p), p);
  for (const must of ["/.env", "/.git/", "/*phpinfo.php", "/*.php.bak", "/server-status"]) assert.ok(PROBE_PATHS.includes(must), must);
  const rules = rcp.build({ vhosts: "*", paths: "backup/, /.env" });
  assert.equal(rules.length, 1);
  assert.equal(rules[0].enabled, true, "nothing legitimate lives on these paths");
  assert.equal(rules[0].action.type, "block");
  assert.deepEqual(rules[0].match.ua_any, []);
  assert.deepEqual(rules[0].match.path_any, [...PROBE_PATHS, "/backup/"], "extras appended once, duplicates dropped");
  assert.deepEqual(rules[0].scope.vhosts, ["*"]);
  assert.ok(validateRecipeVars(rcp, { vhosts: "a.com", paths: "/.well-known/acme-challenge/" }).some((e) => /well-known/.test(e)));
  assert.ok(validateRecipeVars(rcp, { vhosts: "a.com", paths: ".well-known" }).some((e) => /well-known/.test(e)));
  const many = Array.from({ length: LIMITS.patternsPerField }, (_, i) => `/x${i}/`).join(", ");
  assert.ok(validateRecipeVars(rcp, { vhosts: "a.com", paths: many }).some((e) => /too many paths/.test(e)));
  assert.equal(validateRecipeVars(rcp, { vhosts: "a.com", paths: "/old/, /backup/" }).length, 0);
  // the simulator sample turns the wildcard into a concrete path
  assert.equal(simulateInputFromRule(rules[0]).path, "/.env");
});

test("bots_read_only: no verified allow, one write-method block per group, search/scripts/empty start disabled", () => {
  const rcp = recipe("bots_read_only");
  const rules = rcp.build({ vhosts: "a.com", groups: "" });
  assert.equal(rules.length, 3, "default social + ai + seo");
  for (const r of rules) {
    assert.equal(r.action.type, "block");
    assert.equal(r.match.verified_bot, false, "Meta's crawler is FCrDNS-verified: a verified allow would let its POSTs through");
    assert.deepEqual(r.match.methods, [...WRITE_METHODS]);
    assert.ok(!r.match.methods.includes("GET"));
    assert.equal(r.enabled, true, "preview / index crawlers never need to write");
  }
  assert.ok(!rules.some((r) => r.action.type === "allow"));
  assert.deepEqual(rules[0].match.ua_any, botGroup("social").patterns);
  // order follows BOT_GROUPS regardless of how the operator typed the keys
  const custom = rcp.build({ vhosts: "a.com", groups: "scripts, SEO, empty, search" });
  assert.deepEqual(custom.map((r) => r.match.ua_any[0]), [botGroup("search").patterns[0], botGroup("seo").patterns[0], botGroup("scripts").patterns[0], "-"]);
  assert.equal(custom[0].enabled, false, "Googlebot POSTs while rendering");
  assert.equal(custom[1].enabled, true);
  assert.equal(custom[2].enabled, false, "scripts group = webhooks / IoT posters too");
  assert.equal(custom[3].enabled, false, "no-UA block starts disabled (monitors)");
  for (let i = 1; i < custom.length; i += 1) assert.ok(custom[i - 1].priority < custom[i].priority);
  assert.ok(validateRecipeVars(rcp, { vhosts: "a.com", groups: "ai, nope" }).some((e) => /"nope" is not a bot group/.test(e)));
  assert.ok(validateRecipeVars(rcp, { vhosts: "a.com", groups: "" }).some((e) => /required/.test(e)));
});

test("bots_no_qs: per-group has_qs rule with the pass-through regex, block or hard throttle, disabled", () => {
  const rcp = recipe("bots_no_qs");
  const blocks = rcp.build({ ...recipeVarsDefaults(rcp, { vhosts: "shop.gr" }), groups: "social, ai", action: "block" });
  assert.equal(blocks.length, 2);
  for (const r of blocks) {
    assert.equal(r.enabled, false);
    assert.equal(r.action.type, "block");
    assert.equal(r.match.has_qs, true);
    assert.equal(r.match.qs_not_rx, BOT_QS_PASSTHROUGH, "the default pass-through is the var's default");
    assert.deepEqual(r.match.methods, ["GET"]);
    assert.ok(r.priority >= PRIORITY_BANDS.block.from && r.priority <= PRIORITY_BANDS.block.to);
  }
  // pagination / click ids pass, a facet does not
  const rx = new RegExp(BOT_QS_PASSTHROUGH, "i");
  for (const ok of ["page=2", "fbclid=abc", "utm_source=fb&utm_medium=cpc", "paged=3&lang=el", "feed", "page=2&", "PAGE=2"]) assert.ok(rx.test(ok), ok);
  // every parameter must be on the list: a facet grid walked page by page is still a facet grid
  for (const facet of ["min_price=120&filter_color=red", "ind=k&ind=n", "orderby=price", "pageless=1", "filter_color=red&page=3", "page=2&orderby=price", "utm_source=fb&x=1"]) assert.ok(!rx.test(facet), facet);
  // an emptied regex means nothing passes: has_qs alone, no qs_not_rx
  const strict = rcp.build({ vhosts: "shop.gr", groups: "social", action: "block", qs_ok: "" });
  assert.equal(strict[0].match.has_qs, true);
  assert.equal(strict[0].match.qs_not_rx, undefined);
  assert.equal(validateRecipeVars(rcp, { vhosts: "shop.gr", groups: "social", action: "block", qs_ok: "" }).length, 0, "clearing the regex is allowed");
  const th = rcp.build({ vhosts: "shop.gr", groups: "seo", action: "throttle", qs_ok: "(?:^|&)lang=" });
  assert.equal(th.length, 1);
  assert.deepEqual(th[0].action, { type: "throttle", profile: "hard_bot" });
  assert.equal(th[0].match.qs_not_rx, "(?:^|&)lang=");
  assert.ok(th[0].priority >= PRIORITY_BANDS.throttle.from && th[0].priority <= PRIORITY_BANDS.throttle.to);
});

test("lock_panel_subdomains: DAV subdomains get a disabled geo block, browser ones a disabled challenge, office IPs pass both", () => {
  const rcp = recipe("lock_panel_subdomains");
  const rules = rcp.build(recipeVarsDefaults(rcp));
  assert.equal(rules.length, 2);
  assert.equal(rules[0].action.type, "challenge");
  assert.deepEqual(rules[0].scope.vhosts, ["cpanel.*", "webmail.*"]);
  assert.deepEqual(rules[0].match.country_not_in, ["GR", "CY"]);
  assert.equal(rules[1].action.type, "block");
  assert.deepEqual(rules[1].scope.vhosts, ["cpcalendars.*", "cpcontacts.*", "webdisk.*", "autodiscover.*", "autoconfig.*"]);
  assert.equal(rules[1].enabled, false);
  const withIPs = rcp.build({ svc_vhosts: "webdisk.*", web_vhosts: "", countries: "gr", ips: "203.0.113.0/24" });
  assert.equal(withIPs.length, 2, "no browser subdomains → no challenge and no second allow");
  assert.equal(withIPs[0].action.type, "allow");
  assert.deepEqual(withIPs[0].scope.vhosts, ["webdisk.*"]);
  assert.deepEqual(withIPs[0].match.ip_any, ["203.0.113.0/24"]);
  assert.deepEqual(withIPs[1].match.country_not_in, ["GR"]);
  assert.ok(withIPs[0].priority < withIPs[1].priority);
  // one allow per scope: the two vhost lists are each bounded by vhostsPerRule,
  // so their union never travels in a single rule
  const both = rcp.build({ ...recipeVarsDefaults(rcp), ips: "203.0.113.0/24" });
  assert.equal(both.length, 4);
  assert.deepEqual(both.slice(0, 2).map((r) => r.action.type), ["allow", "allow"]);
  assert.deepEqual(both[0].scope.vhosts, ["cpcalendars.*", "cpcontacts.*", "webdisk.*", "autodiscover.*", "autoconfig.*"]);
  assert.deepEqual(both[1].scope.vhosts, ["cpanel.*", "webmail.*"]);
  assert.ok(both[0].priority < both[1].priority && both[1].priority < both[2].priority);
  const many = Array.from({ length: LIMITS.vhostsPerRule }, (_, i) => `h${i}.*`).join(", ");
  assert.equal(validateRecipeVars(rcp, { ...recipeVarsDefaults(rcp), svc_vhosts: many }).length, 0, "each list is validated on its own");
  assert.ok(validateRecipeVars(rcp, { ...recipeVarsDefaults(rcp), svc_vhosts: `${many}, one-more.*` }).some((e) => /Too many vhosts/.test(e)));
});

test("pathPatternMatches mirrors the daemon: prefix without wildcards, full match with; /.well-known/ is refused with matcher semantics", () => {
  assert.ok(pathPatternMatches("/.env", "/.env"));
  assert.ok(pathPatternMatches("/.env", "/.environment"), "wildcard-free = prefix");
  assert.ok(pathPatternMatches("/*/.env", "/bin/.env"), "'*' crosses '/'");
  assert.ok(!pathPatternMatches("/*phpinfo.php", "/phpinfo.php/x"), "wildcard pattern is a full match");
  assert.ok(pathPatternMatches("/wp-admin/admin-ajax.php?action", "/wp-admin/admin-ajax.php", "action=heartbeat"), "the ?query part is matched against the query, not the path");
  assert.ok(pathPatternMatches("/a.b", "/a.b"));
  assert.ok(!pathPatternMatches("/a.b*", "/aXb"), "'.' is literal");
  // the query part is matched per parameter, like queryPatternMatch in Go
  assert.ok(pathPatternMatches("/?wc-ajax", "/", "wc-ajax=get_refreshed_fragments"), "bare key = any value");
  assert.ok(!pathPatternMatches("/?wc-ajax", "/", "page=2"), "the key must be present");
  assert.ok(!pathPatternMatches("/?wc-ajax", "/.well-known/acme-challenge/token"), "no query → a pattern with a query part never matches");
  assert.ok(pathPatternMatches("/x.php?a=b", "/x.php", "c=1&A=B"), "key and value are case-insensitive");
  assert.ok(!pathPatternMatches("/x.php?a=b", "/x.php", "a=bb"), "value is exact, not a prefix");
  assert.ok(pathPatternMatches("/x?mode=%72egister", "/x", "mode=register"), "both sides are URL-decoded");
  assert.ok(pathPatternMatches("/x?", "/xyz", ""), "a bare '?' suffix matches any query");
  const rcp = recipe("throttle_hot_path");
  const base = recipeVarsDefaults(rcp, { vhosts: "a.com" });
  for (const bad of ["/", "/*", "/.we", "/.well-known", "/.well-known*", "/*acme*", "/.well-known/pki-validation/", ".well-known/"]) {
    assert.ok(validateRecipeVars(rcp, { ...base, paths: bad }).some((e) => /well-known/.test(e)), bad);
  }
  for (const ok of ["/.well-known-ish-but-not", "/wellknown/", "/acme/", "/*/token.txt"]) {
    assert.ok(!validateRecipeVars(rcp, { ...base, paths: ok }).some((e) => /well-known/.test(e)), ok);
  }
  // inside the namespace the literal guard applies even when the matcher would not hit a probe path
  assert.ok(validateRecipeVars(rcp, { ...base, paths: "/.well-known/acme-challenge/token/extra" }).some((e) => /well-known/.test(e)));
  // path count: non-probe recipes send the raw list, so exactly the limit is fine
  const atLimit = Array.from({ length: LIMITS.patternsPerField }, (_, i) => `/p${i}/`).join(", ");
  assert.equal(validateRecipeVars(rcp, { ...base, paths: atLimit }).filter((e) => /too many paths/.test(e)).length, 0);
  assert.ok(validateRecipeVars(rcp, { ...base, paths: `${atLimit}, /p-extra/` }).some((e) => /too many paths/.test(e)));
});

test("anything literally under /.well-known is refused even when it is not a prefix of a probe path", () => {
  const rcp = recipe("block_probe_paths");
  const base = recipeVarsDefaults(rcp, { vhosts: "a.com" });
  for (const bad of ["/.well-known/acme-challenge/A", "/.well-known/acme-challenge/token/", "/.well-known/openid", "/.WELL-KNOWN/x", "/.well-known/x?y=1"]) {
    assert.ok(validateRecipeVars(rcp, { ...base, paths: bad }).some((e) => /well-known/.test(e)), bad);
  }
});

test("shadowingRules: an earlier enabled allow or throttle that covers the row's crawlers and is not narrower neutralises it", () => {
  const rcp = recipe("bots_read_only");
  const [social] = rcp.build({ vhosts: "shop.gr", groups: "social" });
  const verifiedAllow = { id: "r_v", enabled: true, priority: 10, scope: { vhosts: ["shop.gr"] }, match: { verified_bot: true }, action: { type: "allow" } };
  const uaAllow = { id: "r_u", enabled: true, priority: 11, scope: { vhosts: ["*.gr"] }, match: { ua_any: [...UA_ALLOW_ALONGSIDE_VERIFIED] }, action: { type: "allow" } };
  const otherVhost = { ...verifiedAllow, id: "r_o", scope: { vhosts: ["other.com"] } };
  const disabled = { ...verifiedAllow, id: "r_d", enabled: false };
  const later = { ...verifiedAllow, id: "r_l", priority: 400 };
  const ipAllow = { id: "r_i", enabled: true, priority: 15, scope: { vhosts: ["shop.gr"] }, match: { ip_any: ["203.0.113.0/24"] }, action: { type: "allow" } };
  const pathAllow = { ...verifiedAllow, id: "r_p", match: { verified_bot: true, path_any: ["/feed/"] } };
  const got = shadowingRules(social, [verifiedAllow, uaAllow, otherVhost, disabled, later, ipAllow, pathAllow]);
  assert.deepEqual(got.map((r) => r.id), ["r_v", "r_u"], "Meta is FCrDNS-verified AND in the UA allow; other vhost / disabled / later / IP / path-scoped allows do not shadow");
  // an AI-group block is not shadowed by a verified allow (none of those crawlers is verifiable) but is by a UA allow naming it
  const [ai] = rcp.build({ vhosts: "shop.gr", groups: "ai" });
  assert.deepEqual(shadowingRules(ai, [verifiedAllow]), []);
  assert.equal(shadowingRules(ai, [{ ...uaAllow, match: { ua_any: ["*GPTBot*"] } }]).length, 1);
  // tame_bots' AI GET throttle (110) shadows a bots_no_qs GET block (360) but not a write-method block (350)
  const tame = recipe("tame_bots").build({ vhosts: "shop.gr" }).map((r, i) => ({ ...r, id: `t${i}` }));
  const [noQS] = recipe("bots_no_qs").build({ vhosts: "shop.gr", groups: "ai", action: "block", qs_ok: "" });
  assert.deepEqual(shadowingRules(noQS, tame).map((r) => r.priority), [110]);
  assert.deepEqual(shadowingRules(ai, tame), [], "GET-only throttle does not cover POST/PUT/PATCH/DELETE");
  // a has_qs throttle only shadows a has_qs row; earlier blocks / challenges are not pass-through and are not reported
  const qsThrottle = { ...tame[2], id: "q", match: { ...tame[2].match, has_qs: true } };
  assert.equal(shadowingRules(noQS, [qsThrottle]).length, 1);
  assert.equal(shadowingRules({ ...noQS, match: { ...noQS.match, has_qs: false } }, [qsThrottle]).length, 0);
  assert.deepEqual(shadowingRules(social, [{ ...uaAllow, action: { type: "block" } }, { ...uaAllow, action: { type: "challenge" } }]), []);
  // conditions AND in the daemon: verified_bot + ua_any only covers the UAs it names, and a
  // pass-through regex on the earlier rule lets queries fall through to the row
  assert.deepEqual(shadowingRules(social, [{ ...verifiedAllow, match: { verified_bot: true, ua_any: ["*Googlebot*"] } }]), [], "verified Googlebot-only allow leaves every social UA for the row");
  assert.equal(shadowingRules(social, [{ ...verifiedAllow, match: { verified_bot: true, ua_any: ["*meta-externalagent*"] } }]).length, 1);
  assert.equal(shadowingRules(noQS, [{ ...qsThrottle, match: { ...qsThrottle.match, qs_not_rx: "page=" } }]).length, 0);
  assert.equal(shadowingRules({ ...noQS, match: { ...noQS.match, qs_not_rx: "page=" } }, [{ ...qsThrottle, match: { ...qsThrottle.match, qs_not_rx: "page=" } }]).length, 1);
  // allows never shadow allows; rows without UA patterns are out of scope
  assert.deepEqual(shadowingRules({ ...social, action: { type: "allow" } }, [verifiedAllow]), []);
  assert.deepEqual(shadowingRules({ ...social, match: { ...social.match, ua_any: [] } }, [verifiedAllow]), []);
});

test("recipe var defaults are the build() fallbacks: an empty required var builds what the form shows", () => {
  for (const key of ["geo_fence", "geo_fence_admin", "lock_panel_subdomains", "geo_challenge", "throttle_hot_path", "lock_dev_sites", "bots_read_only", "bots_no_qs"]) {
    const rcp = recipe(key);
    const withDefaults = rcp.build(recipeVarsDefaults(rcp, { vhosts: "a.com" }));
    const emptied = { ...recipeVarsDefaults(rcp, { vhosts: "a.com" }) };
    for (const v of rcp.vars) if (v.required && v.key !== "vhosts" && v.type !== "select") emptied[v.key] = "";
    // web_vhosts is optional and "" means none there, so compare only the rules the defaults produce
    const built = rcp.build(emptied).map((r) => JSON.stringify(r));
    for (const r of withDefaults) if (!(key === "lock_panel_subdomains" && r.scope.vhosts[0] === "cpanel.*")) assert.ok(built.includes(JSON.stringify(r)), `${key}: ${r.note}`);
  }
});

test("validateRuleForm counts the note in bytes like the daemon", () => {
  const ascii = "a".repeat(LIMITS.noteLen);
  assert.ok(!validateRuleForm(emptyForm({ vhosts: "a.com", uas: "*Evil*", actionType: "block", priority: 300, note: ascii })).errors.some((e) => /Note too long/.test(e)));
  const dashes = "—".repeat(100); // 300 bytes, 100 chars
  assert.ok(validateRuleForm(emptyForm({ vhosts: "a.com", uas: "*Evil*", actionType: "block", priority: 300, note: dashes })).errors.some((e) => /Note too long/.test(e)));
});

test("re2Rejects: lookaround / backreferences only, shared by the form and the recipe validators", () => {
  for (const bad of ["(?=x)", "(?!x)", "(?<=x)", "(?<!x)", "(a)\\1"]) assert.ok(re2Rejects(bad), bad);
  for (const ok of ["(?:^|&)lang=", "(?i)utm_[a-z]+", "a{2,3}", "[^&]+", "\\d+", "(?P<n>x)"]) assert.ok(!re2Rejects(ok), ok);
  const rcp = recipe("bots_no_qs");
  const base = recipeVarsDefaults(rcp, { vhosts: "a.com" });
  assert.ok(validateRecipeVars(rcp, { ...base, qs_ok: "(?<=a)b" }).some((e) => /RE2/.test(e)));
  assert.equal(validateRecipeVars(rcp, { ...base, qs_ok: "(?:^|&)lang=" }).length, 0);
  const form = validateRuleForm(emptyForm({ vhosts: "a.com", hasQS: true, qsNotRx: "(?!x)", actionType: "block", priority: 300, paths: "/x" }));
  assert.ok(form.errors.some((e) => /RE2/.test(e)));
});

test("recipe notes are clamped to LIMITS.noteLen even for one-entry lists that are themselves too long", () => {
  const rcp = recipe("throttle_hot_path");
  const longPath = "/" + "a".repeat(600);
  const [r] = rcp.build({ ...recipeVarsDefaults(rcp, { vhosts: "a.com" }), paths: longPath });
  assert.ok(byteLen(r.note) <= LIMITS.noteLen && byteLen(r.note) >= LIMITS.noteLen - 3, `${byteLen(r.note)} bytes`);
  assert.ok(r.note.length < LIMITS.noteLen, "the em dash and the ellipsis are multi-byte: the daemon counts bytes (Go len)");
  assert.ok(r.note.startsWith("recipe:throttle_hot_path"));
  assert.ok(r.note.endsWith("…"));
  assert.deepEqual(r.match.path_any, [longPath], "the rule itself keeps the full pattern");
});

test("geo_challenge: crawlers first, then a disabled challenge from / outside the countries, optional paths", () => {
  const rcp = recipe("geo_challenge");
  const from = rcp.build({ vhosts: "shop.gr", mode: "from", countries: "sg, ru", paths: "product/, /category/", ips: "" });
  assert.equal(from.length, 3);
  assert.equal(from[0].match.verified_bot, true);
  assert.deepEqual(from[1].match.ua_any, [...UA_ALLOW_ALONGSIDE_VERIFIED]);
  assert.equal(from[2].action.type, "challenge");
  assert.equal(from[2].enabled, false);
  assert.deepEqual(from[2].match.country_in, ["SG", "RU"]);
  assert.deepEqual(from[2].match.country_not_in, []);
  assert.deepEqual(from[2].match.path_any, ["/product/", "/category/"]);
  const outside = rcp.build({ vhosts: "shop.gr", mode: "outside", countries: "GR", paths: "", ips: "203.0.113.7" });
  assert.equal(outside.length, 4);
  assert.deepEqual(outside[2].match.ip_any, ["203.0.113.7"]);
  assert.deepEqual(outside[3].match.country_not_in, ["GR"]);
  assert.deepEqual(outside[3].match.country_in, []);
  assert.deepEqual(outside[3].match.path_any, []);
  assert.ok(outside[3].priority > PRIORITY_BANDS.challenge.from && outside[3].priority < PRIORITY_BANDS.block.from);
});

test("block_dataset_crawlers is an enabled UA block on the dataset group", () => {
  const rules = recipe("block_dataset_crawlers").build({ vhosts: "*" });
  assert.equal(rules.length, 1);
  assert.equal(rules[0].enabled, true);
  assert.deepEqual(rules[0].match.ua_any, botGroup("dataset").patterns);
  assert.equal(rules[0].action.type, "block");
});

test("throttle_hot_path: path-only per-IP throttle, disabled, profile validated", () => {
  const rcp = recipe("throttle_hot_path");
  const rules = rcp.build(recipeVarsDefaults(rcp, { vhosts: "shop.gr" }));
  assert.equal(rules.length, 1);
  assert.equal(rules[0].enabled, false, "throttles humans too");
  assert.deepEqual(rules[0].match.ua_any, []);
  assert.deepEqual(rules[0].match.path_any, ["/wp-admin/admin-ajax.php", "/?wc-ajax", "/forum/download/file.php"]);
  assert.deepEqual(rules[0].action, { type: "throttle", profile: "soft_bot" });
  assert.equal(rcp.build({ vhosts: "a.com", paths: "/search", profile: "hard_bot" })[0].action.profile, "hard_bot");
  assert.equal(rcp.build({ vhosts: "a.com", paths: "/search", profile: "bogus" })[0].action.profile, "soft_bot", "unknown profile never reaches the edge");
  // a pasted 20-path list must not push the note past LIMITS.noteLen
  const long = Array.from({ length: LIMITS.patternsPerField }, (_, i) => `/a-fairly-long-directory-name-${i}/`).join(", ");
  const th = recipe("throttle_hot_path").build({ vhosts: "a.com", paths: long, profile: "soft_bot" })[0];
  assert.ok(th.note.length <= LIMITS.noteLen && /\+17 more/.test(th.note), th.note);
  const gc = recipe("geo_challenge").build({ vhosts: "a.com", mode: "from", countries: "SG", paths: long, ips: "" });
  assert.ok(gc[gc.length - 1].note.length <= LIMITS.noteLen);
  assert.ok(validateRecipeVars(recipe("bots_no_qs"), { vhosts: "a.com", groups: "ai", action: "block", qs_ok: "(?<=a)b" }).some((e) => /RE2/.test(e)));
  assert.equal(validateRecipeVars(recipe("bots_no_qs"), { vhosts: "a.com", groups: "ai", action: "block", qs_ok: "(?:^|&)lang=" }).length, 0);
});

test("lock_dev_sites and xmlrpc_lockdown: optional allow first, enforcing rule disabled", () => {
  const dev = recipe("lock_dev_sites").build({ vhosts: "dev.*", countries: "GR", ips: "203.0.113.0/24" });
  assert.equal(dev.length, 2);
  assert.equal(dev[0].action.type, "allow");
  assert.equal(dev[1].action.type, "challenge");
  assert.equal(dev[1].enabled, false);
  assert.deepEqual(dev[1].match.country_not_in, ["GR"]);
  assert.equal(recipe("lock_dev_sites").build({ vhosts: "dev.*", countries: "GR", ips: "" }).length, 1);

  const x = recipe("xmlrpc_lockdown").build({ vhosts: "*", ips: "192.0.2.0/24" });
  assert.equal(x.length, 2);
  assert.deepEqual(x[0].match.path_any, ["/xmlrpc.php"]);
  assert.deepEqual(x[0].match.ip_any, ["192.0.2.0/24"]);
  assert.equal(x[0].action.type, "allow");
  assert.equal(x[1].action.type, "block");
  assert.deepEqual(x[1].match.methods, ["POST"]);
  assert.equal(x[1].enabled, false, "Jetpack / mobile app use xmlrpc");
  assert.deepEqual(x[1].scope.vhosts, ["*"]);
  assert.equal(recipeVarsDefaults(recipe("xmlrpc_lockdown")).vhosts, "*", "server-wide default when the page has no vhost context");
  assert.equal(recipeVarsDefaults(recipe("xmlrpc_lockdown"), { vhosts: "a.com" }).vhosts, "a.com", "page context wins");
});

test("monitoring_probes is a link to the challenge excludes, and recipe keys are unique", () => {
  const m = recipe("monitoring_probes");
  assert.equal(m.kind, "link");
  assert.match(m.href, /webdetector/);
  const keys = RECIPES.map((r) => r.key);
  assert.equal(new Set(keys).size, keys.length);
  for (const k of keys) assert.match(k, /^[a-z0-9_]+$/, `${k} survives the recipe:<key> note tag`);
});
