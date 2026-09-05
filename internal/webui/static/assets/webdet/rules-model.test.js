// node --test internal/webui/static/assets/webdet/rules-model.test.js
import test from "node:test";
import assert from "node:assert/strict";
import {
  ACTIONS,
  BOT_GROUPS,
  LIMITS,
  RECIPES,
  THROTTLE_PROFILES,
  buildRulePayload,
  describeMatch,
  describeRule,
  emptyForm,
  formFromRule,
  hostPatternMatch,
  isIPOrCIDR,
  positionText,
  priorityTie,
  recipe,
  recipeOf,
  recipeVarsDefaults,
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
  assert.deepEqual(p.match, { ...row.match, country_not_in: [], ip_any: [] });
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
  assert.deepEqual(s, { host: "www.example.com", ip: "", ua: "GPTBot", path: "/forum/ucp.php", method: "POST", country: "US", qs: "mode=register" });
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
    for (const r of rules) {
      assert.equal(recipeOf(r), rcp.key);
      assert.deepEqual(r.scope.vhosts, ["a.com"]);
      // every built rule passes the same validation the editor applies
      const v = validateRuleForm(formFromRule(r));
      assert.deepEqual(v.errors, [], `${rcp.key}: ${v.errors.join(" | ")}`);
      if (r.action.type === "block" && !r.match.ua_any.length) assert.equal(r.enabled, false, `${rcp.key}: catch-all block must start disabled`);
      if (r.action.type === "block" && r.match.ua_any.includes("-")) assert.equal(r.enabled, false, `${rcp.key}: no-UA block must start disabled (monitors)`);
    }
  }
});

test("geo_fence: good bots → (office IPs) → disabled block of everyone outside", () => {
  const rcp = recipe("geo_fence");
  const rules = rcp.build({ vhosts: "shop.gr, www.shop.gr", countries: "gr, cy", ips: "" });
  assert.equal(rules.length, 2);
  assert.equal(rules[0].action.type, "allow");
  assert.ok(rules[0].match.ua_any.includes("*Googlebot*"));
  assert.equal(rules[1].action.type, "block");
  assert.deepEqual(rules[1].match.country_not_in, ["GR", "CY"]);
  assert.deepEqual(rules[1].match.country_in, []);
  assert.equal(rules[1].enabled, false);
  assert.deepEqual(rules[1].scope.vhosts, ["shop.gr", "www.shop.gr"]);

  const withIPs = rcp.build({ vhosts: "shop.gr", countries: "GR", ips: "203.0.113.0/24, 2001:db8::/48" });
  assert.equal(withIPs.length, 3);
  assert.equal(withIPs[1].action.type, "allow");
  assert.deepEqual(withIPs[1].match.ip_any, ["203.0.113.0/24", "2001:db8::/48"]);
  assert.ok(withIPs[0].priority < withIPs[1].priority && withIPs[1].priority < withIPs[2].priority);
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
  for (const ok of ["203.0.113.0/24", "198.51.100.7", "0.0.0.0/0", "2001:db8::/48", "2001:db8::1", "::1", "::", "::ffff:203.0.113.9", "fe80::1/128", "1:2:3:4:5:6:7:8"]) {
    assert.equal(isIPOrCIDR(ok), true, ok);
  }
  for (const bad of ["203.0.113.0/33", "256.1.1.1", "1.2.3", "2001:db8::/129", "2001:db8:::1", "1:2:3:4:5:6:7:8:9", "example.com", "", "1.2.3.4/24/1", "gggg::1",
    "01.2.3.4", "1.2.3.4/024", "1.2.3.4::1"]) {
    assert.equal(isIPOrCIDR(bad), false, bad);
  }
});

test("validateRecipeVars: required + country shape", () => {
  const rcp = recipe("geo_fence");
  assert.ok(validateRecipeVars(rcp, { vhosts: "", countries: "GR" }).some((e) => /Vhosts is required/.test(e)));
  assert.ok(validateRecipeVars(rcp, { vhosts: "a.com", countries: "Greece" }).some((e) => /not a 2-letter/.test(e)));
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
