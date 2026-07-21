// Traffic Rules page: Cloudflare-style per-vhost rules (allow / block /
// challenge / throttle) with quick presets, a rule editor and pre-enforcement
// simulation. Extracted from the vhost-controls page into its own home —
// the API surface (/api/v1/webdet/rules/*) is unchanged and scope-filtered
// server-side, so the page works for admins and (own vhosts only) scoped
// users alike.

export const rulesMixin = {
  data() {
    return {
      rules: [],
      rulesSearch: "",
      ruleEditID: "",
      ruleForm: {
        enabled: true,
        priority: 100,
        vhosts: "",
        countries: "",
        uas: "",
        paths: "",
        methods: "",
        actionType: "throttle",
        throttleProfile: "soft_bot",
        note: "",
        hasQS: false,
        qsNotRx: "",
      },
      presets: [
        { key: "meta_throttle", label: "Preset: Meta throttle", hint: "Throttle known Meta crawlers softly." },
        { key: "challenge_login", label: "Preset: Challenge login", hint: "Challenge repeated login endpoint abuse." },
        { key: "block_country", label: "Preset: Block countries (disabled)", hint: "Start disabled and validate first." },
        // ── throttle presets ──
        { key: "throttle_scrapers", label: "Preset: Throttle script scrapers", hint: "Rate-limit generic script tools: python-requests, curl, wget, Go HTTP client." },
        { key: "throttle_ai_crawlers", label: "Preset: Throttle AI crawlers", hint: "Throttle AI training bots (GPTBot, ClaudeBot, Bytespider…) at medium rate." },
        { key: "throttle_seo_bots", label: "Preset: Throttle SEO bots", hint: "Soft-limit commercial SEO crawlers (Ahrefs, Semrush, MJ12, DotBot)." },
        // ── block / challenge presets ──
        { key: "block_meta_qs", label: "Preset: Block Meta bot QS loop", hint: "Block Meta/GoogleOther bots hitting pages with unexpected query strings. Requires has_qs support." },
        { key: "block_empty_ua", label: "Preset: Block empty UA", hint: "Block requests with no User-Agent header — scanners and raw exploit tools." },
        { key: "block_xmlrpc", label: "Preset: Block xmlrpc.php", hint: "Block all POST requests to xmlrpc.php — brute-force amplifier with no legit use on most sites." },
        { key: "challenge_wp_admin", label: "Preset: Challenge wp-admin", hint: "Challenge POST requests to wp-admin and wp-login — catches credential stuffing." },
        // ── allow preset ──
        { key: "allow_good_bots", label: "Preset: Allow good bots (priority 10)", hint: "Explicit allow for verified search crawlers before any block/challenge rules fire." },
      ],
      simulateForm: {
        host: "",
        ip: "",
        ua: "",
        path: "/",
        method: "GET",
        country: "",
        qs: "",
      },
      simulateResult: null,
    };
  },

  computed: {
    rulesFiltered() {
      const q = String(this.rulesSearch || "").trim().toLowerCase();
      if (!q) return this.rules;
      return this.rules.filter((row) => {
        const hostStr = Array.isArray(row?.scope?.vhosts) ? row.scope.vhosts.join(",") : "";
        const note = String(row?.note || "");
        return String(row?.id || "").toLowerCase().includes(q)
          || hostStr.toLowerCase().includes(q)
          || note.toLowerCase().includes(q)
          || String(row?.action?.type || "").toLowerCase().includes(q);
      });
    },
  },

  methods: {
    // ── Traffic rules ──────────────────────────────────────────────────
    buildRulePayload() {
      const f = this.ruleForm || {};
      const actionType = String(f.actionType || "").trim();
      const payload = {
        enabled: Boolean(f.enabled),
        priority: Number(f.priority || 100),
        scope: { vhosts: this.csvSplit(f.vhosts) },
        match: {
          country_in: this.csvSplit(f.countries).map((x) => x.toUpperCase()),
          ua_any: this.csvSplit(f.uas),
          path_any: this.csvSplit(f.paths),
          methods: this.csvSplit(f.methods).map((x) => x.toUpperCase()),
          has_qs: Boolean(f.hasQS),
          qs_not_rx: String(f.qsNotRx || "").trim() || undefined,
        },
        action: {
          type: actionType,
          profile: actionType === "throttle" ? String(f.throttleProfile || "").trim() : "",
        },
        note: String(f.note || "").trim(),
      };
      if (!payload.scope.vhosts.length) throw new Error("At least one vhost is required.");
      if (!payload.action.type) throw new Error("Action is required.");
      if (payload.action.type === "throttle" && !payload.action.profile) throw new Error("Throttle profile is required.");
      return payload;
    },
    resetRuleForm() {
      this.ruleEditID = "";
      this.ruleForm = {
        enabled: true,
        priority: 100,
        vhosts: "",
        countries: "",
        uas: "",
        paths: "",
        methods: "",
        actionType: "throttle",
        throttleProfile: "soft_bot",
        note: "",
        hasQS: false,
        qsNotRx: "",
      };
    },
    loadRuleIntoForm(row) {
      if (!row) return;
      this.ruleEditID = String(row.id || "");
      this.ruleForm = {
        enabled: Boolean(row.enabled),
        priority: Number(row.priority || 100),
        vhosts: Array.isArray(row?.scope?.vhosts) ? row.scope.vhosts.join(", ") : "",
        countries: Array.isArray(row?.match?.country_in) ? row.match.country_in.join(", ") : "",
        uas: Array.isArray(row?.match?.ua_any) ? row.match.ua_any.join(", ") : "",
        paths: Array.isArray(row?.match?.path_any) ? row.match.path_any.join(", ") : "",
        methods: Array.isArray(row?.match?.methods) ? row.match.methods.join(", ") : "",
        actionType: String(row?.action?.type || "throttle"),
        throttleProfile: String(row?.action?.profile || "soft_bot"),
        note: String(row?.note || ""),
        hasQS: Boolean(row?.match?.has_qs),
        qsNotRx: String(row?.match?.qs_not_rx || ""),
      };
    },
    ruleMatchSummary(row) {
      const m = row?.match || {};
      const parts = [];
      if (Array.isArray(m.country_in) && m.country_in.length) parts.push(`country=${m.country_in.join(",")}`);
      if (Array.isArray(m.methods) && m.methods.length) parts.push(`method=${m.methods.join(",")}`);
      if (Array.isArray(m.ua_any) && m.ua_any.length) parts.push(`ua×${m.ua_any.length}`);
      if (Array.isArray(m.path_any) && m.path_any.length) parts.push(`path×${m.path_any.length}`);
      return parts.length ? parts.join(" | ") : "(no filters)";
    },
    async refreshRules() {
      if (!this.shouldShow("rules")) return;
      const payload = await this.fetchJSONSafe("v1/webdet/rules", { rows: [] });
      this.rules = this.extractRows(payload, "rows");
    },
    async saveRule() {
      let payload;
      try {
        payload = this.buildRulePayload();
      } catch (err) {
        this.actionMsg = `Rule validation failed: ${err}`;
        return;
      }
      try {
        if (this.ruleEditID) {
          await this.postJSON(`v1/webdet/rules/update?id=${encodeURIComponent(this.ruleEditID)}`, payload);
          this.actionMsg = `Rule updated: ${this.ruleEditID}`;
        } else {
          const out = await this.postJSON("v1/webdet/rules/add", payload);
          this.actionMsg = `Rule added: ${out?.rule?.id || "(new)"}`;
        }
        await this.refreshRules();
        this.resetRuleForm();
      } catch (err) {
        this.actionMsg = `Rule save failed: ${err}`;
        console.error("[cfm-admin] rule save failed", err);
      }
    },
    async removeRule(row) {
      const id = String(row?.id || "").trim();
      if (!id) return;
      try {
        await this.postJSON(`v1/webdet/rules/remove?id=${encodeURIComponent(id)}`, {});
        this.actionMsg = `Rule removed: ${id}`;
        await this.refreshRules();
        if (this.ruleEditID === id) this.resetRuleForm();
      } catch (err) {
        this.actionMsg = `Rule remove failed: ${err}`;
        console.error("[cfm-admin] rule remove failed", err);
      }
    },
    applyPreset(presetKey) {
      const host = String(this.vhostFocusHost || this.activeHost || "").trim();
      const baseHost = host || "example.com";
      const set = (form) => {
        this.ruleEditID = "";
        this.ruleForm = { hasQS: false, qsNotRx: "", ...form };
      };
      if (presetKey === "meta_throttle") {
        set({
          enabled: true, priority: 100, vhosts: baseHost, countries: "",
          uas: "*facebookexternalhit*, *meta-externalagent*",
          paths: "", methods: "GET",
          actionType: "throttle", throttleProfile: "soft_bot",
          note: "Preset: Meta crawler soft throttle",
        });
      } else if (presetKey === "challenge_login") {
        set({
          enabled: true, priority: 120, vhosts: baseHost, countries: "",
          uas: "", paths: "/wp-login.php, /xmlrpc.php", methods: "POST",
          actionType: "challenge", throttleProfile: "soft_bot",
          note: "Preset: challenge sensitive login endpoints",
        });
      } else if (presetKey === "block_country") {
        set({
          enabled: false, priority: 200, vhosts: baseHost, countries: "CN, RU",
          uas: "", paths: "", methods: "",
          actionType: "block", throttleProfile: "soft_bot",
          note: "Preset: country block (disabled by default)",
        });
      } else if (presetKey === "throttle_scrapers") {
        set({
          enabled: true, priority: 150, vhosts: baseHost, countries: "",
          uas: "*python-requests*, *python-urllib*, *go-http-client*, *curl*, *wget*",
          paths: "", methods: "GET, POST",
          actionType: "throttle", throttleProfile: "hard_bot",
          note: "Throttle generic script scrapers — hard_bot (0.5 req/s, burst 5)",
        });
      } else if (presetKey === "throttle_ai_crawlers") {
        set({
          enabled: false, priority: 110, vhosts: baseHost, countries: "",
          uas: "*GPTBot*, *ClaudeBot*, *Bytespider*, *CCBot*, *Amazonbot*, *meta-externalagent*",
          paths: "", methods: "GET",
          actionType: "throttle", throttleProfile: "medium_bot",
          note: "Throttle AI training crawlers — medium_bot (1 req/s, burst 10). Start disabled.",
        });
      } else if (presetKey === "throttle_seo_bots") {
        set({
          enabled: true, priority: 130, vhosts: baseHost, countries: "",
          uas: "*AhrefsBot*, *SemrushBot*, *MJ12bot*, *DotBot*, *BLEXBot*, *PetalBot*",
          paths: "", methods: "GET",
          actionType: "throttle", throttleProfile: "soft_bot",
          note: "Throttle commercial SEO crawlers — soft_bot (2 req/s, burst 20)",
        });
      } else if (presetKey === "block_meta_qs") {
        set({
          enabled: false, priority: 80, vhosts: baseHost, countries: "",
          uas: "*facebookexternalhit*, *meta-externalagent*, *GoogleOther*",
          paths: "", methods: "GET",
          actionType: "block", throttleProfile: "",
          note: "Block Meta/GoogleOther bots with unexpected query strings (modsec-style loop prevention)",
          hasQS: true,
          qsNotRx: "(?:^|[&;])(?:fbclid|export|xml)(?:=|[&;]|$)",
        });
      } else if (presetKey === "block_empty_ua") {
        set({
          enabled: true, priority: 50, vhosts: baseHost, countries: "",
          uas: "-", // single dash — exact match for empty UA sent as '-' by nginx
          paths: "", methods: "",
          actionType: "block", throttleProfile: "",
          note: "Block requests with empty/missing User-Agent",
        });
      } else if (presetKey === "block_xmlrpc") {
        set({
          enabled: true, priority: 60, vhosts: baseHost, countries: "",
          uas: "", paths: "/xmlrpc.php", methods: "POST",
          actionType: "block", throttleProfile: "",
          note: "Block xmlrpc.php POST — brute-force amplifier",
        });
      } else if (presetKey === "challenge_wp_admin") {
        set({
          enabled: false, priority: 120, vhosts: baseHost, countries: "",
          uas: "", paths: "/wp-admin/, /wp-login.php", methods: "POST",
          actionType: "challenge", throttleProfile: "",
          note: "Challenge wp-admin / wp-login POST — catches credential stuffing. Validate first.",
        });
      } else if (presetKey === "allow_good_bots") {
        set({
          enabled: true, priority: 10, vhosts: baseHost, countries: "",
          uas: "*Googlebot*, *bingbot*, *Baiduspider*, *Twitterbot*, *LinkedInBot*, *Slackbot*",
          paths: "", methods: "",
          actionType: "allow", throttleProfile: "",
          note: "Allow verified search/social crawlers before any block/challenge rules. Priority 10 runs first.",
        });
      }
    },
    async runRuleSimulation() {
      const req = {
        host: String(this.simulateForm.host || "").trim(),
        ip: String(this.simulateForm.ip || "").trim(),
        ua: String(this.simulateForm.ua || "").trim(),
        path: String(this.simulateForm.path || "/").trim(),
        method: String(this.simulateForm.method || "GET").trim().toUpperCase(),
        country: String(this.simulateForm.country || "").trim().toUpperCase(),
        qs: String(this.simulateForm.qs || "").trim(),
      };
      if (!req.host) {
        this.actionMsg = "Simulation host is required.";
        return;
      }
      try {
        this.simulateResult = await this.postJSON("v1/webdet/rules/simulate", req);
        this.actionMsg = this.simulateResult?.matched
          ? `Simulation matched rule ${this.simulateResult?.rule?.id || ""}`
          : "Simulation: no matching rule.";
      } catch (err) {
        this.actionMsg = `Simulation failed: ${err}`;
        console.error("[cfm-admin] rule simulation failed", err);
      }
    },
  },
};
