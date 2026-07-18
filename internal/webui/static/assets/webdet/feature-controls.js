// Vhost controls page: per-vhost WAF/Challenge/HTTP3 toggles, traffic rules
// (form, presets, simulation), scoped-token management and the per-vhost
// security overview.

export const controlsMixin = {
  data() {
    return {
      vhostControls: [],
      controlsSearch: "",
      controlsSortKey: "host",
      controlsSortDir: "asc",
      vhostControlsLimit: 50,
      // Quick filter chips: "" (all) | challenge_off | waf_off | http3_on —
      // the deviations-from-default an operator actually scans 690 vhosts for.
      controlsQuickFilter: "",
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
      // Token management (admin only)
      tokens: [],
      tokenForm: { vhosts: "", label: "", ttl: "8760h", role: "viewer" },
      tokenCreateMsg: "",
      // Per-vhost Security Overview
      vhostOverview: null,
      vhostOverviewHost: "",
      vhostOverviewHours: 24,
    };
  },

  computed: {
    controlsCounts() {
      let challengeOff = 0;
      let wafOff = 0;
      let http3On = 0;
      for (const row of this.vhostControls) {
        if (!row?.challenge_enabled) challengeOff++;
        if (!row?.waf_enabled) wafOff++;
        if (row?.http3_enabled) http3On++;
      }
      return { challengeOff, wafOff, http3On };
    },
    vhostControlsFiltered() {
      const q = String(this.controlsSearch || "").trim().toLowerCase();
      let filtered = !q
        ? this.vhostControls.slice()
        : this.vhostControls.filter((row) => String(row?.host || "").toLowerCase().includes(q));
      const quick = this.controlsQuickFilter;
      if (quick === "challenge_off") filtered = filtered.filter((row) => !row?.challenge_enabled);
      else if (quick === "waf_off") filtered = filtered.filter((row) => !row?.waf_enabled);
      else if (quick === "http3_on") filtered = filtered.filter((row) => row?.http3_enabled);
      const key = String(this.controlsSortKey || "host");
      const dir = this.controlsSortDir === "desc" ? -1 : 1;
      const boolOrder = (v) => (v ? 1 : 0);
      filtered.sort((a, b) => {
        if (key === "challenge") {
          const cmp = boolOrder(Boolean(a?.challenge_enabled)) - boolOrder(Boolean(b?.challenge_enabled));
          if (cmp !== 0) return cmp * dir;
        } else if (key === "waf") {
          const cmp = boolOrder(Boolean(a?.waf_enabled)) - boolOrder(Boolean(b?.waf_enabled));
          if (cmp !== 0) return cmp * dir;
        } else if (key === "http3") {
          const cmp = boolOrder(Boolean(a?.http3_enabled)) - boolOrder(Boolean(b?.http3_enabled));
          if (cmp !== 0) return cmp * dir;
        } else {
          const cmpHost = String(a?.host || "").localeCompare(String(b?.host || ""), undefined, { sensitivity: "base" });
          if (cmpHost !== 0) return cmpHost * dir;
        }
        return String(a?.host || "").localeCompare(String(b?.host || ""), undefined, { sensitivity: "base" });
      });
      const lim = Number(this.vhostControlsLimit) || 50;
      return lim > 0 ? filtered.slice(0, lim) : filtered;
    },
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
    // ── Per-vhost protection toggles ───────────────────────────────────
    vhostControlEnabled(row, kind) {
      let key;
      if (kind === "challenge") key = "challenge_enabled";
      else if (kind === "waf") key = "waf_enabled";
      else if (kind === "http3") key = "http3_enabled";
      else return false;
      return Boolean(row?.[key]);
    },
    vhostControlToggleable(row, kind) {
      let key;
      if (kind === "challenge") key = "challenge_toggleable";
      else if (kind === "waf") key = "waf_toggleable";
      else if (kind === "http3") key = "http3_toggleable";
      else return false;
      return Boolean(row?.[key]);
    },
    vhostControlMatchedExclude(row, kind) {
      let key;
      if (kind === "challenge") key = "challenge_matched_exclude";
      else if (kind === "waf") key = "waf_matched_exclude";
      else if (kind === "http3") key = "http3_matched_optin";
      else return "";
      return String(row?.[key] || "").trim();
    },
    vhostControlButtonLabel(row, kind) {
      const enabled = this.vhostControlEnabled(row, kind);
      const toggleable = this.vhostControlToggleable(row, kind);
      // HTTP/3 uses opt-in semantics: default is OFF, presence = ON.
      // The labels reflect the actual state — same wording as WAF/Challenge.
      if (kind === "http3") {
        if (enabled) return "ON / ENABLED";
        return toggleable ? "OFF / DEFAULT" : "ON / MATCHED BY PATTERN";
      }
      if (enabled) return "ON / ENABLED";
      return toggleable ? "OFF / DISABLED" : "OFF / MATCHED BY PATTERN";
    },
    vhostControlButtonTitle(row, kind) {
      const enabled = this.vhostControlEnabled(row, kind);
      const matched = this.vhostControlMatchedExclude(row, kind);
      const toggleable = this.vhostControlToggleable(row, kind);
      if (kind === "http3") {
        if (!enabled) {
          return "HTTP/3 (Alt-Svc) is OFF by default. Click to enable for this vhost.";
        }
        if (!matched) return "HTTP/3 (Alt-Svc) enabled for this vhost.";
        if (toggleable) return `HTTP/3 enabled via host opt-in: ${matched}`;
        return `HTTP/3 enabled via wildcard opt-in: ${matched}. Remove/edit that wildcard via CLI to change.`;
      }
      if (enabled) return "";
      if (!matched) return "";
      if (toggleable) return `Excluded by host rule: ${matched}`;
      return `Excluded by non-exact host rule: ${matched}. Remove/edit that rule in Dynamic excludes first.`;
    },
    setControlsQuickFilter(key) {
      this.controlsQuickFilter = this.controlsQuickFilter === key ? "" : key;
    },
    setControlsSort(nextKey) {
      const key = String(nextKey || "").trim().toLowerCase();
      if (!key) return;
      if (this.controlsSortKey === key) {
        this.controlsSortDir = this.controlsSortDir === "asc" ? "desc" : "asc";
        return;
      }
      this.controlsSortKey = key;
      this.controlsSortDir = "asc";
    },
    controlsSortArrow(key) {
      if (this.controlsSortKey !== key) return "";
      return this.controlsSortDir === "asc" ? "↑" : "↓";
    },
    async refreshVhostControls() {
      if (!this.shouldShow("controls")) return;
      const url = new URL(window.location.href);
      const scoped = (url.searchParams.get("vhost") || url.searchParams.get("vhosts") || "").trim();
      const qs = scoped ? `?vhost=${encodeURIComponent(scoped)}` : "";
      const payload = await this.fetchJSONSafe(`v1/webdet/vhosts${qs}`, { rows: [] });
      this.vhostControls = this.extractRows(payload, "rows");
    },
    async toggleVhostProtection(row, kind) {
      const host = String(row?.host || "").trim();
      if (!host) return;
      const currentlyEnabled = this.vhostControlEnabled(row, kind);
      const toggleable = this.vhostControlToggleable(row, kind);
      if (!toggleable) {
        const matched = this.vhostControlMatchedExclude(row, kind);
        if (kind === "http3") {
          this.actionMsg = `HTTP/3 for ${host} is enabled by wildcard opt-in (${matched || "pattern"}). Remove/edit it via CLI to change.`;
        } else {
          this.actionMsg = `${kind.toUpperCase()} for ${host} is disabled by non-exact exclude (${matched || "pattern"}). Remove/edit it in Dynamic excludes first.`;
        }
        return;
      }
      try {
        if (kind === "http3") {
          // HTTP/3 uses an opt-in API: enable adds the host, disable removes it.
          // Opposite of WAF/Challenge which add to an exclude list to disable.
          const endpoint = currentlyEnabled ? "disable" : "enable";
          await this.postJSON(`v1/http3/${endpoint}?host=${encodeURIComponent(host)}`, {});
          this.actionMsg = `HTTP/3 ${currentlyEnabled ? "disabled" : "enabled"} for ${host}`;
        } else if (currentlyEnabled) {
          await this.postJSON(`v1/${kind}/exclude/add?type=host&value=${encodeURIComponent(host)}`, {});
          this.actionMsg = `${kind.toUpperCase()} disabled for ${host}`;
        } else {
          await this.postJSON(`v1/${kind}/exclude/remove?type=host&value=${encodeURIComponent(host)}`, {});
          this.actionMsg = `${kind.toUpperCase()} enabled for ${host}`;
        }
        await this.refreshVhostControls();
      } catch (err) {
        this.actionMsg = `${kind.toUpperCase()} toggle failed for ${host}: ${err}`;
        console.error("[cfm-admin] vhost controls toggle failed", kind, host, err);
      }
    },

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
      if (!this.shouldShow("controls")) return;
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

    // ── Token management (admin only) ──────────────────────────────────
    async refreshTokens() {
      if (!this.isAdmin) return;
      try {
        const rows = await this.fetchJSONSafe("v1/tokens/list", []);
        this.tokens = Array.isArray(rows) ? rows : [];
      } catch (_) { this.tokens = []; }
    },
    async createScopedToken() {
      this.tokenCreateMsg = "";
      const vhosts = this.tokenForm.vhosts.split(",").map((v) => v.trim()).filter(Boolean);
      if (!vhosts.length) { this.tokenCreateMsg = "Vhosts required."; return; }
      try {
        const res = await this.postJSON("v1/auth/token", {
          vhosts,
          label: this.tokenForm.label,
          ttl: this.tokenForm.ttl || "8760h",
          role: this.tokenForm.role || "viewer",
        });
        if (res.error) { this.tokenCreateMsg = res.error; return; }
        this.tokenCreateMsg = `✓ Created: ${res.id}  Token: ${res.token}`;
        await this.refreshTokens();
      } catch (err) { this.tokenCreateMsg = String(err); }
    },
    async revokeToken(id) {
      if (!confirm(`Revoke token ${id}?`)) return;
      try {
        const res = await this.postJSON("v1/tokens/revoke", { id });
        if (res.error) { this.tokenCreateMsg = res.error; return; }
        this.tokenCreateMsg = `✓ Revoked ${id}`;
        await this.refreshTokens();
      } catch (err) { this.tokenCreateMsg = String(err); }
    },

    // ── Security Overview ──────────────────────────────────────────────
    async refreshVhostOverview() {
      const host = String(this.vhostOverviewHost || "").trim();
      if (!host) { this.vhostOverview = null; return; }
      try {
        this.vhostOverview = await this.fetchJSONSafe(
          `v1/webdet/history/vhost-overview?host=${encodeURIComponent(host)}&hours=${this.vhostOverviewHours}`,
          null,
        );
      } catch (_) { this.vhostOverview = null; }
    },
  },
};
