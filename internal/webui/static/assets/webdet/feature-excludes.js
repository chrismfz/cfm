// Dynamic Challenge/WAF excludes: the shared excludes card state, add/remove
// actions and the scoped-token guardrails (path-type hiding, host scoping).

export const excludesMixin = {
  data() {
    return {
      challengeExcludes: [],
      wafExcludes: [],
      challengeExcludeValue: "",
      challengeExcludeType: "host",
      wafExcludeValue: "",
      wafExcludeType: "host",
    };
  },

  methods: {
    async refreshExcludeLists() {
      const [challengeExcludes, wafExcludes] = await Promise.all([
        this.fetchJSONSafe("v1/challenge/exclude/list", []),
        this.fetchJSONSafe("v1/waf/exclude/list", []),
      ]);
      this.challengeExcludes = this.extractRows(challengeExcludes, "rows");
      this.wafExcludes = this.extractRows(wafExcludes, "rows");
    },
    enforceScopedExcludeControls() {
      if (!this.isScoped) {
        document.querySelectorAll('select option[value="path"]').forEach((opt) => {
          opt.hidden = false;
          opt.disabled = false;
        });
        return;
      }
      const firstAllowed = this.allowedVhosts[0] || "";
      if (!this.scopedPathExcludeAllowed) {
        if (this.challengeExcludeType === "path") this.challengeExcludeType = "host";
        if (this.wafExcludeType === "path") this.wafExcludeType = "host";
      }
      if (firstAllowed && this.challengeExcludeType === "host" && !String(this.challengeExcludeValue || "").trim()) {
        this.challengeExcludeValue = firstAllowed;
      }
      if (firstAllowed && this.wafExcludeType === "host" && !String(this.wafExcludeValue || "").trim()) {
        this.wafExcludeValue = firstAllowed;
      }
      const hidePath = !this.scopedPathExcludeAllowed;
      document.querySelectorAll('select option[value="path"]').forEach((opt) => {
        opt.hidden = hidePath;
        opt.disabled = hidePath;
      });
    },
    async addExclude(scope) {
      const isChallenge = scope === "challenge";
      const value = (isChallenge ? this.challengeExcludeValue : this.wafExcludeValue).trim();
      const type = isChallenge ? this.challengeExcludeType : this.wafExcludeType;
      if (!value) {
        this.actionMsg = `Provide a value for ${scope} exclude.`;
        return;
      }
      if (this.isScoped) {
        if (!this.scopedPathExcludeAllowed && type === "path") {
          this.actionMsg = `${scope.toUpperCase()} exclude add failed: scoped tokens are limited to type=host.`;
          return;
        }
        if (type === "host" && !this.isHostAllowedByScope(value)) {
          this.actionMsg = `${scope.toUpperCase()} exclude add failed: host is outside token scope (${this.allowedVhosts.join(", ") || "none"}).`;
          return;
        }
      }
      try {
        await this.postJSON(`v1/${scope}/exclude/add?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`, {});
        this.actionMsg = `${scope.toUpperCase()} exclude added: ${type}=${value}`;
        if (isChallenge) this.challengeExcludeValue = "";
        else this.wafExcludeValue = "";
        await this.refreshExcludeLists();
        await this.refreshHistory?.();
      } catch (err) {
        this.actionMsg = `${scope.toUpperCase()} exclude add failed: ${this.formatApiError(err)}`;
        console.error("[cfm-admin] exclude add failed", scope, err);
      }
    },
    async removeExclude(scope, entry) {
      if (!entry?.value || !entry?.type) return;
      if (this.isScoped && entry.type === "host" && !this.isHostAllowedByScope(entry.value)) {
        this.actionMsg = `${scope.toUpperCase()} exclude remove failed: host is outside token scope (${this.allowedVhosts.join(", ") || "none"}).`;
        return;
      }
      try {
        await this.postJSON(`v1/${scope}/exclude/remove?type=${encodeURIComponent(entry.type)}&value=${encodeURIComponent(entry.value)}`, {});
        this.actionMsg = `${scope.toUpperCase()} exclude removed: ${entry.type}=${entry.value}`;
        await this.refreshExcludeLists();
        await this.refreshHistory?.();
      } catch (err) {
        this.actionMsg = `${scope.toUpperCase()} exclude remove failed: ${this.formatApiError(err)}`;
        console.error("[cfm-admin] exclude remove failed", scope, err);
      }
    },
  },

  watch: {
    isScopedMode() { this.enforceScopedExcludeControls(); },
    scopedPathExcludeAllowed() { this.enforceScopedExcludeControls(); },
    challengeExcludeType() { this.enforceScopedExcludeControls(); },
    wafExcludeType() { this.enforceScopedExcludeControls(); },
    allowedVhosts() { this.enforceScopedExcludeControls(); },
  },
};
