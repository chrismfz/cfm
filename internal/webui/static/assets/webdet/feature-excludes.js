// Dynamic Challenge/WAF excludes: the shared excludes card state, add/remove
// actions and the scoped-token guardrails (path-type gating, host scoping).

import {
  parseScopeHosts,
  pathTypeAllowed,
  literalVhosts,
  looksLikeHostValue,
  challengePathScopeError,
  formatChallengeExcludeScope,
} from "./excludes-model.js";

export const excludesMixin = {
  data() {
    return {
      challengeExcludes: [],
      wafExcludes: [],
      challengeExcludeValue: "",
      challengeExcludeType: "host",
      wafExcludeValue: "",
      wafExcludeType: "host",
      // Comma-separated WAF rule-id spec (e.g. "402" or "401,431-436"). Empty
      // means a legacy whole-WAF exclude (all rules). WAF-only: challenge
      // excludes have no per-rule scoping.
      wafExcludeRules: "",
      // Comma-separated vhost(s) to scope the WAF exclude to (admin only).
      // Empty = all vhosts. The server ignores this for scoped tokens (they
      // are always pinned to their own vhost set), so the input is hidden for
      // scoped users.
      wafExcludeScope: "",
      // Comma-separated vhost(s) a challenge PATH exclude applies to (each
      // also covers its www. alias). Required: an admin names any vhost, a
      // scoped session one or more of its own (prefilled with its first).
      challengeExcludeScope: "",
      // The scope the card prefilled for a tenant, so a switch to an admin
      // session can drop it (and only it).
      challengeScopePrefill: "",
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
    // Render an exclude row's rule scope for the table: "*" when it is a
    // whole-WAF entry (no rule_ids), otherwise the comma-joined rule IDs.
    formatExcludeRules(ids) {
      const a = Array.isArray(ids) ? ids : [];
      return a.length ? a.join(", ") : "*";
    },
    // Render an exclude row's vhost scope: "*" = all vhosts (admin-global),
    // otherwise the comma-joined host list.
    formatExcludeScope(hosts) {
      const a = Array.isArray(hosts) ? hosts : [];
      return a.length ? a.join(", ") : "*";
    },
    formatChallengeExcludeScope(row) {
      return formatChallengeExcludeScope(row);
    },
    // type=path for this card in this session: always for an admin; for a
    // scoped session challenge path excludes only (the malpath carve-out on
    // its own vhosts), never WAF path excludes.
    pathTypeAllowedFor(kind) {
      return pathTypeAllowed(kind, {
        isScoped: this.isScoped,
        scopedExcludeManagementAllowed: this.scopedExcludeManagementAllowed,
        allowedVhosts: this.allowedVhosts,
      });
    },
    enforceScopedExcludeControls() {
      if (this.challengeExcludeType === "path" && !this.pathTypeAllowedFor("challenge")) this.challengeExcludeType = "host";
      if (this.wafExcludeType === "path" && !this.pathTypeAllowedFor("waf")) this.wafExcludeType = "host";
      // A host left in the value box (the type=host prefill) is not a path.
      if (this.challengeExcludeType === "path" && looksLikeHostValue(this.challengeExcludeValue)) this.challengeExcludeValue = "";
      // A scope the session can no longer use (a mode or token change): drop
      // it, so the admin form never carries a tenant's prefill or vice versa.
      const scope = parseScopeHosts(this.challengeExcludeScope);
      if (scope.length && (this.isScoped
        ? challengePathScopeError(scope, { isScoped: true, allowedVhosts: this.allowedVhosts })
        : scope.join(",") === this.challengeScopePrefill)) {
        this.challengeExcludeScope = "";
      }
      if (!this.isScoped) return;
      const firstAllowed = this.allowedVhosts[0] || "";
      const firstLiteral = literalVhosts(this.allowedVhosts)[0] || "";
      if (firstAllowed && this.challengeExcludeType === "host" && !String(this.challengeExcludeValue || "").trim()) {
        this.challengeExcludeValue = firstAllowed;
      }
      if (firstLiteral && this.challengeExcludeType === "path" && !String(this.challengeExcludeScope || "").trim()) {
        this.challengeExcludeScope = firstLiteral;
        this.challengeScopePrefill = firstLiteral;
      }
      if (firstAllowed && this.wafExcludeType === "host" && !String(this.wafExcludeValue || "").trim()) {
        this.wafExcludeValue = firstAllowed;
      }
    },
    async addExclude(scope) {
      const isChallenge = scope === "challenge";
      const value = (isChallenge ? this.challengeExcludeValue : this.wafExcludeValue).trim();
      const type = isChallenge ? this.challengeExcludeType : this.wafExcludeType;
      if (!value) {
        this.actionMsg = `Provide a value for ${scope} exclude.`;
        return;
      }
      if (type === "path" && !this.pathTypeAllowedFor(scope)) {
        this.actionMsg = `${scope.toUpperCase()} exclude add failed: type=path is not available to this token here.`;
        return;
      }
      let challengeScope = [];
      if (isChallenge && type === "path") {
        challengeScope = parseScopeHosts(this.challengeExcludeScope);
        const err = challengePathScopeError(challengeScope, { isScoped: this.isScoped, allowedVhosts: this.allowedVhosts });
        if (err) {
          this.actionMsg = `CHALLENGE exclude add failed: ${err}.`;
          return;
        }
      }
      if (this.isScoped) {
        if (type === "host" && !this.isHostAllowedByScope(value)) {
          this.actionMsg = `${scope.toUpperCase()} exclude add failed: host is outside token scope (${this.allowedVhosts.join(", ") || "none"}).`;
          return;
        }
      }
      try {
        // rule_ids is WAF-only and optional. When present, the server adds a
        // rule-scoped exclude (WAF still runs; only these rule IDs are
        // suppressed); when absent it stays a whole-WAF exclude.
        const rules = isChallenge ? "" : String(this.wafExcludeRules || "").trim();
        // scope_hosts: WAF (admin-only; the server ignores it for scoped
        // tokens, whose input is hidden) and challenge PATH excludes (always
        // sent: required for an admin, and a scoped session narrows its entry
        // to the sites it picked instead of every vhost of the account).
        const scopeHosts = isChallenge
          ? challengeScope.join(",")
          : String(this.wafExcludeScope || "").trim();
        let path = `v1/${scope}/exclude/add?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`;
        if (rules) path += `&rule_ids=${encodeURIComponent(rules)}`;
        if (scopeHosts) path += `&scope_hosts=${encodeURIComponent(scopeHosts)}`;
        await this.postJSON(path, {});
        this.actionMsg = `${scope.toUpperCase()} exclude added: ${type}=${value}${rules ? ` rules=${rules}` : ""}${scopeHosts ? ` scope=${scopeHosts}` : ""}`;
        if (isChallenge) {
          this.challengeExcludeValue = "";
          this.challengeExcludeScope = "";
          // The type did not change, so no watcher re-runs the prefill.
          this.enforceScopedExcludeControls();
        } else {
          this.wafExcludeValue = "";
          this.wafExcludeRules = "";
          this.wafExcludeScope = "";
        }
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
        // A rule-scoped entry is keyed by its exact rule-id set on the server,
        // so removal must echo the row's rule_ids; a whole-WAF entry has none.
        let path = `v1/${scope}/exclude/remove?type=${encodeURIComponent(entry.type)}&value=${encodeURIComponent(entry.value)}`;
        const ids = Array.isArray(entry.rule_ids) ? entry.rule_ids : [];
        if (ids.length) path += `&rule_ids=${encodeURIComponent(ids.join(","))}`;
        // Echo the row's scope so a scope-qualified entry (keyed by its host
        // set on the server) is the one removed, not a same-value global entry.
        const hosts = Array.isArray(entry.scope_hosts) ? entry.scope_hosts : [];
        if (hosts.length) path += `&scope_hosts=${encodeURIComponent(hosts.join(","))}`;
        await this.postJSON(path, {});
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
    scopedExcludeManagementAllowed() { this.enforceScopedExcludeControls(); },
    challengeExcludeType() { this.enforceScopedExcludeControls(); },
    wafExcludeType() { this.enforceScopedExcludeControls(); },
    allowedVhosts() { this.enforceScopedExcludeControls(); },
  },
};
