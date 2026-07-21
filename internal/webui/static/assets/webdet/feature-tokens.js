// API tokens page (admin-only): issue and revoke scoped viewer tokens for
// panel plugins (cPanel, DirectAdmin, …). Extracted from the vhost-controls
// page — same /api/v1/auth/token + /api/v1/tokens/* API. The page is in
// ADMIN_ONLY_NAV_PATHS and the "tokens" section is hidden for scoped users
// (core.js shouldShow), matching the backend's admin-only enforcement.

export const tokensMixin = {
  data() {
    return {
      tokens: [],
      tokenForm: { vhosts: "", label: "", ttl: "8760h", role: "viewer" },
      tokenCreateMsg: "",
    };
  },

  methods: {
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
  },
};
