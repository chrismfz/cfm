// Challenge state + actions: the per-vhost manual/auto challenge status map,
// TTL picker state, and every Challenge/Unchallenge button handler. Defined
// once here — previously duplicated across page copies.

export const challengeMixin = {
  data() {
    return {
      activeChallengeVhosts: [],
      // TTL applied by the Challenge / Manual challenge buttons
      // (v1/challenge/vhost/add; server default is 30m).
      challengeTTL: "30m",
      challengeTTLChoices: [
        { value: "30m", label: "30m" },
        { value: "1h", label: "1h" },
        { value: "2h", label: "2h" },
        { value: "6h", label: "6h" },
        { value: "24h", label: "24h" },
      ],
    };
  },

  computed: {
    challengeTTLLabel() {
      const c = this.challengeTTLChoices.find((x) => x.value === this.challengeTTL);
      return c ? c.label : this.challengeTTL;
    },
    activeChallengeByHost() {
      const byHost = {};
      const rows = Array.isArray(this.activeChallengeVhosts) ? this.activeChallengeVhosts : [];
      for (const row of rows) {
        const host = row?.host;
        if (!host) continue;
        const mode = String(row.mode || "").toLowerCase();
        byHost[host] = {
          manual_active: mode === "manual" || mode === "manual+auto",
          auto_active: mode === "auto" || mode === "manual+auto",
          mode,
        };
      }
      return byHost;
    },
  },

  methods: {
    challengeState(host) {
      const s = this.activeChallengeByHost[host] || {};
      return Boolean(s.manual_active || s.auto_active);
    },
    challengeModeLabel(host) {
      const s = this.activeChallengeByHost[host] || {};
      if (s.manual_active && s.auto_active) return "manual+auto";
      if (s.manual_active) return "manual";
      if (s.auto_active) return "auto";
      return "";
    },
    async fetchScopedActiveChallengeVhosts() {
      if (!this.hasScopedVhosts) return [];
      const checks = this.allowedVhosts.map(async (host) => {
        const status = await this.fetchJSONSafe(`v1/challenge/vhost/status?host=${encodeURIComponent(host)}`, null);
        if (!status || typeof status !== "object") return null;
        const manualActive = Boolean(status.manual_active);
        const autoActive = Boolean(status.auto_active);
        if (!manualActive && !autoActive) return null;
        let mode = "";
        if (manualActive && autoActive) mode = "manual+auto";
        else if (manualActive) mode = "manual";
        else if (autoActive) mode = "auto";
        return {
          host: String(status.host || host),
          mode,
          manual_active: manualActive,
          auto_active: autoActive,
          reason: status.reason,
          expires_at: status.expires_at,
          auto_since: status.auto_since,
          solver_farm: Boolean(status.solver_farm),
        };
      });
      const rows = await Promise.all(checks);
      return rows.filter(Boolean);
    },
    // Refresh the active-challenge list (scoped tokens poll per-vhost status).
    async refreshChallengeVhosts() {
      const rows = this.isScoped
        ? await this.fetchScopedActiveChallengeVhosts()
        : await this.fetchJSONSafe("v1/challenge/vhosts?status=active&mode=all&limit=500", []);
      this.activeChallengeVhosts = this.extractRows(rows, "rows");
      return this.activeChallengeVhosts;
    },
    async toggleChallenge(host) {
      if (!host) return;
      try {
        if (this.challengeState(host)) {
          await this.postJSON("v1/challenge/vhost/remove", { host });
          this.actionMsg = `Challenge removed for ${host}`;
        } else {
          await this.postJSON("v1/challenge/vhost/add", { host, ttl: this.challengeTTL, reason: "cfm-admin-ui" });
          this.actionMsg = `Challenge enabled for ${host} (${this.challengeTTLLabel})`;
        }
        await this.refreshChallengeVhosts();
      } catch (err) {
        this.actionMsg = `Challenge action failed for ${host}: ${err}`;
        console.error("[cfm-admin] challenge action failed", err);
      }
    },
    async manualChallenge(host) {
      if (!host) return;
      try {
        await this.postJSON("v1/challenge/vhost/add", { host, ttl: this.challengeTTL, reason: "cfm-admin-ui-manual" });
        this.actionMsg = `Manual challenge enabled for ${host} (${this.challengeTTLLabel})`;
        await this.refreshChallengeVhosts();
      } catch (err) {
        this.actionMsg = `Manual challenge failed for ${host}: ${err}`;
        console.error("[cfm-admin] manual challenge failed", err);
      }
    },
    async manualUnchallenge(host) {
      if (!host) return;
      try {
        await this.postJSON("v1/challenge/vhost/remove", { host });
        this.actionMsg = `Manual challenge removed for ${host}`;
        await this.refreshChallengeVhosts();
      } catch (err) {
        this.actionMsg = `Manual unchallenge failed for ${host}: ${err}`;
        console.error("[cfm-admin] manual unchallenge failed", err);
      }
    },
    async challengeIPTopHost(ip) {
      if (!ip) return;
      try {
        const details = await this.fetchJSON(`v1/webdet/ip-drilldown?ip=${encodeURIComponent(ip)}`);
        const topHost = Array.isArray(details?.hosts) ? details.hosts[0]?.key : "";
        if (!topHost) {
          this.actionMsg = `No host found for IP ${ip} to challenge`;
          return;
        }
        await this.manualChallenge(topHost);
        this.actionMsg = `Manual challenge enabled for top host ${topHost} (IP ${ip}, ${this.challengeTTLLabel})`;
      } catch (err) {
        this.actionMsg = `Challenge failed for IP ${ip}: ${err}`;
        console.error("[cfm-admin] challenge from IP failed", err);
      }
    },
  },
};
