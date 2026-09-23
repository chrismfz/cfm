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
      // Challenge tier applied by the same buttons. v2 = ChallengeV2: the
      // SAME challenge page is served, but a solve must also pass the passive
      // humanity check to earn clearance (headless farms solve for nothing).
      challengeRung: "v1",
      challengeRungChoices: [
        { value: "v1", label: "challenge" },
        { value: "v2", label: "challenge v2" },
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
          state: String(row.state || ""),
          // ChallengeV2 tier of the covering manual challenge ("v2" or "");
          // decorated by the daemon from its manual store (the verify gate's
          // own source). Shown in the mode pill so the operator can SEE a
          // host is v2-armed before clicking a Challenge button whose picker
          // would explicitly re-tier it (third-review observation).
          rung: String(row.rung || ""),
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
      const v2 = s.rung === "v2" ? " · v2" : "";
      if (s.manual_active && s.auto_active) return "manual+auto" + v2;
      if (s.manual_active) return "manual" + v2;
      if (s.auto_active) return "auto" + v2;
      return "";
    },
    // Under-Attack Mode (I1b): true when the vhost has been escalated above
    // CHALLENGED (the challenge is being defeated, or an operator forced it).
    // Like the `challenged` pill this reads activeChallengeByHost, which on the
    // admin path is store-driven (v1/challenge/vhosts, effectively-active only);
    // a vhost force-escalated with no challenge row therefore badges via the
    // controls knob and the scoped per-host path, but not this admin card — the
    // same store-driven limitation the backend documents for the vhost list.
    underAttackState(host) {
      const s = this.activeChallengeByHost[host] || {};
      return s.state === "under_attack";
    },
    async fetchScopedActiveChallengeVhosts() {
      if (!this.hasScopedVhosts) return [];
      const checks = this.allowedVhosts.map(async (host) => {
        const status = await this.fetchJSONSafe(`v1/challenge/vhost/status?host=${encodeURIComponent(host)}`, null);
        if (!status || typeof status !== "object") return null;
        const manualActive = Boolean(status.manual_active);
        const autoActive = Boolean(status.auto_active);
        const underAttack = String(status.state || "") === "under_attack";
        // Keep an under-attack row even when no challenge is active (an operator
        // may have forced it) so the badge still shows for scoped tenants.
        if (!manualActive && !autoActive && !underAttack) return null;
        let mode = "";
        if (manualActive && autoActive) mode = "manual+auto";
        else if (manualActive) mode = "manual";
        else if (autoActive) mode = "auto";
        return {
          host: String(status.host || host),
          mode,
          manual_active: manualActive,
          auto_active: autoActive,
          state: String(status.state || ""),
          rung: String(status.rung || ""), // v2 tier rides the scoped status too
          reason: status.reason,
          expires_at: status.expires_at,
          auto_since: status.auto_since,
          solver_farm: Boolean(status.solver_farm),
          shadow_outliers: Number(status.shadow_outliers) || 0,
          query_cardinality: Number(status.query_cardinality) || 0,
          cost_pressure: Number(status.cost_pressure) || 0,
          dc_fraction: Number(status.dc_fraction) || 0,
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
    // tier: the Tier-picker value, passed ONLY by call sites that RENDER the
    // picker (the `suspicious` partial). Every other Challenge button omits it
    // → no `rung` in the payload → the server PRESERVES an existing v2 arm
    // (an explicit rung would silently re-tier it — second-review finding).
    async toggleChallenge(host, tier) {
      if (!host) return;
      try {
        if (this.challengeState(host)) {
          await this.postJSON("v1/challenge/vhost/remove", { host });
          this.actionMsg = `Challenge removed for ${host}`;
        } else {
          const body = { host, ttl: this.challengeTTL, reason: "cfm-admin-ui" };
          if (typeof tier === "string" && tier) body.rung = tier;
          await this.postJSON("v1/challenge/vhost/add", body);
          this.actionMsg = `Challenge enabled for ${host} (${this.challengeTTLLabel}${body.rung ? ", " + body.rung : ""})`;
        }
        await this.refreshChallengeVhosts();
      } catch (err) {
        this.actionMsg = `Challenge action failed for ${host}: ${err}`;
        console.error("[cfm-admin] challenge action failed", err);
      }
    },
    async manualChallenge(host, tier) {
      if (!host) return;
      try {
        const body = { host, ttl: this.challengeTTL, reason: "cfm-admin-ui-manual" };
        if (typeof tier === "string" && tier) body.rung = tier;
        await this.postJSON("v1/challenge/vhost/add", body);
        this.actionMsg = `Manual challenge enabled for ${host} (${this.challengeTTLLabel}${body.rung ? ", " + body.rung : ""})`;
        await this.refreshChallengeVhosts();
      } catch (err) {
        this.actionMsg = `Manual challenge failed for ${host}: ${err}`;
        console.error("[cfm-admin] manual challenge failed", err);
      }
    },
    // Tier switch for a vhost that is ALREADY challenged (v1 <-> v2):
    //  - a manual arm is re-tiered in place via v1/challenge/vhost/rung, which
    //    keeps its expiry and reason (a re-arm through vhost/add would reset
    //    both);
    //  - an auto-only challenge has no tier of its own, so "→ v2" arms a
    //    MANUAL v2 challenge for the page's TTL on top of it (it then outlives
    //    the scorer until it expires or is disarmed — the label says so).
    challengeTierTarget(host) {
      const s = this.activeChallengeByHost[host] || {};
      if (s.manual_active) return s.rung === "v2" ? "v1" : "v2";
      if (s.auto_active) return "v2";
      return "";
    },
    challengeTierButtonLabel(host) {
      const s = this.activeChallengeByHost[host] || {};
      const to = this.challengeTierTarget(host);
      if (!to) return "";
      return s.manual_active ? `→ ${to}` : "→ v2 (manual)";
    },
    challengeTierButtonTitle(host) {
      const s = this.activeChallengeByHost[host] || {};
      if (s.manual_active) {
        return s.rung === "v2"
          ? "Switch this manual challenge back to plain v1 (keeps its expiry)"
          : "Switch this manual challenge to v2: solves must also pass the passive humanity check (keeps its expiry)";
      }
      return `Auto challenges have no tier: arm a MANUAL v2 challenge for ${this.challengeTTLLabel} on top of the auto one`;
    },
    async toggleChallengeTier(host) {
      const to = this.challengeTierTarget(host);
      if (!host || !to) return;
      const s = this.activeChallengeByHost[host] || {};
      try {
        if (s.manual_active) {
          const res = await this.postJSON("v1/challenge/vhost/rung", { host, rung: to });
          this.actionMsg = `Challenge on ${res?.host || host} switched ${res?.from || "?"} → ${res?.rung || to} (expiry kept)`;
        } else {
          const res = await this.postJSON("v1/challenge/vhost/add", {
            host, ttl: this.challengeTTL, rung: to, reason: "cfm-admin-ui-tier",
          });
          this.actionMsg = `Manual ${res?.rung || to} challenge armed on ${host} for ${res?.ttl || this.challengeTTLLabel}` +
            (res?.ttl_capped ? " (capped to the 24h customer limit)" : "");
        }
        await this.refreshChallengeVhosts();
      } catch (err) {
        this.actionMsg = `Tier switch failed for ${host}: ${err}`;
        console.error("[cfm-admin] challenge tier switch failed", host, err);
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
