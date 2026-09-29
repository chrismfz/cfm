// Challenge state + actions: the per-vhost manual/auto challenge status map,
// TTL picker state, and every Challenge/Unchallenge button handler. Defined
// once here — previously duplicated across page copies.

import {
  tierButtonLabel,
  tierButtonTitle,
  tierSuffix,
  tierSwitchRequest,
  tierSwitchTarget,
  tierTitle,
  tierUnpinRequest,
  tierUnpinnable,
} from "./challenge-tier.js";

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
          // The host's EFFECTIVE ChallengeV2 tier ("v2" or "") and what
          // decided it (manual arm / operator pin / CHALLENGE_V2_AUTO_VHOST),
          // decorated by the daemon from the verify gate's own resolver.
          // Shown in the mode pill so the operator can SEE a host is v2 —
          // including an automatic challenge — before clicking a Challenge
          // button whose picker would explicitly re-tier it.
          rung: String(row.rung || ""),
          rung_source: String(row.rung_source || ""),
          rung_trigger: String(row.rung_trigger || ""),
          rung_pin: String(row.rung_pin || ""),
          rung_pin_locked: Boolean(row.rung_pin_locked),
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
      const tier = tierSuffix(s);
      if (s.manual_active && s.auto_active) return "manual+auto" + tier;
      if (s.manual_active) return "manual" + tier;
      if (s.auto_active) return "auto" + tier;
      return "";
    },
    challengeModeTitle(host) {
      return tierTitle(this.activeChallengeByHost[host] || {});
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
          // the resolved tier rides the scoped status too
          rung: String(status.rung || ""),
          rung_source: String(status.rung_source || ""),
          rung_trigger: String(status.rung_trigger || ""),
          rung_pin: String(status.rung_pin || ""),
          rung_pin_locked: Boolean(status.rung_pin_locked),
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
    // Tier switch for a vhost that is ALREADY challenged (v1 <-> v2), from
    // the EFFECTIVE tier (challenge-tier.js):
    //  - a manual arm is re-tiered in place via v1/challenge/vhost/rung, which
    //    keeps its expiry and reason (a re-arm through vhost/add would reset
    //    both);
    //  - an automatic challenge is PINNED via v1/challenge/vhost/tier — "→ v1"
    //    is the emergency drop-back from an auto-v2 tier, and "↺ auto" hands
    //    the tier back to CHALLENGE_V2_AUTO_VHOST. A pin never creates or
    //    extends a challenge.
    challengeTierTarget(host) {
      return tierSwitchTarget(this.activeChallengeByHost[host] || {}, host);
    },
    challengeTierButtonLabel(host) {
      return tierButtonLabel(this.activeChallengeByHost[host] || {}, host);
    },
    challengeTierButtonTitle(host) {
      return tierButtonTitle(this.activeChallengeByHost[host] || {}, host);
    },
    challengeTierPinned(host) {
      return tierUnpinnable(this.activeChallengeByHost[host] || {});
    },
    async toggleChallengeTier(host) {
      const s = this.activeChallengeByHost[host] || {};
      const to = tierSwitchTarget(s, host);
      if (!host || !to) return;
      const req = tierSwitchRequest(host, s, to);
      try {
        const res = await this.postJSON(req.path, req.body);
        if (req.path.endsWith("/rung")) {
          this.actionMsg = `Challenge on ${res?.host || host} switched ${res?.from || "?"} → ${res?.rung || to} (expiry kept)` +
            (res?.tier?.rung && res.tier.rung !== (res?.rung || to)
              ? ` — still ${res.tier.rung}: an automatic ${res.tier.trigger || "source"} covers it (pin v1 to drop it)`
              : "");
        } else {
          this.actionMsg = `Automatic challenges on ${res?.host || host} pinned to ${res?.pin || to}` +
            (res?.tier?.rung ? ` — effective tier now ${res.tier.rung}` : "") +
            (res?.ttl_capped ? " (capped to the 24h customer limit)" : "");
        }
        await this.refreshChallengeVhosts();
      } catch (err) {
        this.actionMsg = `Tier switch failed for ${host}: ${err}`;
        console.error("[cfm-admin] challenge tier switch failed", host, err);
      }
    },
    async unpinChallengeTier(host) {
      if (!host) return;
      const req = tierUnpinRequest(host);
      try {
        const res = await this.postJSON(req.path, req.body);
        this.actionMsg = `Tier pin removed on ${res?.host || host} — CHALLENGE_V2_AUTO_VHOST decides` +
          (res?.tier?.rung ? ` (now ${res.tier.rung})` : "");
        await this.refreshChallengeVhosts();
      } catch (err) {
        this.actionMsg = `Unpin failed for ${host}: ${err}`;
        console.error("[cfm-admin] challenge tier unpin failed", host, err);
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
