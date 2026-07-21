// ClamAV insights page: scanner status/health (admin) + per-vhost scan
// coverage (scoped). Reuses the existing scoped /api/v1/webdet/vhosts rows
// (clam_enabled / clam_toggleable / clam_override_present) for coverage and the
// admin-only /api/v1/clam/health for daemon status. Toggling reuses the same
// scoped /api/v1/clam/override/{add,remove} flip as the vhost-controls page.

export const clamMixin = {
  data() {
    return {
      clamHealth: null, // admin: /api/v1/clam/health snapshot (null when scoped or unavailable)
      clamRows: [], // scoped: vhost rows carrying clam_* fields
      clamInfections: [], // recent clam_infected history events (scoped by host)
    };
  },

  computed: {
    clamCoverage() {
      let scanned = 0;
      let notScanned = 0;
      for (const r of this.clamRows) {
        if (r?.clam_enabled) scanned++;
        else notScanned++;
      }
      return { total: this.clamRows.length, scanned, notScanned };
    },
    // Vhosts NOT currently scanned — the deviations an operator scans for.
    clamNotScanned() {
      return this.clamRows.filter((r) => !r?.clam_enabled);
    },
    // Resolved reachability badge for the status card.
    clamStatusBadge() {
      // available is true only when the scanner is running and reporting, so the
      // only live sub-states are reachable (OK) vs breaker-open (DOWN).
      const h = this.clamHealth;
      if (!h || !h.available) return { label: "not running", cls: "" };
      if (h.breaker_open) return { label: "DOWN", cls: "danger" };
      return { label: "OK", cls: "ok" };
    },
  },

  methods: {
    // core.js always invokes refreshLists() — the reliable auto-refresh hook.
    async refreshLists() {
      await Promise.all([this.refreshClamHealth(), this.refreshClamRows(), this.refreshClamInfections()]);
    },
    // Focus host for scoped queries: ?vhost= wins, else the scoped token's first
    // allowed vhost. Admins may omit it (query spans all vhosts).
    clamFocusHost() {
      const url = new URL(window.location.href);
      let host = (url.searchParams.get("vhost") || url.searchParams.get("vhosts") || "").trim();
      if (host.includes(",")) host = host.split(",")[0].trim();
      if (!host && this.isScopedMode && Array.isArray(this.allowedVhosts) && this.allowedVhosts.length) {
        host = String(this.allowedVhosts[0] || "").trim();
      }
      return host;
    },
    async refreshClamInfections() {
      const host = this.clamFocusHost();
      // The history endpoint requires a host for scoped tokens (else 400) —
      // skip rather than fire a doomed request.
      if (this.isScopedMode && !host) {
        this.clamInfections = [];
        return;
      }
      const hq = host ? `&host=${encodeURIComponent(host)}` : "";
      const payload = await this.fetchJSONSafe(`v1/webdet/history/events?type=clam_infected&limit=50&enrich=1${hq}`, { rows: [] });
      this.clamInfections = this.extractRows(payload, "rows");
    },
    async refreshClamHealth() {
      // Daemon status is admin-only; scoped users skip it (and would 403).
      if (!this.isAdmin) {
        this.clamHealth = null;
        return;
      }
      this.clamHealth = await this.fetchJSONSafe("v1/clam/health", null);
    },
    async refreshClamRows() {
      const url = new URL(window.location.href);
      const scoped = (url.searchParams.get("vhost") || url.searchParams.get("vhosts") || "").trim();
      const qs = scoped ? `?vhost=${encodeURIComponent(scoped)}` : "";
      const payload = await this.fetchJSONSafe(`v1/webdet/vhosts${qs}`, { rows: [] });
      this.clamRows = this.extractRows(payload, "rows");
    },
    // Flip a vhost's scan state by toggling its override membership (same
    // semantics as the vhost-controls Clam column). Flipping membership always
    // flips the resolved state regardless of the global default.
    async toggleClamScan(row) {
      const host = String(row?.host || "").trim();
      if (!host) return;
      if (!row?.clam_toggleable) {
        this.actionMsg = `ClamAV scanning for ${host} can't be toggled — it is globally off.`;
        return;
      }
      const currentlyEnabled = Boolean(row?.clam_enabled);
      try {
        const endpoint = row?.clam_override_present ? "remove" : "add";
        await this.postJSON(`v1/clam/override/${endpoint}?type=host&value=${encodeURIComponent(host)}`, {});
        this.actionMsg = `ClamAV scanning ${currentlyEnabled ? "disabled" : "enabled"} for ${host}`;
        await this.refreshClamRows();
      } catch (err) {
        this.actionMsg = `ClamAV toggle failed for ${host}: ${err}`;
        console.error("[cfm-admin] clam toggle failed", host, err);
      }
    },
  },
};
