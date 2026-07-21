// ClamAV insights page: scanner status/health (admin) + per-vhost scan
// coverage (scoped) + per-signature visibility and excludes. Reuses the
// scoped /api/v1/webdet/vhosts rows (clam_* fields) for coverage, the
// admin-only /api/v1/clam/health for daemon status, the scoped
// /api/v1/webdet/history/events (type=clam_infected) for infections, and the
// scoped /api/v1/clam/sigignore/* store for signature excludes (a matching
// entry downgrades the verdict to log-only — no email, no quarantine).

export const clamMixin = {
  data() {
    return {
      clamHealth: null, // admin: /api/v1/clam/health snapshot (null when scoped or unavailable)
      clamRows: [], // scoped: vhost rows carrying clam_* fields
      clamInfections: [], // recent clam_infected history events (scoped by host)
      clamSigIgnores: [], // signature excludes (scoped: own hosts only; admin: all incl. global)
      sigIgnoreNewPattern: "", // add-form state (Signature excludes card)
      sigIgnoreNewHost: "",
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
    // Per-signature aggregation of the loaded infections window: which
    // signature hit, how widely, and whether its hits are being acted on or
    // downgraded (sig-ignored). Sorted by hit count.
    clamSignatures() {
      const bySig = new Map();
      for (const row of this.clamInfections) {
        const sig = String(row?.reason || "").trim();
        if (!sig) continue;
        let agg = bySig.get(sig);
        if (!agg) {
          agg = { sig, hits: 0, hosts: new Set(), lastTs: 0, ignoredHits: 0 };
          bySig.set(sig, agg);
        }
        agg.hits++;
        if (row?.host) agg.hosts.add(row.host);
        if ((row?.ts_unix || 0) > agg.lastTs) agg.lastTs = row.ts_unix;
        if (row?.payload?.sig_ignored) agg.ignoredHits++;
      }
      return [...bySig.values()]
        .map((a) => ({ sig: a.sig, hits: a.hits, vhosts: a.hosts.size, lastTs: a.lastTs, ignoredHits: a.ignoredHits }))
        .sort((x, y) => y.hits - x.hits);
    },
  },

  methods: {
    // core.js always invokes refreshLists() — the reliable auto-refresh hook.
    async refreshLists() {
      await Promise.all([
        this.refreshClamHealth(),
        this.refreshClamRows(),
        this.refreshClamInfections(),
        this.refreshClamSigIgnores(),
      ]);
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
      const payload = await this.fetchJSONSafe(`v1/webdet/history/events?type=clam_infected&limit=200&enrich=1${hq}`, { rows: [] });
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
    async refreshClamSigIgnores() {
      const payload = await this.fetchJSONSafe("v1/clam/sigignore/list", { entries: [] });
      this.clamSigIgnores = this.extractRows(payload, "entries");
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
    // "Ignore this signature" from an infections row: adds an EXACT-signature
    // exclude scoped to that row's vhost (works for admin and scoped users —
    // never global from a row click, that stays a deliberate admin act).
    async ignoreSignatureForRow(row) {
      const sig = String(row?.reason || "").trim();
      const host = String(row?.host || "").trim();
      if (!sig || !host) return;
      await this.addSigIgnore(sig, host);
    },
    // Global ignore from the Signatures card — admin-only (the API enforces it).
    async ignoreSignatureGlobally(sig) {
      await this.addSigIgnore(String(sig || "").trim(), "");
    },
    async addSigIgnore(pattern, host) {
      if (!pattern) return;
      const scope = host || "(global)";
      try {
        const hq = host ? `&host=${encodeURIComponent(host)}` : "";
        await this.postJSON(`v1/clam/sigignore/add?pattern=${encodeURIComponent(pattern)}${hq}`, {});
        this.actionMsg = `Signature exclude added: ${pattern} @ ${scope} (log-only from now on)`;
        await Promise.all([this.refreshClamSigIgnores(), this.refreshClamInfections()]);
      } catch (err) {
        this.actionMsg = `Signature exclude failed for ${pattern} @ ${scope}: ${err}`;
        console.error("[cfm-admin] clam sigignore add failed", pattern, host, err);
      }
    },
    async addSigIgnoreFromForm() {
      const pattern = String(this.sigIgnoreNewPattern || "").trim();
      if (!pattern) return;
      await this.addSigIgnore(pattern, String(this.sigIgnoreNewHost || "").trim());
      this.sigIgnoreNewPattern = "";
      this.sigIgnoreNewHost = "";
    },
    async removeSigIgnore(entry) {
      const pattern = String(entry?.pattern || "").trim();
      if (!pattern) return;
      const host = String(entry?.host || "").trim();
      const scope = host || "(global)";
      try {
        const hq = host ? `&host=${encodeURIComponent(host)}` : "";
        await this.postJSON(`v1/clam/sigignore/remove?pattern=${encodeURIComponent(pattern)}${hq}`, {});
        this.actionMsg = `Signature exclude removed: ${pattern} @ ${scope}`;
        await this.refreshClamSigIgnores();
      } catch (err) {
        this.actionMsg = `Signature exclude removal failed for ${pattern} @ ${scope}: ${err}`;
        console.error("[cfm-admin] clam sigignore remove failed", pattern, host, err);
      }
    },
    // True when this exact signature is already excluded for the row's vhost
    // (exact-pattern check only — glob overlaps still show the button; adding
    // a duplicate is rejected server-side with a clear message).
    sigAlreadyIgnored(row) {
      if (row?.payload?.sig_ignored) return true;
      const sig = String(row?.reason || "").trim().toLowerCase();
      const host = String(row?.host || "").trim().toLowerCase();
      return this.clamSigIgnores.some((e) => {
        const ep = String(e?.pattern || "").toLowerCase();
        const eh = String(e?.host || "").toLowerCase();
        return ep === sig && (eh === "" || eh === host);
      });
    },
  },
};
