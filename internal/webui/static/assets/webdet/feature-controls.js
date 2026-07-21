// Vhost controls page: per-vhost WAF/Challenge/HTTP3/Clam toggles and the
// per-vhost security overview. Traffic rules and API tokens live on their own
// pages (feature-rules.js, feature-tokens.js).

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
      let clamOff = 0;
      let clamInline = 0;
      for (const row of this.vhostControls) {
        if (!row?.challenge_enabled) challengeOff++;
        if (!row?.waf_enabled) wafOff++;
        if (row?.http3_enabled) http3On++;
        if (!row?.clam_enabled) clamOff++;
        if (row?.clam_mode_inline) clamInline++;
      }
      return { challengeOff, wafOff, http3On, clamOff, clamInline };
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
      else if (quick === "clam_off") filtered = filtered.filter((row) => !row?.clam_enabled);
      else if (quick === "clam_inline") filtered = filtered.filter((row) => row?.clam_mode_inline);
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
        } else if (key === "clam") {
          const cmp = boolOrder(Boolean(a?.clam_enabled)) - boolOrder(Boolean(b?.clam_enabled));
          if (cmp !== 0) return cmp * dir;
        } else if (key === "clammode") {
          const cmp = boolOrder(Boolean(a?.clam_mode_inline)) - boolOrder(Boolean(b?.clam_mode_inline));
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
  },

  methods: {
    // ── Per-vhost protection toggles ───────────────────────────────────
    vhostControlEnabled(row, kind) {
      let key;
      if (kind === "challenge") key = "challenge_enabled";
      else if (kind === "waf") key = "waf_enabled";
      else if (kind === "http3") key = "http3_enabled";
      else if (kind === "clam") key = "clam_enabled";
      else if (kind === "clammode") key = "clam_mode_inline";
      else return false;
      return Boolean(row?.[key]);
    },
    vhostControlToggleable(row, kind) {
      let key;
      if (kind === "challenge") key = "challenge_toggleable";
      else if (kind === "waf") key = "waf_toggleable";
      else if (kind === "http3") key = "http3_toggleable";
      else if (kind === "clam") key = "clam_toggleable";
      else if (kind === "clammode") key = "clam_mode_toggleable";
      else return false;
      return Boolean(row?.[key]);
    },
    vhostControlMatchedExclude(row, kind) {
      let key;
      if (kind === "challenge") key = "challenge_matched_exclude";
      else if (kind === "waf") key = "waf_matched_exclude";
      else if (kind === "http3") key = "http3_matched_optin";
      else return ""; // clam/clammode: exact-match only, no pattern to surface
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
      // ClamAV: XOR of global default and per-vhost override. Not-toggleable
      // means ClamAV is globally off (there is no per-vhost pattern lock).
      if (kind === "clam") {
        if (enabled) return "ON / SCANNING";
        return toggleable ? "OFF / NOT SCANNED" : "OFF / GLOBALLY OFF";
      }
      // ClamAV mode: inline blocks an infected upload (fail-open); async only
      // notifies. Not-toggleable = the vhost isn't scanned at all.
      if (kind === "clammode") {
        if (enabled) return "INLINE / BLOCKING";
        return toggleable ? "ASYNC / NOTIFY" : "N/A / NOT SCANNED";
      }
      if (enabled) return "ON / ENABLED";
      return toggleable ? "OFF / DISABLED" : "OFF / MATCHED BY PATTERN";
    },
    vhostControlButtonTitle(row, kind) {
      const enabled = this.vhostControlEnabled(row, kind);
      const matched = this.vhostControlMatchedExclude(row, kind);
      const toggleable = this.vhostControlToggleable(row, kind);
      if (kind === "clam") {
        if (!toggleable) return "ClamAV upload scanning is globally off (CLAMD_ENABLED / hook). Enable it in cfm.conf first.";
        if (enabled) return "ClamAV scans uploads for this vhost. Click to stop scanning it.";
        return "ClamAV upload scanning is off for this vhost. Click to start scanning it.";
      }
      if (kind === "clammode") {
        if (!toggleable) return "Scan mode applies only to scanned vhosts. Enable ClamAV scanning for this vhost first.";
        if (enabled) return "INLINE: an infected upload gets a 403 (fail-open when clamd is down/slow). Click to switch back to async notify-only.";
        return "ASYNC: infections are logged/notified, never blocked. Click to switch this vhost to inline blocking (burn in with CLAM_INLINE_DRY_RUN first).";
      }
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
        } else if (kind === "clam") {
          this.actionMsg = `ClamAV scanning for ${host} can't be toggled — it is globally off (enable CLAMD_ENABLED / scan policy in cfm.conf first).`;
        } else if (kind === "clammode") {
          this.actionMsg = `Scan mode for ${host} needs the vhost scanned first — enable its Clam toggle.`;
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
        } else if (kind === "clam") {
          // ClamAV scan = scanDefault XOR override. Flipping override membership
          // always flips the resolved state regardless of the global default,
          // so add when no override exists, remove when one does.
          const endpoint = row?.clam_override_present ? "remove" : "add";
          await this.postJSON(`v1/clam/override/${endpoint}?type=host&value=${encodeURIComponent(host)}`, {});
          this.actionMsg = `ClamAV scanning ${currentlyEnabled ? "disabled" : "enabled"} for ${host}`;
        } else if (kind === "clammode") {
          // Same XOR flip against the separate mode store.
          const endpoint = row?.clam_mode_override_present ? "remove" : "add";
          await this.postJSON(`v1/clam/mode/${endpoint}?type=host&value=${encodeURIComponent(host)}`, {});
          this.actionMsg = `ClamAV mode for ${host} switched to ${currentlyEnabled ? "async (notify-only)" : "inline (blocking)"}`;
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
