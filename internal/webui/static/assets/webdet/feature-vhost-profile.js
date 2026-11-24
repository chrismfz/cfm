// Vhost page: the profile tabs (Overview, Bots & traffic, WAF & challenges,
// What applies) above the live drilldown, which stays the "Live" tab.
//
// Data, all keyed on the page's activeHost:
//   - GET v1/webdet/vhost-profile?host=          what applies and why (admin)
//   - GET v1/webdet/traffic-mix?host=&window=    who visits, what it costs (admin)
//   - GET v1/webdet/history/vhost-overview?host= WAF hits and challenges, 24 h
// The two admin endpoints mean a scoped (cPanel) viewer never sees the tabs:
// for them the page is the live drilldown, as before.
//
// Wording lives in vhost-profile-model.js (tested); the per-client action
// guardrails and palette are traffic-model.js's. This page edits nothing: each
// tile links to the page that does, filtered to the host.

import * as M from "./vhost-profile-model.js";
import { CLASS_ORDER, CLASS_LABELS, CLASS_COLORS, fmtCount, fmtPct, fmtBytes, fmtSeconds, fmtRate } from "./traffic-model.js";
import { onThemeChange, currentTheme } from "../shared/chart-theme.js";

const PROFILE_REFRESH_MS = 60_000;

export const vhostProfileMixin = {
  data() {
    let initialTab = M.DEFAULT_TAB;
    try { initialTab = M.tab(new URL(window.location.href).searchParams.get("tab") || ""); } catch { /* no URL */ }
    return {
      vpTab: initialTab,
      vpWindow: "1h",
      vpProfile: null,
      vpProfileError: "",
      vpMix: null,
      vpMixError: "",
      vpOverview: null,
      vpLoadedHost: "",
      vpLoadedAt: null,
      vpLoading: false,
      vpLoadSeq: 0,
      vpMixSeq: 0,
      vpTheme: currentTheme(),
      vpTimer: null,
      vpChartW: 900,
      vpChartH: 170,
    };
  },

  computed: {
    // Admin only: both data endpoints are. Scoped viewers keep the live page.
    vpEnabled() { return this.isVhostPage && this.isAdmin && !this.isScoped; },
    vpShowLive() { return !this.vpEnabled || this.vpTab === "live"; },
    vpTabs() {
      return [
        { key: "overview", label: "Overview" },
        { key: "traffic", label: "Bots & traffic" },
        { key: "security", label: "WAF & challenges" },
        { key: "config", label: "What applies" },
        { key: "live", label: "Live" },
      ];
    },
    vpTiles() { return M.postureTiles(this.vpProfile); },
    vpHeadPills() { return M.headPills(this.vpProfile); },
    vpRelated() { return M.relatedHosts(this.vpProfile); },
    vpRuleRows() { return M.ruleRows(this.vpProfile); },
    vpExcludeRows() { return M.excludeRows(this.vpProfile); },
    vpTraffic() { return M.trafficTiles(this.vpMix); },
    vpBots() { return M.botClients(this.vpMix, 10); },
    vpAllClients() {
      const list = Array.isArray(this.vpMix?.clients) ? [...this.vpMix.clients] : [];
      return list.sort((a, b) => Number(b.origin_sec || 0) - Number(a.origin_sec || 0));
    },
    vpDistributed() { return M.distributedClients(this.vpMix); },
    vpArea() { return M.stackedArea(this.vpMix, this.vpChartW, this.vpChartH); },
    vpClassRows() {
      const by = {};
      for (const c of Array.isArray(this.vpMix?.classes) ? this.vpMix.classes : []) by[c.key] = c;
      return CLASS_ORDER.map((k) => ({ key: k, ...(by[k] || { requests: 0, origin_sec: 0, bytes: 0, rps_peak: 0 }) }));
    },
    vpBars() {
      const rows = this.vpClassRows;
      const total = (f) => rows.reduce((s, r) => s + Number(r[f] || 0), 0);
      const seg = (f) => rows.map((r) => ({ key: r.key, frac: total(f) > 0 ? Number(r[f] || 0) / total(f) : 0 }));
      return { requests: seg("requests"), origin: seg("origin_sec") };
    },
    vpSecurity() { return M.securityTiles(this.vpOverview); },
    vpWafRows() { return M.wafRuleRows(this.vpOverview); },
    vpWindowSec() { return Number(this.vpMix?.window_sec || 3600); },
  },

  watch: {
    activeHost(h) { if (this.vpEnabled && h) this.vpLoad(h); },
    vpEnabled(on) { if (on && this.activeHost) this.vpLoad(this.activeHost); },
    vpMix() { if (this.vpTab === "traffic") this.$nextTick(() => this.vpMeasureChart()); },
    // A window change reloads the mix only. It has its own sequence: bumping
    // vpLoadSeq here would orphan a running vpLoad, which then never cleared
    // vpLoading and the minute refresh stopped for good.
    vpWindow() { if (this.vpEnabled && this.activeHost) this.vpLoadMix(this.activeHost); },
  },

  methods: {
    vpColor(k) { return (CLASS_COLORS[this.vpTheme] || CLASS_COLORS.dark)[k] || "var(--muted)"; },
    vpClassLabel(k) { return CLASS_LABELS[k] || k; },
    vpCount(n) { return fmtCount(n); },
    vpPct(x) { return fmtPct(x); },
    vpBytes(b) { return fmtBytes(b); },
    vpSeconds(s) { return fmtSeconds(s); },
    vpRate(r) { return fmtRate(r); },
    vpTickLabel(v) { return v >= 1000 ? `${(v / 1000).toFixed(v >= 10000 ? 0 : 1)}k` : String(v); },
    vpEditURL(page) { return M.editURL(page, this.activeHost); },

    vpSetTab(key) {
      this.vpTab = M.tab(key);
      try {
        const url = new URL(window.location.href);
        if (this.vpTab === M.DEFAULT_TAB) url.searchParams.delete("tab");
        else url.searchParams.set("tab", this.vpTab);
        window.history.replaceState({}, "", url.toString());
      } catch { /* no URL */ }
      if (this.vpTab === "live") {
        // The live charts are not drawn while hidden: draw and size them now.
        this.$nextTick(() => {
          this.renderVhostCharts?.();
          this.resizeVhostCharts?.();
        });
      }
      if (this.vpTab === "traffic") this.$nextTick(() => this.vpMeasureChart());
    },
    vpOpenHost(host) {
      if (!host || host === this.activeHost) return;
      this.vhostFocusHost = host;
      this.applyVhostFocus?.();
    },

    async vpLoad(host) {
      if (!this.vpEnabled || !host) return;
      const seq = ++this.vpLoadSeq;
      this.vpLoading = true;
      if (host !== this.vpLoadedHost) {
        this.vpProfile = null;
        this.vpMix = null;
        this.vpOverview = null;
      }
      const h = encodeURIComponent(host);
      const [profile, overview] = await Promise.all([
        this.fetchJSON(`v1/webdet/vhost-profile?host=${h}`).catch((err) => ({ __error: String(err?.message || err) })),
        this.fetchJSONSafe(`v1/webdet/history/vhost-overview?host=${h}&hours=24`, null),
        this.vpLoadMix(host),
      ]);
      if (seq !== this.vpLoadSeq) return; // a newer load (another host) won
      if (profile && profile.__error) {
        this.vpProfileError = `Could not load what applies to ${host}: ${profile.__error}. A daemon older than the vhost-profile API answers 404 here.`;
        this.vpProfile = null;
      } else {
        this.vpProfileError = "";
        this.vpProfile = profile;
      }
      this.vpOverview = overview;
      this.vpLoadedHost = host;
      this.vpLoadedAt = new Date();
      this.vpLoading = false;
    },
    async vpLoadMix(host) {
      const seq = ++this.vpMixSeq;
      const h = encodeURIComponent(host);
      try {
        const mix = await this.fetchJSON(`v1/webdet/traffic-mix?host=${h}&window=${encodeURIComponent(this.vpWindow)}&clients=25`);
        if (seq !== this.vpMixSeq) return;
        this.vpMix = mix;
        this.vpMixError = "";
      } catch (err) {
        if (seq !== this.vpMixSeq) return;
        this.vpMix = null;
        this.vpMixError = `Could not load the traffic mix: ${String(err?.message || err)}`;
      }
    },
    vpMeasureChart() {
      const el = this.$refs?.vpSeries;
      if (el && el.clientWidth > 0) this.vpChartW = Math.round(el.clientWidth);
    },
  },

  mounted() {
    // The profile changes slowly: refresh it every minute (the live tab keeps
    // its own 5 s refresh), only while auto-refresh is on and a profile tab
    // is in view.
    this.vpTimer = setInterval(() => {
      if (this.autoRefresh && this.vpEnabled && this.vpTab !== "live" && this.activeHost && !this.vpLoading) {
        this.vpLoad(this.activeHost);
      }
    }, PROFILE_REFRESH_MS);
    onThemeChange(() => { this.vpTheme = currentTheme(); });
    this.vpResize = () => this.vpMeasureChart();
    window.addEventListener("resize", this.vpResize);
    this.$nextTick(() => this.vpMeasureChart());
  },
  beforeUnmount() {
    if (this.vpTimer) clearInterval(this.vpTimer);
    if (this.vpResize) window.removeEventListener("resize", this.vpResize);
  },
};
