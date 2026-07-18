// WAF engine analytics: the structured summary card (top rules/hosts/IPs +
// recent events + hits-per-hour chart) backed by v1/waf/engine/summary.

import { initChart, chartColors, onThemeChange } from "../shared/chart-theme.js";

export const wafEngineMixin = {
  data() {
    return {
      wafHours: 24,
      wafEventLimit: 200,
      wafTopN: 10,
      wafSummary: null,
      // Server-side filters: applied before aggregation, so totals and every
      // top list reflect them — the false-positive-hunting workflow.
      wafCountry: "",
      wafRule: "",
    };
  },
  methods: {
    async refreshWAFEngine() {
      if (!this.shouldShow("wafengine")) return;
      const hours = Math.max(1, Math.min(24 * 30, Number(this.wafHours) || 24));
      const limit = Math.max(1, Math.min(2000, Number(this.wafEventLimit) || 200));
      const top = Math.max(1, Math.min(100, Number(this.wafTopN) || 10));
      this.wafHours = hours;
      this.wafEventLimit = limit;
      this.wafTopN = top;
      let url = `v1/waf/engine/summary?hours=${hours}&limit=${limit}&top=${top}&enrich=1`;
      const country = String(this.wafCountry || "").trim();
      const rule = String(this.wafRule || "").trim();
      if (country) url += `&country=${encodeURIComponent(country)}`;
      if (rule) url += `&rule=${encodeURIComponent(rule)}`;
      this.wafSummary = await this.fetchJSONSafe(url, null);
      await this.$nextTick();
      this.renderWAFHistogram();
    },
    // Hits-per-hour chart. The histogram is built server-side AFTER the
    // country/rule filters, so the timeline always matches the numbers.
    renderWAFHistogram() {
      const buckets = this.wafSummary?.histogram || [];
      const el = document.getElementById("waf-hist-chart");
      if (!el || !window.echarts) return;
      if (buckets.length < 2) {
        this._wafHistChart?.dispose();
        this._wafHistChart = null;
        return;
      }
      if (!this._wafHistChart) this._wafHistChart = initChart(el);
      const cc = chartColors();
      const times = buckets.map((b) => {
        const d = new Date(Number(b.ts_unix || 0) * 1000);
        return Number.isNaN(d.getTime()) ? "" : d.toLocaleString(undefined, { day: "2-digit", hour: "2-digit", minute: "2-digit" });
      });
      this._wafHistChart.setOption({
        animation: true,
        tooltip: { trigger: "axis" },
        legend: { top: 2, right: 10, data: ["Hits", "Blocked"] },
        grid: { left: 42, right: 14, top: 28, bottom: 24 },
        xAxis: { type: "category", data: times, axisLabel: { hideOverlap: true } },
        yAxis: { type: "value", minInterval: 1 },
        series: [
          { name: "Hits", type: "bar", barMaxWidth: 14, itemStyle: { color: cc.cyan }, data: buckets.map((b) => b.count) },
          { name: "Blocked", type: "bar", barMaxWidth: 14, itemStyle: { color: cc.red }, data: buckets.map((b) => b.blocked) },
        ],
      }, true);
      this._wafHistChart.resize();
    },
    setWAFRuleFilter(rule) {
      const r = String(rule || "").trim();
      if (!r) return;
      this.wafRule = this.wafRule === r ? "" : r;
      this.refreshWAFEngine();
    },
    setWAFCountryFilter(cc) {
      const c = String(cc || "").trim().toUpperCase();
      if (!c) return;
      this.wafCountry = this.wafCountry === c ? "" : c;
      this.refreshWAFEngine();
    },
    clearWAFFilters() {
      this.wafCountry = "";
      this.wafRule = "";
      this.refreshWAFEngine();
    },
    uriPath(uri) {
      return String(uri || "").split("?")[0] || "/";
    },
    resizeWAFHistogram() { this._wafHistChart?.resize(); },
    // One-click false-positive fix from an event row: add a WAF exclude for
    // the host or the path without retyping it in the excludes card.
    async quickWAFExclude(type, value) {
      const v = String(value || "").trim();
      if (!v) return;
      if (!window.confirm(`Add WAF exclude ${type}=${v}?\n\nMatching requests will BYPASS the WAF engine until the exclude is removed.`)) return;
      try {
        await this.postJSON(`v1/waf/exclude/add?type=${encodeURIComponent(type)}&value=${encodeURIComponent(v)}`, {});
        this.actionMsg = `WAF exclude added: ${type}=${v}`;
        await this.refreshExcludeLists?.();
      } catch (err) {
        this.actionMsg = `WAF exclude add failed: ${this.formatApiError(err)}`;
        console.error("[cfm-admin] quick waf exclude failed", err);
      }
    },
  },

  mounted() {
    this._wafHistResize = () => this.resizeWAFHistogram();
    window.addEventListener("resize", this._wafHistResize);
    onThemeChange(() => {
      this._wafHistChart?.dispose();
      this._wafHistChart = null;
      this.renderWAFHistogram();
    });
  },
  beforeUnmount() {
    if (this._wafHistResize) window.removeEventListener("resize", this._wafHistResize);
    this._wafHistChart?.dispose();
    this._wafHistChart = null;
  },
};
