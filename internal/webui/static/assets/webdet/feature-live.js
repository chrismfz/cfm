// Live traffic: WebTop / suspicious / long-window lists, global IP lists,
// per-vhost drilldown with the live ECharts series, and IP drilldown.
// Used by the overview and vhost-live pages.

export const liveMixin = {
  data() {
    return {
      topShort: [],
      topShortLimit: 20,
      suspicious: [],
      longTop: [],
      longTopLimit: 20,
      ipShort: [],
      ipShortLimit: 20,
      hotIPs: [],
      hotIPsLimit: 20,
      activeIP: "",
      ipDrilldown: null,
      suspiciousHosts: {},
      drilldown: null,
      activeHost: "",
      vhostFocusHost: "",
      vhostSeriesByHost: {},
      vhostSeriesMaxPoints: 120,
      vhostTopIPLimit: 25,
      vhostTopPathLimit: 25,
      // Fetch the server max so the Top IPs "show N" selector (25/50/100)
      // never needs a refetch — the drilldown endpoint caps top at 100.
      drilldownTopN: 100,
      vhostCharts: {
        rps: null,
        bot: null,
        err: null,
        score: null,
        rt: null,
      },
      resizeHandler: null,
    };
  },

  computed: {
    shortDetail() {
      if (!this.drilldown) return null;
      return this.drilldown.short || this.drilldown;
    },
    longDetail() {
      return this.drilldown?.long || null;
    },
    topIPs() {
      return Array.isArray(this.shortDetail?.top_ips) ? this.shortDetail.top_ips : [];
    },
    enrichedTopIPsByIP() {
      const rows = Array.isArray(this.shortDetail?.enriched_top_ips) ? this.shortDetail.enriched_top_ips : [];
      const byIP = {};
      for (const row of rows) {
        if (row && row.ip) byIP[row.ip] = row;
      }
      return byIP;
    },
    topIPRows() {
      return this.topIPs.map((ipRow) => {
        const info = this.enrichedTopIPsByIP[ipRow.key] || {};
        return {
          ...ipRow,
          country: info.country || "-",
          asn: info.asn ? `AS${String(info.asn).replace(/^AS/i, "")}` : "-",
          company: info.asn_name || "-",
        };
      });
    },
    // The drilldown Top IPs rows actually rendered (Show-N applied) —
    // the unit "select all listed" and value-quick-select operate on.
    visibleTopIPRows() { return this.topIPRows.slice(0, this.vhostTopIPLimit); },
    topPaths() {
      return Array.isArray(this.shortDetail?.top_paths) ? this.shortDetail.top_paths : [];
    },
    topAgents() {
      return Array.isArray(this.shortDetail?.top_agents) ? this.shortDetail.top_agents : [];
    },
    activeTopShortRow() {
      if (!this.activeHost || !Array.isArray(this.topShort)) return null;
      return this.topShort.find((row) => row?.host === this.activeHost) || null;
    },
    activeVhostSeries() {
      const host = String(this.activeHost || "").trim();
      return this.vhostSeriesByHost[host] || [];
    },
    liveKPI() {
      const row = this.activeTopShortRow || {};
      const short = this.shortDetail || {};
      const errPct = Number.isFinite(Number(row.err_ratio)) ? Number(row.err_ratio) * 100 : Number(short.err_ratio || 0) * 100;
      const botPct = Number.isFinite(Number(row.bot_ratio)) ? Number(row.bot_ratio) * 100 : Number(short.bot_ratio || 0) * 100;
      return {
        challengeMode: this.challengeModeLabel(this.activeHost),
        score: Number(row.score ?? short.short_score ?? 0),
        errPct,
        botPct,
        rtMs: Number(short.proc_avg_sec || 0) * 1000,
        uniqIP: Number(row.unique_ips ?? short.unique_ips ?? 0),
        reasons: Array.isArray(row.reasons) ? row.reasons : [],
      };
    },
    keyMetrics() {
      if (!this.shortDetail) return [];
      const s = this.shortDetail;
      const pick = (label, key, type = "num") => ({
        label,
        value: type === "pct" ? `${this.num((s[key] || 0) * 100)}%` : this.num(s[key]),
      });
      return [
        pick("Total req", "total_req"),
        pick("Short score", "short_score"),
        pick("RPS", "rps"),
        pick("Err ratio", "err_ratio", "pct"),
        pick("Auth401 ratio", "auth401_ratio", "pct"),
        pick("Bot ratio", "bot_ratio", "pct"),
        pick("UA diversity", "ua_diversity"),
        pick("Path diversity", "path_diversity"),
        pick("POST ratio", "post_ratio", "pct"),
        pick("Unique paths", "unique_paths"),
        pick("Unique UAs", "unique_uas"),
      ];
    },
    longReasons() {
      return Array.isArray(this.longDetail?.reasons) ? this.longDetail.reasons : [];
    },
    rawDrilldownPretty() {
      if (!this.drilldown) return "";
      return JSON.stringify(this.drilldown, null, 2);
    },
    rawIPDrilldownPretty() {
      if (!this.ipDrilldown) return "";
      return JSON.stringify(this.ipDrilldown, null, 2);
    },
    suspiciousAndChallenged() {
      const byHost = {};
      for (const row of this.suspicious) {
        if (!row?.host) continue;
        byHost[row.host] = {
          ...row,
          source: "suspicious",
          fromSuspicious: true,
          fromChallenge: false,
        };
      }
      for (const row of this.activeChallengeVhosts) {
        const host = row?.host;
        if (!host) continue;
        const existing = byHost[host] || { host };
        const mergedReasons = [
          ...(Array.isArray(existing.reasons) ? existing.reasons : []),
          ...(Array.isArray(row.reasons) ? row.reasons : []),
        ];
        byHost[host] = {
          ...existing,
          score: existing.score ?? row.score,
          rps: existing.rps ?? row.rps,
          unique_ips: existing.unique_ips ?? row.uniq_ip,
          reasons: mergedReasons.length ? Array.from(new Set(mergedReasons)) : existing.reasons,
          challenge_mode: row.mode,
          fromSuspicious: Boolean(existing.fromSuspicious),
          fromChallenge: true,
          source: existing.fromSuspicious ? "both" : "challenged",
        };
      }
      return Object.values(byHost).sort((a, b) => {
        const aCh = this.challengeState(a.host) ? 1 : 0;
        const bCh = this.challengeState(b.host) ? 1 : 0;
        if (bCh !== aCh) return bCh - aCh;
        return (Number(b.score) || 0) - (Number(a.score) || 0);
      });
    },
  },

  methods: {
    // ── Charts ─────────────────────────────────────────────────────────
    chartTextColor() { return "#dbe7f7"; },
    chartAxisColor() { return "#7f93ad"; },
    chartSplitColor() { return "rgba(159,176,195,0.18)"; },
    vhostChartTimes() {
      return this.activeVhostSeries.map((p) => {
        const d = new Date(Number(p.at || 0));
        return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString();
      });
    },
    baseLineOption({ yName = "", min = null, max = null } = {}) {
      return {
        backgroundColor: "transparent",
        animation: true,
        tooltip: { trigger: "axis", axisPointer: { type: "cross" } },
        legend: {
          top: 6,
          right: 10,
          textStyle: { color: this.chartTextColor() },
        },
        grid: { left: 52, right: 18, top: 34, bottom: 28 },
        xAxis: {
          type: "category",
          boundaryGap: false,
          data: this.vhostChartTimes(),
          axisLine: { lineStyle: { color: this.chartAxisColor() } },
          axisLabel: { color: this.chartAxisColor(), hideOverlap: true },
        },
        yAxis: {
          type: "value",
          name: yName,
          min,
          max,
          axisLine: { lineStyle: { color: this.chartAxisColor() } },
          axisLabel: { color: this.chartAxisColor() },
          splitLine: { lineStyle: { color: this.chartSplitColor() } },
          nameTextStyle: { color: this.chartAxisColor() },
        },
      };
    },
    ensureVhostCharts() {
      if (!window.echarts) return;
      const initOne = (key, elId) => {
        const el = document.getElementById(elId);
        if (!el) return null;
        if (this.vhostCharts[key]) return this.vhostCharts[key];
        this.vhostCharts[key] = window.echarts.init(el);
        return this.vhostCharts[key];
      };
      initOne("rps", "vhost-rps-chart");
      initOne("bot", "vhost-bot-chart");
      initOne("err", "vhost-err-chart");
      initOne("score", "vhost-score-chart");
      initOne("rt", "vhost-rt-chart");
    },
    disposeVhostCharts() {
      for (const key of Object.keys(this.vhostCharts || {})) {
        if (this.vhostCharts[key]) {
          this.vhostCharts[key].dispose();
          this.vhostCharts[key] = null;
        }
      }
    },
    resizeVhostCharts() {
      for (const key of Object.keys(this.vhostCharts || {})) {
        this.vhostCharts[key]?.resize();
      }
    },
    renderVhostCharts() {
      if (!window.echarts || !Array.isArray(this.activeVhostSeries) || this.activeVhostSeries.length < 2) {
        return;
      }
      this.ensureVhostCharts();

      const times = this.vhostChartTimes();
      const rows = this.activeVhostSeries;
      const r2xx = rows.map((r) => Number(r.r2xx || 0));
      const r4xx = rows.map((r) => Number(r.r4xx || 0));
      const r5xx = rows.map((r) => Number(r.r5xx || 0));
      const bot = rows.map((r) => Number(r.bot || 0));
      const err = rows.map((r) => Number(r.err || 0));
      const score = rows.map((r) => Number(r.score || 0));
      const rt = rows.map((r) => Number(r.rt || 0));

      const commonXAxis = {
        type: "category",
        boundaryGap: false,
        data: times,
        axisLine: { lineStyle: { color: this.chartAxisColor() } },
        axisLabel: { color: this.chartAxisColor(), hideOverlap: true },
      };
      const legend = (data) => ({
        top: 6,
        right: 10,
        textStyle: { color: this.chartTextColor() },
        data,
      });

      this.vhostCharts.rps?.setOption({
        ...this.baseLineOption({ yName: "RPS", min: 0 }),
        xAxis: commonXAxis,
        legend: legend(["2xx", "4xx", "5xx"]),
        series: [
          { name: "2xx", type: "line", smooth: true, showSymbol: false, lineStyle: { color: "#2ec9d7", width: 2 }, data: r2xx },
          { name: "4xx", type: "line", smooth: true, showSymbol: false, lineStyle: { color: "#f1d64a", width: 2 }, data: r4xx },
          { name: "5xx", type: "line", smooth: true, showSymbol: false, lineStyle: { color: "#db6178", width: 2 }, data: r5xx },
        ],
      }, true);
      this.vhostCharts.bot?.setOption({
        ...this.baseLineOption({ yName: "%", min: 0, max: 100 }),
        xAxis: commonXAxis,
        legend: legend(["Bot %"]),
        series: [
          { name: "Bot %", type: "line", smooth: true, showSymbol: false, lineStyle: { color: "#2ec9d7", width: 2 }, data: bot },
        ],
      }, true);
      this.vhostCharts.err?.setOption({
        ...this.baseLineOption({ yName: "%", min: 0, max: 100 }),
        xAxis: commonXAxis,
        legend: legend(["Error %"]),
        series: [
          { name: "Error %", type: "line", smooth: true, showSymbol: false, lineStyle: { color: "#f1d64a", width: 2 }, data: err },
        ],
      }, true);
      this.vhostCharts.score?.setOption({
        ...this.baseLineOption({ yName: "Score", min: 0, max: 1 }),
        xAxis: commonXAxis,
        legend: legend(["Threat score"]),
        series: [
          { name: "Threat score", type: "line", smooth: true, showSymbol: false, lineStyle: { color: "#87d45b", width: 2 }, data: score },
        ],
      }, true);
      this.vhostCharts.rt?.setOption({
        ...this.baseLineOption({ yName: "ms", min: 0 }),
        xAxis: commonXAxis,
        legend: legend(["Response ms"]),
        series: [
          { name: "Response ms", type: "line", smooth: true, showSymbol: false, lineStyle: { color: "#db62e6", width: 2 }, data: rt },
        ],
      }, true);

      this.$nextTick(() => this.resizeVhostCharts());
    },

    // ── Focus / series ─────────────────────────────────────────────────
    syncVhostQuery(host) {
      if (!this.isVhostPage) return;
      const h = String(host || "").trim();
      const url = new URL(window.location.href);
      if (h) url.searchParams.set("host", h);
      else url.searchParams.delete("host");
      window.history.replaceState({}, "", url.toString());
    },
    async applyVhostFocus() {
      let host = String(this.vhostFocusHost || "").trim();
      if (this.hasScopedVhosts && !this.allowedVhosts.includes(host.toLowerCase())) host = this.allowedVhosts[0] || "";
      if (!host) {
        this.actionMsg = "Provide a vhost to open live view.";
        return;
      }
      this.vhostFocusHost = host;
      this.syncVhostQuery(host);
      await this.loadHost(host, false);
    },
    ensureHostSeries(host) {
      if (!host) return;
      if (!this.vhostSeriesByHost[host]) this.vhostSeriesByHost[host] = [];
    },
    pushHostSeriesPoint(host) {
      if (!host) return;
      this.ensureHostSeries(host);
      const row = this.activeTopShortRow || {};
      const short = this.shortDetail || {};
      const err = Number.isFinite(Number(row.err_ratio)) ? Number(row.err_ratio) * 100 : Number(short.err_ratio || 0) * 100;
      const bot = Number.isFinite(Number(row.bot_ratio)) ? Number(row.bot_ratio) * 100 : Number(short.bot_ratio || 0) * 100;
      const rt = Number(short.proc_avg_sec || 0) * 1000;
      const point = {
        at: Date.now(),
        r2xx: Number(row.rps_2xx || 0),
        r4xx: Number(row.rps_4xx || 0),
        r5xx: Number(row.rps_5xx || 0),
        err,
        bot,
        score: Number(row.score ?? short.short_score ?? 0),
        rt,
      };
      const list = this.vhostSeriesByHost[host];
      list.push(point);
      if (list.length > this.vhostSeriesMaxPoints) {
        list.splice(0, list.length - this.vhostSeriesMaxPoints);
      }
    },

    // ── Drilldowns ─────────────────────────────────────────────────────
    scrollToDrilldown() {
      const el = document.getElementById("drilldown-card");
      if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
    },
    async loadHost(host, shouldScroll = true) {
      if (this.hasScopedVhosts && !this.allowedVhosts.includes(String(host || "").trim().toLowerCase())) return;
      if (!host) return;
      this.activeHost = host;
      this.ensureHostSeries(host);
      try {
        this.drilldown = await this.fetchJSON(`v1/webdet/drilldown?host=${encodeURIComponent(host)}&top=${this.drilldownTopN}`);
        await this.$nextTick();
        this.renderVhostCharts();
        if (shouldScroll) this.scrollToDrilldown();
      } catch (err) {
        console.error("[cfm-admin] drilldown failed", err);
        this.drilldown = { error: String(err), host };
        if (shouldScroll) this.scrollToDrilldown();
      }
    },
    async loadIP(ip) {
      if (!ip) return;
      this.activeIP = ip;
      this.ipDrilldown = await this.fetchJSONSafe(`v1/webdet/ip-drilldown?ip=${encodeURIComponent(ip)}`, { ip, error: "failed to load ip drilldown" });
    },

    // ── Refresh hooks (called by core.refreshAll) ──────────────────────
    pageNeedsInitialRefresh() { return this.topShort.length === 0; },
    async refreshLists() {
      const topLimit = Math.max(1, Math.min(500, Number(this.topShortLimit) || 20));
      const longLimit = Math.max(1, Math.min(500, Number(this.longTopLimit) || 20));
      const ipLimit = Math.max(1, Math.min(500, Number(this.ipShortLimit) || 20));
      const hotLimit = Math.max(1, Math.min(500, Number(this.hotIPsLimit) || 20));
      this.topShortLimit = topLimit;
      this.longTopLimit = longLimit;
      this.ipShortLimit = ipLimit;
      this.hotIPsLimit = hotLimit;

      const skipAdminEndpoints = [];
      if (this.isScoped) {
        if (this.shouldShow("globalips") || this.shouldShow("ipdrilldown")) skipAdminEndpoints.push("v1/webdet/ip-short");
        if (this.shouldShow("webtop")) skipAdminEndpoints.push("v1/webdet/hot-ips");
      }

      const tasks = [
        (this.shouldShow("webtop") || this.shouldShow("vhost"))
          ? this.fetchJSONSafe(`v1/webdet/top-short?limit=${topLimit}`, { rows: [] })
          : Promise.resolve({ rows: [] }),
        this.shouldShow("suspicious")
          ? this.fetchJSONSafe(`v1/webdet/suspicious?limit=${longLimit}`, { rows: [] })
          : Promise.resolve({ rows: [] }),
        this.shouldShow("longtop")
          ? this.fetchJSONSafe(`v1/webdet/long-top?limit=${longLimit}`, { rows: [] })
          : Promise.resolve({ rows: [] }),
        !this.isScoped && (this.shouldShow("globalips") || this.shouldShow("ipdrilldown"))
          ? this.fetchJSONSafe(`v1/webdet/ip-short?limit=${ipLimit}`, { short: [] })
          : Promise.resolve({ short: [] }),
        !this.isScoped && this.shouldShow("webtop")
          ? this.fetchJSONSafe(`v1/webdet/hot-ips?limit=${hotLimit}`, [])
          : Promise.resolve([]),
        this.refreshChallengeVhosts(),
      ];

      const [topShort, suspicious, longTop, ipShort, hotIPs] = await Promise.all(tasks);

      this.topShort = this.extractRows(topShort, "rows");
      this.suspicious = this.extractRows(suspicious, "rows");
      this.longTop = this.extractRows(longTop, "rows");
      this.ipShort = this.extractRows(ipShort, "short");
      this.hotIPs = this.extractRows(hotIPs, "rows");
      this.logScopedAdminSkipsOnce(skipAdminEndpoints);
      if (this.hasScopedVhosts) {
        const allow = new Set(this.allowedVhosts);
        const byHost = (row) => allow.has(String(row?.host || "").toLowerCase());
        this.topShort = this.topShort.filter(byHost);
        this.suspicious = this.suspicious.filter(byHost);
        this.longTop = this.longTop.filter(byHost);
        this.activeChallengeVhosts = this.activeChallengeVhosts.filter(byHost);
      }
      this.suspiciousHosts = Object.fromEntries(this.suspicious.map((row) => [row.host, true]));
    },
    async afterListsRefreshed() {
      if (this.shouldShow("vhost") && this.isVhostPage) {
        const vhostTarget =
          String(this.vhostFocusHost || "").trim() ||
          String(this.activeHost || "").trim() ||
          this.topShort[0]?.host;
        if (vhostTarget) {
          this.vhostFocusHost = vhostTarget;
          this.syncVhostQuery(vhostTarget);
          await this.loadHost(vhostTarget, false);
          this.pushHostSeriesPoint(vhostTarget);
          await this.$nextTick();
          this.renderVhostCharts();
        }
      } else if (this.shouldShow("vhost") && this.activeHost) {
        this.pushHostSeriesPoint(this.activeHost);
        await this.$nextTick();
        this.renderVhostCharts();
      }
      if (this.shouldShow("ipdrilldown") && !this.activeIP && this.ipShort[0]?.ip) {
        await this.loadIP(this.ipShort[0].ip);
      }
    },
  },

  mounted() {
    this.resizeHandler = () => this.resizeVhostCharts();
    window.addEventListener("resize", this.resizeHandler);
    this.$nextTick(() => this.resizeVhostCharts());
  },
  beforeUnmount() {
    if (this.resizeHandler) window.removeEventListener("resize", this.resizeHandler);
    this.disposeVhostCharts();
  },
};
