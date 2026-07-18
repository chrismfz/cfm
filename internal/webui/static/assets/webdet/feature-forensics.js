// Forensics: webdetector history (events/summary/stats, prune/truncate) and
// the analyze-ip / analyze-host tools.

export const forensicsMixin = {
  data() {
    return {
      historyHost: "",
      historyIP: "",
      historyType: "",
      historyEvents: [],
      historySummary: null,
      historyStats: null,
      historyBusy: false,
    };
  },

  methods: {
    historyForensicsTitle(row) {
      const p = (row && row.payload) || {};
      const lines = [];
      if (p.ua) lines.push(`UA: ${p.ua}`);
      if (p.referer) lines.push(`Referer: ${p.referer}`);
      if (p.ct) lines.push(`Content-Type: ${p.ct}`);
      return lines.length ? lines.join("\n") : "-";
    },
    async refreshHistory() {
      const host = String(this.historyHost || "").trim();
      const ip = String(this.historyIP || "").trim();
      const evType = String(this.historyType || "").trim();
      const q = [];
      if (host) q.push(`host=${encodeURIComponent(host)}`);
      if (ip) q.push(`ip=${encodeURIComponent(ip)}`);
      const qs = q.length ? `&${q.join("&")}` : "";
      const evQS = evType ? `${qs}&type=${encodeURIComponent(evType)}` : qs;
      const [events, summary, stats] = await Promise.all([
        this.fetchJSONSafe(`v1/webdet/history/events?limit=50&enrich=1${evQS}`, { rows: [] }),
        this.fetchJSONSafe(`v1/webdet/history/summary?hours=24${qs}`, null),
        this.fetchJSONSafe("v1/webdet/history/stats", null),
      ]);
      this.historyEvents = this.extractRows(events, "rows");
      this.historySummary = summary;
      this.historyStats = stats;
    },
    async pruneHistory(days = 30) {
      this.historyBusy = true;
      try {
        await this.postJSON(`v1/webdet/history/prune?days=${encodeURIComponent(days)}`, {});
        this.actionMsg = `History pruned (older than ${days} days)`;
        await this.refreshHistory();
      } catch (err) {
        this.actionMsg = `History prune failed: ${err}`;
      } finally {
        this.historyBusy = false;
      }
    },
    async truncateHistory() {
      if (!window.confirm("Delete all webdetector history? This cannot be undone.")) return;
      this.historyBusy = true;
      try {
        await this.postJSON("v1/webdet/history/truncate?confirm=yes", {});
        this.actionMsg = "History truncated";
        await this.refreshHistory();
      } catch (err) {
        this.actionMsg = `History truncate failed: ${err}`;
      } finally {
        this.historyBusy = false;
      }
    },
  },
};

// IP drilldown for the forensics page: fetches the global ip-short list to
// auto-load the hottest IP, plus the drilldown fetch itself. The overview
// page gets the same state from feature-live.js instead — the two mixins
// are never loaded together.
export const ipDrilldownMixin = {
  data() {
    return {
      ipShort: [],
      ipShortLimit: 20,
      activeIP: "",
      ipDrilldown: null,
    };
  },
  computed: {
    rawIPDrilldownPretty() {
      if (!this.ipDrilldown) return "";
      return JSON.stringify(this.ipDrilldown, null, 2);
    },
  },
  methods: {
    async loadIP(ip) {
      if (!ip) return;
      this.activeIP = ip;
      this.ipDrilldown = await this.fetchJSONSafe(`v1/webdet/ip-drilldown?ip=${encodeURIComponent(ip)}`, { ip, error: "failed to load ip drilldown" });
    },
    async refreshLists() {
      const ipLimit = Math.max(1, Math.min(500, Number(this.ipShortLimit) || 20));
      this.ipShortLimit = ipLimit;
      if (this.isScoped) {
        this.logScopedAdminSkipsOnce(["v1/webdet/ip-short"]);
        return;
      }
      const payload = await this.fetchJSONSafe(`v1/webdet/ip-short?limit=${ipLimit}`, { short: [] });
      this.ipShort = this.extractRows(payload, "short");
    },
    async afterListsRefreshed() {
      if (this.shouldShow("ipdrilldown") && !this.activeIP && this.ipShort[0]?.ip) {
        await this.loadIP(this.ipShort[0].ip);
      }
    },
  },
};

// Analyze is its own small mixin: the forensics page renders its card, and
// the overview's Global Top IPs "Analyze" button reuses the same actions.
export const analyzeMixin = {
  data() {
    return {
      analyzeTarget: "",
      analyzeLast: "",
      analyzeMode: "ip",
      analyzeResult: null,
      analyzeLoading: false,
    };
  },
  computed: {
    rawAnalyzePretty() {
      if (!this.analyzeResult) return "";
      return JSON.stringify(this.analyzeResult, null, 2);
    },
  },
  methods: {
    async analyzeIP(ip) {
      if (!ip) return;
      this.analyzeTarget = ip;
      this.analyzeMode = "ip";
      await this.runAnalyze("ip");
    },
    async runAnalyze(mode = this.analyzeMode) {
      const target = String(this.analyzeTarget || "").trim();
      const last = String(this.analyzeLast || "").trim();
      if (!target) {
        this.actionMsg = "Provide an IP or vhost to analyze.";
        return;
      }
      this.analyzeMode = mode;
      this.analyzeLoading = true;
      try {
        let path = mode === "host"
          ? `v1/webdet/analyze-host?host=${encodeURIComponent(target)}`
          : `v1/webdet/analyze-ip?ip=${encodeURIComponent(target)}`;
        if (last) path += `&last=${encodeURIComponent(last)}`;
        this.analyzeResult = await this.fetchJSON(path);
        this.actionMsg = `Analyze ${mode} loaded for ${target}`;
      } catch (err) {
        const error = this.formatApiError(err);
        this.analyzeResult = { error, target, mode };
        this.actionMsg = `Analyze failed for ${target}: ${error}`;
      } finally {
        this.analyzeLoading = false;
      }
    },
  },
};
