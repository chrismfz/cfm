// The analyze-ip / analyze-host tools (offline TSV), mounted by the
// Protection page's Tools tab (feature-protection.js). The history views that
// lived here (the Forensics page) are that page's Events tab now.

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
