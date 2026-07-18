// WAF engine analytics: the structured summary card (top rules/hosts/IPs +
// recent events) backed by v1/waf/engine/summary.

export const wafEngineMixin = {
  data() {
    return {
      wafHours: 24,
      wafEventLimit: 200,
      wafTopN: 10,
      wafSummary: null,
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
      this.wafSummary = await this.fetchJSONSafe(`v1/waf/engine/summary?hours=${hours}&limit=${limit}&top=${top}&enrich=1`, null);
    },
  },
};
