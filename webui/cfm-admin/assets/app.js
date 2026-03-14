(() => {
  const { createApp } = window.Vue;

  createApp({
    data() {
      return {
        loading: false,
        topShort: [],
        suspicious: [],
        drilldown: null,
        activeHost: '',
        timer: null,
      };
    },
    computed: {
      drilldownPretty() {
        if (!this.drilldown) return 'Select a host to load drilldown details.';
        return JSON.stringify(this.drilldown, null, 2);
      },
    },
    methods: {
      num(v) {
        if (v === null || v === undefined || Number.isNaN(Number(v))) return '-';
        return Number(v).toFixed(2).replace(/\.00$/, '');
      },
      async fetchJSON(path) {
        const res = await fetch(`/cfm-admin/api/${path}`, {
          credentials: 'same-origin',
          headers: { 'Accept': 'application/json' },
        });
        if (!res.ok) {
          throw new Error(`${path} -> HTTP ${res.status}`);
        }
        return res.json();
      },
      async refreshAll() {
        this.loading = true;
        try {
          const [topShort, suspicious] = await Promise.all([
            this.fetchJSON('v1/webdet/top-short?limit=50'),
            this.fetchJSON('v1/webdet/suspicious?limit=20'),
          ]);
          this.topShort = Array.isArray(topShort) ? topShort : [];
          this.suspicious = Array.isArray(suspicious) ? suspicious : [];
          if (!this.activeHost && this.topShort[0]?.host) {
            await this.loadHost(this.topShort[0].host);
          }
        } catch (err) {
          console.error('[cfm-admin] refresh failed', err);
        } finally {
          this.loading = false;
        }
      },
      async loadHost(host) {
        if (!host) return;
        this.activeHost = host;
        try {
          this.drilldown = await this.fetchJSON(`v1/webdet/drilldown?host=${encodeURIComponent(host)}`);
        } catch (err) {
          console.error('[cfm-admin] drilldown failed', err);
          this.drilldown = { error: String(err), host };
        }
      },
    },
    mounted() {
      this.refreshAll();
      this.timer = setInterval(this.refreshAll, 5000);
    },
    beforeUnmount() {
      if (this.timer) clearInterval(this.timer);
    },
  }).mount('#app');
})();
