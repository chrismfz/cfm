(() => {
  const { createApp } = window.Vue;

  createApp({
    data() {
      return {
        loading: false,
        autoRefresh: true,
        topShort: [],
        suspicious: [],
        suspiciousHosts: {},
        challengeStatus: {},
        drilldown: null,
        activeHost: '',
        actionMsg: '',
        timer: null,
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
      topPaths() {
        return Array.isArray(this.shortDetail?.top_paths) ? this.shortDetail.top_paths : [];
      },
      topAgents() {
        return Array.isArray(this.shortDetail?.top_agents) ? this.shortDetail.top_agents : [];
      },
      keyMetrics() {
        if (!this.shortDetail) return [];
        const s = this.shortDetail;
        const pick = (label, key, type = 'num') => ({
          label,
          value: type === 'pct' ? `${this.num((s[key] || 0) * 100)}%` : this.num(s[key]),
        });
        return [
          pick('Total req', 'total_req'),
          pick('Short score', 'short_score'),
          pick('RPS', 'rps'),
          pick('Err ratio', 'err_ratio', 'pct'),
          pick('Auth401 ratio', 'auth401_ratio', 'pct'),
          pick('Bot ratio', 'bot_ratio', 'pct'),
          pick('UA diversity', 'ua_diversity'),
          pick('Path diversity', 'path_diversity'),
          pick('POST ratio', 'post_ratio', 'pct'),
          pick('Unique paths', 'unique_paths'),
          pick('Unique UAs', 'unique_uas'),
        ];
      },
      longReasons() {
        return Array.isArray(this.longDetail?.reasons) ? this.longDetail.reasons : [];
      },
      rawDrilldownPretty() {
        if (!this.drilldown) return '';
        return JSON.stringify(this.drilldown, null, 2);
      },
    },
    methods: {
      extractRows(payload, key = 'rows') {
        if (Array.isArray(payload)) return payload;
        if (payload && Array.isArray(payload[key])) return payload[key];
        return [];
      },
      num(v) {
        if (v === null || v === undefined || Number.isNaN(Number(v))) return '-';
        return Number(v).toFixed(2).replace(/\.00$/, '');
      },
      async fetchJSON(path) {
        const res = await fetch(`/cfm-admin/api/${path}`, {
          credentials: 'same-origin',
          headers: { Accept: 'application/json' },
        });
        if (!res.ok) throw new Error(`${path} -> HTTP ${res.status}`);
        return res.json();
      },
      async postJSON(path, body) {
        const res = await fetch(`/cfm-admin/api/${path}`, {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            Accept: 'application/json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(body),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || `${path} -> HTTP ${res.status}`);
        return data;
      },
      startAutoRefresh() {
        if (this.timer) clearInterval(this.timer);
        this.autoRefresh = true;
        this.timer = setInterval(() => this.refreshAll(), 5000);
      },
      stopAutoRefresh() {
        this.autoRefresh = false;
        if (this.timer) {
          clearInterval(this.timer);
          this.timer = null;
        }
      },
      async logout() {
        this.stopAutoRefresh();
        this.actionMsg = 'Attempting Basic-Auth logout (browser-dependent)...';
        try {
          await fetch('/cfm-admin/api/v1/webdet/summary', {
            headers: { Authorization: `Basic ${btoa('logout:logout')}` },
            cache: 'no-store',
          });
        } catch (_) {
          // best-effort only
        }
        window.location.href = '/cfm-admin/?logout=1';
      },
      challengeState(host) {
        const s = this.challengeStatus[host] || {};
        return Boolean(s.manual_active || s.auto_active);
      },
      async refreshChallengeStatuses() {
        const hosts = this.topShort.slice(0, 25).map((r) => r.host).filter(Boolean);
        const next = {};
        await Promise.all(
          hosts.map(async (host) => {
            try {
              next[host] = await this.fetchJSON(`v1/challenge/vhost/status?host=${encodeURIComponent(host)}`);
            } catch (_) {
              next[host] = { manual_active: false, auto_active: false };
            }
          }),
        );
        this.challengeStatus = next;
      },
      async toggleChallenge(host) {
        if (!host) return;
        try {
          if (this.challengeState(host)) {
            await this.postJSON('v1/challenge/vhost/remove', { host });
            this.actionMsg = `Challenge removed for ${host}`;
          } else {
            await this.postJSON('v1/challenge/vhost/add', { host, ttl: '30m', reason: 'cfm-admin-ui' });
            this.actionMsg = `Challenge enabled for ${host}`;
          }
          this.challengeStatus[host] = await this.fetchJSON(`v1/challenge/vhost/status?host=${encodeURIComponent(host)}`);
        } catch (err) {
          this.actionMsg = `Challenge action failed for ${host}: ${err}`;
          console.error('[cfm-admin] challenge action failed', err);
        }
      },
      async blockIP(ip) {
        if (!ip) return;
        try {
          await this.postJSON('v1/firewall/block', {
            ip,
            ttl: '1h',
            reason: `cfm-admin-ui host=${this.activeHost || '-'}`,
          });
          this.actionMsg = `Blocked IP ${ip} for 1h`;
        } catch (err) {
          this.actionMsg = `IP block failed for ${ip}: ${err}`;
          console.error('[cfm-admin] block action failed', err);
        }
      },
      async refreshAll() {
        this.loading = true;
        try {
          const [topShort, suspicious] = await Promise.all([
            this.fetchJSON('v1/webdet/top-short?limit=50'),
            this.fetchJSON('v1/webdet/suspicious?limit=20'),
          ]);
          this.topShort = this.extractRows(topShort, 'rows');
          this.suspicious = this.extractRows(suspicious, 'rows');
          this.suspiciousHosts = Object.fromEntries(this.suspicious.map((row) => [row.host, true]));
          await this.refreshChallengeStatuses();

          if (!this.activeHost && this.topShort[0]?.host) {
            await this.loadHost(this.topShort[0].host);
          }
        } catch (err) {
          console.error('[cfm-admin] refresh failed', err);
          this.actionMsg = `Refresh failed: ${err}`;
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
      this.startAutoRefresh();
    },
    beforeUnmount() {
      if (this.timer) clearInterval(this.timer);
    },
  }).mount('#app');
})();
