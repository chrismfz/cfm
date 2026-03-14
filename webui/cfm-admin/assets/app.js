(() => {
  const { createApp } = window.Vue;

  createApp({
    data() {
      return {
        loading: false,
        autoRefresh: true,
        refreshIntervalSec: 5,
        topShort: [],
        topShortLimit: 20,
        suspicious: [],
        longTop: [],
        longTopLimit: 20,
        ipShort: [],
        ipShortLimit: 20,
        hotIPs: [],
        hotIPsLimit: 20,
        activeIP: '',
        ipDrilldown: null,
        analyzeTarget: '',
        analyzeMode: 'ip',
        analyzeResult: null,
        analyzeLoading: false,
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
            country: info.country || '-',
            asn: info.asn ? `AS${String(info.asn).replace(/^AS/i, '')}` : '-',
            company: info.asn_name || '-',
          };
        });
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
      rawIPDrilldownPretty() {
        if (!this.ipDrilldown) return '';
        return JSON.stringify(this.ipDrilldown, null, 2);
      },
      rawAnalyzePretty() {
        if (!this.analyzeResult) return '';
        return JSON.stringify(this.analyzeResult, null, 2);
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
      pct(v) {
        if (v === null || v === undefined || Number.isNaN(Number(v))) return '-';
        return `${(Number(v) * 100).toFixed(1).replace(/\.0$/, '')}%`;
      },
      reasonText(row) {
        if (Array.isArray(row?.reasons)) return row.reasons.join(', ');
        return row?.reasons || row?.reason || '-';
      },
      async fetchJSON(path) {
        const res = await fetch(`/cfm-admin/api/${path}`, {
          credentials: 'same-origin',
          headers: { Accept: 'application/json' },
        });
        if (!res.ok) throw new Error(`${path} -> HTTP ${res.status}`);
        return res.json();
      },
      async fetchJSONSafe(path, fallback) {
        try {
          return await this.fetchJSON(path);
        } catch (err) {
          console.error('[cfm-admin] fetch failed', path, err);
          return fallback;
        }
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
        const sec = Math.max(1, Math.min(300, Number(this.refreshIntervalSec) || 5));
        this.refreshIntervalSec = sec;
        this.autoRefresh = true;
        this.timer = setInterval(() => this.refreshAll(), sec * 1000);
      },
      applyRefreshInterval() {
        const sec = Math.max(1, Math.min(300, Number(this.refreshIntervalSec) || 5));
        this.refreshIntervalSec = sec;
        if (this.autoRefresh) this.startAutoRefresh();
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
      async loadIP(ip) {
        if (!ip) return;
        this.activeIP = ip;
        this.ipDrilldown = await this.fetchJSONSafe(`v1/webdet/ip-drilldown?ip=${encodeURIComponent(ip)}`, { ip, error: 'failed to load ip drilldown' });
      },
      async runAnalyze(mode = this.analyzeMode) {
        const target = String(this.analyzeTarget || '').trim();
        if (!target) {
          this.actionMsg = 'Provide an IP or vhost to analyze.';
          return;
        }
        this.analyzeMode = mode;
        this.analyzeLoading = true;
        try {
          const path = mode === 'host'
            ? `v1/webdet/analyze-host?host=${encodeURIComponent(target)}`
            : `v1/webdet/analyze-ip?ip=${encodeURIComponent(target)}`;
          this.analyzeResult = await this.fetchJSON(path);
          this.actionMsg = `Analyze ${mode} loaded for ${target}`;
        } catch (err) {
          this.analyzeResult = { error: String(err), target, mode };
          this.actionMsg = `Analyze failed for ${target}: ${err}`;
        } finally {
          this.analyzeLoading = false;
        }
      },
      async refreshAll() {
        this.loading = true;
        try {
          const topLimit = Math.max(1, Math.min(500, Number(this.topShortLimit) || 20));
          const longLimit = Math.max(1, Math.min(500, Number(this.longTopLimit) || 20));
          const ipLimit = Math.max(1, Math.min(500, Number(this.ipShortLimit) || 20));
          const hotLimit = Math.max(1, Math.min(500, Number(this.hotIPsLimit) || 20));
          this.topShortLimit = topLimit;
          this.longTopLimit = longLimit;
          this.ipShortLimit = ipLimit;
          this.hotIPsLimit = hotLimit;
          const [topShort, suspicious, longTop, ipShort, hotIPs] = await Promise.all([
            this.fetchJSONSafe(`v1/webdet/top-short?limit=${topLimit}`, { rows: [] }),
            this.fetchJSONSafe(`v1/webdet/suspicious?limit=${longLimit}`, { rows: [] }),
            this.fetchJSONSafe(`v1/webdet/long-top?limit=${longLimit}`, { rows: [] }),
            this.fetchJSONSafe(`v1/webdet/ip-short?limit=${ipLimit}`, { short: [] }),
            this.fetchJSONSafe(`v1/webdet/hot-ips?limit=${hotLimit}`, []),
          ]);
          this.topShort = this.extractRows(topShort, 'rows');
          this.suspicious = this.extractRows(suspicious, 'rows');
          this.longTop = this.extractRows(longTop, 'rows');
          this.ipShort = this.extractRows(ipShort, 'short');
          this.hotIPs = this.extractRows(hotIPs, 'rows');
          this.suspiciousHosts = Object.fromEntries(this.suspicious.map((row) => [row.host, true]));
          await this.refreshChallengeStatuses();

          if (!this.activeHost && this.topShort[0]?.host) {
            await this.loadHost(this.topShort[0].host, false);
          }
          if (!this.activeIP && this.ipShort[0]?.ip) {
            await this.loadIP(this.ipShort[0].ip);
          }
        } catch (err) {
          console.error('[cfm-admin] refresh failed', err);
          this.actionMsg = `Refresh failed: ${err}`;
        } finally {
          this.loading = false;
        }
      },
      scrollToDrilldown() {
        const el = document.getElementById('drilldown-card');
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      },
      async loadHost(host, shouldScroll = true) {
        if (!host) return;
        this.activeHost = host;
        try {
          this.drilldown = await this.fetchJSON(`v1/webdet/drilldown?host=${encodeURIComponent(host)}`);
          if (shouldScroll) this.scrollToDrilldown();
        } catch (err) {
          console.error('[cfm-admin] drilldown failed', err);
          this.drilldown = { error: String(err), host };
          if (shouldScroll) this.scrollToDrilldown();
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
