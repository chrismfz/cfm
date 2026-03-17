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
        activeChallengeVhosts: [],
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
        drilldown: null,
        activeHost: '',
        actionMsg: '',
        challengeExcludes: [],
        wafExcludes: [],
        challengeExcludeValue: '',
        challengeExcludeType: 'host',
        wafExcludeValue: '',
        wafExcludeType: 'host',
        timer: null,
        refreshInProgress: false,
        historyHost: '',
        historyIP: '',
        historyEvents: [],
        historySummary: null,
        historyStats: null,
        historyBusy: false,
        wafHours: 24,
        wafEventLimit: 200,
        wafTopN: 10,
        wafSummary: null,
        pageMode: 'overview',
        vhostFocusHost: '',
        vhostSeriesByHost: {},
        vhostSeriesMaxPoints: 120,
        vhostTopIPLimit: 25,
        vhostTopPathLimit: 25,
        drilldownTopN: 50,
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
      activeTopShortRow() {
        if (!this.activeHost || !Array.isArray(this.topShort)) return null;
        return this.topShort.find((row) => row?.host === this.activeHost) || null;
      },
      activeVhostSeries() {
        const host = String(this.activeHost || '').trim();
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
      rpsSeriesChart() {
        const rows = this.activeVhostSeries;
        const keys = ['r2xx', 'r4xx', 'r5xx'];
        const maxY = Math.max(1, ...rows.flatMap((r) => keys.map((k) => Number(r[k] || 0))));
        return {
          maxY,
          series: [
            { key: 'r2xx', cls: 'line-cyan', points: this.sparkPoints(rows.map((r) => Number(r.r2xx || 0)), maxY) },
            { key: 'r4xx', cls: 'line-yellow', points: this.sparkPoints(rows.map((r) => Number(r.r4xx || 0)), maxY) },
            { key: 'r5xx', cls: 'line-red', points: this.sparkPoints(rows.map((r) => Number(r.r5xx || 0)), maxY) },
          ],
        };
      },
      botSeriesChart() {
        const values = this.activeVhostSeries.map((r) => Number(r.bot || 0));
        return {
          maxY: 100,
          points: this.sparkPoints(values, 100),
          last: values.length ? values[values.length - 1] : 0,
        };
      },
      errSeriesChart() {
        const values = this.activeVhostSeries.map((r) => Number(r.err || 0));
        return {
          maxY: 100,
          points: this.sparkPoints(values, 100),
          last: values.length ? values[values.length - 1] : 0,
        };
      },
      scoreSeriesChart() {
        const values = this.activeVhostSeries.map((r) => Number(r.score || 0));
        return {
          maxY: 1,
          points: this.sparkPoints(values, 1),
          last: values.length ? values[values.length - 1] : 0,
        };
      },
      rtSeriesChart() {
        const values = this.activeVhostSeries.map((r) => Number(r.rt || 0));
        const maxY = Math.max(100, ...values);
        return {
          maxY,
          points: this.sparkPoints(values, maxY),
          last: values.length ? values[values.length - 1] : 0,
        };
      },

      isOverviewPage() {
        return this.pageMode === 'overview';
      },
      isVhostPage() {
        return this.pageMode === 'vhost';
      },
      isForensicsPage() {
        return this.pageMode === 'forensics';
      },
      isWAFPage() {
        return this.pageMode === 'waf';
      },
      pageTitle() {
        if (this.isVhostPage) return 'WebDetector / vhost live';
        if (this.isForensicsPage) return 'WebDetector / forensics';
        if (this.isWAFPage) return 'WebDetector / WAF engine';
        return 'WebDetector / overview';
      },
      activeChallengeByHost() {
        const byHost = {};
        const rows = Array.isArray(this.activeChallengeVhosts) ? this.activeChallengeVhosts : [];
        for (const row of rows) {
          const host = row?.host;
          if (!host) continue;
          const mode = String(row.mode || '').toLowerCase();
          byHost[host] = {
            manual_active: mode === 'manual' || mode === 'manual+auto',
            auto_active: mode === 'auto' || mode === 'manual+auto',
            mode,
          };
        }
        return byHost;
      },
      suspiciousAndChallenged() {

        const byHost = {};

        for (const row of this.suspicious) {
          if (!row?.host) continue;
          byHost[row.host] = {
            ...row,
            source: 'suspicious',
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
            source: existing.fromSuspicious ? 'both' : 'challenged',
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

      shouldShow(section) {
        const groups = {
          overview: new Set(['webtop', 'suspicious', 'longtop', 'globalips', 'excludes', 'vhost']),
          vhost: new Set(['vhost']),
          forensics: new Set(['history', 'ipdrilldown', 'analyze', 'excludes']),
          waf: new Set(['wafengine', 'excludes']),
        };
        const active = groups[this.pageMode] || groups.overview;
        return active.has(section);
      },

      vhostLiveURL(host) {
        const h = String(host || '').trim();
        if (!h) return '/cfm-admin/webdetector/vhost/';
        return `/cfm-admin/webdetector/vhost/?host=${encodeURIComponent(h)}`;
      },
      forensicsURL(host) {
        const h = String(host || '').trim();
        if (!h) return '/cfm-admin/webdetector/forensics/';
        return `/cfm-admin/webdetector/forensics/?host=${encodeURIComponent(h)}`;
      },
      openVhostLive(host, newTab = true) {
        const h = String(host || '').trim();
        if (!h) return;
        const url = this.vhostLiveURL(h);
        if (newTab) {
          window.open(url, '_blank', 'noopener');
        } else {
          window.location.href = url;
        }
      },
      openForensics(host, newTab = true) {
        const h = String(host || '').trim();
        if (!h) return;
        const url = this.forensicsURL(h);
        if (newTab) {
          window.open(url, '_blank', 'noopener');
        } else {
          window.location.href = url;
        }
      },
      syncVhostQuery(host) {
        if (!this.isVhostPage) return;
        const h = String(host || '').trim();
        const url = new URL(window.location.href);
        if (h) url.searchParams.set('host', h);
        else url.searchParams.delete('host');
        window.history.replaceState({}, '', url.toString());
      },
      async applyVhostFocus() {
        const host = String(this.vhostFocusHost || '').trim();
        if (!host) {
          this.actionMsg = 'Provide a vhost to open live view.';
          return;
        }
        this.vhostFocusHost = host;
        this.syncVhostQuery(host);
        await this.loadHost(host, false);
      },
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
      fmtTs(unix) {
        const v = Number(unix || 0);
        if (!v) return '-';
        const d = new Date(v * 1000);
        if (Number.isNaN(d.getTime())) return '-';
        return d.toISOString().replace('T', ' ').slice(0, 19);
      },
      sparkPoints(values, maxY = 1) {
        const width = 520;
        const height = 140;
        if (!Array.isArray(values) || values.length < 2) return '';
        const safeMax = Math.max(0.0001, Number(maxY) || 1);
        return values.map((raw, idx) => {
          const x = (idx / (values.length - 1)) * width;
          const y = height - (Math.max(0, Number(raw) || 0) / safeMax) * height;
          return `${x.toFixed(2)},${Math.min(height, Math.max(0, y)).toFixed(2)}`;
        }).join(' ');
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
        const s = this.activeChallengeByHost[host] || {};
        return Boolean(s.manual_active || s.auto_active);
      },
      challengeModeLabel(host) {
        const s = this.activeChallengeByHost[host] || {};
        if (s.manual_active && s.auto_active) return 'manual+auto';
        if (s.manual_active) return 'manual';
        if (s.auto_active) return 'auto';
        return '';
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
          // Only re-fetch challenge state — no need to reload all 6 endpoints
          const fresh = await this.fetchJSONSafe('v1/challenge/vhosts?status=active&mode=all&limit=500', []);
          this.activeChallengeVhosts = this.extractRows(fresh, 'rows');
        } catch (err) {
          this.actionMsg = `Challenge action failed for ${host}: ${err}`;
          console.error('[cfm-admin] challenge action failed', err);
        }
      },
      async manualChallenge(host) {
        if (!host) return;
        try {
          await this.postJSON('v1/challenge/vhost/add', { host, ttl: '30m', reason: 'cfm-admin-ui-manual' });
          this.actionMsg = `Manual challenge enabled for ${host}`;
          const fresh = await this.fetchJSONSafe('v1/challenge/vhosts?status=active&mode=all&limit=500', []);
          this.activeChallengeVhosts = this.extractRows(fresh, 'rows');
        } catch (err) {
          this.actionMsg = `Manual challenge failed for ${host}: ${err}`;
          console.error('[cfm-admin] manual challenge failed', err);
        }
      },
      async manualUnchallenge(host) {
        if (!host) return;
        try {
          await this.postJSON('v1/challenge/vhost/remove', { host });
          this.actionMsg = `Manual challenge removed for ${host}`;
          const fresh = await this.fetchJSONSafe('v1/challenge/vhosts?status=active&mode=all&limit=500', []);
          this.activeChallengeVhosts = this.extractRows(fresh, 'rows');
        } catch (err) {
          this.actionMsg = `Manual unchallenge failed for ${host}: ${err}`;
          console.error('[cfm-admin] manual unchallenge failed', err);
        }
      },
      async analyzeIP(ip) {
        if (!ip) return;
        this.analyzeTarget = ip;
        this.analyzeMode = 'ip';
        await this.runAnalyze('ip');
      },
      async challengeIPTopHost(ip) {
        if (!ip) return;
        try {
          const details = await this.fetchJSON(`v1/webdet/ip-drilldown?ip=${encodeURIComponent(ip)}`);
          const topHost = Array.isArray(details?.hosts) ? details.hosts[0]?.key : '';
          if (!topHost) {
            this.actionMsg = `No host found for IP ${ip} to challenge`;
            return;
          }
          await this.manualChallenge(topHost);
          this.actionMsg = `Manual challenge enabled for top host ${topHost} (IP ${ip})`;
        } catch (err) {
          this.actionMsg = `Challenge failed for IP ${ip}: ${err}`;
          console.error('[cfm-admin] challenge from IP failed', err);
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

      async refreshExcludeLists() {
        const [challengeExcludes, wafExcludes] = await Promise.all([
          this.fetchJSONSafe('v1/challenge/exclude/list', []),
          this.fetchJSONSafe('v1/waf/exclude/list', []),
        ]);
        this.challengeExcludes = this.extractRows(challengeExcludes, 'rows');
        this.wafExcludes = this.extractRows(wafExcludes, 'rows');
      },
      async addExclude(scope) {
        const isChallenge = scope === 'challenge';
        const value = (isChallenge ? this.challengeExcludeValue : this.wafExcludeValue).trim();
        const type = isChallenge ? this.challengeExcludeType : this.wafExcludeType;
        if (!value) {
          this.actionMsg = `Provide a value for ${scope} exclude.`;
          return;
        }
        try {
          await this.postJSON(`v1/${scope}/exclude/add?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`, {});
          this.actionMsg = `${scope.toUpperCase()} exclude added: ${type}=${value}`;
          if (isChallenge) this.challengeExcludeValue = '';
          else this.wafExcludeValue = '';
          await this.refreshExcludeLists();
          await this.refreshHistory();
        } catch (err) {
          this.actionMsg = `${scope.toUpperCase()} exclude add failed: ${err}`;
          console.error('[cfm-admin] exclude add failed', scope, err);
        }
      },
      async removeExclude(scope, entry) {
        if (!entry?.value || !entry?.type) return;
        try {
          await this.postJSON(`v1/${scope}/exclude/remove?type=${encodeURIComponent(entry.type)}&value=${encodeURIComponent(entry.value)}`, {});
          this.actionMsg = `${scope.toUpperCase()} exclude removed: ${entry.type}=${entry.value}`;
          await this.refreshExcludeLists();
          await this.refreshHistory();
        } catch (err) {
          this.actionMsg = `${scope.toUpperCase()} exclude remove failed: ${err}`;
          console.error('[cfm-admin] exclude remove failed', scope, err);
        }
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


      formatTs(tsUnix) {
        if (!tsUnix) return '-';
        const d = new Date(Number(tsUnix) * 1000);
        if (isNaN(d.getTime())) return String(tsUnix);
        return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
      },
      formatBytes(bytes) {
        const n = Number(bytes || 0);
        if (!Number.isFinite(n) || n <= 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB'];
        let v = n;
        let i = 0;
        while (v >= 1024 && i < units.length - 1) {
          v /= 1024;
          i += 1;
        }
        return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
      },
      jumpToHistory() {
        const el = document.getElementById('history-card');
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      },
      openHistoryPage(host = '', ip = '') {
        const url = new URL('/cfm-admin/webdetector/forensics/', window.location.origin);
        const h = String(host || '').trim();
        const i = String(ip || '').trim();
        if (h) url.searchParams.set('host', h);
        if (i) url.searchParams.set('ip', i);
        url.hash = 'history-card';
        window.location.href = `${url.pathname}${url.search}${url.hash}`;
      },
      async historyForHost(host) {
        if (!host) return;
        this.historyHost = host;
        this.historyIP = '';
        if (!this.shouldShow('history')) {
          this.openHistoryPage(host, '');
          return;
        }
        await this.refreshHistory();
        this.jumpToHistory();
      },
      async historyForIP(ip) {
        if (!ip) return;
        this.historyIP = ip;
        if (!this.historyHost) this.historyHost = this.activeHost || '';
        if (!this.shouldShow('history')) {
          this.openHistoryPage(this.historyHost, ip);
          return;
        }
        await this.refreshHistory();
        this.jumpToHistory();
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
        if (!window.confirm('Delete all webdetector history? This cannot be undone.')) return;
        this.historyBusy = true;
        try {
          await this.postJSON('v1/webdet/history/truncate?confirm=yes', {});
          this.actionMsg = 'History truncated';
          await this.refreshHistory();
        } catch (err) {
          this.actionMsg = `History truncate failed: ${err}`;
        } finally {
          this.historyBusy = false;
        }
      },


      async refreshWAFEngine() {
        if (!this.shouldShow('wafengine')) return;
        const hours = Math.max(1, Math.min(24 * 30, Number(this.wafHours) || 24));
        const limit = Math.max(1, Math.min(2000, Number(this.wafEventLimit) || 200));
        const top = Math.max(1, Math.min(100, Number(this.wafTopN) || 10));
        this.wafHours = hours;
        this.wafEventLimit = limit;
        this.wafTopN = top;
        this.wafSummary = await this.fetchJSONSafe(`v1/waf/engine/summary?hours=${hours}&limit=${limit}&top=${top}`, null);
      },

      async refreshHistory() {
        const host = String(this.historyHost || '').trim();
        const ip = String(this.historyIP || '').trim();
        const q = [];
        if (host) q.push(`host=${encodeURIComponent(host)}`);
        if (ip) q.push(`ip=${encodeURIComponent(ip)}`);
        const qs = q.length ? `&${q.join('&')}` : '';
        const [events, summary, stats] = await Promise.all([
          this.fetchJSONSafe(`v1/webdet/history/events?limit=50${qs}`, { rows: [] }),
          this.fetchJSONSafe(`v1/webdet/history/summary?hours=24${qs}`, null),
          this.fetchJSONSafe('v1/webdet/history/stats', null),
        ]);
        this.historyEvents = this.extractRows(events, 'rows');
        this.historySummary = summary;
        this.historyStats = stats;
      },

      async refreshAll() {
        if (this.refreshInProgress) return;
        this.refreshInProgress = true;
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
          const tasks = [
            (this.shouldShow('webtop') || this.shouldShow('vhost')) ? this.fetchJSONSafe(`v1/webdet/top-short?limit=${topLimit}`, { rows: [] }) : Promise.resolve({ rows: [] }),
            this.shouldShow('suspicious') ? this.fetchJSONSafe(`v1/webdet/suspicious?limit=${longLimit}`, { rows: [] }) : Promise.resolve({ rows: [] }),
            this.shouldShow('longtop') ? this.fetchJSONSafe(`v1/webdet/long-top?limit=${longLimit}`, { rows: [] }) : Promise.resolve({ rows: [] }),
            this.shouldShow('globalips') || this.shouldShow('ipdrilldown') ? this.fetchJSONSafe(`v1/webdet/ip-short?limit=${ipLimit}`, { short: [] }) : Promise.resolve({ short: [] }),
            this.shouldShow('webtop') ? this.fetchJSONSafe(`v1/webdet/hot-ips?limit=${hotLimit}`, []) : Promise.resolve([]),
            this.fetchJSONSafe('v1/challenge/vhosts?status=active&mode=all&limit=500', []),
          ];
          const [topShort, suspicious, longTop, ipShort, hotIPs, activeChallengeVhosts] = await Promise.all(tasks);
          this.topShort = this.extractRows(topShort, 'rows');
          this.suspicious = this.extractRows(suspicious, 'rows');
          this.longTop = this.extractRows(longTop, 'rows');
          this.ipShort = this.extractRows(ipShort, 'short');
          this.hotIPs = this.extractRows(hotIPs, 'rows');
          this.activeChallengeVhosts = this.extractRows(activeChallengeVhosts, 'rows');
          this.suspiciousHosts = Object.fromEntries(this.suspicious.map((row) => [row.host, true]));
          if (this.shouldShow('excludes')) await this.refreshExcludeLists();
          if (this.shouldShow('history')) await this.refreshHistory();
          if (this.shouldShow('wafengine')) await this.refreshWAFEngine();

          if (this.shouldShow('vhost') && this.isVhostPage) {
            const vhostTarget = String(this.vhostFocusHost || '').trim() || String(this.activeHost || '').trim() || this.topShort[0]?.host;
            if (vhostTarget) {
              this.vhostFocusHost = vhostTarget;
              this.syncVhostQuery(vhostTarget);
              await this.loadHost(vhostTarget, false);
              this.pushHostSeriesPoint(vhostTarget);
            }
          } else if (this.shouldShow('vhost') && this.activeHost) {
            // overview: push series point for whichever host is open, but don't re-fetch drilldown
            this.pushHostSeriesPoint(this.activeHost);
          }
          if (this.shouldShow('ipdrilldown') && !this.activeIP && this.ipShort[0]?.ip) {
            await this.loadIP(this.ipShort[0].ip);
          }
        } catch (err) {
          console.error('[cfm-admin] refresh failed', err);
          this.actionMsg = `Refresh failed: ${err}`;
        } finally {
          this.loading = false;
          this.refreshInProgress = false;
        }
      },
      scrollToDrilldown() {
        const el = document.getElementById('drilldown-card');
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      },
      async loadHost(host, shouldScroll = true) {
        if (!host) return;
        this.activeHost = host;
        this.ensureHostSeries(host);
        try {
          this.drilldown = await this.fetchJSON(`v1/webdet/drilldown?host=${encodeURIComponent(host)}&top=${this.drilldownTopN}`);
          if (shouldScroll) this.scrollToDrilldown();
        } catch (err) {
          console.error('[cfm-admin] drilldown failed', err);
          this.drilldown = { error: String(err), host };
          if (shouldScroll) this.scrollToDrilldown();
        }
      },
    },
    mounted() {
      const path = (window.location.pathname || '').replace(/\/+$/, '/');
      if (path.includes('/webdetector/forensics/')) this.pageMode = 'forensics';
      else if (path.includes('/webdetector/vhost/')) this.pageMode = 'vhost';
      else if (path.includes('/webdetector/waf/')) this.pageMode = 'waf';
      else this.pageMode = 'overview';

      const currentURL = new URL(window.location.href);
      const qHost = currentURL.searchParams.get('host');
      const qIP = currentURL.searchParams.get('ip');
      if (this.isVhostPage && qHost) {
        this.vhostFocusHost = qHost.trim();
        this.activeHost = this.vhostFocusHost;
      }
      if ((this.isForensicsPage || this.isWAFPage) && qHost) {
        this.historyHost = qHost.trim();
      }
      if ((this.isForensicsPage || this.isWAFPage) && qIP) {
        this.historyIP = qIP.trim();
      }

      this.refreshAll();
      if (this.isForensicsPage) {
        this.stopAutoRefresh();
      } else {
        this.startAutoRefresh();
      }

      if (this.isForensicsPage && currentURL.hash === '#history-card') {
        setTimeout(() => this.jumpToHistory(), 120);
      }
    },
    beforeUnmount() {
      if (this.timer) clearInterval(this.timer);
    },
  }).mount('#app');
})();
