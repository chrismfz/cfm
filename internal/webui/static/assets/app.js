(() => {
  const { createApp } = window.Vue;

  const _authCtx = window.CFMAuthContext || {
    getToken: () => '',
    waitForToken: async () => '',
    onAuthContextChanged: () => () => {},
    loadMe: async () => {
      const res = await fetch('/cfm-admin/api/v1/tokens/me', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
      if (!res.ok) throw new Error(`v1/tokens/me -> HTTP ${res.status}`);
      return res.json();
    },
  };
  let _scopedToken = _authCtx.getToken();
  let _lateTokenReinitialized = false;
  let _lateTokenReinitPending = false;
  let _appVm = null;

  function triggerLateTokenReinit() {
    if (_lateTokenReinitialized) return;
    _lateTokenReinitialized = true;
    if (_appVm && typeof _appVm.onLateScopedToken === 'function') {
      _appVm.onLateScopedToken().catch((err) => {
        console.error('[cfm-webui] late token re-init failed', err);
      });
      return;
    }
    _lateTokenReinitPending = true;
  }

  function waitForScopedToken(timeoutMs = 1200) {
    return _authCtx.waitForToken(timeoutMs);
  }

  _authCtx.onAuthContextChanged((evt) => {
    _scopedToken = _authCtx.getToken();
    if (evt && evt.modeChanged) {
      triggerLateTokenReinit();
    }
  });


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
        // Token management
        isAdmin: false,
        isScopedMode: false,
        tokenRole: 'viewer',
        allowedVhosts: [],
        meLoaded: false,
        tokens: [],
        tokenForm: { vhosts: '', label: '', ttl: '8760h', role: 'viewer' },
        tokenCreateMsg: '',
        // Per-vhost Security Overview
        vhostOverview: null,
        vhostOverviewHost: '',
        vhostOverviewHours: 24,
        pageMode: 'overview',
        vhostControls: [],
        controlsSearch: '',
        controlsSortKey: 'host',
        controlsSortDir: 'asc',
        vhostControlsLimit: 50,
        rules: [],
        rulesSearch: '',
        ruleEditID: '',
        ruleForm: {
          enabled: true,
          priority: 100,
          vhosts: '',
          countries: '',
          uas: '',
          paths: '',
          methods: '',
          actionType: 'throttle',
          throttleProfile: 'soft_bot',
          note: '',
	  hasQS: false,
	  qsNotRx: '',
        },
        presets: [
          { key: 'meta_throttle', label: 'Preset: Meta throttle', hint: 'Throttle known Meta crawlers softly.' },
          { key: 'challenge_login', label: 'Preset: Challenge login', hint: 'Challenge repeated login endpoint abuse.' },
          { key: 'block_country', label: 'Preset: Block countries (disabled)', hint: 'Start disabled and validate first.' },
  // ── throttle presets ──
  { key: 'throttle_scrapers',    label: 'Preset: Throttle script scrapers', hint: 'Rate-limit generic script tools: python-requests, curl, wget, Go HTTP client.' },
  { key: 'throttle_ai_crawlers', label: 'Preset: Throttle AI crawlers',     hint: 'Throttle AI training bots (GPTBot, ClaudeBot, Bytespider…) at medium rate.' },
  { key: 'throttle_seo_bots',    label: 'Preset: Throttle SEO bots',        hint: 'Soft-limit commercial SEO crawlers (Ahrefs, Semrush, MJ12, DotBot).' },
  // ── block / challenge presets ──
  { key: 'block_meta_qs',        label: 'Preset: Block Meta bot QS loop',   hint: 'Block Meta/GoogleOther bots hitting pages with unexpected query strings. Requires has_qs support.' },
  { key: 'block_empty_ua',       label: 'Preset: Block empty UA',           hint: 'Block requests with no User-Agent header — scanners and raw exploit tools.' },
  { key: 'block_xmlrpc',         label: 'Preset: Block xmlrpc.php',         hint: 'Block all POST requests to xmlrpc.php — brute-force amplifier with no legit use on most sites.' },
  { key: 'challenge_wp_admin',   label: 'Preset: Challenge wp-admin',       hint: 'Challenge POST requests to wp-admin and wp-login — catches credential stuffing.' },
  // ── allow preset ──
  { key: 'allow_good_bots',      label: 'Preset: Allow good bots (priority 10)', hint: 'Explicit allow for verified search crawlers before any block/challenge rules fire.' },
        ],
        simulateForm: {
          host: '',
          ip: '',
          ua: '',
          path: '/',
          method: 'GET',
          country: '',
	  qs: ''
        },
        simulateResult: null,
        vhostFocusHost: '',
        vhostSeriesByHost: {},
        vhostSeriesMaxPoints: 120,
        vhostTopIPLimit: 25,
        vhostTopPathLimit: 25,
        drilldownTopN: 50,
        vhostCharts: {
          rps: null,
          bot: null,
          err: null,
          score: null,
          rt: null,
        },
        resizeHandler: null,
        scopedSkipInfoLogged: false,
        tokenBootLogged: false,
        modeChangeLogged: false,
      };
    },

    computed: {
      isScoped() { return this.isScopedMode; },
      canWrite() { return this.isAdmin || this.tokenRole !== 'viewer'; },
      hasScopedVhosts() { return this.isScoped && this.allowedVhosts.length > 0; },
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
      isControlsPage() {
        return this.pageMode === 'controls';
      },
      pageTitle() {
        if (this.isVhostPage) return 'WebDetector / vhost live';
        if (this.isForensicsPage) return 'WebDetector / forensics';
        if (this.isWAFPage) return 'WebDetector / WAF engine';
        if (this.isControlsPage) return 'WebDetector / vhost controls';
        return 'WebDetector / overview';
      },
      vhostControlsFiltered() {
        const q = String(this.controlsSearch || '').trim().toLowerCase();
        const filtered = !q
          ? this.vhostControls.slice()
          : this.vhostControls.filter((row) => String(row?.host || '').toLowerCase().includes(q));
        const key = String(this.controlsSortKey || 'host');
        const dir = this.controlsSortDir === 'desc' ? -1 : 1;
        const boolOrder = (v) => (v ? 1 : 0);
        filtered.sort((a, b) => {
          if (key === 'challenge') {
            const cmp = boolOrder(Boolean(a?.challenge_enabled)) - boolOrder(Boolean(b?.challenge_enabled));
            if (cmp !== 0) return cmp * dir;
          } else if (key === 'waf') {
            const cmp = boolOrder(Boolean(a?.waf_enabled)) - boolOrder(Boolean(b?.waf_enabled));
            if (cmp !== 0) return cmp * dir;
          } else {
            const cmpHost = String(a?.host || '').localeCompare(String(b?.host || ''), undefined, { sensitivity: 'base' });
            if (cmpHost !== 0) return cmpHost * dir;
          }
          return String(a?.host || '').localeCompare(String(b?.host || ''), undefined, { sensitivity: 'base' });
        });
        const lim = Number(this.vhostControlsLimit) || 50;
        return lim > 0 ? filtered.slice(0, lim) : filtered;
      },
      rulesFiltered() {
        const q = String(this.rulesSearch || '').trim().toLowerCase();
        if (!q) return this.rules;
        return this.rules.filter((row) => {
          const hostStr = Array.isArray(row?.scope?.vhosts) ? row.scope.vhosts.join(',') : '';
          const note = String(row?.note || '');
          return String(row?.id || '').toLowerCase().includes(q)
            || hostStr.toLowerCase().includes(q)
            || note.toLowerCase().includes(q)
            || String(row?.action?.type || '').toLowerCase().includes(q);
        });
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
      chartTextColor() {
        return '#dbe7f7';
      },
      chartAxisColor() {
        return '#7f93ad';
      },
      chartSplitColor() {
        return 'rgba(159,176,195,0.18)';
      },
      vhostChartTimes() {
        return this.activeVhostSeries.map((p) => {
          const d = new Date(Number(p.at || 0));
          return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString();
        });
      },
      baseLineOption({ yName = '', min = null, max = null } = {}) {
        return {
          backgroundColor: 'transparent',
          animation: true,
          tooltip: { trigger: 'axis', axisPointer: { type: 'cross' } },
          legend: {
            top: 6,
            right: 10,
            textStyle: { color: this.chartTextColor() },
          },
          grid: { left: 52, right: 18, top: 34, bottom: 28 },
          xAxis: {
            type: 'category',
            boundaryGap: false,
            data: this.vhostChartTimes(),
            axisLine: { lineStyle: { color: this.chartAxisColor() } },
            axisLabel: { color: this.chartAxisColor(), hideOverlap: true },
          },
          yAxis: {
            type: 'value',
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

        initOne('rps', 'vhost-rps-chart');
        initOne('bot', 'vhost-bot-chart');
        initOne('err', 'vhost-err-chart');
        initOne('score', 'vhost-score-chart');
        initOne('rt', 'vhost-rt-chart');
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
          type: 'category',
          boundaryGap: false,
          data: times,
          axisLine: { lineStyle: { color: this.chartAxisColor() } },
          axisLabel: { color: this.chartAxisColor(), hideOverlap: true },
        };

        this.vhostCharts.rps?.setOption({
          ...this.baseLineOption({ yName: 'RPS', min: 0 }),
          xAxis: commonXAxis,
          legend: {
            top: 6,
            right: 10,
            textStyle: { color: this.chartTextColor() },
            data: ['2xx', '4xx', '5xx'],
          },
          series: [
            { name: '2xx', type: 'line', smooth: true, showSymbol: false, lineStyle: { color: '#2ec9d7', width: 2 }, data: r2xx },
            { name: '4xx', type: 'line', smooth: true, showSymbol: false, lineStyle: { color: '#f1d64a', width: 2 }, data: r4xx },
            { name: '5xx', type: 'line', smooth: true, showSymbol: false, lineStyle: { color: '#db6178', width: 2 }, data: r5xx },
          ],
        }, true);

        this.vhostCharts.bot?.setOption({
          ...this.baseLineOption({ yName: '%', min: 0, max: 100 }),
          xAxis: commonXAxis,
          legend: {
            top: 6,
            right: 10,
            textStyle: { color: this.chartTextColor() },
            data: ['Bot %'],
          },
          series: [
            { name: 'Bot %', type: 'line', smooth: true, showSymbol: false, lineStyle: { color: '#2ec9d7', width: 2 }, data: bot },
          ],
        }, true);

        this.vhostCharts.err?.setOption({
          ...this.baseLineOption({ yName: '%', min: 0, max: 100 }),
          xAxis: commonXAxis,
          legend: {
            top: 6,
            right: 10,
            textStyle: { color: this.chartTextColor() },
            data: ['Error %'],
          },
          series: [
            { name: 'Error %', type: 'line', smooth: true, showSymbol: false, lineStyle: { color: '#f1d64a', width: 2 }, data: err },
          ],
        }, true);

        this.vhostCharts.score?.setOption({
          ...this.baseLineOption({ yName: 'Score', min: 0, max: 1 }),
          xAxis: commonXAxis,
          legend: {
            top: 6,
            right: 10,
            textStyle: { color: this.chartTextColor() },
            data: ['Threat score'],
          },
          series: [
            { name: 'Threat score', type: 'line', smooth: true, showSymbol: false, lineStyle: { color: '#87d45b', width: 2 }, data: score },
          ],
        }, true);

        this.vhostCharts.rt?.setOption({
          ...this.baseLineOption({ yName: 'ms', min: 0 }),
          xAxis: commonXAxis,
          legend: {
            top: 6,
            right: 10,
            textStyle: { color: this.chartTextColor() },
            data: ['Response ms'],
          },
          series: [
            { name: 'Response ms', type: 'line', smooth: true, showSymbol: false, lineStyle: { color: '#db62e6', width: 2 }, data: rt },
          ],
        }, true);

        this.$nextTick(() => this.resizeVhostCharts());
      },

      shouldShow(section) {
        if (this.isScoped) {
          const hiddenForScoped = new Set(['globalips', 'tokens', 'excludes']);
          if (hiddenForScoped.has(section)) return false;
        }
        const groups = {
          overview: new Set(['webtop', 'suspicious', 'longtop', 'globalips', 'excludes', 'vhost']),
          vhost: new Set(['vhost']),
          forensics: new Set(['history', 'ipdrilldown', 'analyze', 'excludes']),
          waf: new Set(['wafengine', 'excludes']),
          controls: new Set(['controls', 'tokens', 'vhost_overview']),
        };
        const active = groups[this.pageMode] || groups.overview;
        return active.has(section);
      },
      logScopedAdminSkipsOnce(paths) {
        if (!this.isScoped || this.scopedSkipInfoLogged) return;
        const list = Array.isArray(paths) ? paths.filter(Boolean) : [];
        if (!list.length) return;
        console.info('[cfm-admin] scoped mode: skipped admin/global endpoints:', list.join(', '));
        this.scopedSkipInfoLogged = true;
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
        if (newTab) window.open(url, '_blank', 'noopener');
        else window.location.href = url;
      },
      openForensics(host, newTab = true) {
        const h = String(host || '').trim();
        if (!h) return;
        const url = this.forensicsURL(h);
        if (newTab) window.open(url, '_blank', 'noopener');
        else window.location.href = url;
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
        let host = String(this.vhostFocusHost || '').trim();
        if (this.hasScopedVhosts && !this.allowedVhosts.includes(host.toLowerCase())) host = this.allowedVhosts[0] || '';
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
        const headers = { Accept: 'application/json' };
        if (_scopedToken) headers['Authorization'] = `Bearer ${_scopedToken}`;
        const res = await fetch(`/cfm-admin/api/${path}`, {
          credentials: 'same-origin',
          headers,
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
        if (!this.canWrite) {
          const writePrefixes = ['v1/challenge/', 'v1/firewall/', 'v1/webdet/rules/', 'v1/tokens/revoke', 'v1/auth/token', 'v1/webdet/history/prune', 'v1/webdet/history/truncate', 'v1/waf/exclude/', 'v1/challenge/exclude/', 'v1/webdet/vhost-controls/'];
          if (writePrefixes.some((prefix) => String(path).startsWith(prefix))) {
            throw new Error('read-only scoped viewer token');
          }
        }
        const headers = {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        };
        if (_scopedToken) headers['Authorization'] = `Bearer ${_scopedToken}`;
        const res = await fetch(`/cfm-admin/api/${path}`, {
          method: 'POST',
          credentials: 'same-origin',
          headers,
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
        await fetch('/cfm-admin/logout', {
          method: 'POST',
          credentials: 'same-origin',
          redirect: 'manual',
        }).catch(() => {});
        window.location.href = '/cfm-admin/login';
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
        if (this.isScoped) {
          this.challengeExcludes = [];
          this.wafExcludes = [];
          this.logScopedAdminSkipsOnce(['v1/challenge/exclude/list', 'v1/waf/exclude/list']);
          return;
        }
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
      vhostControlEnabled(row, kind) {
        const key = kind === 'challenge' ? 'challenge_enabled' : 'waf_enabled';
        return Boolean(row?.[key]);
      },
      vhostControlToggleable(row, kind) {
        const key = kind === 'challenge' ? 'challenge_toggleable' : 'waf_toggleable';
        return Boolean(row?.[key]);
      },
      vhostControlMatchedExclude(row, kind) {
        const key = kind === 'challenge' ? 'challenge_matched_exclude' : 'waf_matched_exclude';
        return String(row?.[key] || '').trim();
      },
      vhostControlButtonLabel(row, kind) {
        const enabled = this.vhostControlEnabled(row, kind);
        if (enabled) return 'ON / ENABLED';
        const toggleable = this.vhostControlToggleable(row, kind);
        return toggleable ? 'OFF / DISABLED' : 'OFF / MATCHED BY PATTERN';
      },
      vhostControlButtonTitle(row, kind) {
        const enabled = this.vhostControlEnabled(row, kind);
        if (enabled) return '';
        const matched = this.vhostControlMatchedExclude(row, kind);
        const toggleable = this.vhostControlToggleable(row, kind);
        if (!matched) return '';
        if (toggleable) return `Excluded by host rule: ${matched}`;
        return `Excluded by non-exact host rule: ${matched}. Remove/edit that rule in Dynamic excludes first.`;
      },
      setControlsSort(nextKey) {
        const key = String(nextKey || '').trim().toLowerCase();
        if (!key) return;
        if (this.controlsSortKey === key) {
          this.controlsSortDir = this.controlsSortDir === 'asc' ? 'desc' : 'asc';
          return;
        }
        this.controlsSortKey = key;
        this.controlsSortDir = 'asc';
      },
      controlsSortArrow(key) {
        if (this.controlsSortKey !== key) return '';
        return this.controlsSortDir === 'asc' ? '↑' : '↓';
      },
      async refreshVhostControls() {
        if (!this.shouldShow('controls')) return;
        const url = new URL(window.location.href);
        const scoped = (url.searchParams.get('vhost') || url.searchParams.get('vhosts') || '').trim();
        const qs = scoped ? `?vhost=${encodeURIComponent(scoped)}` : '';
        const payload = await this.fetchJSONSafe(`v1/webdet/vhosts${qs}`, { rows: [] });
        this.vhostControls = this.extractRows(payload, 'rows');
      },
      async toggleVhostProtection(row, kind) {
        const host = String(row?.host || '').trim();
        if (!host) return;
        const currentlyEnabled = this.vhostControlEnabled(row, kind);
        const toggleable = this.vhostControlToggleable(row, kind);
        if (!toggleable) {
          const matched = this.vhostControlMatchedExclude(row, kind);
          this.actionMsg = `${kind.toUpperCase()} for ${host} is disabled by non-exact exclude (${matched || 'pattern'}). Remove/edit it in Dynamic excludes first.`;
          return;
        }
        try {
          if (currentlyEnabled) {
            await this.postJSON(`v1/${kind}/exclude/add?type=host&value=${encodeURIComponent(host)}`, {});
            this.actionMsg = `${kind.toUpperCase()} disabled for ${host}`;
          } else {
            await this.postJSON(`v1/${kind}/exclude/remove?type=host&value=${encodeURIComponent(host)}`, {});
            this.actionMsg = `${kind.toUpperCase()} enabled for ${host}`;
          }
          await this.refreshVhostControls();
        } catch (err) {
          this.actionMsg = `${kind.toUpperCase()} toggle failed for ${host}: ${err}`;
          console.error('[cfm-admin] vhost controls toggle failed', kind, host, err);
        }
      },
      csvSplit(v) {
        return String(v || '')
          .split(',')
          .map((x) => x.trim())
          .filter(Boolean);
      },
      buildRulePayload() {
        const f = this.ruleForm || {};
        const actionType = String(f.actionType || '').trim();
        const payload = {
          enabled: Boolean(f.enabled),
          priority: Number(f.priority || 100),
          scope: { vhosts: this.csvSplit(f.vhosts) },
          match: {
            country_in: this.csvSplit(f.countries).map((x) => x.toUpperCase()),
            ua_any: this.csvSplit(f.uas),
            path_any: this.csvSplit(f.paths),
            methods: this.csvSplit(f.methods).map((x) => x.toUpperCase()),
	    has_qs:     Boolean(f.hasQS),
	    qs_not_rx:  String(f.qsNotRx || '').trim() || undefined,
          },
          action: {
            type: actionType,
            profile: actionType === 'throttle' ? String(f.throttleProfile || '').trim() : '',
          },
          note: String(f.note || '').trim(),
        };
        if (!payload.scope.vhosts.length) throw new Error('At least one vhost is required.');
        if (!payload.action.type) throw new Error('Action is required.');
        if (payload.action.type === 'throttle' && !payload.action.profile) throw new Error('Throttle profile is required.');
        return payload;
      },
      resetRuleForm() {
        this.ruleEditID = '';
        this.ruleForm = {
          enabled: true,
          priority: 100,
          vhosts: '',
          countries: '',
          uas: '',
          paths: '',
          methods: '',
          actionType: 'throttle',
          throttleProfile: 'soft_bot',
          note: '',
	  hasQS: false,
	  qsNotRx: '',
        };
      },
      loadRuleIntoForm(row) {
        if (!row) return;
        this.ruleEditID = String(row.id || '');
        this.ruleForm = {
          enabled: Boolean(row.enabled),
          priority: Number(row.priority || 100),
          vhosts: Array.isArray(row?.scope?.vhosts) ? row.scope.vhosts.join(', ') : '',
          countries: Array.isArray(row?.match?.country_in) ? row.match.country_in.join(', ') : '',
          uas: Array.isArray(row?.match?.ua_any) ? row.match.ua_any.join(', ') : '',
          paths: Array.isArray(row?.match?.path_any) ? row.match.path_any.join(', ') : '',
          methods: Array.isArray(row?.match?.methods) ? row.match.methods.join(', ') : '',
          actionType: String(row?.action?.type || 'throttle'),
          throttleProfile: String(row?.action?.profile || 'soft_bot'),
          note: String(row?.note || ''),
	  hasQS:   Boolean(row?.match?.has_qs),
	  qsNotRx: String(row?.match?.qs_not_rx || ''),
        };
      },
      ruleMatchSummary(row) {
        const m = row?.match || {};
        const parts = [];
        if (Array.isArray(m.country_in) && m.country_in.length) parts.push(`country=${m.country_in.join(',')}`);
        if (Array.isArray(m.methods) && m.methods.length) parts.push(`method=${m.methods.join(',')}`);
        if (Array.isArray(m.ua_any) && m.ua_any.length) parts.push(`ua×${m.ua_any.length}`);
        if (Array.isArray(m.path_any) && m.path_any.length) parts.push(`path×${m.path_any.length}`);
        return parts.length ? parts.join(' | ') : '(no filters)';
      },
      async refreshRules() {
        if (!this.shouldShow('controls')) return;
        const payload = await this.fetchJSONSafe('v1/webdet/rules', { rows: [] });
        this.rules = this.extractRows(payload, 'rows');
      },
      async saveRule() {
        let payload;
        try {
          payload = this.buildRulePayload();
        } catch (err) {
          this.actionMsg = `Rule validation failed: ${err}`;
          return;
        }
        try {
          if (this.ruleEditID) {
            await this.postJSON(`v1/webdet/rules/update?id=${encodeURIComponent(this.ruleEditID)}`, payload);
            this.actionMsg = `Rule updated: ${this.ruleEditID}`;
          } else {
            const out = await this.postJSON('v1/webdet/rules/add', payload);
            this.actionMsg = `Rule added: ${out?.rule?.id || '(new)'}`;
          }
          await this.refreshRules();
          this.resetRuleForm();
        } catch (err) {
          this.actionMsg = `Rule save failed: ${err}`;
          console.error('[cfm-admin] rule save failed', err);
        }
      },
      async removeRule(row) {
        const id = String(row?.id || '').trim();
        if (!id) return;
        try {
          await this.postJSON(`v1/webdet/rules/remove?id=${encodeURIComponent(id)}`, {});
          this.actionMsg = `Rule removed: ${id}`;
          await this.refreshRules();
          if (this.ruleEditID === id) this.resetRuleForm();
        } catch (err) {
          this.actionMsg = `Rule remove failed: ${err}`;
          console.error('[cfm-admin] rule remove failed', err);
        }
      },
      applyPreset(presetKey) {
        const host = String(this.vhostFocusHost || this.activeHost || '').trim();
        const baseHost = host || 'example.com';
        if (presetKey === 'meta_throttle') {
          this.ruleEditID = '';
          this.ruleForm = {
            enabled: true,
            priority: 100,
            vhosts: baseHost,
            countries: '',
            uas: '*facebookexternalhit*, *meta-externalagent*',
            paths: '',
            methods: 'GET',
            actionType: 'throttle',
            throttleProfile: 'soft_bot',
            note: 'Preset: Meta crawler soft throttle',
          };
        } else if (presetKey === 'challenge_login') {
          this.ruleEditID = '';
          this.ruleForm = {
            enabled: true,
            priority: 120,
            vhosts: baseHost,
            countries: '',
            uas: '',
            paths: '/wp-login.php, /xmlrpc.php',
            methods: 'POST',
            actionType: 'challenge',
            throttleProfile: 'soft_bot',
            note: 'Preset: challenge sensitive login endpoints',
          };
        } else if (presetKey === 'block_country') {
          this.ruleEditID = '';
          this.ruleForm = {
            enabled: false,
            priority: 200,
            vhosts: baseHost,
            countries: 'CN, RU',
            uas: '',
            paths: '',
            methods: '',
            actionType: 'block',
            throttleProfile: 'soft_bot',
            note: 'Preset: country block (disabled by default)',
          };
        } else if (presetKey === 'throttle_scrapers') {
          this.ruleEditID = '';
  this.ruleForm = {
    enabled: true, priority: 150,
    vhosts: baseHost, countries: '',
    uas: '*python-requests*, *python-urllib*, *go-http-client*, *curl*, *wget*',
    paths: '', methods: 'GET, POST',
    actionType: 'throttle', throttleProfile: 'hard_bot',
    note: 'Throttle generic script scrapers — hard_bot (0.5 req/s, burst 5)',
    hasQS: false, qsNotRx: '',
  };
} else if (presetKey === 'throttle_ai_crawlers') {
  this.ruleEditID = '';
  this.ruleForm = {
    enabled: false, priority: 110,
    vhosts: baseHost, countries: '',
    uas: '*GPTBot*, *ClaudeBot*, *Bytespider*, *CCBot*, *Amazonbot*, *meta-externalagent*',
    paths: '', methods: 'GET',
    actionType: 'throttle', throttleProfile: 'medium_bot',
    note: 'Throttle AI training crawlers — medium_bot (1 req/s, burst 10). Start disabled.',
    hasQS: false, qsNotRx: '',
  };
} else if (presetKey === 'throttle_seo_bots') {
 this.ruleEditID = '';
  this.ruleForm = {
    enabled: true, priority: 130,
    vhosts: baseHost, countries: '',
    uas: '*AhrefsBot*, *SemrushBot*, *MJ12bot*, *DotBot*, *BLEXBot*, *PetalBot*',
    paths: '', methods: 'GET',
    actionType: 'throttle', throttleProfile: 'soft_bot',
    note: 'Throttle commercial SEO crawlers — soft_bot (2 req/s, burst 20)',
    hasQS: false, qsNotRx: '',
  };
} else if (presetKey === 'block_meta_qs') {
 this.ruleEditID = '';
  this.ruleForm = {
    enabled: false, priority: 80,
    vhosts: baseHost, countries: '',
    uas: '*facebookexternalhit*, *meta-externalagent*, *GoogleOther*',
    paths: '', methods: 'GET',
    actionType: 'block', throttleProfile: '',
    note: 'Block Meta/GoogleOther bots with unexpected query strings (modsec-style loop prevention)',
    hasQS: true,
    qsNotRx: '(?:^|[&;])(?:fbclid|export|xml)(?:=|[&;]|$)',
  };
} else if (presetKey === 'block_empty_ua') {
 this.ruleEditID = '';
  this.ruleForm = {
    enabled: true, priority: 50,
    vhosts: baseHost, countries: '',
    uas: '-',   // single dash — exact match for empty UA sent as '-' by nginx
    paths: '', methods: '',
    actionType: 'block', throttleProfile: '',
    note: 'Block requests with empty/missing User-Agent',
    hasQS: false, qsNotRx: '',
  };
} else if (presetKey === 'block_xmlrpc') {
 this.ruleEditID = '';
  this.ruleForm = {
    enabled: true, priority: 60,
    vhosts: baseHost, countries: '',
    uas: '', paths: '/xmlrpc.php', methods: 'POST',
    actionType: 'block', throttleProfile: '',
    note: 'Block xmlrpc.php POST — brute-force amplifier',
    hasQS: false, qsNotRx: '',
  };
} else if (presetKey === 'challenge_wp_admin') {
 this.ruleEditID = '';
  this.ruleForm = {
    enabled: false, priority: 120,
    vhosts: baseHost, countries: '',
    uas: '', paths: '/wp-admin/, /wp-login.php', methods: 'POST',
    actionType: 'challenge', throttleProfile: '',
    note: 'Challenge wp-admin / wp-login POST — catches credential stuffing. Validate first.',
    hasQS: false, qsNotRx: '',
  };
} else if (presetKey === 'allow_good_bots') {
 this.ruleEditID = '';
  this.ruleForm = {
    enabled: true, priority: 10,
    vhosts: baseHost, countries: '',
    uas: '*Googlebot*, *bingbot*, *Baiduspider*, *Twitterbot*, *LinkedInBot*, *Slackbot*',
    paths: '', methods: '',
    actionType: 'allow', throttleProfile: '',
    note: 'Allow verified search/social crawlers before any block/challenge rules. Priority 10 runs first.',
    hasQS: false, qsNotRx: '',
  };
}
      },
      async runRuleSimulation() {
        const req = {
          host: String(this.simulateForm.host || '').trim(),
          ip: String(this.simulateForm.ip || '').trim(),
          ua: String(this.simulateForm.ua || '').trim(),
          path: String(this.simulateForm.path || '/').trim(),
          method: String(this.simulateForm.method || 'GET').trim().toUpperCase(),
          country: String(this.simulateForm.country || '').trim().toUpperCase(),
	  qs: String(this.simulateForm.qs || '').trim(),
        };
        if (!req.host) {
          this.actionMsg = 'Simulation host is required.';
          return;
        }
        try {
          this.simulateResult = await this.postJSON('v1/webdet/rules/simulate', req);
          this.actionMsg = this.simulateResult?.matched
            ? `Simulation matched rule ${this.simulateResult?.rule?.id || ''}`
            : 'Simulation: no matching rule.';
        } catch (err) {
          this.actionMsg = `Simulation failed: ${err}`;
          console.error('[cfm-admin] rule simulation failed', err);
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
        this.wafSummary = await this.fetchJSONSafe(`v1/waf/engine/summary?hours=${hours}&limit=${limit}&top=${top}&enrich=1`, null);
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

          const skipAdminEndpoints = [];
          if (this.isScoped) {
            if (this.shouldShow('globalips') || this.shouldShow('ipdrilldown')) skipAdminEndpoints.push('v1/webdet/ip-short');
            if (this.shouldShow('webtop')) skipAdminEndpoints.push('v1/webdet/hot-ips');
            skipAdminEndpoints.push('v1/challenge/vhosts?status=active&mode=all&limit=500');
          }

          const tasks = [
            (this.shouldShow('webtop') || this.shouldShow('vhost'))
              ? this.fetchJSONSafe(`v1/webdet/top-short?limit=${topLimit}`, { rows: [] })
              : Promise.resolve({ rows: [] }),
            this.shouldShow('suspicious')
              ? this.fetchJSONSafe(`v1/webdet/suspicious?limit=${longLimit}`, { rows: [] })
              : Promise.resolve({ rows: [] }),
            this.shouldShow('longtop')
              ? this.fetchJSONSafe(`v1/webdet/long-top?limit=${longLimit}`, { rows: [] })
              : Promise.resolve({ rows: [] }),
            !this.isScoped && (this.shouldShow('globalips') || this.shouldShow('ipdrilldown'))
              ? this.fetchJSONSafe(`v1/webdet/ip-short?limit=${ipLimit}`, { short: [] })
              : Promise.resolve({ short: [] }),
            !this.isScoped && this.shouldShow('webtop')
              ? this.fetchJSONSafe(`v1/webdet/hot-ips?limit=${hotLimit}`, [])
              : Promise.resolve([]),
            this.isScoped
              ? Promise.resolve([])
              : this.fetchJSONSafe('v1/challenge/vhosts?status=active&mode=all&limit=500', []),
          ];

          const [topShort, suspicious, longTop, ipShort, hotIPs, activeChallengeVhosts] = await Promise.all(tasks);

          this.topShort = this.extractRows(topShort, 'rows');
          this.suspicious = this.extractRows(suspicious, 'rows');
          this.longTop = this.extractRows(longTop, 'rows');
          this.ipShort = this.extractRows(ipShort, 'short');
          this.hotIPs = this.extractRows(hotIPs, 'rows');
          this.activeChallengeVhosts = this.extractRows(activeChallengeVhosts, 'rows');
          this.logScopedAdminSkipsOnce(skipAdminEndpoints);
          if (this.hasScopedVhosts) {
            const allow = new Set(this.allowedVhosts);
            const byHost = (row) => allow.has(String(row?.host || '').toLowerCase());
            this.topShort = this.topShort.filter(byHost);
            this.suspicious = this.suspicious.filter(byHost);
            this.longTop = this.longTop.filter(byHost);
            this.activeChallengeVhosts = this.activeChallengeVhosts.filter(byHost);
          }
          this.suspiciousHosts = Object.fromEntries(this.suspicious.map((row) => [row.host, true]));

          if (this.shouldShow('excludes')) await this.refreshExcludeLists();
          if (this.shouldShow('history')) await this.refreshHistory();
          if (this.shouldShow('wafengine')) await this.refreshWAFEngine();
          if (this.shouldShow('controls')) await this.refreshVhostControls();
          if (this.shouldShow('controls')) await this.refreshRules();
          if (this.shouldShow('tokens')) await this.refreshTokens();
          if (this.shouldShow('vhost_overview') && this.vhostOverviewHost) await this.refreshVhostOverview();

          if (this.shouldShow('vhost') && this.isVhostPage) {
            const vhostTarget =
              String(this.vhostFocusHost || '').trim() ||
              String(this.activeHost || '').trim() ||
              this.topShort[0]?.host;

            if (vhostTarget) {
              this.vhostFocusHost = vhostTarget;
              this.syncVhostQuery(vhostTarget);
              await this.loadHost(vhostTarget, false);
              this.pushHostSeriesPoint(vhostTarget);
              await this.$nextTick();
              this.renderVhostCharts();
            }
          } else if (this.shouldShow('vhost') && this.activeHost) {
            this.pushHostSeriesPoint(this.activeHost);
            await this.$nextTick();
            this.renderVhostCharts();
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
      // ── Token management ──────────────────────────────────────────────────
      applyScopedChrome() {
        const nav = document.querySelector('.top-nav');
        if (nav) {
          nav.querySelectorAll('a[href]').forEach((a) => {
            const href = a.getAttribute('href') || '';
            if (!this.isScoped) {
              a.style.display = '';
              return;
            }
            const adminOnly = href === '/cfm-admin/' || href.includes('/webdetector/controls/') || href.includes('/governor/');
            a.style.display = adminOnly ? 'none' : '';
          });
        }
        const meta = document.querySelector('.topbar .meta');
        if (meta && !meta.querySelector('.scoped-badge')) {
          const badge = document.createElement('span');
          badge.className = 'pill scoped-badge';
          meta.prepend(badge);
        }
        const badge = document.querySelector('.scoped-badge');
        if (badge) badge.textContent = this.isScoped ? 'Scoped view' : 'Global view';
      },

      async checkAdminStatus() {
        const hadTokenAtStart = Boolean(_scopedToken);
        if (!hadTokenAtStart) {
          await waitForScopedToken(1500);
          _scopedToken = _authCtx.getToken();
        }
        const me = await _authCtx.loadMe({ preferScopedToken: true });
        const prevMode = this.isScopedMode ? 'scoped' : 'global';
        this.isScopedMode = Boolean(me?.scoped);
        this.isAdmin = !this.isScopedMode;
        this.tokenRole = String(me?.role || (this.isAdmin ? 'admin' : 'viewer')).toLowerCase();
        this.allowedVhosts = Array.isArray(me?.vhosts) ? me.vhosts.map((v) => String(v || '').trim().toLowerCase()).filter(Boolean) : [];
        if (this.hasScopedVhosts) {
          const firstHost = this.allowedVhosts[0];
          if (!this.vhostFocusHost) this.vhostFocusHost = firstHost;
          if (!this.vhostOverviewHost) this.vhostOverviewHost = firstHost;
          if (!this.historyHost) this.historyHost = firstHost;
          this.ruleForm.vhosts = this.allowedVhosts.join(', ');
          if (!this.simulateForm.host) this.simulateForm.host = firstHost;
        }
        this.meLoaded = true;
        this.applyScopedChrome();
        const newMode = this.isScopedMode ? 'scoped' : 'global';
        if (!this.modeChangeLogged && prevMode !== newMode) {
          console.info('[cfm-webui] mode_changed', { from: prevMode, to: newMode });
          this.modeChangeLogged = true;
        }
      },

      async onLateScopedToken() {
        const prevMode = this.isScopedMode ? 'scoped' : 'global';
        await this.checkAdminStatus();
        this.applyScopedChrome();
        const newMode = this.isScopedMode ? 'scoped' : 'global';
        if (prevMode !== newMode) {
          await this.refreshAll();
        }
      },

      async refreshTokens() {
        if (!this.isAdmin) return;
        try {
          const rows = await this.fetchJSONSafe('v1/tokens/list', []);
          this.tokens = Array.isArray(rows) ? rows : [];
        } catch (_) { this.tokens = []; }
      },

      async createScopedToken() {
        this.tokenCreateMsg = '';
        const vhosts = this.tokenForm.vhosts.split(',').map(v => v.trim()).filter(Boolean);
        if (!vhosts.length) { this.tokenCreateMsg = 'Vhosts required.'; return; }
        try {
          const res = await this.postJSON('v1/auth/token', {
            vhosts,
            label: this.tokenForm.label,
            ttl: this.tokenForm.ttl || '8760h',
            role: this.tokenForm.role || 'viewer',
          });
          if (res.error) { this.tokenCreateMsg = res.error; return; }
          this.tokenCreateMsg = `✓ Created: ${res.id}  Token: ${res.token}`;
          await this.refreshTokens();
        } catch (err) { this.tokenCreateMsg = String(err); }
      },

      async revokeToken(id) {
        if (!confirm(`Revoke token ${id}?`)) return;
        try {
          const res = await this.postJSON('v1/tokens/revoke', { id });
          if (res.error) { this.tokenCreateMsg = res.error; return; }
          this.tokenCreateMsg = `✓ Revoked ${id}`;
          await this.refreshTokens();
        } catch (err) { this.tokenCreateMsg = String(err); }
      },

      // ── Security Overview ─────────────────────────────────────────────────
      async refreshVhostOverview() {
        const host = String(this.vhostOverviewHost || '').trim();
        if (!host) { this.vhostOverview = null; return; }
        try {
          this.vhostOverview = await this.fetchJSONSafe(
            `v1/webdet/history/vhost-overview?host=${encodeURIComponent(host)}&hours=${this.vhostOverviewHours}`,
            null
          );
        } catch (_) { this.vhostOverview = null; }
      },

      async loadHost(host, shouldScroll = true) {
        if (this.hasScopedVhosts && !this.allowedVhosts.includes(String(host || '').trim().toLowerCase())) return;
        if (!host) return;
        this.activeHost = host;
        this.ensureHostSeries(host);

        try {
          this.drilldown = await this.fetchJSON(`v1/webdet/drilldown?host=${encodeURIComponent(host)}&top=${this.drilldownTopN}`);
          await this.$nextTick();
          this.renderVhostCharts();
          if (shouldScroll) this.scrollToDrilldown();
        } catch (err) {
          console.error('[cfm-admin] drilldown failed', err);
          this.drilldown = { error: String(err), host };
          if (shouldScroll) this.scrollToDrilldown();
        }
      },
    },

    mounted() {
      _appVm = this;
      if (_lateTokenReinitPending && typeof this.onLateScopedToken === 'function') {
        _lateTokenReinitPending = false;
        this.onLateScopedToken().catch((err) => {
          console.error('[cfm-webui] late token re-init failed', err);
        });
      }
      const path = (window.location.pathname || '').replace(/\/+$/, '/');

      if (path.includes('/webdetector/forensics/')) this.pageMode = 'forensics';
      else if (path.includes('/webdetector/vhost/')) this.pageMode = 'vhost';
      else if (path.includes('/webdetector/waf/')) this.pageMode = 'waf';
      else if (path.includes('/webdetector/controls/')) this.pageMode = 'controls';
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

      this.resizeHandler = () => this.resizeVhostCharts();
      window.addEventListener('resize', this.resizeHandler);

      if (!this.tokenBootLogged) {
        console.info('[cfm-webui] token_present_at_boot', { present: Boolean(_scopedToken) });
        this.tokenBootLogged = true;
      }
      const firstCheckDelayMs = 120;
      setTimeout(() => {
        this.checkAdminStatus()
          .catch((err) => console.warn('[cfm-webui] checkAdminStatus failed', err))
          .finally(() => this.refreshAll());
      }, firstCheckDelayMs);
      this.$nextTick(() => this.resizeVhostCharts());

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
      if (_appVm === this) _appVm = null;
      if (this.timer) clearInterval(this.timer);
      if (this.resizeHandler) window.removeEventListener('resize', this.resizeHandler);
      this.disposeVhostCharts();
    },
  }).mount('#app');
})();
