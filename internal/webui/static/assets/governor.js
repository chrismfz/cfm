(() => {

  const _authCtx = window.CFMAuthContext || {
    getToken: () => '',
    waitForToken: async () => '',
    onAuthContextChanged: () => () => {},
    loadMe: async ({ preferScopedToken = true } = {}) => {
      const headers = { Accept: 'application/json' };
      if (preferScopedToken && _scopedToken) headers.Authorization = `Bearer ${_scopedToken}`;
      const res = await fetch('/cfm-admin/api/v1/tokens/me', { credentials: 'same-origin', headers });
      if (!res.ok) throw new Error(`v1/tokens/me -> HTTP ${res.status}`);
      return res.json();
    },
  };
  let _scopedToken = _authCtx.getToken();
  const TOKEN_BOOT_WAIT_MS = 1200;
  let _lateTokenReinitialized = false;

  function waitForScopedTokenOrTimeout(timeoutMs = TOKEN_BOOT_WAIT_MS) {
    if (_scopedToken) return Promise.resolve('present');
    return _authCtx.waitForToken(timeoutMs).then((tok) => {
      _scopedToken = _authCtx.getToken();
      return tok ? 'postmessage' : 'timeout';
    });
  }

  _authCtx.onAuthContextChanged((evt) => {
    _scopedToken = _authCtx.getToken();
    if (evt && evt.modeChanged && !_lateTokenReinitialized) {
      _lateTokenReinitialized = true;
      onLateScopedToken().catch((err) => {
        console.error('[cfm-admin governor] late token re-init failed', err);
      });
    }
  });


  const appRoot = document.getElementById('app');
  appRoot?.removeAttribute('v-cloak');

  const el = {
    autoState: document.getElementById('autoState'),
    refreshBtn: document.getElementById('refreshBtn'),
    toggleAutoBtn: document.getElementById('toggleAutoBtn'),

    kpiRow: document.getElementById('kpiRow'),
    connSpark: document.getElementById('connSpark'),
    cpuSpark: document.getElementById('cpuSpark'),
    cpuMeta: document.getElementById('cpuMeta'),

    connUsersBody: document.getElementById('connUsersBody'),
    runningBody: document.getElementById('runningBody'),
    cpuBody: document.getElementById('cpuBody'),
    histBody: document.getElementById('histBody'),
    locksBody: document.getElementById('locksBody'),
    killsBody: document.getElementById('killsBody'),
    psBody: document.getElementById('psBody'),

    loadEventsBtn: document.getElementById('loadEventsBtn'),
    loadSummaryBtn: document.getElementById('loadSummaryBtn'),
    pruneBtn: document.getElementById('pruneBtn'),
    truncateBtn: document.getElementById('truncateBtn'),
    filterUser: document.getElementById('filterUser'),
    filterDB: document.getElementById('filterDB'),
    filterType: document.getElementById('filterType'),
    filterLimit: document.getElementById('filterLimit'),
    summaryHours: document.getElementById('summaryHours'),
    summaryText: document.getElementById('summaryText'),
    eventsBody: document.getElementById('eventsBody'),
    lastEventsN: document.getElementById('lastEventsN'),
    topUsersN: document.getElementById('topUsersN'),
    applyEventViewsBtn: document.getElementById('applyEventViewsBtn'),
    lastEventsBody: document.getElementById('lastEventsBody'),
    topUsersBody: document.getElementById('topUsersBody'),
    pruneDays: document.getElementById('pruneDays'),
    actionMsg: document.getElementById('actionMsg'),
    viewModeTitle: document.getElementById('viewModeTitle'),
    cpuCard: document.getElementById('cpuCard'),
    locksCard: document.getElementById('locksCard'),
    psCard: document.getElementById('psCard'),
    summaryCard: document.getElementById('summaryCard'),
    eventsCard: document.getElementById('events-card'),
    retentionCard: document.getElementById('retentionCard'),
  };

  const st = {
    auto: true,
    timer: null,
    refreshFn: null,
    connLabels: [],
    connPctSeries: [],
    cpuLabels: [],
    cpuSeries: [],
    qrySeries: [],
    maxPoints: 80,
    eventRows: [],
    isScopedMode: false,
    tokenMissingAtBoot: false,
    authRecheckCyclesRemaining: 0,
  };
  const ADMIN_ONLY_API_PATHS = new Set([
    '/v1/mysql/state',
    '/v1/mysql/cpu',
    '/v1/mysql/history',
    '/v1/mysql/locks',
    '/v1/mysql/kills',
    '/v1/mysql/processlist',
    '/v1/mysql/history/events',
    '/v1/mysql/history/summary',
    '/v1/mysql/history/prune',
    '/v1/mysql/history/truncate',
  ]);

  function showMsg(msg) {
    el.actionMsg.style.display = msg ? '' : 'none';
    el.actionMsg.textContent = msg || '';
  }

  const createApiClient = window.CFMApiClient?.createApiClient || window.createApiClient;
  const uiScope = window.CFMUiScope || {};
  const api = createApiClient({
    basePath: '/cfm-admin/api',
    getToken: () => _scopedToken,
    isScoped: () => st.isScopedMode,
    adminOnlyPaths: ADMIN_ONLY_API_PATHS,
    retryAuthRace: true,
  });
  const scopedApi = createApiClient({
    basePath: '/api',
    getToken: () => _scopedToken,
    isScoped: () => false,
    retryAuthRace: true,
  });



  async function ensureAuthContext(opts = {}) {
    const shouldWait = Boolean(opts.waitForToken);
    const waitMs = Number(opts.waitMs) > 0 ? Number(opts.waitMs) : 350;
    if (shouldWait && !_scopedToken) {
      await waitForScopedTokenOrTimeout(waitMs);
    }

    let me = null;
    try {
      me = await _authCtx.loadMe({ preferScopedToken: true });
      _scopedToken = _authCtx.getToken();
    } catch (_) {}

    return {
      scoped: Boolean(me && (me.isScopedMode ?? me.is_scoped_mode ?? me.scoped)),
      role: String((me && me.role) || 'admin'),
    };
  }

  async function loadViewerContext(opts = {}) {
    const auth = await ensureAuthContext(opts);
    const isScopedMode = auth.scoped;
    const canWrite = !isScopedMode || String(auth.role || '').toLowerCase() !== 'viewer';

    uiScope.applyScopedNavFiltering?.({
      navSelector: '.top-nav',
      scoped: isScopedMode,
      adminOnlyMatcher: (href) => href === '/cfm-admin/' || href.includes('/webdetector/controls/') || href.includes('/governor/'),
    });
    const badge = uiScope.applyScopedBadge?.({
      selector: '.topbar .meta',
      scopedLabel: 'Scoped MySQL view',
      globalLabel: 'Global view',
    });
    if (badge) badge.textContent = isScopedMode ? 'Scoped MySQL view' : 'Global view';

    return { isScopedMode, canWrite, role: auth.role };
  }

  function esc(v) {
    return String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function openHistoryFilter(user = '', dbName = '') {
    if (st.isScopedMode) return;
    if (el.filterUser) el.filterUser.value = user || '';
    if (el.filterDB) el.filterDB.value = dbName || '';
    const card = document.getElementById('events-card');
    card?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    loadEvents().catch((err) => showMsg(`Error: ${err?.message || err}`));
  }


  function runtimeSeconds(row) {
    const sec = Number(row.runtime_sec ?? row.RuntimeSec);
    if (Number.isFinite(sec) && sec >= 0) return sec.toFixed(0);
    const ns = Number(row.runtime ?? row.Runtime);
    if (Number.isFinite(ns) && ns >= 0) return (ns / 1e9).toFixed(0);
    return '-';
  }

  function riskLabel(row) {
    if ((row.locked || 0) > 0) return '🔴 locked';
    if ((row.max_idle || 0) > 300) return '🟡 stale';
    return '🟢 ok';
  }

  function waitPct(cpuSec, busySec) {
    if (!busySec || busySec <= 0) return '-';
    const wait = Math.max(0, (busySec - cpuSec) / busySec * 100);
    return `${wait.toFixed(0)}%`;
  }

  function cpuBar(cpuSec) {
    const max = 10;
    let n = Math.round((cpuSec || 0) * max);
    if (n > max) n = max;
    if (n < 0) n = 0;
    return `[${'█'.repeat(n)}${'░'.repeat(max - n)}]`;
  }

  function histBar(peak) {
    const max = 10;
    let n = Math.round((peak || 0));
    if (n > max) n = max;
    if (n < 0) n = 0;
    return `[${'█'.repeat(n)}${'░'.repeat(max - n)}]`;
  }

  function pushSeries(arr, v) {
    arr.push(Number(v) || 0);
    if (arr.length > st.maxPoints) arr.splice(0, arr.length - st.maxPoints);
  }

  function pushSeriesLabel(labels, label) {
    labels.push(label);
    if (labels.length > st.maxPoints) labels.splice(0, labels.length - st.maxPoints);
  }

  function pushSeriesPoint(labels, series, label, value) {
    pushSeriesLabel(labels, label);
    pushSeries(series, value);
  }

  function safeChartLabel(label) {
    const raw = (label ?? '').toString().trim();
    if (!raw || raw === '-') return new Date().toLocaleTimeString();

    const iso = new Date(raw);
    if (!Number.isNaN(iso.getTime())) return iso.toLocaleTimeString();

    const match = raw.match(/(\d{2}:\d{2}:\d{2})/);
    return match ? match[1] : raw;
  }

  function initCharts() {
    if (!window.echarts) return;
    st.connChart = echarts.init(el.connSpark);
    st.cpuChart = echarts.init(el.cpuSpark);

    st.connChart.setOption({
      backgroundColor: 'transparent',
      animation: true,
      tooltip: { trigger: 'axis', axisPointer: { type: 'cross' } },
      grid: { left: 45, right: 20, top: 20, bottom: 30 },
      xAxis: { type: 'category', boundaryGap: false, data: [] },
      yAxis: { type: 'value', name: 'Conn %' },
      series: [{ name: 'Connection pressure', type: 'line', smooth: true, showSymbol: false, lineStyle: { color: '#f1d64a', width: 2 }, data: [] }],
    });

    st.cpuChart.setOption({
      backgroundColor: 'transparent',
      animation: true,
      tooltip: { trigger: 'axis', axisPointer: { type: 'cross' } },
      legend: { top: 0, right: 10, textStyle: { color: '#dbe7f7' }, data: ['CPU', 'Queries'] },
      grid: { left: 50, right: 50, top: 35, bottom: 30 },
      xAxis: { type: 'category', boundaryGap: false, data: [] },
      yAxis: [{ type: 'value', name: 'CPU sec' }, { type: 'value', name: 'Queries' }],
      series: [
        { name: 'CPU', type: 'line', smooth: true, showSymbol: false, lineStyle: { color: '#2ec9d7', width: 2 }, data: [] },
        { name: 'Queries', type: 'line', smooth: true, showSymbol: false, yAxisIndex: 1, lineStyle: { color: '#db62e6', width: 2 }, data: [] },
      ],
    });
  }


  function normalizeState(raw) {
    if (!raw || typeof raw !== 'object') {
      return { conn: {}, per_user: [], running: [], mode: '-', flavor: '-', ts: '-' };
    }
    if (raw.conn && (Array.isArray(raw.per_user) || Array.isArray(raw.running))) {
      return raw;
    }
    const conn = {
      total: Number(raw.TotalConn ?? raw.total ?? 0),
      max: Number(raw.MaxConn ?? raw.max ?? 0),
      active: Number(raw.ActiveConn ?? raw.active ?? 0),
      sleeping: Number(raw.SleepConn ?? raw.sleeping ?? 0),
      locked: Number(raw.LockedConn ?? raw.locked ?? 0),
      pct: Number(raw.ConnPct ?? raw.conn_pct ?? 0),
    };
    const perUserRaw = Array.isArray(raw.PerUser) ? raw.PerUser : (Array.isArray(raw.per_user) ? raw.per_user : []);
    const runningRaw = Array.isArray(raw.Running) ? raw.Running : (Array.isArray(raw.running) ? raw.running : []);

    return {
      ts: raw.ts || raw.Ts || '-',
      mode: raw.mode || raw.Mode || '-',
      flavor: raw.flavor || raw.Flavor || '-',
      conn,
      per_user: perUserRaw.map((u) => ({
        user: u.user ?? u.User ?? '',
        total: Number(u.total ?? u.Total ?? 0),
        active: Number(u.active ?? u.Active ?? 0),
        sleeping: Number(u.sleeping ?? u.Sleeping ?? 0),
        locked: Number(u.locked ?? u.Locked ?? 0),
        max_idle_sec: Number(u.max_idle_sec ?? u.MaxSleepSec ?? 0),
      })),
      running: runningRaw.map((r) => ({
        id: Number(r.id ?? r.ID ?? 0),
        user: r.user ?? r.User ?? '',
        db: r.db ?? r.DB ?? '',
        time_sec: Number(r.time_sec ?? r.TimeSec ?? 0),
        state: r.state ?? r.State ?? '',
        info: r.info ?? r.Info ?? '',
      })),
    };
  }

  function renderConnection(state) {
    const conn = state?.conn || {};
    const users = Array.isArray(state?.per_user) ? state.per_user : [];
    const running = Array.isArray(state?.running) ? state.running : [];

    el.kpiRow.innerHTML = `
      <span class="pill">${esc(state?.ts || '-')}</span>
      <span class="pill">mode=${esc(state?.mode || '-')}</span>
      <span class="pill">flavor=${esc(state?.flavor || '-')}</span>
      <span class="pill">conn=${esc(conn.total || 0)}/${esc(conn.max || 0)} (${esc((conn.pct || 0).toFixed(0))}%)</span>
      <span class="pill">active=${esc(conn.active || 0)}</span>
      <span class="pill">sleep=${esc(conn.sleeping || 0)}</span>
      <span class="pill">locked=${esc(conn.locked || 0)}</span>`;

    el.connUsersBody.innerHTML = users.length ? users.map((u) => `
      <tr>
        <td>${esc(u.user)}</td>
        <td>${esc(u.total)}</td>
        <td>${esc(u.active)}</td>
        <td>${esc(u.sleeping)}</td>
        <td>${esc(u.locked)}</td>
        <td>${esc(u.max_idle_sec || '-')}</td>
        <td>${riskLabel(u)}</td>
        <td><button class="btn-quiet btn-sm" data-user="${esc(u.user)}" data-db="">History</button></td>
      </tr>`).join('') : '<tr><td colspan="8" class="muted">No users.</td></tr>';

    el.runningBody.innerHTML = running.length ? running.slice(0, 120).map((r) => `
      <tr>
        <td>${esc(r.id)}</td>
        <td>${esc(r.user)}</td>
        <td>${esc(r.db)}</td>
        <td>${esc(r.time_sec)}s</td>
        <td>${esc(r.state)}</td>
        <td class="truncate" title="${esc(r.info)}">${esc(r.info)}</td>
        <td><button class="btn-quiet btn-sm" data-user="${esc(r.user)}" data-db="${esc(r.db)}">History</button></td>
      </tr>`).join('') : '<tr><td colspan="7" class="muted">No running queries.</td></tr>';

    pushSeriesPoint(st.connLabels, st.connPctSeries, safeChartLabel(state?.ts), conn.pct || 0);
    st.connChart?.setOption({
      xAxis: { data: st.connLabels },
      series: [{ data: st.connPctSeries }],
    });

    el.connUsersBody.querySelectorAll('button[data-user]').forEach((btn) => {
      btn.addEventListener('click', () => openHistoryFilter(btn.dataset.user || '', ''));
    });
    el.runningBody.querySelectorAll('button[data-user],button[data-db]').forEach((btn) => {
      btn.addEventListener('click', () => openHistoryFilter(btn.dataset.user || '', btn.dataset.db || ''));
    });
  }

  function renderCPU(payload) {
    const users = Array.isArray(payload?.users) ? payload.users : [];
    const totalCPU = users.reduce((a, b) => a + (Number(b.cpu_sec) || 0), 0);
    const totalQry = users.reduce((a, b) => a + (Number(b.query_count) || 0), 0);

    el.cpuMeta.innerHTML = `
      <span class="pill">perf_schema=${payload?.perf_schema_ok ? 'ON' : 'OFF'}</span>
      <span class="pill">cpu_active=${payload?.perf_cpu_active ? 'yes' : 'no'}</span>
      <span class="pill">userstat=${payload?.userstat_ok ? 'ON' : (payload?.userstat_off ? 'OFF' : '-')}</span>
      <span class="pill">total_cpu=${totalCPU.toFixed(3)}s</span>
      <span class="pill">total_queries=${totalQry}</span>`;

    el.cpuBody.innerHTML = users.length ? users.map((u) => `
      <tr>
        <td>${esc(u.user)}</td>
        <td>${(Number(u.cpu_sec) || 0).toFixed(3)}</td>
        <td>${waitPct(Number(u.cpu_sec) || 0, Number(u.busy_sec) || 0)}</td>
        <td>${esc(u.query_count || 0)}</td>
        <td>${(Number(u.avg_query_msec) || 0).toFixed(2)}</td>
        <td>${esc(u.rows_read || 0)}</td>
        <td>${esc(u.rows_sent || 0)}</td>
        <td><code>${cpuBar(Number(u.cpu_sec) || 0)}</code></td>
        <td><button class="btn-quiet btn-sm" data-user="${esc(u.user)}">History</button></td>
      </tr>`).join('') : '<tr><td colspan="9" class="muted">No CPU/query activity.</td></tr>';

    pushSeriesPoint(st.cpuLabels, st.cpuSeries, safeChartLabel(payload?.ts), totalCPU);
    pushSeries(st.qrySeries, totalQry);
    st.cpuChart?.setOption({
      xAxis: { data: st.cpuLabels },
      series: [{ data: st.cpuSeries }, { data: st.qrySeries }],
    });
    el.cpuBody.querySelectorAll('button[data-user]').forEach((btn) => {
      btn.addEventListener('click', () => openHistoryFilter(btn.dataset.user || '', ''));
    });
  }

  function renderHist(payload) {
    const users = Array.isArray(payload?.users) ? payload.users : [];
    el.histBody.innerHTML = users.length ? users.map((u) => `
      <tr>
        <td>${esc(u.user)}</td>
        <td>${esc(u.peak_conns || 0)}</td>
        <td>${(Number(u.avg_conns) || 0).toFixed(1)}</td>
        <td>${esc(u.peak_active || 0)}</td>
        <td>${(Number(u.avg_active) || 0).toFixed(1)}</td>
        <td>${esc(u.peak_locked || 0)}</td>
        <td>${esc(u.samples || 0)}</td>
        <td><code>${histBar(Number(u.peak_conns) || 0)}</code></td>
        <td><button class="btn-quiet btn-sm" data-user="${esc(u.user)}">History</button></td>
      </tr>`).join('') : '<tr><td colspan="9" class="muted">No history yet.</td></tr>';
    el.histBody.querySelectorAll('button[data-user]').forEach((btn) => {
      btn.addEventListener('click', () => openHistoryFilter(btn.dataset.user || '', ''));
    });
  }

  function renderLocks(payload) {
    const rows = Array.isArray(payload?.lock_graph) ? payload.lock_graph : [];
    if (!rows.length) {
      el.locksBody.innerHTML = '<tr><td colspan="5" class="muted">No locks.</td></tr>';
      return;
    }
    el.locksBody.innerHTML = rows.map((g) => {
      const b = g.blocker || g.Blocker || {};
      const waiters = Array.isArray(g.waiters) ? g.waiters : (Array.isArray(g.Waiters) ? g.Waiters : []);
      return `<tr>
        <td>${esc(b.id ?? b.ID ?? 0)}</td>
        <td>${esc(b.user ?? b.User ?? '')}</td>
        <td>${esc(b.db ?? b.DB ?? '')}</td>
        <td>${esc(b.state ?? b.State ?? '')}</td>
        <td>${esc(waiters.length)}</td>
      </tr>`;
    }).join('');
  }

  function renderKills(payload) {
    const rows = Array.isArray(payload?.kills) ? payload.kills : [];
    if (!rows.length) {
      el.killsBody.innerHTML = '<tr><td colspan="9" class="muted">No kills recorded.</td></tr>';
      return;
    }
    el.killsBody.innerHTML = rows.slice(0, 120).map((r) => `
      <tr>
        <td>${esc(r.ts || r.Ts || '')}</td>
        <td>${esc(r.action || r.Action || '')}</td>
        <td>${esc(r.user || r.User || '')}</td>
        <td>${esc(r.db || r.DB || '')}</td>
        <td>${esc(r.pid || r.PID || 0)}</td>
        <td>${esc(runtimeSeconds(r))}</td>
        <td>${esc(r.result || r.Result || '')}</td>
        <td class="truncate" title="${esc(r.reason || r.Reason || '')}">${esc(r.reason || r.Reason || '')}</td>
        <td><button class="btn-quiet btn-sm" data-user="${esc(r.user || r.User || '')}" data-db="${esc(r.db || r.DB || '')}">History</button></td>
      </tr>`).join('');
    el.killsBody.querySelectorAll('button[data-user],button[data-db]').forEach((btn) => {
      btn.addEventListener('click', () => openHistoryFilter(btn.dataset.user || '', btn.dataset.db || ''));
    });
  }

  function renderPS(payload) {
    const rows = Array.isArray(payload?.running) ? payload.running : [];
    if (!rows.length) {
      el.psBody.innerHTML = '<tr><td colspan="8" class="muted">No processlist rows.</td></tr>';
      return;
    }
    el.psBody.innerHTML = rows.slice(0, 200).map((r) => `
      <tr>
        <td>${esc(r.id ?? r.ID ?? 0)}</td>
        <td>${esc(r.user ?? r.User ?? '')}</td>
        <td>${esc(r.db ?? r.DB ?? '')}</td>
        <td>${esc(r.command ?? r.Command ?? '')}</td>
        <td>${esc(r.time_sec ?? r.TimeSec ?? 0)}s</td>
        <td>${esc(r.state ?? r.State ?? '')}</td>
        <td class="truncate" title="${esc(r.info ?? r.Info ?? '')}">${esc(r.info ?? r.Info ?? '')}</td>
        <td><button class="btn-quiet btn-sm" data-user="${esc(r.user ?? r.User ?? '')}" data-db="${esc(r.db ?? r.DB ?? '')}">History</button></td>
      </tr>`).join('');
    el.psBody.querySelectorAll('button[data-user],button[data-db]').forEach((btn) => {
      btn.addEventListener('click', () => openHistoryFilter(btn.dataset.user || '', btn.dataset.db || ''));
    });
  }

  function renderEventViews(rows) {
    const allRows = Array.isArray(rows) ? rows : [];
    const lastN = Math.max(1, Math.min(500, Number(el.lastEventsN?.value) || 10));
    const topN = Math.max(1, Math.min(100, Number(el.topUsersN?.value) || 10));

    const lastRows = allRows.slice(0, lastN);
    el.lastEventsBody.innerHTML = lastRows.length ? lastRows.map((r) => `
      <tr>
        <td>${esc(r.ts_unix)}</td>
        <td>${esc(r.event_type)}</td>
        <td>${esc(r.user || '-')}</td>
        <td>${esc(r.db || '-')}</td>
      </tr>`).join('') : '<tr><td colspan="4" class="muted">No events.</td></tr>';

    const counts = new Map();
    allRows.forEach((r) => {
      const user = String(r?.user || '').trim() || '(unknown)';
      counts.set(user, (counts.get(user) || 0) + 1);
    });
    const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, topN);
    el.topUsersBody.innerHTML = ranked.length ? ranked.map(([user, n]) => {
      const share = allRows.length ? ((n / allRows.length) * 100).toFixed(1) : '0.0';
      return `<tr><td>${esc(user)}</td><td>${esc(n)}</td><td>${esc(share)}%</td></tr>`;
    }).join('') : '<tr><td colspan="3" class="muted">No users.</td></tr>';
  }

  function renderEvents(rows) {
    if (!Array.isArray(rows) || !rows.length) {
      st.eventRows = [];
      el.eventsBody.innerHTML = '<tr><td colspan="9" class="muted">No events found.</td></tr>';
      renderEventViews([]);
      return;
    }
    st.eventRows = rows;
    el.eventsBody.innerHTML = rows.map((r) => `
      <tr>
        <td>${esc(r.ts_unix)}</td>
        <td>${esc(r.event_type)}</td>
        <td>${esc(r.user)}</td>
        <td>${esc(r.db)}</td>
        <td>${esc(r.action)}</td>
        <td>${esc(r.result)}</td>
        <td>${esc(r.pid)}</td>
        <td>${esc(r.runtime_ms)}</td>
        <td title="${esc(r.reason)}" class="truncate">${esc(r.reason)}</td>
      </tr>`).join('');
    renderEventViews(rows);
  }

  async function loadEvents() {
    const q = new URLSearchParams();
    q.set('limit', String(Number(el.filterLimit.value) || 100));
    if (el.filterUser.value.trim()) q.set('user', el.filterUser.value.trim());
    if (el.filterDB.value.trim()) q.set('db', el.filterDB.value.trim());
    if (!st.isScopedMode && el.filterType.value.trim()) q.set('type', el.filterType.value.trim());
    if (st.isScopedMode) {
      const payload = await scopedApi(`/v1/mysql/user-history?${q.toString()}`);
      renderEvents((payload.users || []).map((u) => ({
        ts_unix: payload.ts || '-',
        event_type: 'user_history',
        user: u.user || '-',
        db: '-',
        action: 'aggregate',
        result: `samples=${u.samples || 0}`,
        pid: '-',
        runtime_ms: '-',
        reason: `peak=${u.peak_conns || 0}, avg=${(Number(u.avg_conns) || 0).toFixed(1)}, peak_active=${u.peak_active || 0}`,
      })));
      return;
    }
    const payload = await api(`/v1/mysql/history/events?${q.toString()}`);
    renderEvents(payload.rows || []);
  }

  async function loadSummary() {
    const hours = Math.max(1, Number(el.summaryHours.value) || 24);
    if (st.isScopedMode) {
      const q = new URLSearchParams();
      q.set('window', `${hours}h`);
      if (el.filterUser.value.trim()) q.set('user', el.filterUser.value.trim());
      if (el.filterDB.value.trim()) q.set('db', el.filterDB.value.trim());
      const s = await scopedApi(`/v1/mysql/user-history?${q.toString()}`);
      el.summaryText.textContent = JSON.stringify({
        mode: 'scoped',
        ts: s.ts,
        window: s.window,
        sample_count: s.sample_count,
        total_users: Array.isArray(s.users) ? s.users.length : 0,
        users: s.users || [],
      }, null, 2);
      return;
    }
    const s = await api(`/v1/mysql/history/summary?hours=${hours}`);
    el.summaryText.textContent = JSON.stringify(s, null, 2);
  }

  async function loadOps() {
    if (st.isScopedMode) {
      const q = new URLSearchParams();
      if (el.filterUser?.value.trim()) q.set('user', el.filterUser.value.trim());
      if (el.filterDB?.value.trim()) q.set('db', el.filterDB.value.trim());
      const suffix = q.toString() ? `?${q.toString()}` : '';
      const kills = await scopedApi(`/v1/mysql/user-kills${suffix}`);
      renderKills(kills);
      return;
    }
    const [locks, kills, ps] = await Promise.all([
      api('/v1/mysql/locks'),
      api('/v1/mysql/kills'),
      api('/v1/mysql/processlist'),
    ]);
    renderLocks(locks);
    renderKills(kills);
    renderPS(ps);
  }

  async function loadLive() {
    if (st.isScopedMode) {
      const q = new URLSearchParams();
      if (el.filterUser?.value.trim()) q.set('user', el.filterUser.value.trim());
      if (el.filterDB?.value.trim()) q.set('db', el.filterDB.value.trim());
      const suffix = q.toString() ? `?${q.toString()}` : '';
      const histQ = new URLSearchParams(q.toString());
      histQ.set('window', '1h');
      histQ.set('top', '40');
      const [summary, hist] = await Promise.all([
        scopedApi(`/v1/mysql/user-summary${suffix}`),
        scopedApi(`/v1/mysql/user-history?${histQ.toString()}`),
      ]);
      renderConnection(normalizeState(summary));
      renderHist(hist);
      return;
    }
    const [state, cpu, hist] = await Promise.all([
      api('/v1/mysql/state'),
      api('/v1/mysql/cpu'),
      api('/v1/mysql/history?window=1h&top=40'),
    ]);
    renderConnection(normalizeState(state));
    renderCPU(cpu);
    renderHist(hist);
  }

  async function prune() {
    if (st.isScopedMode) return;
    const days = Math.max(1, Number(el.pruneDays.value) || 30);
    const out = await api(`/v1/mysql/history/prune?days=${days}`, { method: 'POST' });
    showMsg(`Pruned days=${days}, rows_deleted=${out.rows_deleted ?? 0}`);
    await loadEvents();
    await loadSummary();
  }

  async function truncate() {
    if (st.isScopedMode) return;
    if (!window.confirm('Delete all MySQL governor history rows?')) return;
    const out = await api('/v1/mysql/history/truncate?confirm=yes', { method: 'POST' });
    showMsg(`History truncated, rows_deleted=${out.rows_deleted ?? 0}`);
    await loadEvents();
    await loadSummary();
  }

  async function refreshScopedMode() {
    showMsg('');
    const q = new URLSearchParams();
    if (el.filterUser?.value.trim()) q.set('user', el.filterUser.value.trim());
    if (el.filterDB?.value.trim()) q.set('db', el.filterDB.value.trim());
    const summarySuffix = q.toString() ? `?${q.toString()}` : '';
    const historyQ = new URLSearchParams(q.toString());
    historyQ.set('window', '1h');
    historyQ.set('top', '40');
    const checks = await Promise.allSettled([
      scopedApi(`/v1/mysql/user-summary${summarySuffix}`),
      scopedApi(`/v1/mysql/user-history?${historyQ.toString()}`),
      scopedApi(`/v1/mysql/user-kills${summarySuffix}`),
    ]);
    if (checks[0].status === 'fulfilled') {
      renderConnection(normalizeState(checks[0].value));
    }
    if (checks[1].status === 'fulfilled') {
      renderHist(checks[1].value);
      el.summaryText.textContent = JSON.stringify({
        mode: 'scoped',
        ts: checks[1].value.ts,
        window: checks[1].value.window,
        sample_count: checks[1].value.sample_count,
        total_users: Array.isArray(checks[1].value.users) ? checks[1].value.users.length : 0,
        users: checks[1].value.users || [],
      }, null, 2);
      renderEvents((checks[1].value.users || []).map((u) => ({
        ts_unix: checks[1].value.ts || '-',
        event_type: 'user_history',
        user: u.user || '-',
        db: '-',
        action: 'aggregate',
        result: `samples=${u.samples || 0}`,
        pid: '-',
        runtime_ms: '-',
        reason: `peak=${u.peak_conns || 0}, avg=${(Number(u.avg_conns) || 0).toFixed(1)}, peak_active=${u.peak_active || 0}`,
      })));
    }
    if (checks[2].status === 'fulfilled') {
      renderKills(checks[2].value);
    }
    const failed = checks
      .map((res, idx) => ({
        res,
        label: (idx === 0 ? 'user-summary' : idx === 1 ? 'user-history' : 'user-kills'),
      }))
      .filter((x) => x.res.status === 'rejected');

    if (!failed.length) return;

    failed.forEach((x) => {
      console.error(`[cfm-admin governor] refresh failed (${x.label})`, x.res.reason);
    });
    const msg = failed.map((x) => `${x.label}: ${x.res.reason?.message || x.res.reason || 'failed'}`).join(' | ');
    showMsg(`Partial refresh error: ${msg}`);
  }

  async function refreshAdminMode() {
    showMsg('');
    const checks = await Promise.allSettled([loadLive(), loadOps(), loadSummary(), loadEvents()]);
    const failed = checks
      .map((res, idx) => ({
        res,
        label: (idx === 0 ? 'live' : idx === 1 ? 'ops' : idx === 2 ? 'summary' : 'events'),
      }))
      .filter((x) => x.res.status === 'rejected');

    if (!failed.length) return;

    failed.forEach((x) => {
      console.error(`[cfm-admin governor] refresh failed (${x.label})`, x.res.reason);
    });
    const msg = failed.map((x) => `${x.label}: ${x.res.reason?.message || x.res.reason || 'failed'}`).join(' | ');
    showMsg(`Partial refresh error: ${msg}`);
  }

  function refresh() {
    return (async () => {
      await maybeRefreshAuthContext();
      const fn = st.refreshFn || (st.isScopedMode ? refreshScopedMode : refreshAdminMode);
      return fn();
    })();
  }

  function startAuto() {
    st.auto = true;
    el.autoState.textContent = 'ON';
    el.toggleAutoBtn.textContent = 'Stop';
    clearInterval(st.timer);
    st.timer = setInterval(() => {
      refresh().catch((err) => {
        console.error('[cfm-admin governor] auto refresh failed', err);
      });
    }, 5000);
  }

  function stopAuto() {
    st.auto = false;
    el.autoState.textContent = 'OFF';
    el.toggleAutoBtn.textContent = 'Start';
    clearInterval(st.timer);
    st.timer = null;
  }

  function toggleAuto() {
    if (st.auto) stopAuto(); else startAuto();
  }

  el.refreshBtn?.addEventListener('click', refresh);
  el.toggleAutoBtn?.addEventListener('click', toggleAuto);
  el.loadEventsBtn?.addEventListener('click', () => loadEvents().catch((err) => showMsg(`Error: ${err?.message || err}`)));
  el.applyEventViewsBtn?.addEventListener('click', () => renderEventViews(st.eventRows));
  el.lastEventsN?.addEventListener('change', () => renderEventViews(st.eventRows));
  el.topUsersN?.addEventListener('change', () => renderEventViews(st.eventRows));
  el.loadSummaryBtn?.addEventListener('click', () => loadSummary().catch((err) => showMsg(`Error: ${err?.message || err}`)));
  el.pruneBtn?.addEventListener('click', () => prune().catch((err) => showMsg(`Error: ${err?.message || err}`)));
  el.truncateBtn?.addEventListener('click', () => truncate().catch((err) => showMsg(`Error: ${err?.message || err}`)));

  if (window.echarts) {
    initCharts();
    window.addEventListener('resize', () => {
      st.connChart?.resize();
      st.cpuChart?.resize();
    });
  } else {
    showMsg('ECharts is unavailable; chart rendering disabled.');
  }

  function setPanelScopedState(panel, scoped, note) {
    if (!panel) return;
    panel.style.opacity = scoped ? '0.5' : '';
    panel.style.filter = scoped ? 'grayscale(0.35)' : '';
    panel.style.pointerEvents = scoped ? 'none' : '';
    panel.dataset.scopedDisabled = scoped ? '1' : '0';
    let help = panel.querySelector('.scoped-panel-note');
    if (scoped) {
      if (!help) {
        help = document.createElement('p');
        help.className = 'muted scoped-panel-note';
        panel.prepend(help);
      }
      help.textContent = note || 'Unavailable in scoped mode.';
    } else if (help) {
      help.remove();
    }
  }

  function setScopedUI(scoped) {
    st.isScopedMode = scoped;
    if (el.viewModeTitle) {
      el.viewModeTitle.textContent = scoped ? 'Scoped MySQL view · Connection pressure' : 'Connection pressure';
    }
    setPanelScopedState(el.cpuCard, false, '');
    setPanelScopedState(el.locksCard, false, '');
    setPanelScopedState(el.psCard, false, '');
    setPanelScopedState(el.retentionCard, false, '');
    [el.cpuCard, el.locksCard, el.psCard, el.retentionCard].forEach((card) => {
      if (card) card.style.display = scoped ? 'none' : '';
    });
    if (el.filterType) el.filterType.disabled = scoped;
  }

  function applyViewerContext(ctx) {
    setScopedUI(ctx.isScopedMode);
    if (!ctx.canWrite) {
      [el.pruneBtn, el.truncateBtn].forEach((n) => { if (n) n.style.display = 'none'; });
    }
  }

  function configurePollingMode() {
    st.refreshFn = st.isScopedMode ? refreshScopedMode : refreshAdminMode;
    if (st.auto) startAuto();
  }

  function logModeTransition(from, to) {
    if (from === to) return;
    console.info(`[cfm-admin governor] mode_changed ${from}->${to}`);
  }

  async function maybeRefreshAuthContext() {
    if (st.isScopedMode) return false;
    if (!st.tokenMissingAtBoot || st.authRecheckCyclesRemaining <= 0) return false;
    st.authRecheckCyclesRemaining -= 1;
    const auth = await ensureAuthContext({ waitForToken: true, waitMs: 350 });
    if (!auth.scoped) return false;

    logModeTransition('global', 'scoped');
    applyViewerContext({
      isScopedMode: true,
      canWrite: String(auth.role || '').toLowerCase() !== 'viewer',
      role: auth.role || '',
    });
    st.refreshFn = refreshScopedMode;
    if (st.auto) {
      clearInterval(st.timer);
      startAuto();
    }
    return true;
  }

  async function onLateScopedToken() {
    const wasScoped = st.isScopedMode;
    const ctx = await loadViewerContext();
    applyViewerContext(ctx);
    configurePollingMode();
    logModeTransition(wasScoped ? 'scoped' : 'global', ctx.isScopedMode ? 'scoped' : 'global');
    await refresh();
    console.info('[cfm-admin governor] startup mode', {
      token_present_at_boot: false,
      scoped_me: ctx.isScopedMode,
      mode_selected: ctx.isScopedMode ? 'scoped' : 'global',
    });
  }

  (async function boot() {
    const tokenPresentAtBoot = Boolean(_scopedToken);
    st.tokenMissingAtBoot = !tokenPresentAtBoot;
    const ctx = await loadViewerContext({ waitForToken: true, waitMs: TOKEN_BOOT_WAIT_MS });
    st.authRecheckCyclesRemaining = (!ctx.isScopedMode && st.tokenMissingAtBoot) ? 2 : 0;
    applyViewerContext(ctx);
    configurePollingMode();
    await refresh();
    console.info('[cfm-admin governor] startup mode', {
      token_present_at_boot: tokenPresentAtBoot,
      scoped_me: ctx.isScopedMode,
      mode_selected: ctx.isScopedMode ? 'scoped' : 'global',
    });
  })();
})();
