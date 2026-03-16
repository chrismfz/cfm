(() => {
  const appRoot = document.getElementById('app');
  appRoot?.removeAttribute('v-cloak');

  const el = {
    autoState: document.getElementById('autoState'),
    refreshBtn: document.getElementById('refreshBtn'),
    toggleAutoBtn: document.getElementById('toggleAutoBtn'),

    kpiRow: document.getElementById('kpiRow'),
    connSparkLine: document.getElementById('connSparkLine'),
    cpuSparkLine: document.getElementById('cpuSparkLine'),
    qrySparkLine: document.getElementById('qrySparkLine'),
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
    pruneDays: document.getElementById('pruneDays'),
    actionMsg: document.getElementById('actionMsg'),
  };

  const st = {
    auto: true,
    timer: null,
    connPctSeries: [],
    cpuSeries: [],
    qrySeries: [],
    maxPoints: 80,
  };

  function showMsg(msg) {
    el.actionMsg.style.display = msg ? '' : 'none';
    el.actionMsg.textContent = msg || '';
  }

  async function api(path, opts = {}) {
    const res = await fetch(`/cfm-admin/api${path}`, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  function esc(v) {
    return String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function openHistoryFilter(user = '', dbName = '') {
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

  function pointsFromSeries(series) {
    if (!series.length) return '';
    const w = 800;
    const h = 140;
    const max = Math.max(1, ...series);
    return series.map((v, i) => {
      const x = series.length === 1 ? 0 : (i / (series.length - 1)) * w;
      const y = h - (v / max) * (h - 6) - 3;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
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

    pushSeries(st.connPctSeries, conn.pct || 0);
    el.connSparkLine.setAttribute('points', pointsFromSeries(st.connPctSeries));

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

    pushSeries(st.cpuSeries, totalCPU);
    pushSeries(st.qrySeries, totalQry);
    el.cpuSparkLine.setAttribute('points', pointsFromSeries(st.cpuSeries));
    el.qrySparkLine.setAttribute('points', pointsFromSeries(st.qrySeries));
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

  function renderEvents(rows) {
    if (!Array.isArray(rows) || !rows.length) {
      el.eventsBody.innerHTML = '<tr><td colspan="9" class="muted">No events found.</td></tr>';
      return;
    }
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
  }

  async function loadEvents() {
    const q = new URLSearchParams();
    q.set('limit', String(Number(el.filterLimit.value) || 100));
    if (el.filterUser.value.trim()) q.set('user', el.filterUser.value.trim());
    if (el.filterDB.value.trim()) q.set('db', el.filterDB.value.trim());
    if (el.filterType.value.trim()) q.set('type', el.filterType.value.trim());
    const payload = await api(`/v1/mysql/history/events?${q.toString()}`);
    renderEvents(payload.rows || []);
  }

  async function loadSummary() {
    const hours = Math.max(1, Number(el.summaryHours.value) || 24);
    const s = await api(`/v1/mysql/history/summary?hours=${hours}`);
    el.summaryText.textContent = JSON.stringify(s, null, 2);
  }

  async function loadOps() {
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
    const days = Math.max(1, Number(el.pruneDays.value) || 30);
    const out = await api(`/v1/mysql/history/prune?days=${days}`, { method: 'POST' });
    showMsg(`Pruned days=${days}, rows_deleted=${out.rows_deleted ?? 0}`);
    await loadEvents();
    await loadSummary();
  }

  async function truncate() {
    if (!window.confirm('Delete all MySQL governor history rows?')) return;
    const out = await api('/v1/mysql/history/truncate?confirm=yes', { method: 'POST' });
    showMsg(`History truncated, rows_deleted=${out.rows_deleted ?? 0}`);
    await loadEvents();
    await loadSummary();
  }

  async function refresh() {
    showMsg('');
    const checks = await Promise.allSettled([loadLive(), loadOps(), loadSummary(), loadEvents()]);
    const failed = checks
      .map((res, idx) => ({
        res,
        label: idx === 0 ? 'live' : idx === 1 ? 'ops' : idx === 2 ? 'summary' : 'events',
      }))
      .filter((x) => x.res.status === 'rejected');

    if (!failed.length) return;

    failed.forEach((x) => {
      console.error(`[cfm-admin governor] refresh failed (${x.label})`, x.res.reason);
    });
    const msg = failed.map((x) => `${x.label}: ${x.res.reason?.message || x.res.reason || 'failed'}`).join(' | ');
    showMsg(`Partial refresh error: ${msg}`);
  }

  function startAuto() {
    st.auto = true;
    el.autoState.textContent = 'ON';
    el.toggleAutoBtn.textContent = 'Stop';
    clearInterval(st.timer);
    st.timer = setInterval(() => refresh(), 5000);
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
  el.loadSummaryBtn?.addEventListener('click', () => loadSummary().catch((err) => showMsg(`Error: ${err?.message || err}`)));
  el.pruneBtn?.addEventListener('click', () => prune().catch((err) => showMsg(`Error: ${err?.message || err}`)));
  el.truncateBtn?.addEventListener('click', () => truncate().catch((err) => showMsg(`Error: ${err?.message || err}`)));

  startAuto();
  refresh();
})();
