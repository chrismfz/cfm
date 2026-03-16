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
      </tr>`).join('') : '<tr><td colspan="7" class="muted">No users.</td></tr>';

    el.runningBody.innerHTML = running.length ? running.slice(0, 120).map((r) => `
      <tr>
        <td>${esc(r.id)}</td>
        <td>${esc(r.user)}</td>
        <td>${esc(r.db)}</td>
        <td>${esc(r.time_sec)}s</td>
        <td>${esc(r.state)}</td>
        <td class="truncate" title="${esc(r.info)}">${esc(r.info)}</td>
      </tr>`).join('') : '<tr><td colspan="6" class="muted">No running queries.</td></tr>';

    pushSeries(st.connPctSeries, conn.pct || 0);
    el.connSparkLine.setAttribute('points', pointsFromSeries(st.connPctSeries));
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
      </tr>`).join('') : '<tr><td colspan="8" class="muted">No CPU/query activity.</td></tr>';

    pushSeries(st.cpuSeries, totalCPU);
    pushSeries(st.qrySeries, totalQry);
    el.cpuSparkLine.setAttribute('points', pointsFromSeries(st.cpuSeries));
    el.qrySparkLine.setAttribute('points', pointsFromSeries(st.qrySeries));
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
      </tr>`).join('') : '<tr><td colspan="8" class="muted">No history yet.</td></tr>';
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

  async function loadLive() {
    const [state, cpu, hist] = await Promise.all([
      api('/v1/mysql/state'),
      api('/v1/mysql/cpu'),
      api('/v1/mysql/history?window=1h&top=40'),
    ]);
    renderConnection(state);
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
    const checks = await Promise.allSettled([loadLive(), loadSummary(), loadEvents()]);
    const failed = checks
      .map((res, idx) => ({
        res,
        label: idx === 0 ? 'live' : idx === 1 ? 'summary' : 'events',
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
