// /cfm-admin/assets/health.js
//
// Health page — box-wide metric history + anomaly feed. Admin-only (the
// nav link hides for scoped viewers; the backends 403). Data comes from
// the endpoints the daemon already maintains:
//
//   GET /api/v1/health/timeseries?window=&step=   (in-memory ring, ≤24h)
//   GET /api/v1/health/anomalies?since=
//
// Charts follow the shared cfm ECharts theme (chart-theme.js): one value
// axis per chart, a legend whenever a chart carries ≥2 series, axis
// tooltip, no dual axes — series are grouped by unit (%, load, Mbps, °C).

(() => {
  const controller = window.CFMControllerBootstrap.initSharedController({});
  const api = controller.createApiClient({
    basePath: '/cfm-admin/api',
    isScoped: () => false,
  });

  const el = {
    autoState:     document.getElementById('autoState'),
    refreshBtn:    document.getElementById('refreshBtn'),
    toggleAutoBtn: document.getElementById('toggleAutoBtn'),
    windowSelect:  document.getElementById('windowSelect'),
    pointsInfo:    document.getElementById('pointsInfo'),
    actionMsg:     document.getElementById('actionMsg'),
    pageMeta:      document.getElementById('healthPageMeta'),
    utilChart:     document.getElementById('utilChart'),
    loadChart:     document.getElementById('loadChart'),
    netChart:      document.getElementById('netChart'),
    tempCard:      document.getElementById('tempCard'),
    tempChart:     document.getElementById('tempChart'),
    lveCard:       document.getElementById('lveCard'),
    lveMeta:       document.getElementById('lveMeta'),
    lveBody:       document.getElementById('lveBody'),
    anomaliesBody: document.getElementById('anomaliesBody'),
  };

  // window → aggregation step (server clamps window to the ring's reach).
  const WINDOW_STEPS = { '1h': '1m', '3h': '3m', '6h': '5m', '24h': '15m' };

  const st = {
    auto: true,
    timer: null,
    window: '1h',
    points: [],
    nodeID: '',
    charts: {}, // key -> echarts instance
  };

  function escapeHTML(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function flashMsg(text, kind) {
    if (!el.actionMsg) return;
    el.actionMsg.textContent = text || '';
    el.actionMsg.style.display = text ? '' : 'none';
    el.actionMsg.className = 'pill' + (kind ? ' ' + kind : '');
    if (text) {
      window.clearTimeout(flashMsg._t);
      flashMsg._t = window.setTimeout(() => { el.actionMsg.style.display = 'none'; }, 6000);
    }
  }

  // ── charts ────────────────────────────────────────────────────────────────

  function lineSeries(name, data, color) {
    return {
      name, type: 'line', smooth: true, showSymbol: false,
      lineStyle: { color, width: 2 }, itemStyle: { color }, data,
    };
  }

  function baseOption(labels, series, yName, yOpts = {}) {
    const multi = series.length > 1;
    return {
      animation: false,
      tooltip: { trigger: 'axis' },
      ...(multi ? { legend: { top: 0, right: 10 } } : {}),
      grid: { left: 48, right: 16, top: multi ? 32 : 16, bottom: 26 },
      xAxis: { type: 'category', boundaryGap: false, data: labels },
      yAxis: { type: 'value', name: yName, min: 0, ...yOpts },
      series,
    };
  }

  function ensureChart(key, dom) {
    if (!dom || !window.CFMChartTheme) return null;
    if (!st.charts[key]) st.charts[key] = window.CFMChartTheme.initChart(dom);
    return st.charts[key];
  }

  function disposeCharts() {
    for (const key of Object.keys(st.charts)) {
      st.charts[key]?.dispose?.();
      delete st.charts[key];
    }
  }

  function renderCharts() {
    if (!window.CFMChartTheme || !window.echarts) return;
    const cc = window.CFMChartTheme.chartColors();
    const pts = st.points;
    const labels = pts.map((p) => {
      const t = new Date(p.collected_at);
      return Number.isNaN(t.getTime()) ? '' : t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    });
    const col = (key) => pts.map((p) => {
      const v = Number(p[key]);
      return Number.isFinite(v) ? Number(v.toFixed(2)) : null;
    });

    ensureChart('util', el.utilChart)?.setOption(baseOption(labels, [
      lineSeries('CPU %', col('cpu_pct'), cc.cyan),
      lineSeries('RAM %', col('ram_used_pct'), cc.blue),
      lineSeries('Swap %', col('swap_used_pct'), cc.purple),
      lineSeries('Disk / %', col('disk_root_pct'), cc.yellow),
    ], '%', { max: 100 }), true);

    ensureChart('load', el.loadChart)?.setOption(
      baseOption(labels, [lineSeries('load1', col('load1'), cc.green)], 'load'), true);

    ensureChart('net', el.netChart)?.setOption(baseOption(labels, [
      lineSeries('in Mbps', col('rx_mbps'), cc.cyan),
      lineSeries('out Mbps', col('tx_mbps'), cc.yellow),
    ], 'Mbps'), true);

    // Temperature card only when the box actually reports sensors.
    const temps = col('temp_max_c');
    const hasTemp = temps.some((v) => Number.isFinite(v) && v > 0);
    if (el.tempCard) el.tempCard.style.display = hasTemp ? '' : 'none';
    if (hasTemp) {
      ensureChart('temp', el.tempChart)?.setOption(
        baseOption(labels, [lineSeries('max °C', temps, cc.red)], '°C'), true);
    }
  }

  // ── anomalies ─────────────────────────────────────────────────────────────

  function renderAnomalies(items) {
    if (!el.anomaliesBody) return;
    if (!items.length) {
      el.anomaliesBody.innerHTML = '<tr><td colspan="9" class="muted">no anomalies in window 🎉</td></tr>';
      return;
    }
    const rows = items.slice(-300).reverse().map((a) => {
      const when = new Date(a.when);
      const ts = Number.isNaN(when.getTime()) ? '-' : when.toLocaleTimeString();
      const ipCell = a.src_ip
        ? `<a href="/cfm-admin/webdetector/?ip=${encodeURIComponent(a.src_ip)}"><code>${escapeHTML(a.src_ip)}</code></a>`
        : '<span class="muted">-</span>';
      const path = a.path ? `${a.method ? `${a.method} ` : ''}${a.path}` : '-';
      return `<tr>
        <td>${escapeHTML(ts)}</td>
        <td>${escapeHTML(a.source || '-')}</td>
        <td>${escapeHTML(a.signal || '-')}</td>
        <td>${escapeHTML(a.reason || '-')}</td>
        <td>${escapeHTML(a.scope || '-')}</td>
        <td>${escapeHTML(String(a.count ?? 1))}</td>
        <td>${ipCell}</td>
        <td style="word-break:break-all" title="${escapeHTML(a.user_agent || '')}">${escapeHTML(path)}</td>
        <td>${escapeHTML(a.status ? String(a.status) : '-')}</td>
      </tr>`;
    });
    el.anomaliesBody.innerHTML = rows.join('');
  }

  // ── LVE per-tenant CPU (CloudLinux) ─────────────────────────────────────────

  // limitCPU renders the lCPU cap as cores (10000 units = 1 core; 0 = unlimited),
  // minimal digits so it matches the `cfm lve` CLI exactly (6c / 15.5c / 100c).
  function fmtLimit(l) {
    if (!(l > 0)) return '∞';
    return `${parseFloat((l / 10000).toFixed(2))}c`;
  }

  function fmtPctOfLimit(s) {
    if (!(s.limit_cpu > 0)) return '<span class="muted">-</span>';
    const pct = Number(s.pct_of_limit) || 0;
    let cls = '';
    if (pct >= 90) cls = 'danger';
    else if (pct >= 70) cls = 'warn';
    const txt = `${pct.toFixed(0)}%`;
    return cls ? `<span class="pill ${cls}">${txt}</span>` : txt;
  }

  // renderLVE fills the LVE card from the /system/lve-cpu payload, hiding the
  // whole card when the host isn't CloudLinux (available:false). While the
  // collector warms up (ready:false) it shows a one-line note instead of a
  // stale/empty table.
  function renderLVE(data) {
    if (!el.lveCard) return;
    if (!data || data.available !== true) {
      el.lveCard.style.display = 'none';
      return;
    }
    el.lveCard.style.display = '';
    if (data.ready !== true) {
      if (el.lveMeta) el.lveMeta.textContent = `CloudLinux — collector warming up (first delta needs two samples, ~${data.interval_sec || 15}s)`;
      if (el.lveBody) el.lveBody.innerHTML = '<tr><td colspan="8" class="muted">warming up…</td></tr>';
      return;
    }
    const rows = Array.isArray(data.top) ? data.top : [];
    if (el.lveMeta) {
      const when = data.sampled_at ? new Date(data.sampled_at) : null;
      const ts = when && !Number.isNaN(when.getTime()) ? when.toLocaleTimeString() : '';
      el.lveMeta.textContent = `CloudLinux — ${data.tenants ?? rows.length} tenants · interval ${data.interval_sec || 15}s${ts ? ` · ${ts}` : ''} · CPU cores over last interval, hottest first`;
    }
    if (!el.lveBody) return;
    if (!rows.length) {
      el.lveBody.innerHTML = '<tr><td colspan="8" class="muted">no tenants reported</td></tr>';
      return;
    }
    el.lveBody.innerHTML = rows.map((s) => `<tr>
      <td>${escapeHTML(String(s.reseller ?? 0))}</td>
      <td>${escapeHTML(String(s.uid ?? 0))}</td>
      <td>${(Number(s.cores) || 0).toFixed(2)}</td>
      <td>${fmtPctOfLimit(s)}</td>
      <td>${escapeHTML(fmtLimit(Number(s.limit_cpu) || 0))}</td>
      <td>${escapeHTML(String(s.num_cpu ?? 0))}</td>
      <td>${escapeHTML(String(s.ep ?? 0))}</td>
      <td>${escapeHTML(String(s.nproc ?? 0))}</td>
    </tr>`).join('');
  }

  // ── data loading ──────────────────────────────────────────────────────────

  async function loadAll() {
    const step = WINDOW_STEPS[st.window] || '1m';
    try {
      const [ts, an, lve] = await Promise.all([
        api(`/v1/health/timeseries?window=${st.window}&step=${step}`),
        api(`/v1/health/anomalies?since=${st.window}`).catch(() => null),
        api('/v1/system/lve-cpu?top=50').catch(() => null),
      ]);
      st.points = Array.isArray(ts?.points) ? ts.points : [];
      st.nodeID = ts?.node_id || '';
      if (el.pageMeta) el.pageMeta.textContent = st.nodeID;
      if (el.pointsInfo) {
        el.pointsInfo.textContent = st.points.length
          ? `${st.points.length} buckets · ${st.points.reduce((n, p) => n + (p.sample_count || 0), 0)} samples`
          : 'no samples yet — the health detector fills the ring every ~10-20s after daemon start';
      }
      renderCharts();
      renderAnomalies(Array.isArray(an?.anomalies) ? an.anomalies : []);
      renderLVE(lve);
    } catch (err) {
      console.error('[health] load failed', err);
      flashMsg(`load failed: ${err.message || err}`, 'danger');
    }
  }

  // ── wiring ────────────────────────────────────────────────────────────────

  el.windowSelect?.addEventListener('change', () => {
    st.window = el.windowSelect.value || '1h';
    loadAll();
  });

  el.refreshBtn?.addEventListener('click', loadAll);

  el.toggleAutoBtn?.addEventListener('click', () => {
    st.auto = !st.auto;
    if (el.autoState) el.autoState.textContent = st.auto ? 'ON' : 'OFF';
    el.toggleAutoBtn.textContent = st.auto ? 'Stop' : 'Start';
    if (st.auto) startTimer(); else stopTimer();
  });

  function startTimer() {
    stopTimer();
    st.timer = window.setInterval(loadAll, 30000);
  }
  function stopTimer() {
    if (st.timer) { window.clearInterval(st.timer); st.timer = null; }
  }

  // Registered ECharts themes are fixed at init — rebuild on toggle.
  window.CFMChartTheme?.onThemeChange?.(() => {
    disposeCharts();
    renderCharts();
  });

  window.addEventListener('resize', () => {
    for (const key of Object.keys(st.charts)) st.charts[key]?.resize?.();
  });

  // ── bootstrap ─────────────────────────────────────────────────────────────

  (async () => {
    try {
      if (typeof window.CFMAuthContext?.waitForToken === 'function') {
        await window.CFMAuthContext.waitForToken(450);
      }
    } catch (_) {}
    await loadAll();
    if (st.auto) startTimer();
  })();
})();
