(() => {
  const q = (id) => document.getElementById(id);
  const detectorColumns = [
    { key: 'name', label: 'name', sortable: true, numeric: false },
    { key: 'runs', label: 'runs', sortable: true, numeric: true },
    { key: 'failures', label: 'failures', sortable: true, numeric: true },
    { key: 'timeouts', label: 'timeouts', sortable: true, numeric: true },
    { key: 'avg_run_ms', label: 'avg_run_ms', sortable: true, numeric: true },
    { key: 'total_run_seconds', label: 'total_run_seconds', sortable: true, numeric: true },
  ];

  const el = {
    refreshBtn: q('refreshBtn'),
    livePayload: q('livePayload'),
    liveDetectorTable: q('liveDetectorTable'),
    liveKpiCards: q('liveKpiCards'),
    durationSec: q('durationSec'),
    startCaptureBtn: q('startCaptureBtn'),
    captureMsg: q('captureMsg'),
    captureID: q('captureID'),
    loadCaptureBtn: q('loadCaptureBtn'),
    exportJSONBtn: q('exportJSONBtn'),
    exportTextBtn: q('exportTextBtn'),
    capturePayload: q('capturePayload'),
    captureDetectorTable: q('captureDetectorTable'),
    captureKpiCards: q('captureKpiCards'),
    captureDetectorSelect: q('captureDetectorSelect'),
    captureAvgMsChart: q('captureAvgMsChart'),
    captureRunsChart: q('captureRunsChart'),
    captureWebdetectorChart: q('captureWebdetectorChart'),
  };
  const tableState = {};
  const captureCharts = {
    avgMs: null,
    runs: null,
    webdetector: null,
  };
  let currentCapture = null;

  async function api(path, opts = {}) {
    const res = await fetch(`/cfm-admin/api${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...opts,
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(text || `HTTP ${res.status}`);
    }
    return text;
  }

  function parseJSONWithGuard(raw) {
    try {
      return JSON.parse(raw);
    } catch (err) {
      console.warn('Could not parse JSON payload:', err);
      return null;
    }
  }

  function coerceNumber(value) {
    const n = Number(value);
    return Number.isFinite(n) ? n : 0;
  }

  function normalizeDetector(detector, fallbackName) {
    if (!detector || typeof detector !== 'object') return null;
    const name = String(detector.name || fallbackName || '').trim();
    return {
      name: name || '(unknown)',
      runs: coerceNumber(detector.runs),
      failures: coerceNumber(detector.failures),
      timeouts: coerceNumber(detector.timeouts),
      avg_run_ms: coerceNumber(detector.avg_run_ms),
      total_run_seconds: coerceNumber(detector.total_run_seconds),
      lines_seen: coerceNumber(detector.lines_seen),
      parse_failures: coerceNumber(detector.parse_failures),
      avg_run_once_ms: coerceNumber(detector.avg_run_once_ms),
    };
  }

  function detectorsFromPayload(payload) {
    if (!payload || typeof payload !== 'object') return [];
    const raw = payload.detectors;
    if (Array.isArray(raw)) {
      return raw
        .map((item, idx) => normalizeDetector(item, `detector_${idx + 1}`))
        .filter(Boolean);
    }
    if (raw && typeof raw === 'object') {
      return Object.entries(raw)
        .map(([name, value]) => normalizeDetector(value, name))
        .filter(Boolean);
    }
    return [];
  }

  function sortDetectors(detectors, sortKey, direction) {
    const sorted = [...detectors];
    sorted.sort((a, b) => {
      const av = a?.[sortKey];
      const bv = b?.[sortKey];
      if (typeof av === 'number' || typeof bv === 'number') {
        return (coerceNumber(av) - coerceNumber(bv)) * direction;
      }
      return String(av || '').localeCompare(String(bv || '')) * direction;
    });
    return sorted;
  }

  function renderDetectorTable(detectors, targetEl) {
    if (!targetEl) return;
    if (!Array.isArray(detectors) || !detectors.length) {
      targetEl.innerHTML = '<p class="muted">No detectors available.</p>';
      return;
    }
    const key = targetEl.id || 'default';
    const currentSort = tableState[key] || { key: 'avg_run_ms', direction: -1 };
    const sorted = sortDetectors(detectors, currentSort.key, currentSort.direction);

    const table = document.createElement('table');
    table.className = 'compact-table';
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    detectorColumns.forEach((col) => {
      const th = document.createElement('th');
      if (col.sortable) {
        const btn = document.createElement('button');
        btn.className = 'btn-quiet btn-sm';
        btn.textContent = col.label;
        if (currentSort.key === col.key) {
          btn.textContent += currentSort.direction === -1 ? ' ▼' : ' ▲';
        }
        btn.addEventListener('click', () => {
          const prev = tableState[key] || { key: 'avg_run_ms', direction: -1 };
          const nextDirection = prev.key === col.key ? prev.direction * -1 : -1;
          tableState[key] = { key: col.key, direction: nextDirection };
          renderDetectorTable(detectors, targetEl);
        });
        th.appendChild(btn);
      } else {
        th.textContent = col.label;
      }
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    sorted.forEach((detector) => {
      const tr = document.createElement('tr');
      detectorColumns.forEach((col) => {
        const td = document.createElement('td');
        const val = detector?.[col.key];
        td.textContent = col.numeric ? String(coerceNumber(val)) : String(val ?? '');
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    targetEl.innerHTML = '';
    const wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    wrap.appendChild(table);
    targetEl.appendChild(wrap);
  }

  function renderKpiCards(targetEl, rows) {
    if (!targetEl) return;
    targetEl.innerHTML = '';
    rows.forEach(({ label, value }) => {
      const pill = document.createElement('span');
      pill.className = 'pill';
      pill.textContent = `${label}: ${value}`;
      targetEl.appendChild(pill);
    });
  }

  function destroyCaptureCharts() {
    Object.keys(captureCharts).forEach((key) => {
      if (captureCharts[key]) {
        captureCharts[key].dispose();
        captureCharts[key] = null;
      }
    });
  }

  function chartInit(elRef) {
    if (!elRef || !window.echarts) return null;
    return window.echarts.init(elRef);
  }

  function buildCaptureSeries(capture, detectorName) {
    const snapshots = Array.isArray(capture?.snapshots) ? capture.snapshots : [];
    const x = [];
    const avgMs = [];
    const runs = [];
    const failures = [];
    const linesSeen = [];
    const parseFailures = [];
    const avgRunOnceMs = [];
    snapshots.forEach((snap) => {
      const now = String(snap?.now || '');
      const detectors = detectorsFromPayload(snap);
      const target = detectors.find((d) => d.name === detectorName) || detectors[0];
      if (!target) return;
      x.push(now);
      avgMs.push(target.avg_run_ms);
      runs.push(target.runs);
      failures.push(target.failures);
      linesSeen.push(target.lines_seen);
      parseFailures.push(target.parse_failures);
      avgRunOnceMs.push(target.avg_run_once_ms);
    });
    return { x, avgMs, runs, failures, linesSeen, parseFailures, avgRunOnceMs };
  }

  function renderCaptureCharts(capture, detectorName) {
    const snapshots = Array.isArray(capture?.snapshots) ? capture.snapshots : [];
    destroyCaptureCharts();
    if (!snapshots.length) return;
    const series = buildCaptureSeries(capture, detectorName);
    if (!series.x.length) return;

    captureCharts.avgMs = chartInit(el.captureAvgMsChart);
    captureCharts.runs = chartInit(el.captureRunsChart);
    captureCharts.webdetector = chartInit(el.captureWebdetectorChart);
    captureCharts.avgMs?.setOption({
      title: { text: `${detectorName} avg_run_ms` },
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: series.x },
      yAxis: { type: 'value' },
      series: [{ type: 'line', data: series.avgMs, name: 'avg_run_ms' }],
    });
    captureCharts.runs?.setOption({
      title: { text: `${detectorName} runs / failures` },
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: series.x },
      yAxis: { type: 'value' },
      series: [
        { type: 'line', data: series.runs, name: 'runs' },
        { type: 'line', data: series.failures, name: 'failures' },
      ],
    });
    captureCharts.webdetector?.setOption({
      title: { text: `${detectorName} webdetector` },
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: series.x },
      yAxis: { type: 'value' },
      series: [
        { type: 'line', data: series.linesSeen, name: 'lines_seen' },
        { type: 'line', data: series.parseFailures, name: 'parse_failures' },
        { type: 'line', data: series.avgRunOnceMs, name: 'avg_run_once_ms' },
      ],
    });
  }

  function populateDetectorSelector(capture) {
    if (!el.captureDetectorSelect) return;
    const snapshots = Array.isArray(capture?.snapshots) ? capture.snapshots : [];
    const names = new Set();
    snapshots.forEach((snap) => {
      detectorsFromPayload(snap).forEach((det) => names.add(det.name));
    });
    const options = Array.from(names);
    el.captureDetectorSelect.innerHTML = '';
    if (!options.length) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = 'No detectors';
      el.captureDetectorSelect.appendChild(opt);
      return;
    }
    options.forEach((name) => {
      const opt = document.createElement('option');
      opt.value = name;
      opt.textContent = name;
      el.captureDetectorSelect.appendChild(opt);
    });
    el.captureDetectorSelect.value = options[0];
  }

  function summarizeCapture(capture) {
    const snapshots = Array.isArray(capture?.snapshots) ? capture.snapshots : [];
    const latest = snapshots[snapshots.length - 1] || capture;
    const detectors = detectorsFromPayload(latest);
    renderDetectorTable(detectors, el.captureDetectorTable);
    renderKpiCards(el.captureKpiCards, [
      { label: 'snapshots', value: snapshots.length },
      { label: 'detectors', value: detectors.length },
      { label: 'capture_id', value: String(capture?.id || '-') },
    ]);
    populateDetectorSelector(capture);
    const selected = el.captureDetectorSelect?.value || detectors[0]?.name || '';
    if (selected) {
      renderCaptureCharts(capture, selected);
    } else {
      destroyCaptureCharts();
    }
  }

  function summarizeLive(liveObj) {
    const detectors = detectorsFromPayload(liveObj);
    renderDetectorTable(detectors, el.liveDetectorTable);
    renderKpiCards(el.liveKpiCards, [
      { label: 'detectors', value: detectors.length },
      {
        label: 'max_avg_ms',
        value: detectors.reduce((max, d) => Math.max(max, d.avg_run_ms), 0),
      },
    ]);
  }

  async function loadLive() {
    const payload = await api('/v1/debug/live');
    el.livePayload.textContent = payload;
    const parsed = parseJSONWithGuard(payload);
    summarizeLive(parsed);
  }

  async function startCapture() {
    const duration = Number(el.durationSec.value || 20);
    const payload = await api('/v1/debug/capture', {
      method: 'POST',
      body: JSON.stringify({ duration_sec: duration }),
    });
    el.capturePayload.textContent = payload;
    const parsed = parseJSONWithGuard(payload);
    if (parsed) {
      if (parsed?.id) el.captureID.value = parsed.id;
      el.captureMsg.textContent = `Capture ${parsed.id} status: ${parsed.status}`;
      currentCapture = parsed;
      summarizeCapture(parsed);
    } else {
      el.captureMsg.textContent = 'Capture request sent.';
    }
  }

  async function loadCapture() {
    const id = String(el.captureID.value || '').trim();
    if (!id) {
      el.captureMsg.textContent = 'Enter a capture ID first.';
      return;
    }
    const payload = await api(`/v1/debug/capture/${encodeURIComponent(id)}`);
    el.capturePayload.textContent = payload;
    const parsed = parseJSONWithGuard(payload);
    currentCapture = parsed;
    summarizeCapture(parsed);
  }

  async function exportCapture(format) {
    const id = String(el.captureID.value || '').trim();
    if (!id) {
      el.captureMsg.textContent = 'Enter a capture ID first.';
      return;
    }
    const payload = await api(`/v1/debug/export?id=${encodeURIComponent(id)}&format=${format}`);
    el.capturePayload.textContent = payload;
    if (format === 'json') {
      const parsed = parseJSONWithGuard(payload);
      currentCapture = parsed;
      summarizeCapture(parsed);
    }
  }

  async function safeRun(fn) {
    try {
      await fn();
      el.captureMsg.textContent = '';
    } catch (err) {
      console.error(err);
      el.captureMsg.textContent = String(err.message || err);
    }
  }

  el.refreshBtn?.addEventListener('click', () => safeRun(loadLive));
  el.startCaptureBtn?.addEventListener('click', () => safeRun(startCapture));
  el.loadCaptureBtn?.addEventListener('click', () => safeRun(loadCapture));
  el.exportJSONBtn?.addEventListener('click', () => safeRun(() => exportCapture('json')));
  el.exportTextBtn?.addEventListener('click', () => safeRun(() => exportCapture('txt')));
  el.captureDetectorSelect?.addEventListener('change', () => {
    if (!currentCapture) return;
    renderCaptureCharts(currentCapture, el.captureDetectorSelect.value);
  });

  safeRun(loadLive);
})();
