import { initChart as cfmInitChart, onThemeChange as cfmOnThemeChange } from "./shared/chart-theme.js";

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
    captureSummary: q('captureSummary'),
    captureDetectorSelect: q('captureDetectorSelect'),
    detectorFilterInput: q('detectorFilterInput'),
    nonZeroOnlyToggle: q('nonZeroOnlyToggle'),
    topNSelect: q('topNSelect'),
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
  const viewState = {
    detectorFilter: '',
    nonZeroOnly: false,
    topN: 0,
    focusDetector: '',
    sortKey: 'avg_run_ms',
    sortDirection: -1,
  };
  let currentCapture = null;

  function syncURLFromViewState() {
    const params = new URLSearchParams(window.location.search);
    const pairs = {
      detector: viewState.detectorFilter || '',
      nonZero: viewState.nonZeroOnly ? '1' : '',
      topN: viewState.topN > 0 ? String(viewState.topN) : '',
      focus: viewState.focusDetector || '',
      sort: viewState.sortKey || '',
      dir: String(viewState.sortDirection || -1),
      captureId: String(el.captureID?.value || '').trim(),
    };
    Object.entries(pairs).forEach(([key, value]) => {
      if (value) params.set(key, value);
      else params.delete(key);
    });
    const next = `${window.location.pathname}${params.toString() ? `?${params.toString()}` : ''}`;
    window.history.replaceState(null, '', next);
  }

  function initViewStateFromURL() {
    const params = new URLSearchParams(window.location.search);
    viewState.detectorFilter = String(params.get('detector') || '').trim();
    viewState.nonZeroOnly = params.get('nonZero') === '1';
    viewState.topN = Math.max(0, coerceNumber(params.get('topN')));
    viewState.focusDetector = String(params.get('focus') || '').trim();
    viewState.sortKey = String(params.get('sort') || 'avg_run_ms');
    viewState.sortDirection = coerceNumber(params.get('dir')) === 1 ? 1 : -1;
    const captureId = String(params.get('captureId') || '').trim();

    if (el.detectorFilterInput) el.detectorFilterInput.value = viewState.detectorFilter;
    if (el.nonZeroOnlyToggle) el.nonZeroOnlyToggle.checked = viewState.nonZeroOnly;
    if (el.topNSelect) {
      const rawTop = viewState.topN > 0 ? String(viewState.topN) : '0';
      const hasOption = Array.from(el.topNSelect.options).some((opt) => opt.value === rawTop);
      el.topNSelect.value = hasOption ? rawTop : '0';
      if (!hasOption) viewState.topN = 0;
    }
    if (el.captureID && captureId) el.captureID.value = captureId;
    syncURLFromViewState();
  }

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

  function applyViewFilters(detectors) {
    let filtered = Array.isArray(detectors) ? [...detectors] : [];
    if (viewState.detectorFilter) {
      const needle = viewState.detectorFilter.toLowerCase();
      filtered = filtered.filter((d) => d.name.toLowerCase().includes(needle));
    }
    if (viewState.nonZeroOnly) {
      filtered = filtered.filter((d) => d.failures > 0 || d.timeouts > 0);
    }
    filtered = sortDetectors(filtered, viewState.sortKey, viewState.sortDirection);
    if (viewState.topN > 0) {
      filtered = filtered.slice(0, viewState.topN);
    }
    return filtered;
  }

  function renderDetectorTable(detectors, targetEl, opts = {}) {
    if (!targetEl) return;
    if (!Array.isArray(detectors) || !detectors.length) {
      targetEl.innerHTML = '<p class="muted">No detectors available.</p>';
      return;
    }
    const key = targetEl.id || 'default';
    const allowPin = Boolean(opts.allowPin);
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
          if (targetEl === el.captureDetectorTable) {
            viewState.sortKey = col.key;
            viewState.sortDirection = nextDirection;
            syncURLFromViewState();
            rerenderCapture();
            return;
          }
          renderDetectorTable(detectors, targetEl, opts);
        });
        th.appendChild(btn);
      } else {
        th.textContent = col.label;
      }
      headRow.appendChild(th);
    });

    if (allowPin) {
      const th = document.createElement('th');
      th.textContent = 'actions';
      headRow.appendChild(th);
    }

    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    sorted.forEach((detector) => {
      const tr = document.createElement('tr');
      if (allowPin && detector.name === viewState.focusDetector) {
        tr.className = 'pinned-row';
      }
      detectorColumns.forEach((col) => {
        const td = document.createElement('td');
        const val = detector?.[col.key];
        td.textContent = col.numeric ? String(coerceNumber(val)) : String(val ?? '');
        tr.appendChild(td);
      });
      if (allowPin) {
        const td = document.createElement('td');
        td.className = 'actions-cell';
        const pin = document.createElement('button');
        pin.className = detector.name === viewState.focusDetector ? 'btn-sm' : 'btn-quiet btn-sm';
        pin.textContent = detector.name === viewState.focusDetector ? 'Pinned' : 'Pin detector';
        pin.addEventListener('click', () => {
          viewState.focusDetector = detector.name;
          if (el.captureDetectorSelect) el.captureDetectorSelect.value = detector.name;
          syncURLFromViewState();
          rerenderCapture();
        });
        td.appendChild(pin);
        tr.appendChild(td);
      }
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
    return cfmInitChart(elRef);
  }

  // Re-render the last capture with the new theme when the toggle flips.
  let lastCaptureRender = null;
  cfmOnThemeChange(() => {
    if (lastCaptureRender) renderCaptureCharts(lastCaptureRender.capture, lastCaptureRender.detectorName);
  });

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
      const detectors = applyViewFilters(detectorsFromPayload(snap));
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
    lastCaptureRender = { capture, detectorName };
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

  function summarizeCapture(capture) {
    const snapshots = Array.isArray(capture?.snapshots) ? capture.snapshots : [];
    const first = snapshots[0] || null;
    const last = snapshots[snapshots.length - 1] || capture;
    const startMs = Date.parse(String(first?.now || ''));
    const endMs = Date.parse(String(last?.now || ''));
    const durationSec = Number.isFinite(startMs) && Number.isFinite(endMs)
      ? Math.max(0, Math.round((endMs - startMs) / 1000))
      : Math.max(0, snapshots.length - 1);
    const firstMap = new Map(detectorsFromPayload(first).map((d) => [d.name, d]));
    const lastAll = detectorsFromPayload(last);
    const filtered = applyViewFilters(lastAll);

    const detectorStats = new Map();
    snapshots.forEach((snap) => {
      detectorsFromPayload(snap).forEach((det) => {
        if (!detectorStats.has(det.name)) {
          detectorStats.set(det.name, { count: 0, min: Infinity, max: -Infinity, sum: 0 });
        }
        const s = detectorStats.get(det.name);
        s.count += 1;
        s.min = Math.min(s.min, det.avg_run_ms);
        s.max = Math.max(s.max, det.avg_run_ms);
        s.sum += det.avg_run_ms;
      });
    });

    const deltas = filtered.map((det) => {
      const begin = firstMap.get(det.name) || normalizeDetector({ name: det.name }, det.name);
      return {
        name: det.name,
        runsDelta: det.runs - begin.runs,
        failuresDelta: det.failures - begin.failures,
        timeoutsDelta: det.timeouts - begin.timeouts,
        linesSeenDelta: det.lines_seen - begin.lines_seen,
        parseFailuresDelta: det.parse_failures - begin.parse_failures,
      };
    });

    const topLatency = filtered
      .map((det) => {
        const st = detectorStats.get(det.name);
        return {
          name: det.name,
          avg: st && st.count ? st.sum / st.count : 0,
          min: st?.count ? st.min : 0,
          max: st?.count ? st.max : 0,
        };
      })
      .sort((a, b) => b.avg - a.avg)[0];
    const runGrowth = [...deltas].sort((a, b) => b.runsDelta - a.runsDelta)[0];

    const failuresIntroduced = deltas.filter((d) => d.failuresDelta > 0 || d.timeoutsDelta > 0);
    const webdetectorGrowth = [...deltas].sort((a, b) => b.linesSeenDelta - a.linesSeenDelta)[0];

    if (el.captureSummary) {
      const cards = [
        {
          title: 'Top latency detector',
          value: topLatency
            ? `${topLatency.name} avg ${topLatency.avg.toFixed(1)}ms (min ${topLatency.min.toFixed(1)} / max ${topLatency.max.toFixed(1)})`
            : 'No data',
          tone: topLatency && topLatency.avg > 1000 ? 'warn' : '',
        },
        {
          title: 'Largest run growth',
          value: runGrowth ? `${runGrowth.name} +${runGrowth.runsDelta} runs` : 'No data',
          tone: runGrowth && runGrowth.runsDelta <= 0 ? 'warn' : '',
        },
        {
          title: 'Any failures/timeouts introduced',
          value: failuresIntroduced.length
            ? failuresIntroduced
                .slice(0, 3)
                .map((d) => `${d.name} (+${d.failuresDelta} fail, +${d.timeoutsDelta} timeout)`)
                .join(' · ')
            : 'No new failures/timeouts',
          tone: failuresIntroduced.length ? 'danger' : '',
        },
        {
          title: 'Webdetector ingest trend',
          value: webdetectorGrowth
            ? `${webdetectorGrowth.name} lines_seen ${webdetectorGrowth.linesSeenDelta >= 0 ? '+' : ''}${webdetectorGrowth.linesSeenDelta}, parse_failures ${webdetectorGrowth.parseFailuresDelta >= 0 ? '+' : ''}${webdetectorGrowth.parseFailuresDelta}`
            : 'No data',
          tone: webdetectorGrowth && webdetectorGrowth.parseFailuresDelta > 0 ? 'warn' : '',
        },
      ];
      el.captureSummary.innerHTML = '';
      cards.forEach((card) => {
        const node = document.createElement('div');
        node.className = 'summary-card';
        const h = document.createElement('h4');
        h.textContent = card.title;
        const value = document.createElement('div');
        value.className = 'value';
        value.textContent = card.value;
        const pill = document.createElement('span');
        pill.className = `pill ${card.tone}`.trim();
        pill.textContent = card.tone ? card.tone.toUpperCase() : 'OK';
        node.appendChild(h);
        node.appendChild(value);
        node.appendChild(pill);
        el.captureSummary.appendChild(node);
      });
    }

    renderDetectorTable(filtered, el.captureDetectorTable, { allowPin: true });
    renderKpiCards(el.captureKpiCards, [
      { label: 'snapshots', value: snapshots.length },
      { label: 'detectors', value: filtered.length },
      { label: 'duration_sec', value: durationSec },
      { label: 'capture_id', value: String(capture?.id || '-') },
    ]);

    const options = filtered.map((d) => d.name);
    if (el.captureDetectorSelect) {
      el.captureDetectorSelect.innerHTML = '';
      if (!options.length) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = 'No detectors';
        el.captureDetectorSelect.appendChild(opt);
      } else {
        options.forEach((name) => {
          const opt = document.createElement('option');
          opt.value = name;
          opt.textContent = name;
          el.captureDetectorSelect.appendChild(opt);
        });
      }
    }

    if (options.length) {
      if (!options.includes(viewState.focusDetector)) {
        viewState.focusDetector = options[0];
      }
      if (el.captureDetectorSelect) el.captureDetectorSelect.value = viewState.focusDetector;
      renderCaptureCharts(capture, viewState.focusDetector);
    } else {
      viewState.focusDetector = '';
      destroyCaptureCharts();
    }
    syncURLFromViewState();
  }

  function rerenderCapture() {
    if (!currentCapture) return;
    summarizeCapture(currentCapture);
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

  initViewStateFromURL();
  tableState.captureDetectorTable = { key: viewState.sortKey, direction: viewState.sortDirection };

  el.refreshBtn?.addEventListener('click', () => safeRun(loadLive));
  el.startCaptureBtn?.addEventListener('click', () => safeRun(startCapture));
  el.loadCaptureBtn?.addEventListener('click', () => safeRun(loadCapture));
  el.exportJSONBtn?.addEventListener('click', () => safeRun(() => exportCapture('json')));
  el.exportTextBtn?.addEventListener('click', () => safeRun(() => exportCapture('txt')));

  el.captureDetectorSelect?.addEventListener('change', () => {
    if (!currentCapture) return;
    viewState.focusDetector = el.captureDetectorSelect.value;
    syncURLFromViewState();
    renderCaptureCharts(currentCapture, viewState.focusDetector);
  });

  el.detectorFilterInput?.addEventListener('input', () => {
    viewState.detectorFilter = String(el.detectorFilterInput.value || '').trim();
    rerenderCapture();
  });
  el.nonZeroOnlyToggle?.addEventListener('change', () => {
    viewState.nonZeroOnly = Boolean(el.nonZeroOnlyToggle.checked);
    rerenderCapture();
  });
  el.topNSelect?.addEventListener('change', () => {
    viewState.topN = Math.max(0, coerceNumber(el.topNSelect.value));
    rerenderCapture();
  });

  safeRun(loadLive);
  if (el.captureID?.value) {
    safeRun(loadCapture);
  }
})();
