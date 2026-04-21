(() => {
  function clone(v) {
    try { if (typeof structuredClone === 'function') return structuredClone(v); } catch (_) {}
    return JSON.parse(JSON.stringify(v || {}));
  }

  const SAMPLE_EVENT = {
    Host: 'edge-1', Kind: 'NOTIFIER/TEST', SrcIP: '203.0.113.10', Reason: 'Manual test from UI', Severity: 'info',
  };

  const state = {
    currentConfig: { notifier: {}, dedupe: {}, channels: [], detectors: {} },
    draftConfig: { notifier: {}, dedupe: {}, channels: [], detectors: {} },
    path: '', isDirty: false, pendingDelete: null, pendingLeave: null,
    tab: 'overview', historyRows: [], detectorHints: ['*'],
    runtime: { loaded_at: null, reloaded_at: null, config_path: '', config_hash: '', last_load_ok: false, last_load_error: '', last_reload_error: '' },
    metricsMeta: { generated_at: '', source: '', window_start: '', window_end: '', total_rows_scanned: 0, degraded: false, warnings: [] },
    metricsUpdatedTimer: null,
    recentActions: [],
    historyPollTimer: null,
    historyPollMs: 7000,
    historyLatestCursor: '',
    historyKnownCursors: new Set(),
    historyPollInFlight: false,
  };

  const byId = (id) => document.getElementById(id);

  function request(path, opts = {}) {
    return fetch(path, { credentials: 'same-origin', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, ...opts })
      .then(async (res) => {
        const payload = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(payload.error || `Request failed (${res.status})`);
        return payload;
      });
  }

  function normalizeConfig(input) {
    const cfg = input && typeof input === 'object' ? clone(input) : {};
    cfg.notifier = cfg.notifier && typeof cfg.notifier === 'object' ? cfg.notifier : {};
    cfg.dedupe = cfg.dedupe && typeof cfg.dedupe === 'object' ? cfg.dedupe : {};
    cfg.channels = Array.isArray(cfg.channels) ? cfg.channels.map((c) => ({ ...c, id: String(c.id || c.name || '').trim() })) : [];
    if (Array.isArray(cfg.detectors)) {
      const map = {};
      for (const row of cfg.detectors) {
        const key = String(row?.key || row?.name || '').trim();
        if (!key) continue;
        map[key] = { notify: row.notify !== false, channels: Array.isArray(row.channels) ? row.channels : [], min_severity: row.min_severity || '', cooldown: row.cooldown || '' };
      }
      cfg.detectors = map;
    }
    cfg.detectors = cfg.detectors && typeof cfg.detectors === 'object' ? cfg.detectors : {};
    return cfg;
  }

  function configsEqual(a, b) {
    try { return JSON.stringify(a) === JSON.stringify(b); } catch (_) { return false; }
  }

  function showStatus(msg, ok = true) {
    const el = byId('notifierStatus'); if (!el) return;
    el.textContent = msg; el.style.color = ok ? '#4ade80' : '#f87171';
  }
  const TAB_STATUS_IDS = {
    overview: 'notifierStatusOverview',
    channels: 'notifierStatusChannels',
    routing: 'notifierStatusRouting',
    templates: 'notifierStatusTemplates',
    test: 'notifierStatusTest',
    history: 'notifierStatusHistory',
  };

  function clearTabStatus(tab = null) {
    const tabs = tab ? [tab] : Object.keys(TAB_STATUS_IDS);
    tabs.forEach((name) => {
      const el = byId(TAB_STATUS_IDS[name]);
      if (!el) return;
      el.style.display = 'none';
      el.textContent = '';
    });
  }

  function showTabStatus(tab, msg, ok = true) {
    const el = byId(TAB_STATUS_IDS[tab]);
    if (!el) return showStatus(msg, ok);
    el.style.display = '';
    el.textContent = msg;
    el.style.color = ok ? '#4ade80' : '#f87171';
  }

  function renderRecentActions() {
    const list = byId('notifierRecentActionsList');
    if (!list) return;
    list.replaceChildren();
    if (!state.recentActions.length) {
      const li = document.createElement('li');
      li.className = 'muted';
      li.textContent = 'No actions yet.';
      list.appendChild(li);
      return;
    }
    state.recentActions.forEach((entry) => {
      const li = document.createElement('li');
      li.textContent = `[${entry.at}] ${entry.action}: ${entry.result}`;
      li.className = entry.ok ? '' : 'danger-text';
      list.appendChild(li);
    });
  }

  function pushRecentAction(action, result, ok = true) {
    const at = new Date().toLocaleTimeString();
    state.recentActions.unshift({ at, action, result, ok });
    state.recentActions = state.recentActions.slice(0, 12);
    renderRecentActions();
  }

  function syncDirty() {
    state.isDirty = !configsEqual(state.currentConfig, state.draftConfig);
    const badge = byId('notifierDirtyBadge');
    if (badge) { badge.textContent = state.isDirty ? 'Unsaved changes' : 'Saved'; badge.className = state.isDirty ? 'pill warn' : 'pill'; }
    renderOverview(); renderTestChannels(); renderTemplatePreview();
  }

  function rowInput(v, cls = 'input', ph = '') {
    const i = document.createElement('input'); i.className = cls; i.value = v == null ? '' : String(v); i.placeholder = ph; return i;
  }

  function csv(raw) { return String(raw || '').split(',').map((v) => v.trim()).filter(Boolean); }

  function renderTabs() {
    document.querySelectorAll('.notifier-tab-btn').forEach((btn) => {
      const active = btn.dataset.tab === state.tab;
      btn.classList.toggle('btn-nav-active', active);
    });
    document.querySelectorAll('.notifier-tab-panel').forEach((p) => { p.style.display = p.dataset.tab === state.tab ? '' : 'none'; });
    clearTabStatus();
  }

  function renderOverview(counters = null) {
    const enabled = state.draftConfig.notifier.enabled !== false;
    byId('notifierOverviewEnabled').textContent = state.draftConfig.notifier.enabled === false ? 'Disabled' : 'Enabled';
    const toggleBtn = byId('notifierOverviewToggleEnabled');
    if (toggleBtn) toggleBtn.textContent = enabled ? 'Disable notifier' : 'Enable notifier';
    const loadedAt = state.runtime.loaded_at || '';
    byId('notifierOverviewLoadedAt').textContent = loadedAt || '-';
    if (state.runtime.reloaded_at) {
      byId('notifierOverviewLastReload').textContent = state.runtime.reloaded_at;
    } else if (loadedAt) {
      byId('notifierOverviewLastReload').textContent = `Not manually reloaded yet (loaded at ${loadedAt})`;
    } else {
      byId('notifierOverviewLastReload').textContent = 'Not manually reloaded yet';
    }
    byId('notifierOverviewPath').textContent = state.runtime.config_path || state.path || '-';
    byId('notifierOverviewLoadResult').textContent = state.runtime.last_reload_error || (state.runtime.last_load_ok ? 'OK' : (state.runtime.last_load_error || 'Unknown'));
    const body = byId('notifierOverviewCountersBody');
    if (!body || !counters) return;
    body.replaceChildren();
    Object.keys(counters).sort().forEach((channel) => {
      const c = counters[channel];
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${channel}</td><td>${c.h1.attempts}</td><td>${c.h1.success}</td><td>${c.h1.fail}</td><td>${c.h24.attempts}</td><td>${c.h24.success}</td><td>${c.h24.fail}</td><td style="font-family:ui-monospace, SFMono-Regular, Menlo, monospace">${c.trend || ''}</td>`;
      body.appendChild(tr);
    });
  }

  function relativeAge(ts) {
    const at = Date.parse(ts || '');
    if (!at) return '-';
    const sec = Math.max(0, Math.floor((Date.now() - at) / 1000));
    if (sec < 60) return `${sec}s ago`;
    if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
    return `${Math.floor(sec / 3600)}h ago`;
  }

  function setMetricsMeta(meta = {}) {
    state.metricsMeta = { ...state.metricsMeta, ...meta };
    byId('notifierMetricsSource').textContent = state.metricsMeta.source || '-';
    byId('notifierMetricsWindowStart').textContent = state.metricsMeta.window_start || '-';
    byId('notifierMetricsWindowEnd').textContent = state.metricsMeta.window_end || '-';
    byId('notifierMetricsRowsScanned').textContent = String(state.metricsMeta.total_rows_scanned || 0);
    byId('notifierMetricsUpdatedAgo').textContent = state.metricsMeta.generated_at ? `Updated ${relativeAge(state.metricsMeta.generated_at)}` : '-';
    const warning = byId('notifierMetricsWarning');
    if (warning) {
      if (state.metricsMeta.degraded) {
        const details = Array.isArray(state.metricsMeta.warnings) ? state.metricsMeta.warnings.join('; ') : '';
        warning.textContent = `⚠ Metrics are degraded. ${details}`;
        warning.style.display = '';
      } else {
        warning.style.display = 'none';
        warning.textContent = '';
      }
    }
  }

  function toSparkline(points) {
    const chars = '▁▂▃▄▅▆▇█';
    const max = Math.max(...points, 0);
    if (max <= 0) return '';
    return points.map((v) => chars[Math.max(0, Math.min(chars.length - 1, Math.round((v / max) * (chars.length - 1))))]).join('');
  }

  function setToggleResultChip(text = '', type = 'default') {
    const chip = byId('notifierOverviewToggleResult');
    if (!chip) return;
    if (!text) {
      chip.style.display = 'none';
      chip.textContent = '';
      chip.className = 'pill';
      return;
    }
    chip.style.display = '';
    chip.textContent = text;
    chip.className = type === 'warn' ? 'pill warn' : (type === 'danger' ? 'pill danger' : 'pill');
  }

  function addChannel() {
    const type = String(byId('notifierNewChannelType')?.value || 'sendmail');
    const nameRaw = String(byId('notifierNewChannelName')?.value || '').trim();
    const base = nameRaw || `${type}-channel`;
    const ids = new Set((state.draftConfig.channels || []).map((c) => String(c.id || '')));
    let id = base; let i = 2;
    while (ids.has(id)) { id = `${base}-${i}`; i += 1; }
    state.draftConfig.channels.push({ id, type, enabled: true, to: [], path: '/usr/sbin/sendmail' });
    if (byId('notifierNewChannelName')) byId('notifierNewChannelName').value = '';
    renderChannels(); syncDirty();
  }

  function renderChannels() {
    const body = byId('notifierChannelsBody'); if (!body) return;
    body.replaceChildren();
    for (const ch of state.draftConfig.channels || []) {
      const tr = document.createElement('tr');
      const idInput = rowInput(ch.id, 'input input-wide', 'name');
      idInput.oninput = () => { ch.id = String(idInput.value || '').trim(); syncDirty(); renderDetectors(); };

      const typeInput = rowInput(ch.type || '', 'input', 'sendmail/smtp/slack_webhook');
      typeInput.oninput = () => { ch.type = String(typeInput.value || '').trim(); renderChannels(); syncDirty(); };

      const enabledBtn = document.createElement('button'); enabledBtn.className = 'btn-quiet btn-sm'; enabledBtn.textContent = ch.enabled === false ? 'Disabled' : 'Enabled';
      enabledBtn.onclick = () => { ch.enabled = ch.enabled === false; renderChannels(); syncDirty(); };

      const fields = document.createElement('div'); fields.className = 'chips';
      const addField = (label, key, ph = '') => {
        const input = rowInput(ch[key] || '', 'input', ph);
        input.oninput = () => { ch[key] = String(input.value || '').trim(); syncDirty(); };
        const wrap = document.createElement('label'); wrap.className = 'muted'; wrap.textContent = `${label} `; wrap.appendChild(input); fields.appendChild(wrap);
      };
      if (ch.type === 'sendmail') { addField('path', 'path', '/usr/sbin/sendmail'); addField('to', 'toCSV', 'a@b,c@d'); }
      if (ch.type === 'smtp') { addField('host', 'host', 'smtp.example.com:587'); addField('from', 'from', 'cfm@example.com'); addField('to', 'toCSV', 'ops@example.com'); }
      if (ch.type === 'slack' || ch.type === 'slack_webhook') { addField('webhook_url', 'webhook_url', 'https://hooks.slack...'); addField('mention', 'mention', '@ops'); }
      if (ch.toCSV != null) ch.to = csv(ch.toCSV);

      const testBtn = document.createElement('button'); testBtn.className = 'btn-quiet btn-sm'; testBtn.textContent = 'Test';
      testBtn.onclick = () => runChannelTest([ch.id]);

      const delBtn = document.createElement('button'); delBtn.className = 'btn-danger btn-sm'; delBtn.textContent = 'Delete';
      delBtn.onclick = () => openDelete({ kind: 'channel', id: ch.id });

      tr.append(cell(idInput), cell(typeInput), cell(enabledBtn), cell(fields), cell(testBtn), cell(delBtn));
      body.appendChild(tr);
    }
  }

  function renderDetectorHints() {
    const dl = byId('notifierDetectorKeys'); if (!dl) return;
    dl.replaceChildren();
    state.detectorHints.forEach((key) => {
      const opt = document.createElement('option'); opt.value = key; dl.appendChild(opt);
    });
  }

  function addDetector() {
    let next = '*';
    if (state.draftConfig.detectors['*']) {
      let i = 1;
      while (state.draftConfig.detectors[`detector/${i}`]) i += 1;
      next = `detector/${i}`;
    }
    state.draftConfig.detectors[next] = { notify: true, channels: [], min_severity: '', cooldown: '' };
    renderDetectors(); syncDirty();
  }

  function renderDetectors() {
    const body = byId('notifierDetectorsBody'); if (!body) return;
    body.replaceChildren();
    const allChannels = (state.draftConfig.channels || []).map((c) => c.id).filter(Boolean);
    Object.keys(state.draftConfig.detectors || {}).sort().forEach((key) => {
      const d = state.draftConfig.detectors[key] || {};
      const tr = document.createElement('tr');
      const keyInput = rowInput(key, 'input input-wide'); keyInput.setAttribute('list', 'notifierDetectorKeys');
      keyInput.onchange = () => {
        const next = String(keyInput.value || '').trim();
        if (!next || next === key || state.draftConfig.detectors[next]) { keyInput.value = key; return; }
        state.draftConfig.detectors[next] = d; delete state.draftConfig.detectors[key]; renderDetectors(); syncDirty();
      };
      const notifyBtn = document.createElement('button'); notifyBtn.className = 'btn-quiet btn-sm'; notifyBtn.textContent = d.notify === false ? 'Off' : 'On';
      notifyBtn.onclick = () => { d.notify = d.notify === false; renderDetectors(); syncDirty(); };

      const channelsWrap = document.createElement('div'); channelsWrap.className = 'chips';
      allChannels.forEach((id) => {
        const label = document.createElement('label'); label.className = 'pill';
        const chk = document.createElement('input'); chk.type = 'checkbox'; chk.checked = (d.channels || []).includes(id);
        chk.onchange = () => {
          const set = new Set(Array.isArray(d.channels) ? d.channels : []);
          if (chk.checked) set.add(id); else set.delete(id);
          d.channels = Array.from(set); syncDirty();
        };
        label.append(chk, document.createTextNode(` ${id}`)); channelsWrap.appendChild(label);
      });
      const sev = rowInput(d.min_severity || '', 'input', 'info/warn/error'); sev.oninput = () => { d.min_severity = sev.value.trim(); syncDirty(); };
      const cool = rowInput(d.cooldown || '', 'input', '5m'); cool.oninput = () => { d.cooldown = cool.value.trim(); syncDirty(); };
      const del = document.createElement('button'); del.className = 'btn-danger btn-sm'; del.textContent = 'Delete'; del.onclick = () => openDelete({ kind: 'detector', id: key });
      tr.append(cell(keyInput), cell(notifyBtn), cell(channelsWrap), cell(sev), cell(cool), cell(del));
      body.appendChild(tr);
    });
  }

  function renderTemplateFields() {
    const n = state.draftConfig.notifier || {}, d = state.draftConfig.dedupe || {};
    byId('notifierSubjectTemplate').value = n.subject_template || '';
    byId('notifierBodyTemplate').value = n.body_template || '';
    byId('notifierDedupeKey').value = d.key || '';
    byId('notifierDedupeCooldown').value = d.cooldown || '';
    byId('notifierDefaultCooldown').value = n.default_cooldown || '';
    renderTemplatePreview();
  }

  function renderTemplatePreview() {
    const n = state.draftConfig.notifier || {}, d = state.draftConfig.dedupe || {};
    const applyTemplate = (tpl) => String(tpl || '').replace(/\{\{\.([A-Za-z0-9_]+)\}\}/g, (_, k) => SAMPLE_EVENT[k] || SAMPLE_EVENT[k.charAt(0).toUpperCase() + k.slice(1)] || '');
    const subject = applyTemplate(n.subject_template || '[CFM] {{.Kind}} from {{.Host}}');
    const body = applyTemplate(n.body_template || '{{.Reason}} ({{.SrcIP}})');
    const dedupeKey = applyTemplate(d.key || '{{.Host}}|{{.Kind}}|{{.SrcIP}}|{{.Reason}}');
    byId('notifierTemplatePreview').textContent = `Sample event:\n${JSON.stringify(SAMPLE_EVENT, null, 2)}\n\nSubject => ${subject}\nBody => ${body}\nDedupe key => ${dedupeKey}`;
  }

  function renderTestChannels() {
    const wrap = byId('notifierTestChannels'); if (!wrap) return;
    wrap.replaceChildren();
    (state.draftConfig.channels || []).forEach((ch) => {
      const label = document.createElement('label'); label.className = 'pill';
      const chk = document.createElement('input'); chk.type = 'checkbox'; chk.value = ch.id;
      label.append(chk, document.createTextNode(` ${ch.id}`)); wrap.appendChild(label);
    });
  }

  async function runChannelTest(channels) {
    const subject = byId('notifierTestSubject')?.value || '[CFM TEST] Channel connectivity';
    const body = byId('notifierTestBody')?.value || 'This is a test notification from CFM WebUI.';
    const event = { kind: 'NOTIFIER/TEST', section: 'notifier_test', severity: 'info', src_ip: '203.0.113.10', reason: 'Manual test from UI', extra: { target: channels.join(',') } };
    const payloadNew = { channels, event, subject, body };
    const payloadOld = { channels, payload: event };
    const out = byId('notifierTestResult');
    out.textContent = 'Sending test...';
    try {
      let res;
      try { res = await request('/cfm-admin/api/v1/notifier/test', { method: 'POST', body: JSON.stringify(payloadNew) }); }
      catch (_) { res = await request('/cfm-admin/api/v1/notifier/test', { method: 'POST', body: JSON.stringify(payloadOld) }); }
      out.textContent = JSON.stringify(res, null, 2);
      showTabStatus('test', 'Test notification sent.');
      pushRecentAction('test send result', 'success', true);
    } catch (err) {
      out.textContent = err.message;
      showTabStatus('test', err.message, false);
      pushRecentAction('test send result', err.message, false);
    }
  }

  function historyFilters() {
    const limitRaw = Number(byId('notifierHistoryLimit')?.value || 100);
    const limit = limitRaw === 50 ? 50 : 100;
    return {
      limit,
      channel: String(byId('notifierHistoryChannel')?.value || '').trim(),
      kind: String(byId('notifierHistoryKind')?.value || '').trim(),
      status: String(byId('notifierHistoryStatus')?.value || 'all'),
    };
  }

  function historyQueryString(filters, sinceCursor = '') {
    const p = new URLSearchParams();
    p.set('limit', String(filters.limit));
    if (filters.channel) p.set('channel', filters.channel);
    if (filters.kind) p.set('kind', filters.kind);
    p.set('status', filters.status);
    if (sinceCursor) p.set('since', sinceCursor);
    return p.toString();
  }

  function historyRowToHTML(row) {
    return `<td>${row.time || ''}</td><td>${row.kind || ''}</td><td>${row.channel || ''}</td><td>${row.status || ''}</td><td>${row.reason || ''}</td><td>${row.error || ''}</td>`;
  }

  function prependHistoryRows(rows) {
    const body = byId('notifierHistoryBody');
    if (!body || !Array.isArray(rows) || rows.length === 0) return 0;
    let added = 0;
    for (let i = rows.length - 1; i >= 0; i -= 1) {
      const row = rows[i];
      if (!row?.cursor || state.historyKnownCursors.has(row.cursor)) continue;
      state.historyKnownCursors.add(row.cursor);
      const tr = document.createElement('tr');
      tr.innerHTML = historyRowToHTML(row);
      body.insertBefore(tr, body.firstChild);
      state.historyRows.unshift(row);
      if (row.kind) state.detectorHints.push(row.kind);
      added += 1;
    }
    return added;
  }

  function replaceHistoryRows(rows) {
    const body = byId('notifierHistoryBody');
    if (!body) return;
    state.historyRows = Array.isArray(rows) ? rows : [];
    state.historyKnownCursors = new Set(state.historyRows.map((row) => String(row?.cursor || '')).filter(Boolean));
    body.replaceChildren();
    for (const row of state.historyRows) {
      const tr = document.createElement('tr');
      tr.innerHTML = historyRowToHTML(row);
      body.appendChild(tr);
      if (row.kind) state.detectorHints.push(row.kind);
    }
  }

  async function fetchHistory({ poll = false } = {}) {
    const filters = historyFilters();
    byId('notifierHistoryLimit').value = String(filters.limit);
    const qs = historyQueryString(filters, poll ? state.historyLatestCursor : '');
    const payload = await request(`/cfm-admin/api/v1/notifier/history?${qs}`);
    const rows = Array.isArray(payload.rows) ? payload.rows : [];
    if (poll) {
      const added = prependHistoryRows(rows);
      if (added > 0) showTabStatus('history', `Added ${added} new row${added === 1 ? '' : 's'}.`);
    } else {
      replaceHistoryRows(rows);
    }
    if (state.historyRows[0]?.cursor) state.historyLatestCursor = state.historyRows[0].cursor;
    state.detectorHints = Array.from(new Set(state.detectorHints)); renderDetectorHints();
  }

  async function pollHistory() {
    if (state.tab !== 'history' || state.historyPollInFlight) return;
    if (!state.historyLatestCursor) return fetchHistory({ poll: false });
    state.historyPollInFlight = true;
    try {
      await fetchHistory({ poll: true });
    } catch (_) {
      // keep UI quiet during background polls
    } finally {
      state.historyPollInFlight = false;
    }
  }

  function stopHistoryPolling() {
    if (state.historyPollTimer) {
      window.clearInterval(state.historyPollTimer);
      state.historyPollTimer = null;
    }
  }

  function startHistoryPolling() {
    stopHistoryPolling();
    fetchHistory({ poll: false }).catch((e) => showStatus(e.message, false));
    state.historyPollTimer = window.setInterval(() => { pollHistory(); }, state.historyPollMs);
  }

  function setTab(nextTab) {
    if (!nextTab || state.tab === nextTab) return;
    const prevTab = state.tab;
    state.tab = nextTab;
    renderTabs();
    if (prevTab === 'history' && nextTab !== 'history') stopHistoryPolling();
    if (nextTab === 'history') startHistoryPolling();
  }

  async function refreshCounters() {
    const [h1, h24] = await Promise.all([
      request('/cfm-admin/api/v1/notifier/metrics?window=1h'),
      request('/cfm-admin/api/v1/notifier/metrics?window=24h'),
    ]);
    const counters = {};
    const add = (channel) => {
      if (!counters[channel]) counters[channel] = { h1: { attempts: 0, success: 0, fail: 0 }, h24: { attempts: 0, success: 0, fail: 0 }, trend: '' };
      return counters[channel];
    };
    Object.entries(h1.per_channel || {}).forEach(([channel, attempts]) => { add(channel).h1.attempts = Number(attempts || 0); });
    Object.entries(h24.per_channel || {}).forEach(([channel, attempts]) => { add(channel).h24.attempts = Number(attempts || 0); });
    const allSeries = Array.isArray(h24.series) ? h24.series : [];
    const recent = allSeries.slice(-12).map((b) => Number(b.attempts || 0));
    const spark = toSparkline(recent);
    Object.keys(counters).forEach((channel) => { counters[channel].trend = spark; });

    const empty = byId('notifierMetricsEmptyState');
    if (empty) {
      if ((h1.total_attempts || 0) === 0 && (h24.total_attempts || 0) === 0) {
        empty.style.display = '';
        empty.textContent = 'No deliveries in last 1h/24h.';
      } else if ((h1.total_attempts || 0) === 0) {
        empty.style.display = '';
        empty.textContent = 'No deliveries in last 1h.';
      } else if ((h24.total_attempts || 0) === 0) {
        empty.style.display = '';
        empty.textContent = 'No deliveries in last 24h.';
      } else {
        empty.style.display = 'none';
        empty.textContent = '';
      }
    }
    setMetricsMeta({
      generated_at: h1.generated_at || '',
      source: h1.source || (h1.cached ? 'cache' : 'live'),
      window_start: h1.window_start || h1.from || '',
      window_end: h1.window_end || h1.to || '',
      total_rows_scanned: h1.total_rows_scanned || 0,
      degraded: !!(h1.degraded || h24.degraded),
      warnings: [...(h1.warnings || []), ...(h24.warnings || [])],
    });
    renderOverview(counters);
  }

  function openDelete(target) {
    state.pendingDelete = target;
    byId('notifierDeleteConfirmText').textContent = `Delete ${target.kind} "${target.id}"?`;
    byId('notifierDeleteConfirmModal').style.display = 'flex';
  }

  function closeDelete() { state.pendingDelete = null; byId('notifierDeleteConfirmModal').style.display = 'none'; }

  function doDelete() {
    const p = state.pendingDelete; if (!p) return;
    if (p.kind === 'channel') {
      state.draftConfig.channels = (state.draftConfig.channels || []).filter((c) => c.id !== p.id);
      Object.keys(state.draftConfig.detectors || {}).forEach((k) => {
        const list = Array.isArray(state.draftConfig.detectors[k].channels) ? state.draftConfig.detectors[k].channels : [];
        state.draftConfig.detectors[k].channels = list.filter((id) => id !== p.id);
      });
      renderChannels(); renderDetectors();
    } else { delete state.draftConfig.detectors[p.id]; renderDetectors(); }
    closeDelete(); syncDirty();
  }

  function computeSummary() {
    const c0 = new Set((state.currentConfig.channels || []).map((c) => c.id));
    const c1 = new Set((state.draftConfig.channels || []).map((c) => c.id));
    const d0 = new Set(Object.keys(state.currentConfig.detectors || {}));
    const d1 = new Set(Object.keys(state.draftConfig.detectors || {}));
    return {
      channels_added: Array.from(c1).filter((k) => !c0.has(k)), channels_removed: Array.from(c0).filter((k) => !c1.has(k)),
      detectors_added: Array.from(d1).filter((k) => !d0.has(k)), detectors_removed: Array.from(d0).filter((k) => !d1.has(k)),
    };
  }

  async function validateDraftServer() {
    try {
      const res = await request('/cfm-admin/api/v1/notifier/validate', { method: 'POST', body: JSON.stringify({ draft: state.draftConfig }) });
      return { ok: !!res.ok, errors: res.errors || [] };
    } catch (_) {
      const res = await request('/cfm-admin/api/v1/notifier/validate', { method: 'POST', body: JSON.stringify({ config: state.draftConfig }) });
      return { ok: !!res.ok, errors: res.errors || [] };
    }
  }

  async function previewDiff() {
    try {
      const res = await request('/cfm-admin/api/v1/notifier/preview', { method: 'POST', body: JSON.stringify({ draft: state.draftConfig }) });
      return res.diff || '(No textual diff)';
    } catch (_) {
      const res = await request('/cfm-admin/api/v1/notifier/preview', { method: 'POST', body: JSON.stringify({ config: state.draftConfig }) });
      return res.diff || '(No textual diff)';
    }
  }

  function openValidationErrors(errors) {
    const ul = byId('notifierValidationErrorsList'); ul.replaceChildren();
    errors.forEach((e) => {
      const li = document.createElement('li');
      li.textContent = typeof e === 'string' ? e : `${e.path || 'draft'}: ${e.message || 'invalid'}`;
      ul.appendChild(li);
    });
    byId('notifierValidationErrorsModal').style.display = 'flex';
  }

  async function openSaveModal() {
    const validation = await validateDraftServer();
    if (!validation.ok) return openValidationErrors(validation.errors);
    const s = computeSummary();
    byId('notifierSaveChannelsSummary').textContent = `Channels added: ${s.channels_added.join(', ') || 'none'}\nChannels removed: ${s.channels_removed.join(', ') || 'none'}\nDetectors added: ${s.detectors_added.join(', ') || 'none'}\nDetectors removed: ${s.detectors_removed.join(', ') || 'none'}`;
    byId('notifierSaveDiffPreview').textContent = 'Loading diff...';
    byId('notifierSaveModal').style.display = 'flex';
    byId('notifierSaveDiffPreview').textContent = await previewDiff();
  }

  async function saveDraft() {
    const create_backup = byId('notifierSaveBackup')?.checked !== false;
    const reload_after_save = byId('notifierSaveReload')?.checked !== false;
    try {
      await request('/cfm-admin/api/v1/notifier/save', { method: 'POST', body: JSON.stringify({ draft: state.draftConfig, options: { create_backup, reload_after_save } }) });
    } catch (_) {
      await request('/cfm-admin/api/v1/notifier/config', { method: 'PUT', body: JSON.stringify({ config: state.draftConfig }) });
      if (reload_after_save) await request('/cfm-admin/api/v1/notifier/reload', { method: 'POST', body: '{}' });
    }
    state.currentConfig = normalizeConfig(state.draftConfig);
    byId('notifierSaveModal').style.display = 'none';
    syncDirty();
    showTabStatus('overview', 'Saved config and reloaded notifier.');
    pushRecentAction('save config', reload_after_save ? 'saved + reload requested' : 'saved', true);
    if (reload_after_save) await refreshRuntimeStatus();
    await refreshCounters();
  }

  async function loadConfig() {
    const payload = await request('/cfm-admin/api/v1/notifier/config');
    const cfg = normalizeConfig(payload.config || payload);
    state.currentConfig = cfg; state.draftConfig = normalizeConfig(cfg); state.path = payload.path || '';
    renderChannels(); renderDetectors(); renderTemplateFields(); renderTestChannels(); syncDirty();
    renderOverview();
    setToggleResultChip();
    showStatus(`Loaded config from ${state.path || 'default path'}.`);
    await refreshCounters();
  }

  async function refreshRuntimeStatus() {
    const status = await request('/cfm-admin/api/v1/notifier/status');
    state.runtime = {
      loaded_at: status.loaded_at || null,
      reloaded_at: status.reloaded_at || null,
      config_path: status.config_path || '',
      config_hash: status.config_hash || '',
      last_load_ok: status.last_load_ok !== false,
      last_load_error: status.last_load_error || '',
      last_reload_error: status.last_reload_error || '',
    };
    renderOverview();
  }

  function discardDraft() {
    state.draftConfig = normalizeConfig(state.currentConfig);
    renderChannels(); renderDetectors(); renderTemplateFields(); syncDirty();
    setToggleResultChip();
    showTabStatus('overview', 'Draft discarded.');
  }

  async function restoreBackup() {
    const id = String(byId('notifierRestoreBackupId')?.value || '').trim();
    if (!id) {
      showTabStatus('history', 'Backup id is required.', false);
      return;
    }
    await request('/cfm-admin/api/v1/notifier/backups/restore', { method: 'POST', body: JSON.stringify({ id }) });
    showTabStatus('history', `Backup restored: ${id}`);
    pushRecentAction('restore backup', id, true);
    await loadConfig();
    await refreshRuntimeStatus();
    await fetchHistory();
  }

  function openUnsavedLeave(fn) { state.pendingLeave = fn; byId('notifierUnsavedLeaveModal').style.display = 'flex'; }
  function closeUnsavedLeave() { state.pendingLeave = null; byId('notifierUnsavedLeaveModal').style.display = 'none'; }
  function runPendingLeave() { const fn = state.pendingLeave; closeUnsavedLeave(); if (typeof fn === 'function') fn(); }
  function openDisableConfirm() { byId('notifierDisableConfirmModal').style.display = 'flex'; }
  function closeDisableConfirm() { byId('notifierDisableConfirmModal').style.display = 'none'; }

  async function applyNotifierEnabled(targetEnabled) {
    const currentEnabled = state.draftConfig.notifier.enabled !== false;
    if (currentEnabled === targetEnabled) {
      renderOverview();
      showStatus(targetEnabled ? 'Notifier is already enabled.' : 'Notifier is already disabled.');
      return;
    }
    state.draftConfig.notifier.enabled = targetEnabled;
    syncDirty();
    renderOverview();
    setToggleResultChip('pending save', 'warn');
    try {
      await request('/cfm-admin/api/v1/notifier/save', {
        method: 'POST',
        body: JSON.stringify({ draft: state.draftConfig, options: { create_backup: true, reload_after_save: true } }),
      });
      state.currentConfig = normalizeConfig(state.draftConfig);
      syncDirty();
      setToggleResultChip('saved to file');
      await refreshRuntimeStatus();
      if (state.runtime.last_reload_error) {
        setToggleResultChip('reload failed', 'danger');
        showStatus(`Saved config but reload failed: ${state.runtime.last_reload_error}`, false);
        pushRecentAction('save config', `reload failed: ${state.runtime.last_reload_error}`, false);
        return;
      }
      setToggleResultChip('reload applied');
      showStatus('Saved config and applied notifier reload.');
      pushRecentAction('save config', 'saved + reload applied', true);
      await refreshCounters();
    } catch (err) {
      setToggleResultChip('reload failed', 'danger');
      showStatus(err.message || 'Failed to apply notifier enabled state.', false);
      pushRecentAction('save config', err.message || 'Failed to apply notifier enabled state.', false);
    }
  }

  function bindTemplateInputs() {
    [['notifierSubjectTemplate', 'subject_template', 'notifier'], ['notifierBodyTemplate', 'body_template', 'notifier'], ['notifierDedupeKey', 'key', 'dedupe'], ['notifierDedupeCooldown', 'cooldown', 'dedupe'], ['notifierDefaultCooldown', 'default_cooldown', 'notifier']].forEach(([id, key, root]) => {
      byId(id)?.addEventListener('input', (e) => { state.draftConfig[root][key] = String(e.target.value || ''); syncDirty(); renderTemplatePreview(); });
    });
  }

  function cell(child) { const td = document.createElement('td'); td.appendChild(child); return td; }

  function init() {
    document.querySelectorAll('.notifier-tab-btn').forEach((btn) => btn.addEventListener('click', () => { setTab(btn.dataset.tab); }));
    byId('notifierAddChannelBtn')?.addEventListener('click', addChannel);
    byId('notifierAddDetectorBtn')?.addEventListener('click', addDetector);
    byId('notifierSaveDraftBtn')?.addEventListener('click', () => openSaveModal().catch((e) => showStatus(e.message, false)));
    byId('notifierSaveConfirmBtn')?.addEventListener('click', () => saveDraft().catch((e) => showStatus(e.message, false)));
    byId('notifierSaveCancelBtn')?.addEventListener('click', () => { byId('notifierSaveModal').style.display = 'none'; });
    byId('notifierValidationErrorsCloseBtn')?.addEventListener('click', () => { byId('notifierValidationErrorsModal').style.display = 'none'; });

    byId('notifierDiscardBtn')?.addEventListener('click', () => (state.isDirty ? openUnsavedLeave(discardDraft) : discardDraft()));
    byId('notifierReloadFromFileBtn')?.addEventListener('click', () => (state.isDirty ? openUnsavedLeave(() => loadConfig().catch((e) => showStatus(e.message, false))) : loadConfig().catch((e) => showStatus(e.message, false))));
    byId('notifierReloadBtn')?.addEventListener('click', () => request('/cfm-admin/api/v1/notifier/reload', { method: 'POST', body: '{}' }).then(async () => {
      await refreshRuntimeStatus();
      showTabStatus('overview', 'Notifier reloaded successfully.');
      pushRecentAction('reload notifier', 'success', true);
    }).catch((e) => {
      showTabStatus('overview', e.message, false);
      pushRecentAction('reload notifier', e.message, false);
    }));

    byId('notifierDeleteConfirmCancelBtn')?.addEventListener('click', closeDelete);
    byId('notifierDeleteConfirmBtn')?.addEventListener('click', doDelete);
    byId('notifierUnsavedLeaveCancelBtn')?.addEventListener('click', closeUnsavedLeave);
    byId('notifierUnsavedLeaveDiscardBtn')?.addEventListener('click', runPendingLeave);

    byId('notifierRunTestBtn')?.addEventListener('click', () => {
      const selected = Array.from(document.querySelectorAll('#notifierTestChannels input[type="checkbox"]:checked')).map((x) => x.value);
      if (!selected.length) return showTabStatus('test', 'Select at least one channel for test.', false);
      runChannelTest(selected);
    });
    byId('notifierHistoryRefreshBtn')?.addEventListener('click', () => fetchHistory({ poll: false }).catch((e) => showStatus(e.message, false)));
    byId('notifierOverviewRefreshMetrics')?.addEventListener('click', () => refreshCounters().catch((e) => showStatus(e.message, false)));
    byId('notifierOverviewToggleEnabled')?.addEventListener('click', () => {
      const currentEnabled = state.draftConfig.notifier.enabled !== false;
      if (currentEnabled) {
        openDisableConfirm();
        return;
      }
      applyNotifierEnabled(true).catch((e) => showStatus(e.message, false));
    });
    byId('notifierDisableConfirmCancelBtn')?.addEventListener('click', closeDisableConfirm);
    byId('notifierDisableConfirmBtn')?.addEventListener('click', () => {
      closeDisableConfirm();
      applyNotifierEnabled(false).catch((e) => showStatus(e.message, false));
    });
    byId('notifierRestoreBackupBtn')?.addEventListener('click', () => restoreBackup().catch((e) => {
      showTabStatus('history', e.message, false);
      pushRecentAction('restore backup', e.message, false);
    }));

    bindTemplateInputs(); renderTabs(); renderDetectorHints(); renderRecentActions();
    state.metricsUpdatedTimer = window.setInterval(() => setMetricsMeta(), 1000);
    loadConfig()
      .then(() => refreshRuntimeStatus())
      .catch((err) => showStatus(err.message || 'Failed to load config.', false));
    if (state.tab === 'history') startHistoryPolling();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true }); else init();
})();
