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
  }

  function renderOverview(counters = null) {
    byId('notifierOverviewEnabled').textContent = state.draftConfig.notifier.enabled === false ? 'Disabled' : 'Enabled';
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
      tr.innerHTML = `<td>${channel}</td><td>${c.h1.attempts}</td><td>${c.h1.success}</td><td>${c.h1.fail}</td><td>${c.h24.attempts}</td><td>${c.h24.success}</td><td>${c.h24.fail}</td>`;
      body.appendChild(tr);
    });
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
      out.textContent = JSON.stringify(res, null, 2); showStatus('Test notification sent.');
    } catch (err) {
      out.textContent = err.message; showStatus(err.message, false);
    }
  }

  async function fetchHistory() {
    const p = new URLSearchParams();
    p.set('limit', String(Math.max(1, Number(byId('notifierHistoryLimit')?.value || 50))));
    const c = String(byId('notifierHistoryChannel')?.value || '').trim(); if (c) p.set('channel', c);
    const k = String(byId('notifierHistoryKind')?.value || '').trim(); if (k) p.set('kind', k);
    p.set('status', String(byId('notifierHistoryStatus')?.value || 'all'));
    const payload = await request(`/cfm-admin/api/v1/notifier/history?${p.toString()}`);
    state.historyRows = Array.isArray(payload.rows) ? payload.rows : [];
    const body = byId('notifierHistoryBody'); body.replaceChildren();
    for (const row of state.historyRows) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${row.time || ''}</td><td>${row.kind || ''}</td><td>${row.channel || ''}</td><td>${row.status || ''}</td><td>${row.reason || ''}</td><td>${row.error || ''}</td>`;
      body.appendChild(tr);
      if (row.kind) state.detectorHints.push(row.kind);
    }
    state.detectorHints = Array.from(new Set(state.detectorHints)); renderDetectorHints();
  }

  async function refreshCounters() {
    await fetchHistory();
    const now = Date.now();
    const counters = {};
    const add = (channel) => {
      if (!counters[channel]) counters[channel] = { h1: { attempts: 0, success: 0, fail: 0 }, h24: { attempts: 0, success: 0, fail: 0 } };
      return counters[channel];
    };
    for (const row of state.historyRows) {
      const ts = Date.parse(row.time || ''); if (!ts) continue;
      const age = now - ts; const ch = row.channel || 'unknown'; const status = row.status === 'error' ? 'fail' : 'success';
      if (age <= 24 * 3600 * 1000) { const c = add(ch); c.h24.attempts += 1; c.h24[status] += 1; }
      if (age <= 3600 * 1000) { const c = add(ch); c.h1.attempts += 1; c.h1[status] += 1; }
    }
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
    showStatus('Saved config and reloaded notifier.');
    if (reload_after_save) await refreshRuntimeStatus();
    await refreshCounters();
  }

  async function loadConfig() {
    const payload = await request('/cfm-admin/api/v1/notifier/config');
    const cfg = normalizeConfig(payload.config || payload);
    state.currentConfig = cfg; state.draftConfig = normalizeConfig(cfg); state.path = payload.path || '';
    renderChannels(); renderDetectors(); renderTemplateFields(); renderTestChannels(); syncDirty();
    renderOverview();
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
    showStatus('Draft discarded.');
  }

  function openUnsavedLeave(fn) { state.pendingLeave = fn; byId('notifierUnsavedLeaveModal').style.display = 'flex'; }
  function closeUnsavedLeave() { state.pendingLeave = null; byId('notifierUnsavedLeaveModal').style.display = 'none'; }
  function runPendingLeave() { const fn = state.pendingLeave; closeUnsavedLeave(); if (typeof fn === 'function') fn(); }

  function bindTemplateInputs() {
    [['notifierSubjectTemplate', 'subject_template', 'notifier'], ['notifierBodyTemplate', 'body_template', 'notifier'], ['notifierDedupeKey', 'key', 'dedupe'], ['notifierDedupeCooldown', 'cooldown', 'dedupe'], ['notifierDefaultCooldown', 'default_cooldown', 'notifier']].forEach(([id, key, root]) => {
      byId(id)?.addEventListener('input', (e) => { state.draftConfig[root][key] = String(e.target.value || ''); syncDirty(); renderTemplatePreview(); });
    });
  }

  function cell(child) { const td = document.createElement('td'); td.appendChild(child); return td; }

  function init() {
    document.querySelectorAll('.notifier-tab-btn').forEach((btn) => btn.addEventListener('click', () => { state.tab = btn.dataset.tab; renderTabs(); }));
    byId('notifierAddChannelBtn')?.addEventListener('click', addChannel);
    byId('notifierAddDetectorBtn')?.addEventListener('click', addDetector);
    byId('notifierSaveDraftBtn')?.addEventListener('click', () => openSaveModal().catch((e) => showStatus(e.message, false)));
    byId('notifierSaveConfirmBtn')?.addEventListener('click', () => saveDraft().catch((e) => showStatus(e.message, false)));
    byId('notifierSaveCancelBtn')?.addEventListener('click', () => { byId('notifierSaveModal').style.display = 'none'; });
    byId('notifierValidationErrorsCloseBtn')?.addEventListener('click', () => { byId('notifierValidationErrorsModal').style.display = 'none'; });

    byId('notifierDiscardBtn')?.addEventListener('click', () => (state.isDirty ? openUnsavedLeave(discardDraft) : discardDraft()));
    byId('notifierReloadFromFileBtn')?.addEventListener('click', () => (state.isDirty ? openUnsavedLeave(() => loadConfig().catch((e) => showStatus(e.message, false))) : loadConfig().catch((e) => showStatus(e.message, false))));
    byId('notifierReloadBtn')?.addEventListener('click', () => request('/cfm-admin/api/v1/notifier/reload', { method: 'POST', body: '{}' }).then(async () => { await refreshRuntimeStatus(); showStatus('Notifier reloaded successfully.'); }).catch((e) => showStatus(e.message, false)));

    byId('notifierDeleteConfirmCancelBtn')?.addEventListener('click', closeDelete);
    byId('notifierDeleteConfirmBtn')?.addEventListener('click', doDelete);
    byId('notifierUnsavedLeaveCancelBtn')?.addEventListener('click', closeUnsavedLeave);
    byId('notifierUnsavedLeaveDiscardBtn')?.addEventListener('click', runPendingLeave);

    byId('notifierRunTestBtn')?.addEventListener('click', () => {
      const selected = Array.from(document.querySelectorAll('#notifierTestChannels input[type="checkbox"]:checked')).map((x) => x.value);
      if (!selected.length) return showStatus('Select at least one channel for test.', false);
      runChannelTest(selected);
    });
    byId('notifierHistoryRefreshBtn')?.addEventListener('click', () => fetchHistory().catch((e) => showStatus(e.message, false)));
    byId('notifierOverviewRefreshMetrics')?.addEventListener('click', () => refreshCounters().catch((e) => showStatus(e.message, false)));
    byId('notifierOverviewToggleEnabled')?.addEventListener('click', () => { state.draftConfig.notifier.enabled = state.draftConfig.notifier.enabled === false; syncDirty(); renderOverview(); });

    bindTemplateInputs(); renderTabs(); renderDetectorHints();
    loadConfig()
      .then(() => refreshRuntimeStatus())
      .catch((err) => showStatus(err.message || 'Failed to load config.', false));
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true }); else init();
})();
