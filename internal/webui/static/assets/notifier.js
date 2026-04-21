(() => {
  function cloneConfig(config) {
    try {
      if (typeof structuredClone === 'function') return structuredClone(config);
    } catch (_) {}
    return JSON.parse(JSON.stringify(config || {}));
  }

  function normalizeConfig(config) {
    const next = config && typeof config === 'object' ? config : {};
    next.channels = Array.isArray(next.channels) ? next.channels : [];
    next.detectors = next.detectors && typeof next.detectors === 'object' ? next.detectors : {};
    return next;
  }

  function configsEqual(a, b) {
    try {
      return JSON.stringify(a || {}) === JSON.stringify(b || {});
    } catch (_) {
      return false;
    }
  }

  let state = {
    currentConfig: { channels: [], detectors: {} },
    draftConfig: { channels: [], detectors: {} },
    path: '',
    isDirty: false,
    testResults: [],
    activeTab: 'config',
    historyRows: [],
    historyStack: [''],
    historyPage: 0,
    historyHasMore: false,
    historyNextCursor: '',
    backups: [],
    activeBackupID: '',
  };

  function byId(id) { return document.getElementById(id); }

  function showStatus(msg, ok = true) {
    const el = byId('notifierStatus');
    if (!el) return;
    el.textContent = msg;
    el.style.color = ok ? '#4ade80' : '#f87171';
  }

  let toastTimer = null;
  function showToast(msg, ms = 4500) {
    const el = byId('notifierToast');
    if (!el) return;
    el.textContent = msg;
    el.style.display = 'block';
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.style.display = 'none'; }, ms);
  }

  function syncDirtyState() {
    state.isDirty = !configsEqual(state.draftConfig, state.currentConfig);
    const badge = byId('notifierDirtyBadge');
    if (badge) {
      badge.textContent = state.isDirty ? 'Unsaved changes' : 'Saved';
      badge.className = state.isDirty ? 'pill warn' : 'pill';
    }
  }

  async function request(path, opts = {}) {
    const res = await fetch(path, {
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      ...opts,
    });
    const payload = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(payload.error || `Request failed (${res.status})`);
    return payload;
  }

  async function loadConfig() {
    const payload = await request('/cfm-admin/api/v1/notifier/config');
    const loaded = normalizeConfig(cloneConfig(payload.config || { channels: [], detectors: {} }));
    state = {
      ...state,
      currentConfig: loaded,
      draftConfig: cloneConfig(loaded),
      path: payload.path || '',
    };
    render();
    await loadBackups();
    showStatus(`Loaded config from ${state.path || 'default path'}.`);
  }

  async function saveConfig() {
    const payload = await request('/cfm-admin/api/v1/notifier/config', {
      method: 'PUT',
      body: JSON.stringify({ config: state.draftConfig }),
    });
    state.currentConfig = normalizeConfig(cloneConfig(state.draftConfig));
    syncDirtyState();
    await loadBackups();
    showToast(`Saved + backup created (${payload.backup_id || 'n/a'})`);
    showStatus(`Config saved to ${payload.path || state.path}.`);
  }

  async function previewConfigDiff() {
    const payload = await request('/cfm-admin/api/v1/notifier/preview', {
      method: 'POST',
      body: JSON.stringify({ config: state.draftConfig }),
    });
    return payload.diff || '';
  }

  function cancelEdits() {
    state.draftConfig = normalizeConfig(cloneConfig(state.currentConfig));
    render();
    showStatus('Unsaved edits discarded.');
  }

  function revertSection(section) {
    if (section !== 'channels' && section !== 'detectors') return;
    state.draftConfig[section] = cloneConfig(state.currentConfig[section]);
    render();
    showStatus(`Reverted ${section} to saved state.`);
  }

  async function reloadNotifier() {
    await request('/cfm-admin/api/v1/notifier/reload', { method: 'POST', body: '{}' });
    showStatus('Notifier reloaded successfully.');
  }

  async function loadBackups() {
    const payload = await request('/cfm-admin/api/v1/notifier/backups');
    state.backups = Array.isArray(payload.backups) ? payload.backups : [];
    renderBackups();
  }

  async function previewBackupDiff(backupID) {
    const q = new URLSearchParams({ id: backupID });
    const payload = await request(`/cfm-admin/api/v1/notifier/backups/diff?${q.toString()}`);
    state.activeBackupID = backupID;
    const box = byId('notifierBackupDiffPreview');
    if (box) box.textContent = payload.diff || '(No diff)';
    const modal = byId('notifierBackupDiffModal');
    if (modal) modal.style.display = 'flex';
  }

  async function restoreBackup(backupID) {
    const payload = await request('/cfm-admin/api/v1/notifier/backups/restore', {
      method: 'POST',
      body: JSON.stringify({ id: backupID }),
    });
    closeBackupDiffModal();
    await loadConfig();
    showToast(`Backup restored (${payload.restored_id || backupID}), notifier reloaded`);
    showStatus(`Restored backup ${backupID} and reloaded notifier.`);
  }

  function parseSampleInput() {
    const raw = (byId('notifierTestSample')?.value || '').trim();
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Sample payload must be a JSON object.');
    }
    return parsed;
  }

  async function runNotifierTest() {
    const channel = (byId('notifierTestChannel')?.value || '').trim();
    const detector = (byId('notifierTestDetector')?.value || '').trim();
    if (!channel) throw new Error('Channel is required.');
    const sample = parseSampleInput();
    const payload = await request('/cfm-admin/api/v1/notifier/test', {
      method: 'POST',
      body: JSON.stringify({ channel, detector, sample }),
    });
    state.testResults = Array.isArray(payload.results) ? payload.results : [];
    renderTests();
    showStatus(`Completed notifier test for ${channel}.`, true);
  }

  function channelTargets(ch) {
    if (Array.isArray(ch.to) && ch.to.length) return ch.to.join(', ');
    if (ch.webhook_url) return ch.webhook_url;
    if (ch.host) return `${ch.host}${ch.from ? ` (${ch.from})` : ''}`;
    if (ch.path) return ch.path;
    return '-';
  }

  function renderChannels() {
    const body = byId('notifierChannelsBody');
    if (!body) return;
    body.replaceChildren();
    for (const channel of state.draftConfig.channels) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${channel.id || ''}</td>
        <td>${channel.type || ''}</td>
        <td>${channel.enabled !== false ? 'yes' : 'no'}</td>
        <td class="muted">${channelTargets(channel)}</td>
        <td class="actions-cell"></td>
      `;
      const actions = tr.querySelector('.actions-cell');
      const edit = document.createElement('button');
      edit.className = 'btn-quiet btn-sm';
      edit.textContent = 'Edit';
      edit.onclick = () => editChannel(channel.id);
      const del = document.createElement('button');
      del.className = 'btn-danger btn-sm';
      del.textContent = 'Delete';
      del.onclick = () => deleteChannel(channel.id);
      actions.append(edit, del);
      body.appendChild(tr);
    }
  }

  function renderDetectors() {
    const body = byId('notifierDetectorsBody');
    if (!body) return;
    body.replaceChildren();
    const keys = Object.keys(state.draftConfig.detectors || {}).sort();
    for (const detector of keys) {
      const ov = state.draftConfig.detectors[detector] || {};
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${detector}</td>
        <td>${ov.notify !== false ? 'yes' : 'no'}</td>
        <td>${ov.cooldown || '-'}</td>
        <td>${ov.min_severity || '-'}</td>
        <td>${Array.isArray(ov.channels) && ov.channels.length ? ov.channels.join(', ') : '-'}</td>
        <td class="actions-cell"></td>
      `;
      const actions = tr.querySelector('.actions-cell');
      const edit = document.createElement('button');
      edit.className = 'btn-quiet btn-sm';
      edit.textContent = 'Edit';
      edit.onclick = () => editDetector(detector);
      const del = document.createElement('button');
      del.className = 'btn-danger btn-sm';
      del.textContent = 'Delete';
      del.onclick = () => deleteDetector(detector);
      actions.append(edit, del);
      body.appendChild(tr);
    }
  }

  function render() {
    renderChannels();
    renderDetectors();
    renderTests();
    renderHistory();
    applyTabVisibility();
    syncDirtyState();
    renderBackups();
  }

  function renderBackups() {
    const body = byId('notifierBackupsBody');
    if (!body) return;
    body.replaceChildren();
    for (const b of state.backups || []) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${b.id || '-'}</code></td>
        <td>${b.created || '-'}</td>
        <td>${b.size ?? '-'}</td>
        <td class="actions-cell"></td>
      `;
      const actions = tr.querySelector('.actions-cell');
      const preview = document.createElement('button');
      preview.className = 'btn-quiet btn-sm';
      preview.textContent = 'Preview diff';
      preview.onclick = () => previewBackupDiff(String(b.id || '')).catch((e) => showStatus(e.message, false));
      const restore = document.createElement('button');
      restore.className = 'btn-danger btn-sm';
      restore.textContent = 'Restore';
      restore.onclick = () => restoreBackup(String(b.id || '')).catch((e) => showStatus(e.message, false));
      actions.append(preview, restore);
      body.appendChild(tr);
    }
  }

  function renderTests() {
    const body = byId('notifierTestsBody');
    if (!body) return;
    body.replaceChildren();
    for (const result of state.testResults || []) {
      const tr = document.createElement('tr');
      const statusText = result.success || result.status === 'success' ? 'success' : 'failure';
      const statusColor = statusText === 'success' ? '#4ade80' : '#f87171';
      tr.innerHTML = `
        <td>${result.channel || '-'}</td>
        <td>${result.attempted_at || '-'}</td>
        <td style="color:${statusColor};font-weight:600">${statusText}</td>
        <td>${result.error || '-'}</td>
        <td>${result.delivery_duration || '-'}</td>
      `;
      body.appendChild(tr);
    }
  }

  function applyTabVisibility() {
    const active = state.activeTab || 'config';
    document.querySelectorAll('[data-notifier-tab]').forEach((el) => {
      if (el.getAttribute('data-notifier-tab') === active) {
        el.style.display = '';
      } else {
        el.style.display = 'none';
      }
    });
  }

  function setActiveTab(tab) {
    if (tab !== 'tests' && tab !== 'history') tab = 'config';
    state.activeTab = tab;
    applyTabVisibility();
    if (tab === 'history' && state.historyRows.length === 0) {
      loadHistory().catch((e) => showStatus(e.message, false));
    }
  }

  function historyFilters() {
    const limitRaw = parseInt(byId('notifierHistoryLimit')?.value || '50', 10);
    return {
      kind: (byId('notifierHistoryKind')?.value || '').trim(),
      channel: (byId('notifierHistoryChannel')?.value || '').trim(),
      status: (byId('notifierHistoryStatus')?.value || '').trim(),
      limit: Number.isFinite(limitRaw) ? Math.max(1, Math.min(200, limitRaw)) : 50,
    };
  }

  function buildHistoryURL(beforeCursor = '') {
    const f = historyFilters();
    const q = new URLSearchParams();
    q.set('limit', String(f.limit));
    if (beforeCursor) q.set('before', beforeCursor);
    if (f.kind) q.set('kind', f.kind);
    if (f.channel) q.set('channel', f.channel);
    if (f.status) q.set('status', f.status);
    return `/cfm-admin/api/v1/notifier/history?${q.toString()}`;
  }

  async function loadHistory(beforeCursor = '') {
    const payload = await request(buildHistoryURL(beforeCursor));
    state.historyRows = Array.isArray(payload.rows) ? payload.rows : [];
    state.historyHasMore = payload.has_more === true;
    state.historyNextCursor = payload.next_cursor || '';
    renderHistory();
  }

  function historyApplyFilters() {
    state.historyStack = [''];
    state.historyPage = 0;
    loadHistory('').catch((e) => showStatus(e.message, false));
  }

  function historyNextPage() {
    if (!state.historyHasMore || !state.historyNextCursor) return;
    state.historyStack.push(state.historyNextCursor);
    state.historyPage = state.historyStack.length - 1;
    loadHistory(state.historyNextCursor).catch((e) => showStatus(e.message, false));
  }

  function historyPrevPage() {
    if (state.historyPage <= 0) return;
    state.historyStack.pop();
    state.historyPage = state.historyStack.length - 1;
    const before = state.historyStack[state.historyPage] || '';
    loadHistory(before).catch((e) => showStatus(e.message, false));
  }

  function prettyJSON(v) {
    try {
      return JSON.stringify(v || {}, null, 2);
    } catch (_) {
      return '{}';
    }
  }

  function renderHistory() {
    const body = byId('notifierHistoryBody');
    if (!body) return;
    body.replaceChildren();
    for (const row of state.historyRows || []) {
      const tr = document.createElement('tr');
      const statusColor = row.status === 'error' ? '#f87171' : '#4ade80';
      tr.innerHTML = `
        <td>${row.time || '-'}</td>
        <td>${row.host || '-'}</td>
        <td>${row.kind || '-'}</td>
        <td>${row.srcip || '-'}</td>
        <td>${row.reason || '-'}</td>
        <td>${row.channel || '-'}</td>
        <td style="color:${statusColor};font-weight:600">${row.status || '-'}</td>
        <td></td>
      `;
      const detailsTD = tr.children[7];
      const details = document.createElement('details');
      const summary = document.createElement('summary');
      summary.textContent = 'View';
      const pre = document.createElement('pre');
      pre.style.maxWidth = '720px';
      pre.style.whiteSpace = 'pre-wrap';
      pre.textContent = prettyJSON(row.payload);
      details.append(summary, pre);
      detailsTD.appendChild(details);
      body.appendChild(tr);
    }
    const label = byId('notifierHistoryPageLabel');
    if (label) {
      const count = (state.historyRows || []).length;
      label.textContent = `Page ${state.historyPage + 1} • ${count} row${count === 1 ? '' : 's'}`;
    }
    const prevBtn = byId('notifierHistoryPrevBtn');
    if (prevBtn) prevBtn.disabled = state.historyPage <= 0;
    const nextBtn = byId('notifierHistoryNextBtn');
    if (nextBtn) nextBtn.disabled = !(state.historyHasMore && state.historyNextCursor);
  }

  function upsertChannel(existingId = '') {
    const source = state.draftConfig.channels.find((c) => c.id === existingId) || {};
    const id = prompt('Channel ID', source.id || '');
    if (!id) return;
    const type = prompt('Type (sendmail, smtp, slack, slack_webhook)', source.type || 'sendmail');
    if (!type) return;
    const enabled = confirm('Enable this channel?');
    const to = prompt('Recipients/targets CSV (optional)', Array.isArray(source.to) ? source.to.join(',') : '');
    const from = prompt('From (optional)', source.from || '');
    const webhook = prompt('Webhook URL (optional)', source.webhook_url || '');
    const host = prompt('SMTP host (optional)', source.host || '');
    const ch = {
      ...source,
      id: id.trim(),
      type: type.trim(),
      enabled,
      to: to ? to.split(',').map((v) => v.trim()).filter(Boolean) : [],
      from: from || '',
      webhook_url: webhook || '',
      host: host || '',
    };
    state.draftConfig.channels = state.draftConfig.channels.filter((c) => c.id !== existingId && c.id !== ch.id);
    state.draftConfig.channels.push(ch);
    state.draftConfig.channels.sort((a, b) => String(a.id).localeCompare(String(b.id)));
    renderChannels();
    syncDirtyState();
  }

  function editChannel(id) { upsertChannel(id); }
  function deleteChannel(id) {
    if (!confirm(`Delete channel ${id}?`)) return;
    state.draftConfig.channels = state.draftConfig.channels.filter((c) => c.id !== id);
    renderChannels();
    syncDirtyState();
  }

  function upsertDetector(existing = '') {
    const source = (state.draftConfig.detectors || {})[existing] || {};
    const detector = (prompt('Detector name', existing || '') || '').trim().toLowerCase();
    if (!detector) return;
    const notify = confirm('Send notifications for this detector?');
    const cooldown = (prompt('Cooldown (optional, e.g. 5m)', source.cooldown || '') || '').trim();
    const minSeverity = (prompt('Minimum severity (optional)', source.min_severity || '') || '').trim();
    const channels = (prompt('Channel IDs CSV (optional)', Array.isArray(source.channels) ? source.channels.join(',') : '') || '')
      .split(',').map((v) => v.trim()).filter(Boolean);

    if (!state.draftConfig.detectors || typeof state.draftConfig.detectors !== 'object') state.draftConfig.detectors = {};
    if (existing && existing !== detector) delete state.draftConfig.detectors[existing];
    state.draftConfig.detectors[detector] = { notify, cooldown, min_severity: minSeverity, channels };
    renderDetectors();
    syncDirtyState();
  }

  function editDetector(detector) { upsertDetector(detector); }
  function deleteDetector(detector) {
    if (!confirm(`Delete detector override ${detector}?`)) return;
    delete state.draftConfig.detectors[detector];
    renderDetectors();
    syncDirtyState();
  }

  function keyedChannels(config) {
    const out = {};
    for (const channel of config?.channels || []) {
      if (!channel || !channel.id) continue;
      out[String(channel.id)] = channel;
    }
    return out;
  }

  function keyedDetectors(config) {
    return config?.detectors && typeof config.detectors === 'object' ? config.detectors : {};
  }

  function summarizeFieldChanges(prefix, beforeObj, afterObj) {
    const keys = Array.from(new Set([...(Object.keys(beforeObj || {})), ...(Object.keys(afterObj || {}))])).sort();
    const changes = [];
    for (const key of keys) {
      if (JSON.stringify((beforeObj || {})[key]) === JSON.stringify((afterObj || {})[key])) continue;
      changes.push(`${prefix}.${key}`);
    }
    return changes;
  }

  function computeSaveSummary() {
    const currentChannels = keyedChannels(state.currentConfig);
    const draftChannels = keyedChannels(state.draftConfig);
    const channelAdded = [];
    const channelEdited = [];
    const channelRemoved = [];
    for (const id of Object.keys(draftChannels).sort()) {
      if (!currentChannels[id]) channelAdded.push(id);
      else if (JSON.stringify(currentChannels[id]) !== JSON.stringify(draftChannels[id])) channelEdited.push(id);
    }
    for (const id of Object.keys(currentChannels).sort()) {
      if (!draftChannels[id]) channelRemoved.push(id);
    }

    const currentDetectors = keyedDetectors(state.currentConfig);
    const draftDetectors = keyedDetectors(state.draftConfig);
    const detectorAdded = [];
    const detectorEdited = [];
    const detectorRemoved = [];
    for (const name of Object.keys(draftDetectors).sort()) {
      if (!currentDetectors[name]) detectorAdded.push(name);
      else if (JSON.stringify(currentDetectors[name]) !== JSON.stringify(draftDetectors[name])) detectorEdited.push(name);
    }
    for (const name of Object.keys(currentDetectors).sort()) {
      if (!draftDetectors[name]) detectorRemoved.push(name);
    }

    const globalsChanged = [
      ...summarizeFieldChanges('notifier', state.currentConfig.notifier || {}, state.draftConfig.notifier || {}),
      ...summarizeFieldChanges('dedupe', state.currentConfig.dedupe || {}, state.draftConfig.dedupe || {}),
    ];

    const destructive = [];
    for (const channelID of channelRemoved) {
      const usedBy = [];
      for (const [detectorName, override] of Object.entries(draftDetectors)) {
        if (Array.isArray(override?.channels) && override.channels.includes(channelID)) usedBy.push(detectorName);
      }
      if (usedBy.length) {
        destructive.push(`Channel "${channelID}" is removed but still referenced by detector overrides: ${usedBy.join(', ')}.`);
      }
    }

    return {
      channels: { added: channelAdded, edited: channelEdited, removed: channelRemoved },
      detectors: { added: detectorAdded, edited: detectorEdited, removed: detectorRemoved },
      globalsChanged,
      destructive,
    };
  }

  function renderSummaryList(id, parts) {
    const el = byId(id);
    if (!el) return;
    el.replaceChildren();
    const addLine = (txt) => {
      const li = document.createElement('li');
      li.textContent = txt;
      el.appendChild(li);
    };
    for (const part of parts) addLine(part);
    if (!parts.length) addLine('No changes.');
  }

  async function openSaveModal() {
    const summary = computeSaveSummary();
    renderSummaryList('notifierSaveChannelsSummary', [
      `Added: ${summary.channels.added.join(', ') || 'none'}`,
      `Edited: ${summary.channels.edited.join(', ') || 'none'}`,
      `Removed: ${summary.channels.removed.join(', ') || 'none'}`,
    ]);
    renderSummaryList('notifierSaveDetectorsSummary', [
      `Added: ${summary.detectors.added.join(', ') || 'none'}`,
      `Edited: ${summary.detectors.edited.join(', ') || 'none'}`,
      `Removed: ${summary.detectors.removed.join(', ') || 'none'}`,
    ]);
    renderSummaryList(
      'notifierSaveGlobalsSummary',
      summary.globalsChanged.length ? summary.globalsChanged.map((key) => `Edited: ${key}`) : []
    );

    const destructiveWrap = byId('notifierSaveDestructiveWrap');
    const destructiveCheckbox = byId('notifierSaveDestructiveConfirm');
    const confirmBtn = byId('notifierSaveConfirmBtn');
    if (destructiveWrap && destructiveCheckbox && confirmBtn) {
      destructiveCheckbox.checked = false;
      if (summary.destructive.length) {
        destructiveWrap.style.display = '';
        renderSummaryList('notifierSaveGlobalsSummary', [
          ...(summary.globalsChanged.length ? summary.globalsChanged.map((key) => `Edited: ${key}`) : ['No changes.']),
          `Destructive actions: ${summary.destructive.join(' ')}`,
        ]);
      } else {
        destructiveWrap.style.display = 'none';
      }
      confirmBtn.disabled = summary.destructive.length > 0;
      destructiveCheckbox.onchange = () => {
        confirmBtn.disabled = summary.destructive.length > 0 && !destructiveCheckbox.checked;
      };
    }

    const diffBox = byId('notifierSaveDiffPreview');
    if (diffBox) {
      diffBox.textContent = 'Loading diff preview…';
      try {
        const diffText = await previewConfigDiff();
        diffBox.textContent = diffText || '(No textual diff)';
      } catch (err) {
        diffBox.textContent = `Failed to load preview: ${err.message}`;
      }
    }
    const modal = byId('notifierSaveModal');
    if (modal) modal.style.display = 'flex';
  }

  function closeSaveModal() {
    const modal = byId('notifierSaveModal');
    if (modal) modal.style.display = 'none';
  }

  function closeBackupDiffModal() {
    const modal = byId('notifierBackupDiffModal');
    if (modal) modal.style.display = 'none';
  }

  function init() {
    window.addEventListener('beforeunload', (evt) => {
      if (!state.isDirty) return;
      evt.preventDefault();
      evt.returnValue = 'You have unsaved changes';
    });

    byId('notifierRefreshBtn')?.addEventListener('click', () => loadConfig().catch((e) => showStatus(e.message, false)));
    byId('notifierSaveBtn')?.addEventListener('click', () => openSaveModal().catch((e) => showStatus(e.message, false)));
    byId('notifierSaveCancelBtn')?.addEventListener('click', closeSaveModal);
    byId('notifierSaveConfirmBtn')?.addEventListener('click', () => {
      saveConfig()
        .then(closeSaveModal)
        .catch((e) => showStatus(e.message, false));
    });
    byId('notifierCancelBtn')?.addEventListener('click', cancelEdits);
    byId('notifierRevertAllBtn')?.addEventListener('click', cancelEdits);
    byId('notifierRevertChannelsBtn')?.addEventListener('click', () => revertSection('channels'));
    byId('notifierRevertDetectorsBtn')?.addEventListener('click', () => revertSection('detectors'));
    byId('notifierReloadBtn')?.addEventListener('click', () => reloadNotifier().catch((e) => showStatus(e.message, false)));
    byId('notifierAddChannelBtn')?.addEventListener('click', () => upsertChannel(''));
    byId('notifierAddDetectorBtn')?.addEventListener('click', () => upsertDetector(''));
    byId('notifierRunTestBtn')?.addEventListener('click', () => runNotifierTest().catch((e) => showStatus(e.message, false)));
    byId('notifierTabConfigBtn')?.addEventListener('click', () => setActiveTab('config'));
    byId('notifierTabTestsBtn')?.addEventListener('click', () => setActiveTab('tests'));
    byId('notifierTabHistoryBtn')?.addEventListener('click', () => setActiveTab('history'));
    byId('notifierHistoryApplyBtn')?.addEventListener('click', historyApplyFilters);
    byId('notifierHistoryNextBtn')?.addEventListener('click', historyNextPage);
    byId('notifierHistoryPrevBtn')?.addEventListener('click', historyPrevPage);
    byId('notifierBackupsRefreshBtn')?.addEventListener('click', () => loadBackups().catch((e) => showStatus(e.message, false)));
    byId('notifierBackupDiffCloseBtn')?.addEventListener('click', closeBackupDiffModal);
    byId('notifierBackupRestoreBtn')?.addEventListener('click', () => {
      if (!state.activeBackupID) return;
      restoreBackup(state.activeBackupID).catch((e) => showStatus(e.message, false));
    });
    loadConfig().catch((e) => showStatus(e.message || 'Failed to load notifier config.', false));
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
