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
    historyDetectorTelemetry: { sections: [], kinds: [] },
    detectorModalEditing: '',
    detectorModalReturnDraft: null,
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
    await refreshDetectorSuggestionTelemetry();
    await loadBackups();
    showStatus(`Loaded config from ${state.path || 'default path'}.`);
  }

  async function refreshDetectorSuggestionTelemetry() {
    try {
      const payload = await request('/cfm-admin/api/v1/notifier/history?limit=200&status=all');
      const rows = Array.isArray(payload.rows) ? payload.rows : [];
      const sectionSet = new Set();
      const kindSet = new Set();
      for (const row of rows) {
        const section = String(row?.payload?.section || '').trim();
        const kind = String(row?.kind || row?.payload?.kind || '').trim();
        if (section) sectionSet.add(section);
        if (kind) kindSet.add(kind);
      }
      state.historyDetectorTelemetry = {
        sections: Array.from(sectionSet).sort((a, b) => a.localeCompare(b)),
        kinds: Array.from(kindSet).sort((a, b) => a.localeCompare(b)),
      };
    } catch (_) {
      state.historyDetectorTelemetry = { sections: [], kinds: [] };
    }
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
    const raw = (byId('notifierTestPayload')?.value || '').trim();
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Sample payload must be a JSON object.');
    }
    return parsed;
  }

  function buildTestPayloadInput() {
    const sample = parseSampleInput();
    const subject = (byId('notifierTestSubject')?.value || '').trim();
    const body = (byId('notifierTestBody')?.value || '').trim();
    const severity = (byId('notifierTestSeverity')?.value || '').trim();
    const srcIP = (byId('notifierTestSrcIP')?.value || '').trim();
    if (subject) sample.subject = subject;
    if (body) sample.body = body;
    if (severity) sample.severity = severity;
    if (srcIP) sample.srcip = srcIP;
    return sample;
  }

  async function runNotifierTest(channels = []) {
    const channelInput = (byId('notifierTestChannel')?.value || '').trim();
    const targetChannels = [...channels];
    if (channelInput) targetChannels.push(channelInput);
    const uniqueChannels = Array.from(new Set(targetChannels.map((c) => String(c || '').trim()).filter(Boolean)));
    if (!uniqueChannels.length) throw new Error('Channel is required.');
    const payloadInput = buildTestPayloadInput();
    const payload = await request('/cfm-admin/api/v1/notifier/test', {
      method: 'POST',
      body: JSON.stringify({ channels: uniqueChannels, payload: payloadInput }),
    });
    state.testResults = Array.isArray(payload.results) ? payload.results : [];
    renderTests();
    showStatus(`Completed notifier test for ${uniqueChannels.join(', ')}.`, true);
  }

  async function runEnabledChannelTests() {
    const enabled = (state.draftConfig.channels || [])
      .filter((ch) => ch?.enabled !== false)
      .map((ch) => String(ch?.id || '').trim())
      .filter(Boolean);
    if (!enabled.length) throw new Error('No enabled channels found.');
    await runNotifierTest(enabled);
  }

  function runSingleChannelTest(channelID) {
    setActiveTab('tests');
    runNotifierTest([String(channelID || '').trim()]).catch((e) => showStatus(e.message, false));
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
      const test = document.createElement('button');
      test.className = 'btn-quiet btn-sm';
      test.textContent = 'Test this channel';
      test.onclick = () => runSingleChannelTest(channel.id);
      actions.append(edit, test, del);
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
        <td style="color:${statusColor};font-weight:600">${statusText}</td>
        <td>${result.error || '-'}</td>
        <td>${result.latency || result.delivery_duration || '-'}</td>
        <td>${result.attempted_at || '-'}</td>
        <td><code>${result.correlation_id || '-'}</code></td>
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

  function findDetectorChannelImpacts(config, channelIDs = []) {
    const targets = new Set((channelIDs || []).map((id) => String(id || '').trim()).filter(Boolean));
    const impacts = [];
    for (const [detectorName, override] of Object.entries(keyedDetectors(config))) {
      const channels = Array.isArray(override?.channels) ? override.channels : [];
      channels.forEach((channelID, idx) => {
        const normalized = String(channelID || '').trim();
        if (!normalized) return;
        if (targets.size > 0 && !targets.has(normalized)) return;
        impacts.push({
          detector: detectorName,
          channel: normalized,
          kind: 'detector_override',
          section: `channels[${idx}]`,
        });
      });
    }
    return impacts;
  }

  function applyChannelRemap(fromID, toID) {
    for (const detectorName of Object.keys(keyedDetectors(state.draftConfig))) {
      const override = state.draftConfig.detectors[detectorName];
      if (!Array.isArray(override?.channels)) continue;
      const next = [];
      for (const channelID of override.channels) {
        const normalized = String(channelID || '').trim();
        if (!normalized) continue;
        next.push(normalized === fromID ? toID : normalized);
      }
      override.channels = Array.from(new Set(next));
    }
  }

  function removeChannelReferences(channelID) {
    for (const detectorName of Object.keys(keyedDetectors(state.draftConfig))) {
      const override = state.draftConfig.detectors[detectorName];
      if (!Array.isArray(override?.channels)) continue;
      override.channels = override.channels.map((id) => String(id || '').trim()).filter((id) => id && id !== channelID);
    }
  }

  function editChannel(id) { upsertChannel(id); }
  function deleteChannel(id) {
    const channelID = String(id || '').trim();
    if (!channelID) return;
    if (!confirm(`Delete channel ${channelID}?`)) return;

    const impacts = findDetectorChannelImpacts(state.draftConfig, [channelID]);
    if (impacts.length) {
      const affectedDetectors = impacts.map((impact) => impact.detector).join(', ');
      const remap = confirm(
        `Channel ${channelID} is still referenced by detector overrides: ${affectedDetectors}.\n\n`
        + 'Click OK to remap all detector references to another channel. Click Cancel to choose removal instead.'
      );
      if (remap) {
        const candidates = state.draftConfig.channels
          .map((ch) => String(ch?.id || '').trim())
          .filter((candidate) => candidate && candidate !== channelID);
        if (!candidates.length) {
          showStatus(`Cannot remap ${channelID}: no other channels are available.`, false);
          return;
        }
        const nextID = (
          prompt(`Remap ${channelID} references to which channel?\nAvailable: ${candidates.join(', ')}`, candidates[0]) || ''
        ).trim();
        if (!nextID) return;
        if (!candidates.includes(nextID)) {
          showStatus(`Invalid remap target: ${nextID}.`, false);
          return;
        }
        applyChannelRemap(channelID, nextID);
        showStatus(`Remapped detector references from ${channelID} to ${nextID}.`);
      } else {
        const removeRefs = confirm(`Remove ${channelID} from each affected detector override and continue deleting the channel?`);
        if (!removeRefs) return;
        removeChannelReferences(channelID);
        showStatus(`Removed detector references to ${channelID}.`);
      }
    }

    state.draftConfig.channels = state.draftConfig.channels.filter((c) => String(c?.id || '').trim() !== channelID);
    render();
    syncDirtyState();
  }

  function validateDetectorKey(value) {
    const key = String(value || '').trim();
    if (!key) return { ok: false, message: 'Detector key is required.' };
    if (/\s/.test(key)) return { ok: false, message: 'Detector key cannot include whitespace.' };
    if (/[\r\n\[\]"]/.test(key)) {
      return { ok: false, message: 'Detector key cannot include line breaks, quotes, or brackets.' };
    }
    if (key.length > 128) return { ok: false, message: 'Detector key is too long (max 128 chars).' };
    return { ok: true, message: '' };
  }

  function detectorSuggestionKeys() {
    const out = new Set(Object.keys(state.draftConfig.detectors || {}));
    for (const section of state.historyDetectorTelemetry.sections || []) out.add(section);
    for (const kind of state.historyDetectorTelemetry.kinds || []) out.add(kind);
    return Array.from(out).sort((a, b) => a.localeCompare(b));
  }

  function renderDetectorSuggestionList() {
    const list = byId('notifierDetectorSuggestions');
    if (!list) return;
    list.replaceChildren();
    for (const key of detectorSuggestionKeys()) {
      const opt = document.createElement('option');
      opt.value = key;
      list.appendChild(opt);
    }
  }

  function closeDetectorModal() {
    const modal = byId('notifierDetectorModal');
    if (modal) modal.style.display = 'none';
  }

  function openDetectorModal(existing = '') {
    const source = (state.draftConfig.detectors || {})[existing] || {};
    state.detectorModalEditing = existing;
    renderDetectorSuggestionList();

    const nameInput = byId('notifierDetectorNameInput');
    const notifyInput = byId('notifierDetectorNotifyInput');
    const cooldownInput = byId('notifierDetectorCooldownInput');
    const minSeverityInput = byId('notifierDetectorMinSeverityInput');
    const errLine = byId('notifierDetectorNameError');
    const selectedChannels = Array.isArray(source.channels) ? source.channels : [];
    if (nameInput) nameInput.value = existing || '';
    if (notifyInput) notifyInput.checked = source.notify !== false;
    if (cooldownInput) cooldownInput.value = source.cooldown || '';
    if (minSeverityInput) minSeverityInput.value = source.min_severity || '';
    renderDetectorChannelOptions(selectedChannels);
    if (errLine) errLine.textContent = '';
    const modal = byId('notifierDetectorModal');
    if (modal) modal.style.display = 'flex';
    nameInput?.focus();
  }

  function saveDetectorFromModal() {
    const existing = state.detectorModalEditing || '';
    const detector = (byId('notifierDetectorNameInput')?.value || '').trim();
    const validation = validateDetectorKey(detector);
    const errLine = byId('notifierDetectorNameError');
    if (!validation.ok) {
      if (errLine) errLine.textContent = validation.message;
      return;
    }
    const notify = byId('notifierDetectorNotifyInput')?.checked !== false;
    const cooldown = (byId('notifierDetectorCooldownInput')?.value || '').trim();
    const minSeverity = (byId('notifierDetectorMinSeverityInput')?.value || '').trim();
    const channels = Array.from(byId('notifierDetectorChannelsInput')?.selectedOptions || [])
      .map((opt) => String(opt.value || '').trim())
      .filter(Boolean);
    const channelList = channelCatalog();
    const knownChannels = new Set(channelList.map((ch) => ch.id));
    const unknown = channels.filter((name) => !knownChannels.has(name));
    if (unknown.length) {
      if (errLine) errLine.textContent = `Unknown channel(s): ${unknown.join(', ')}`;
      return;
    }
    const disabledPicked = channelList.filter((channel) => channels.includes(channel.id) && !channel.enabled).map((channel) => channel.id);
    if (disabledPicked.length) {
      showStatus(`Warning: selected disabled channel(s): ${disabledPicked.join(', ')}.`, false);
    } else if (!channels.length) {
      showStatus('No channels selected for this override; notifier falls back to global channel order.', true);
    }

    if (!state.draftConfig.detectors || typeof state.draftConfig.detectors !== 'object') state.draftConfig.detectors = {};
    if (existing && existing !== detector) delete state.draftConfig.detectors[existing];
    state.draftConfig.detectors[detector] = { notify, cooldown, min_severity: minSeverity, channels };
    closeDetectorModal();
    renderDetectors();
    syncDirtyState();
  }

  function upsertDetector(existing = '') { openDetectorModal(existing); }
  function editDetector(detector) { openDetectorModal(detector); }
  function createChannelFromDetectorModal() {
    state.detectorModalReturnDraft = {
      existing: state.detectorModalEditing || '',
      detector: (byId('notifierDetectorNameInput')?.value || '').trim(),
      notify: byId('notifierDetectorNotifyInput')?.checked !== false,
      cooldown: (byId('notifierDetectorCooldownInput')?.value || '').trim(),
      minSeverity: (byId('notifierDetectorMinSeverityInput')?.value || '').trim(),
      channels: Array.from(byId('notifierDetectorChannelsInput')?.selectedOptions || []).map((opt) => String(opt.value || '').trim()),
    };
    closeDetectorModal();
    setActiveTab('config');
    byId('notifierChannelsSection')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    upsertChannel('');

    const draft = state.detectorModalReturnDraft;
    state.detectorModalReturnDraft = null;
    if (!draft) return;
    openDetectorModal(draft.existing || '');
    if (byId('notifierDetectorNameInput')) byId('notifierDetectorNameInput').value = draft.detector || draft.existing || '';
    if (byId('notifierDetectorNotifyInput')) byId('notifierDetectorNotifyInput').checked = draft.notify !== false;
    if (byId('notifierDetectorCooldownInput')) byId('notifierDetectorCooldownInput').value = draft.cooldown || '';
    if (byId('notifierDetectorMinSeverityInput')) byId('notifierDetectorMinSeverityInput').value = draft.minSeverity || '';
    renderDetectorChannelOptions(draft.channels || []);
  }
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

  function channelCatalog() {
    return Object.values(keyedChannels(state.draftConfig))
      .map((ch) => ({
        id: String(ch?.id || '').trim(),
        enabled: ch?.enabled !== false,
      }))
      .filter((ch) => ch.id)
      .sort((a, b) => a.id.localeCompare(b.id));
  }

  function renderDetectorChannelOptions(selected = []) {
    const select = byId('notifierDetectorChannelsInput');
    if (!select) return;
    const selectedSet = new Set((selected || []).map((id) => String(id || '').trim()).filter(Boolean));
    const known = new Set();
    select.replaceChildren();
    for (const channel of channelCatalog()) {
      known.add(channel.id);
      const opt = document.createElement('option');
      opt.value = channel.id;
      opt.textContent = channel.enabled ? channel.id : `${channel.id} (disabled)`;
      if (selectedSet.has(channel.id)) opt.selected = true;
      select.appendChild(opt);
    }
    for (const unknownID of selectedSet) {
      if (known.has(unknownID)) continue;
      const opt = document.createElement('option');
      opt.value = unknownID;
      opt.textContent = `${unknownID} (unknown)`;
      opt.selected = true;
      select.appendChild(opt);
    }
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

    const blockers = [];
    const destructive = [];
    for (const channelID of channelRemoved) {
      const impacts = findDetectorChannelImpacts(state.draftConfig, [channelID]);
      if (!impacts.length) continue;
      const usedBy = Array.from(new Set(impacts.map((impact) => impact.detector))).sort();
      destructive.push(`Channel "${channelID}" is removed but still referenced by detector overrides: ${usedBy.join(', ')}.`);
      blockers.push(...impacts);
    }

    return {
      channels: { added: channelAdded, edited: channelEdited, removed: channelRemoved },
      detectors: { added: detectorAdded, edited: detectorEdited, removed: detectorRemoved },
      globalsChanged,
      destructive,
      blockers,
    };
  }

  function validateDetectorOverrideChannels() {
    const known = keyedChannels(state.draftConfig);
    const unknown = [];
    const disabled = [];
    const empty = [];
    for (const [detectorName, override] of Object.entries(keyedDetectors(state.draftConfig))) {
      const channels = Array.isArray(override?.channels) ? override.channels : [];
      if (!channels.length) {
        empty.push(detectorName);
        continue;
      }
      for (const channelID of channels) {
        const id = String(channelID || '').trim();
        if (!id) continue;
        const channel = known[id];
        if (!channel) {
          unknown.push({ detector: detectorName, channel: id });
          continue;
        }
        if (channel.enabled === false) disabled.push({ detector: detectorName, channel: id });
      }
    }
    return { unknown, disabled, empty };
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
    const impactWrap = byId('notifierSaveImpactWrap');
    if (summary.blockers?.length) {
      if (impactWrap) impactWrap.style.display = '';
      renderSummaryList('notifierSaveImpactList', summary.blockers.map((impact) => (
        `Detector ${impact.detector} • kind=${impact.kind} • section=${impact.section} • channel=${impact.channel}`
      )));
    } else if (impactWrap) {
      impactWrap.style.display = 'none';
    }

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
      confirmBtn.disabled = summary.destructive.length > 0 || summary.blockers?.length > 0;
      destructiveCheckbox.onchange = () => {
        const destructiveBlocked = summary.destructive.length > 0 && !destructiveCheckbox.checked;
        const referenceBlocked = summary.blockers?.length > 0;
        confirmBtn.disabled = destructiveBlocked || referenceBlocked;
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
      const summary = computeSaveSummary();
      if (summary.blockers?.length) {
        showStatus('Cannot save: unresolved detector references to channels scheduled for deletion. Use guided delete options first.', false);
        return;
      }
      const channelValidation = validateDetectorOverrideChannels();
      if (channelValidation.unknown.length) {
        const lines = channelValidation.unknown.map((entry) => `${entry.detector} -> ${entry.channel}`).join(', ');
        showStatus(`Cannot save: detector overrides reference unknown channels (${lines}).`, false);
        return;
      }
      if (channelValidation.disabled.length) {
        const lines = channelValidation.disabled.map((entry) => `${entry.detector} -> ${entry.channel}`).join(', ');
        showStatus(`Warning: saving overrides with disabled channels (${lines}).`, false);
      } else if (channelValidation.empty.length) {
        showStatus(
          `Info: detector overrides with no channels (${channelValidation.empty.join(', ')}) will follow global channel order.`,
          true
        );
      }
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
    byId('notifierRunTestAllBtn')?.addEventListener('click', () => runEnabledChannelTests().catch((e) => showStatus(e.message, false)));
    byId('notifierTabConfigBtn')?.addEventListener('click', () => setActiveTab('config'));
    byId('notifierTabTestsBtn')?.addEventListener('click', () => setActiveTab('tests'));
    byId('notifierTabHistoryBtn')?.addEventListener('click', () => setActiveTab('history'));
    byId('notifierHistoryApplyBtn')?.addEventListener('click', historyApplyFilters);
    byId('notifierHistoryNextBtn')?.addEventListener('click', historyNextPage);
    byId('notifierHistoryPrevBtn')?.addEventListener('click', historyPrevPage);
    byId('notifierBackupsRefreshBtn')?.addEventListener('click', () => loadBackups().catch((e) => showStatus(e.message, false)));
    byId('notifierBackupDiffCloseBtn')?.addEventListener('click', closeBackupDiffModal);
    byId('notifierDetectorCancelBtn')?.addEventListener('click', closeDetectorModal);
    byId('notifierDetectorSaveBtn')?.addEventListener('click', saveDetectorFromModal);
    byId('notifierDetectorCreateChannelBtn')?.addEventListener('click', createChannelFromDetectorModal);
    byId('notifierDetectorNameInput')?.addEventListener('input', () => {
      const key = byId('notifierDetectorNameInput')?.value || '';
      const validation = validateDetectorKey(key);
      const errLine = byId('notifierDetectorNameError');
      if (!errLine) return;
      errLine.textContent = validation.ok ? '' : validation.message;
    });
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
