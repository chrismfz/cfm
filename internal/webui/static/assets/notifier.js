(() => {
  function clone(v) {
    try {
      if (typeof structuredClone === 'function') return structuredClone(v);
    } catch (_) {}
    return JSON.parse(JSON.stringify(v || {}));
  }

  function normalizeConfig(config) {
    const next = config && typeof config === 'object' ? config : {};
    next.channels = Array.isArray(next.channels) ? next.channels : [];
    next.detectors = next.detectors && typeof next.detectors === 'object' ? next.detectors : {};
    return next;
  }

  function request(path, opts = {}) {
    return fetch(path, {
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      ...opts,
    }).then(async (res) => {
      const payload = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(payload.error || `Request failed (${res.status})`);
      return payload;
    });
  }

  let state = {
    currentConfig: { channels: [], detectors: {} },
    draftConfig: { channels: [], detectors: {} },
    path: '',
    isDirty: false,
    pendingDelete: null,
    pendingTabSwitch: null,
    saveSummary: null,
  };

  const byId = (id) => document.getElementById(id);
  const keyedDetectors = (cfg) => (cfg?.detectors && typeof cfg.detectors === 'object' ? cfg.detectors : {});

  function keyedChannels(cfg) {
    const out = {};
    for (const ch of cfg?.channels || []) {
      const id = String(ch?.id || '').trim();
      if (id) out[id] = ch;
    }
    return out;
  }

  function configsEqual(a, b) {
    try { return JSON.stringify(a || {}) === JSON.stringify(b || {}); } catch (_) { return false; }
  }

  function showStatus(msg, ok = true) {
    const el = byId('notifierStatus');
    if (!el) return;
    el.textContent = msg;
    el.style.color = ok ? '#4ade80' : '#f87171';
  }

  function syncDirty() {
    state.isDirty = !configsEqual(state.currentConfig, state.draftConfig);
    const badge = byId('notifierDirtyBadge');
    if (badge) {
      badge.textContent = state.isDirty ? 'Unsaved changes' : 'Saved';
      badge.className = state.isDirty ? 'pill warn' : 'pill';
    }
  }

  function rowInput(value, cls = 'input input-wide', placeholder = '') {
    const input = document.createElement('input');
    input.className = cls;
    input.value = value == null ? '' : String(value);
    input.placeholder = placeholder;
    return input;
  }

  function normalizeCSV(raw) {
    return String(raw || '').split(',').map((v) => v.trim()).filter(Boolean);
  }

  function addChannel() {
    const base = 'channel';
    const known = new Set((state.draftConfig.channels || []).map((c) => String(c?.id || '').trim()).filter(Boolean));
    let n = known.size + 1;
    while (known.has(`${base}-${n}`)) n += 1;
    state.draftConfig.channels.push({ id: `${base}-${n}`, type: 'sendmail', enabled: true, to: [] });
    renderChannels();
    syncDirty();
  }

  function duplicateChannel(id) {
    const src = (state.draftConfig.channels || []).find((c) => String(c?.id || '').trim() === id);
    if (!src) return;
    let copyId = `${id}-copy`;
    const known = new Set((state.draftConfig.channels || []).map((c) => String(c?.id || '').trim()));
    let i = 2;
    while (known.has(copyId)) {
      copyId = `${id}-copy-${i}`;
      i += 1;
    }
    state.draftConfig.channels.push({ ...clone(src), id: copyId });
    renderChannels();
    syncDirty();
  }

  function addDetector() {
    const keys = new Set(Object.keys(keyedDetectors(state.draftConfig)));
    let idx = keys.size + 1;
    let key = `detector/${idx}`;
    while (keys.has(key)) {
      idx += 1;
      key = `detector/${idx}`;
    }
    state.draftConfig.detectors[key] = { notify: true, cooldown: '', min_severity: '', channels: [] };
    renderDetectors();
    syncDirty();
  }

  function duplicateDetector(key) {
    const src = keyedDetectors(state.draftConfig)[key];
    if (!src) return;
    const keys = new Set(Object.keys(keyedDetectors(state.draftConfig)));
    let next = `${key}-copy`;
    let i = 2;
    while (keys.has(next)) {
      next = `${key}-copy-${i}`;
      i += 1;
    }
    state.draftConfig.detectors[next] = clone(src);
    renderDetectors();
    syncDirty();
  }

  function openDeleteConfirm(target) {
    state.pendingDelete = target;
    const msg = byId('notifierDeleteConfirmText');
    if (msg) msg.textContent = `Delete ${target.kind} "${target.id}"?`;
    const modal = byId('notifierDeleteConfirmModal');
    if (modal) modal.style.display = 'flex';
  }

  function closeDeleteConfirm() {
    state.pendingDelete = null;
    const modal = byId('notifierDeleteConfirmModal');
    if (modal) modal.style.display = 'none';
  }

  function doDelete() {
    const pending = state.pendingDelete;
    if (!pending) return;
    if (pending.kind === 'channel') {
      state.draftConfig.channels = state.draftConfig.channels.filter((c) => String(c?.id || '').trim() !== pending.id);
      for (const [name, ov] of Object.entries(keyedDetectors(state.draftConfig))) {
        if (!Array.isArray(ov?.channels)) continue;
        keyedDetectors(state.draftConfig)[name].channels = ov.channels.filter((id) => String(id || '').trim() !== pending.id);
      }
      renderChannels();
      renderDetectors();
    } else {
      delete state.draftConfig.detectors[pending.id];
      renderDetectors();
    }
    syncDirty();
    closeDeleteConfirm();
  }

  function renderChannels() {
    const body = byId('notifierChannelsBody');
    if (!body) return;
    body.replaceChildren();
    for (const channel of state.draftConfig.channels || []) {
      const tr = document.createElement('tr');
      const id = String(channel?.id || '').trim();
      const tdId = document.createElement('td');
      const idInput = rowInput(id, 'input input-wide', 'channel id');
      idInput.oninput = () => {
        channel.id = String(idInput.value || '').trim();
        renderDetectors();
        syncDirty();
      };
      tdId.appendChild(idInput);

      const tdType = document.createElement('td');
      const typeInput = rowInput(channel.type || '', 'input input-wide', 'sendmail|smtp|slack');
      typeInput.oninput = () => { channel.type = String(typeInput.value || '').trim(); syncDirty(); };
      tdType.appendChild(typeInput);

      const tdEnabled = document.createElement('td');
      const enabledBtn = document.createElement('button');
      enabledBtn.className = 'btn-quiet btn-sm';
      enabledBtn.textContent = channel.enabled === false ? 'Disabled' : 'Enabled';
      enabledBtn.onclick = () => {
        channel.enabled = channel.enabled === false;
        renderChannels();
        syncDirty();
      };
      tdEnabled.appendChild(enabledBtn);

      const tdTargets = document.createElement('td');
      const targetsInput = rowInput(Array.isArray(channel.to) ? channel.to.join(', ') : '', 'input input-wide', 'to1,to2');
      targetsInput.oninput = () => { channel.to = normalizeCSV(targetsInput.value); syncDirty(); };
      tdTargets.appendChild(targetsInput);

      const tdActions = document.createElement('td');
      tdActions.className = 'actions-cell';
      const dupBtn = document.createElement('button');
      dupBtn.className = 'btn-quiet btn-sm';
      dupBtn.textContent = 'Duplicate';
      dupBtn.onclick = () => duplicateChannel(id || channel.id);
      const toggleBtn = document.createElement('button');
      toggleBtn.className = 'btn-quiet btn-sm';
      toggleBtn.textContent = channel.enabled === false ? 'Enable' : 'Disable';
      toggleBtn.onclick = () => {
        channel.enabled = channel.enabled === false;
        renderChannels();
        syncDirty();
      };
      const delBtn = document.createElement('button');
      delBtn.className = 'btn-danger btn-sm';
      delBtn.textContent = 'Delete';
      delBtn.onclick = () => openDeleteConfirm({ kind: 'channel', id: id || channel.id });
      tdActions.append(dupBtn, toggleBtn, delBtn);

      tr.append(tdId, tdType, tdEnabled, tdTargets, tdActions);
      body.appendChild(tr);
    }
  }

  function renderDetectors() {
    const body = byId('notifierDetectorsBody');
    if (!body) return;
    body.replaceChildren();
    for (const detector of Object.keys(keyedDetectors(state.draftConfig)).sort()) {
      const ov = keyedDetectors(state.draftConfig)[detector] || {};
      const tr = document.createElement('tr');

      const tdKey = document.createElement('td');
      const keyInput = rowInput(detector, 'input input-wide', 'detector key');
      keyInput.onchange = () => {
        const next = String(keyInput.value || '').trim();
        if (!next || next === detector) return;
        const exists = keyedDetectors(state.draftConfig)[next];
        if (exists) {
          showStatus(`Detector key ${next} already exists.`, false);
          keyInput.value = detector;
          return;
        }
        keyedDetectors(state.draftConfig)[next] = keyedDetectors(state.draftConfig)[detector];
        delete keyedDetectors(state.draftConfig)[detector];
        renderDetectors();
        syncDirty();
      };
      tdKey.appendChild(keyInput);

      const tdNotify = document.createElement('td');
      const notifyBtn = document.createElement('button');
      notifyBtn.className = 'btn-quiet btn-sm';
      notifyBtn.textContent = ov.notify === false ? 'Off' : 'On';
      notifyBtn.onclick = () => {
        ov.notify = ov.notify === false;
        renderDetectors();
        syncDirty();
      };
      tdNotify.appendChild(notifyBtn);

      const tdCooldown = document.createElement('td');
      const cooldownInput = rowInput(ov.cooldown || '', 'input', '5m');
      cooldownInput.oninput = () => { ov.cooldown = String(cooldownInput.value || '').trim(); syncDirty(); };
      tdCooldown.appendChild(cooldownInput);

      const tdSeverity = document.createElement('td');
      const sevInput = rowInput(ov.min_severity || '', 'input', 'warn');
      sevInput.oninput = () => { ov.min_severity = String(sevInput.value || '').trim(); syncDirty(); };
      tdSeverity.appendChild(sevInput);

      const tdChannels = document.createElement('td');
      const channelsInput = rowInput(Array.isArray(ov.channels) ? ov.channels.join(', ') : '', 'input input-wide', 'channel ids csv');
      channelsInput.oninput = () => { ov.channels = normalizeCSV(channelsInput.value); syncDirty(); };
      tdChannels.appendChild(channelsInput);

      const tdActions = document.createElement('td');
      tdActions.className = 'actions-cell';
      const dupBtn = document.createElement('button');
      dupBtn.className = 'btn-quiet btn-sm';
      dupBtn.textContent = 'Duplicate';
      dupBtn.onclick = () => duplicateDetector(detector);
      const toggleBtn = document.createElement('button');
      toggleBtn.className = 'btn-quiet btn-sm';
      toggleBtn.textContent = ov.notify === false ? 'Enable' : 'Disable';
      toggleBtn.onclick = () => {
        ov.notify = ov.notify === false;
        renderDetectors();
        syncDirty();
      };
      const delBtn = document.createElement('button');
      delBtn.className = 'btn-danger btn-sm';
      delBtn.textContent = 'Delete';
      delBtn.onclick = () => openDeleteConfirm({ kind: 'detector override', id: detector });
      tdActions.append(dupBtn, toggleBtn, delBtn);

      tr.append(tdKey, tdNotify, tdCooldown, tdSeverity, tdChannels, tdActions);
      body.appendChild(tr);
    }
  }

  function validateDraft() {
    const errors = [];
    const channelMap = keyedChannels(state.draftConfig);
    for (const ch of state.draftConfig.channels || []) {
      const id = String(ch?.id || '').trim();
      const type = String(ch?.type || '').trim();
      if (!id) errors.push('Channel id is required.');
      if (!type) errors.push(`Channel ${id || '(new)'} type is required.`);
    }
    for (const [detector, ov] of Object.entries(keyedDetectors(state.draftConfig))) {
      if (!String(detector || '').trim()) errors.push('Detector key cannot be empty.');
      for (const channel of Array.isArray(ov?.channels) ? ov.channels : []) {
        const id = String(channel || '').trim();
        if (!id) continue;
        if (!channelMap[id]) errors.push(`Detector ${detector} references unknown channel ${id}.`);
      }
    }
    return errors;
  }

  function openValidationErrors(errors) {
    const list = byId('notifierValidationErrorsList');
    if (list) {
      list.replaceChildren();
      for (const err of errors) {
        const li = document.createElement('li');
        li.textContent = err;
        list.appendChild(li);
      }
    }
    const modal = byId('notifierValidationErrorsModal');
    if (modal) modal.style.display = 'flex';
  }

  function closeValidationErrors() {
    const modal = byId('notifierValidationErrorsModal');
    if (modal) modal.style.display = 'none';
  }

  function computeSummary() {
    const currentChannels = keyedChannels(state.currentConfig);
    const draftChannels = keyedChannels(state.draftConfig);
    const currentDetectors = keyedDetectors(state.currentConfig);
    const draftDetectors = keyedDetectors(state.draftConfig);

    const channelAdded = Object.keys(draftChannels).filter((k) => !currentChannels[k]).sort();
    const channelRemoved = Object.keys(currentChannels).filter((k) => !draftChannels[k]).sort();
    const channelEdited = Object.keys(draftChannels).filter((k) => currentChannels[k] && JSON.stringify(currentChannels[k]) !== JSON.stringify(draftChannels[k])).sort();

    const detectorAdded = Object.keys(draftDetectors).filter((k) => !currentDetectors[k]).sort();
    const detectorRemoved = Object.keys(currentDetectors).filter((k) => !draftDetectors[k]).sort();
    const detectorEdited = Object.keys(draftDetectors).filter((k) => currentDetectors[k] && JSON.stringify(currentDetectors[k]) !== JSON.stringify(draftDetectors[k])).sort();

    return { channelAdded, channelRemoved, channelEdited, detectorAdded, detectorRemoved, detectorEdited };
  }

  async function previewConfigDiff() {
    const payload = await request('/cfm-admin/api/v1/notifier/preview', {
      method: 'POST',
      body: JSON.stringify({ config: state.draftConfig }),
    });
    return payload.diff || '(No textual diff)';
  }

  async function openSaveModal() {
    const errors = validateDraft();
    if (errors.length) {
      openValidationErrors(errors);
      return;
    }
    state.saveSummary = computeSummary();
    byId('notifierSaveChannelsSummary').textContent = `Added: ${state.saveSummary.channelAdded.join(', ') || 'none'}\nEdited: ${state.saveSummary.channelEdited.join(', ') || 'none'}\nRemoved: ${state.saveSummary.channelRemoved.join(', ') || 'none'}`;
    byId('notifierSaveDetectorsSummary').textContent = `Added: ${state.saveSummary.detectorAdded.join(', ') || 'none'}\nEdited: ${state.saveSummary.detectorEdited.join(', ') || 'none'}\nRemoved: ${state.saveSummary.detectorRemoved.join(', ') || 'none'}`;
    const diffEl = byId('notifierSaveDiffPreview');
    if (diffEl) {
      diffEl.textContent = 'Loading diff...';
      try { diffEl.textContent = await previewConfigDiff(); } catch (err) { diffEl.textContent = err.message; }
    }
    const modal = byId('notifierSaveModal');
    if (modal) modal.style.display = 'flex';
  }

  function closeSaveModal() {
    const modal = byId('notifierSaveModal');
    if (modal) modal.style.display = 'none';
  }

  async function saveDraft() {
    await request('/cfm-admin/api/v1/notifier/config', {
      method: 'PUT',
      body: JSON.stringify({ config: state.draftConfig }),
    });
    state.currentConfig = normalizeConfig(clone(state.draftConfig));
    syncDirty();
    closeSaveModal();
    showStatus('Draft saved.');
  }

  function openUnsavedLeave(nextAction) {
    state.pendingTabSwitch = nextAction;
    const modal = byId('notifierUnsavedLeaveModal');
    if (modal) modal.style.display = 'flex';
  }

  function closeUnsavedLeave() {
    state.pendingTabSwitch = null;
    const modal = byId('notifierUnsavedLeaveModal');
    if (modal) modal.style.display = 'none';
  }

  function runPendingLeave() {
    const action = state.pendingTabSwitch;
    closeUnsavedLeave();
    if (typeof action === 'function') action();
  }

  async function loadConfig() {
    const payload = await request('/cfm-admin/api/v1/notifier/config');
    const loaded = normalizeConfig(clone(payload.config || {}));
    state.currentConfig = loaded;
    state.draftConfig = clone(loaded);
    state.path = payload.path || '';
    renderChannels();
    renderDetectors();
    syncDirty();
    showStatus(`Loaded config from ${state.path || 'default path'}.`);
  }

  function discardDraft() {
    state.draftConfig = normalizeConfig(clone(state.currentConfig));
    renderChannels();
    renderDetectors();
    syncDirty();
    showStatus('Draft discarded.');
  }

  function reloadFromFile() {
    loadConfig().catch((err) => showStatus(err.message, false));
  }

  async function reloadNotifier() {
    await request('/cfm-admin/api/v1/notifier/reload', { method: 'POST', body: '{}' });
    showStatus('Notifier reloaded successfully.');
  }

  function init() {
    window.addEventListener('beforeunload', (evt) => {
      if (!state.isDirty) return;
      evt.preventDefault();
      evt.returnValue = 'You have unsaved changes';
    });

    byId('notifierAddChannelBtn')?.addEventListener('click', addChannel);
    byId('notifierAddDetectorBtn')?.addEventListener('click', addDetector);
    byId('notifierSaveDraftBtn')?.addEventListener('click', () => openSaveModal().catch((err) => showStatus(err.message, false)));
    byId('notifierSaveConfirmBtn')?.addEventListener('click', () => saveDraft().catch((err) => showStatus(err.message, false)));
    byId('notifierSaveCancelBtn')?.addEventListener('click', closeSaveModal);

    byId('notifierDiscardBtn')?.addEventListener('click', () => {
      if (!state.isDirty) return discardDraft();
      openUnsavedLeave(() => discardDraft());
    });
    byId('notifierReloadFromFileBtn')?.addEventListener('click', () => {
      if (!state.isDirty) return reloadFromFile();
      openUnsavedLeave(() => reloadFromFile());
    });
    byId('notifierValidateBtn')?.addEventListener('click', () => {
      const errors = validateDraft();
      if (errors.length) return openValidationErrors(errors);
      showStatus('Validation passed.');
    });
    byId('notifierReloadBtn')?.addEventListener('click', () => reloadNotifier().catch((err) => showStatus(err.message, false)));

    byId('notifierDeleteConfirmCancelBtn')?.addEventListener('click', closeDeleteConfirm);
    byId('notifierDeleteConfirmBtn')?.addEventListener('click', doDelete);

    byId('notifierUnsavedLeaveCancelBtn')?.addEventListener('click', closeUnsavedLeave);
    byId('notifierUnsavedLeaveDiscardBtn')?.addEventListener('click', runPendingLeave);

    byId('notifierValidationErrorsCloseBtn')?.addEventListener('click', closeValidationErrors);

    byId('notifierTabConfigBtn')?.addEventListener('click', () => {
      byId('notifierConfigPanels')?.style.setProperty('display', '');
    });

    loadConfig().catch((err) => showStatus(err.message || 'Failed to load config.', false));
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
