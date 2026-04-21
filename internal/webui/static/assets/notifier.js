(() => {
  let state = { config: { channels: [], detectors: {} }, path: '' };

  function byId(id) { return document.getElementById(id); }

  function showStatus(msg, ok = true) {
    const el = byId('notifierStatus');
    if (!el) return;
    el.textContent = msg;
    el.style.color = ok ? '#4ade80' : '#f87171';
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
    state = {
      config: payload.config || { channels: [], detectors: {} },
      path: payload.path || '',
    };
    state.config.channels = Array.isArray(state.config.channels) ? state.config.channels : [];
    state.config.detectors = state.config.detectors && typeof state.config.detectors === 'object' ? state.config.detectors : {};
    render();
    showStatus(`Loaded config from ${state.path || 'default path'}.`);
  }

  async function saveConfig() {
    const payload = await request('/cfm-admin/api/v1/notifier/config', {
      method: 'PUT',
      body: JSON.stringify({ config: state.config }),
    });
    showStatus(`Config saved to ${payload.path || state.path}.`);
  }

  async function reloadNotifier() {
    await request('/cfm-admin/api/v1/notifier/reload', { method: 'POST', body: '{}' });
    showStatus('Notifier reloaded successfully.');
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
    for (const channel of state.config.channels) {
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
    const keys = Object.keys(state.config.detectors || {}).sort();
    for (const detector of keys) {
      const ov = state.config.detectors[detector] || {};
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
  }

  function upsertChannel(existingId = '') {
    const source = state.config.channels.find((c) => c.id === existingId) || {};
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
    state.config.channels = state.config.channels.filter((c) => c.id !== existingId && c.id !== ch.id);
    state.config.channels.push(ch);
    state.config.channels.sort((a, b) => String(a.id).localeCompare(String(b.id)));
    renderChannels();
  }

  function editChannel(id) { upsertChannel(id); }
  function deleteChannel(id) {
    if (!confirm(`Delete channel ${id}?`)) return;
    state.config.channels = state.config.channels.filter((c) => c.id !== id);
    renderChannels();
  }

  function upsertDetector(existing = '') {
    const source = (state.config.detectors || {})[existing] || {};
    const detector = (prompt('Detector name', existing || '') || '').trim().toLowerCase();
    if (!detector) return;
    const notify = confirm('Send notifications for this detector?');
    const cooldown = (prompt('Cooldown (optional, e.g. 5m)', source.cooldown || '') || '').trim();
    const minSeverity = (prompt('Minimum severity (optional)', source.min_severity || '') || '').trim();
    const channels = (prompt('Channel IDs CSV (optional)', Array.isArray(source.channels) ? source.channels.join(',') : '') || '')
      .split(',').map((v) => v.trim()).filter(Boolean);

    if (!state.config.detectors || typeof state.config.detectors !== 'object') state.config.detectors = {};
    if (existing && existing !== detector) delete state.config.detectors[existing];
    state.config.detectors[detector] = { notify, cooldown, min_severity: minSeverity, channels };
    renderDetectors();
  }

  function editDetector(detector) { upsertDetector(detector); }
  function deleteDetector(detector) {
    if (!confirm(`Delete detector override ${detector}?`)) return;
    delete state.config.detectors[detector];
    renderDetectors();
  }

  function init() {
    byId('notifierRefreshBtn')?.addEventListener('click', () => loadConfig().catch((e) => showStatus(e.message, false)));
    byId('notifierSaveBtn')?.addEventListener('click', () => saveConfig().catch((e) => showStatus(e.message, false)));
    byId('notifierReloadBtn')?.addEventListener('click', () => reloadNotifier().catch((e) => showStatus(e.message, false)));
    byId('notifierAddChannelBtn')?.addEventListener('click', () => upsertChannel(''));
    byId('notifierAddDetectorBtn')?.addEventListener('click', () => upsertDetector(''));
    loadConfig().catch((e) => showStatus(e.message || 'Failed to load notifier config.', false));
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
