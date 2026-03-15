(() => {
  const state = {
    loading: false,
    timing: {},
    health: {},
  };

  const el = {
    refreshBtn: document.getElementById('refreshBtn'),
    blockBtn: document.getElementById('blockBtn'),
    unblockBtn: document.getElementById('unblockBtn'),
    targetIP: document.getElementById('targetIP'),
    ttl: document.getElementById('ttl'),
    reason: document.getElementById('reason'),
    actionMsg: document.getElementById('actionMsg'),
    statusText: document.getElementById('statusText'),
    dnatText: document.getElementById('dnatText'),
    sslText: document.getElementById('sslText'),
    timingList: document.getElementById('timingList'),
    timingEmpty: document.getElementById('timingEmpty'),
    healthGrid: document.getElementById('healthGrid'),
  };

  function setLoading(v) {
    state.loading = Boolean(v);
    el.refreshBtn.disabled = state.loading;
    el.refreshBtn.textContent = state.loading ? 'Refreshing...' : 'Refresh now';
  }

  function showMsg(msg) {
    if (!msg) {
      el.actionMsg.style.display = 'none';
      el.actionMsg.textContent = '';
      return;
    }
    el.actionMsg.style.display = '';
    el.actionMsg.textContent = msg;
  }

  async function api(path, opts = {}) {
    const res = await fetch(`/cfm-admin/api${path}`, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.ok === false) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  function num(v) {
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }

  function parseHealth(text) {
    const get = (re) => {
      const m = text.match(re);
      return m ? m[1] : null;
    };
    return {
      cpuLoad: get(/CPU load:\s*([^\n]+)/),
      ramPct: num(get(/RAM:\s*([0-9.]+)%/)),
      diskPct: num(get(/Disk \/:\s*([0-9.]+)%/)),
      connections: get(/Connections:\s*([^\n]+)/),
      conntrack: get(/Conntrack:\s*([^\n]+)/),
      conntrackPct: num(get(/Conntrack:\s*\d+\s*\/\s*\d+\s*\(([0-9.]+)%\)/)),
    };
  }

  function renderHealth() {
    const h = state.health || {};
    const rows = [
      { label: 'CPU load (1m)', value: h.cpuLoad || '-', pct: null },
      { label: 'RAM', value: h.ramPct != null ? `${h.ramPct}%` : '-', pct: h.ramPct },
      { label: 'Disk /', value: h.diskPct != null ? `${h.diskPct}%` : '-', pct: h.diskPct },
      { label: 'Connections', value: h.connections || '-', pct: null },
      { label: 'Conntrack', value: h.conntrack || '-', pct: h.conntrackPct },
    ];
    el.healthGrid.innerHTML = rows.map((k) => {
      const bar = k.pct == null ? '' : `<div class="progress"><span style="width:${Math.max(0, Math.min(100, k.pct))}%"></span></div>`;
      return `<div class="mini-card"><div class="muted">${escapeHTML(k.label)}</div><div><strong>${escapeHTML(String(k.value))}</strong></div>${bar}</div>`;
    }).join('');
  }

  function renderTimings() {
    const entries = Object.entries(state.timing || {}).filter(([k, v]) => Number.isFinite(Number(v)) && !k.includes('cache_hit'));
    if (!entries.length) {
      el.timingList.innerHTML = '';
      el.timingEmpty.style.display = '';
      return;
    }
    el.timingEmpty.style.display = 'none';
    const max = entries.reduce((m, [, v]) => Math.max(m, Number(v)), 1);
    const rows = entries
      .map(([key, value]) => ({ key, value: Number(value), width: Math.max(4, (Number(value) * 100) / max) }))
      .sort((a, b) => b.value - a.value);
    el.timingList.innerHTML = rows.map((r) => (
      `<div class="mini-card"><div class="muted">${escapeHTML(r.key)}</div><div><strong>${r.value} ms</strong></div><div class="progress"><span style="width:${r.width}%"></span></div></div>`
    )).join('');
  }

  function escapeHTML(v) {
    return String(v)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  async function refreshAll() {
    setLoading(true);
    showMsg('');
    try {
      const [status, dnat, ssl] = await Promise.all([
        api('/v1/system/status?timings=1&cache_ttl=10s'),
        api('/v1/system/dnat'),
        api('/v1/system/ssl/stats'),
      ]);
      el.statusText.textContent = status.output || '(empty)';
      state.timing = status.timings || {};
      state.health = parseHealth(el.statusText.textContent);
      renderTimings();
      renderHealth();
      el.dnatText.textContent = dnat.output || '(empty)';
      el.sslText.textContent = JSON.stringify(ssl.stats || {}, null, 2);
    } catch (e) {
      showMsg(`Refresh failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  }

  async function blockIP() {
    try {
      const ip = el.targetIP.value.trim();
      await api('/v1/firewall/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, ttl: el.ttl.value.trim(), reason: el.reason.value.trim() }),
      });
      showMsg(`Blocked ${ip}`);
      refreshAll();
    } catch (e) {
      showMsg(`Block failed: ${e.message}`);
    }
  }

  async function unblockIP() {
    try {
      const ip = el.targetIP.value.trim();
      await api('/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      });
      showMsg(`Unblocked ${ip}`);
      refreshAll();
    } catch (e) {
      showMsg(`Unblock failed: ${e.message}`);
    }
  }

  el.refreshBtn.addEventListener('click', refreshAll);
  el.blockBtn.addEventListener('click', blockIP);
  el.unblockBtn.addEventListener('click', unblockIP);

  refreshAll();
})();
