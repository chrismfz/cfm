(() => {
  const state = {
    loading: false,
    timing: {},
    health: {},
    lua: null,
  };

  const el = {
    refreshBtn:      document.getElementById('refreshBtn'),
    blockBtn:        document.getElementById('blockBtn'),
    unblockBtn:      document.getElementById('unblockBtn'),
    targetIP:        document.getElementById('targetIP'),
    ttl:             document.getElementById('ttl'),
    reason:          document.getElementById('reason'),
    actionMsg:       document.getElementById('actionMsg'),
    statusText:      document.getElementById('statusText'),
    dnatText:        document.getElementById('dnatText'),
    sslText:         document.getElementById('sslText'),
    timingList:      document.getElementById('timingList'),
    timingEmpty:     document.getElementById('timingEmpty'),
    healthGrid:      document.getElementById('healthGrid'),
    nginxStatsGrid:  document.getElementById('nginxStatsGrid'),
  };

  // ── Fetch helpers ──────────────────────────────────────────────────────────

  function setLoading(v) {
    state.loading = Boolean(v);
    el.refreshBtn.disabled = state.loading;
    el.refreshBtn.textContent = state.loading ? 'Refreshing...' : 'Refresh now';
  }

  function showMsg(msg) {
    el.actionMsg.style.display = msg ? '' : 'none';
    el.actionMsg.textContent = msg || '';
  }

  // Go backend (proxied via nginx → 127.0.0.1:6060)
  async function api(path, opts = {}) {
    const res = await fetch(`/cfm-admin/api${path}`, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.ok === false) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  // Lua stats (served directly by nginx content_by_lua_block, no Go involved)
  async function fetchLuaStats() {
    const res = await fetch('/cfm-admin/lua-stats');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  // ── Utils ──────────────────────────────────────────────────────────────────

  function escapeHTML(v) {
    return String(v)
      .replaceAll('&', '&amp;').replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;').replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function fmtBytes(n) {
    const v = Number(n);
    if (!Number.isFinite(v) || v <= 0) return '0 B';
    const u = ['B', 'KB', 'MB', 'GB'];
    let x = v, i = 0;
    while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
    return `${(x >= 10 || i === 0) ? x.toFixed(0) : x.toFixed(1)} ${u[i]}`;
  }

  function fmtAge(s) {
    if (s == null) return '-';
    const n = Number(s);
    if (!Number.isFinite(n)) return '-';
    if (n < 60)   return `${n}s ago`;
    if (n < 3600) return `${Math.floor(n/60)}m ago`;
    return `${Math.floor(n/3600)}h ${Math.floor((n%3600)/60)}m ago`;
  }

  function num(v) {
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }

  // Progress bar HTML with optional color override at >80%
  function progressBar(pct, opts = {}) {
    const p = Math.min(100, Math.max(0, Number(pct) || 0));
    const color = p > 80 ? (opts.dangerColor || '#d9516f')
                : p > 60 ? '#f1d64a'
                : '';
    const style = color ? `background:${color}` : '';
    return `<div class="progress"><span style="width:${p}%;${style}"></span></div>`;
  }

  function miniCard(label, value, sub, pct) {
    return `<div class="mini-card">
      <div class="muted">${label}</div>
      <div><strong>${value}</strong>${sub ? `<span class="muted"> ${sub}</span>` : ''}</div>
      ${pct != null ? progressBar(pct) : ''}
    </div>`;
  }

  // Mode badge for WAF rules
  const MODE_COLORS = {
    block:     'color:#ffc9d3;border-color:#8f3b4d;background:rgba(217,81,111,.15)',
    challenge: 'color:#ffd27c;border-color:#91651f;background:rgba(170,115,22,.15)',
    logonly:   'color:#8dd0ff;border-color:#2a5f8f;background:rgba(77,163,255,.1)',
    disabled:  'color:var(--muted);border-color:var(--border);background:transparent',
  };
  function modeBadge(mode) {
    const s = MODE_COLORS[mode] || MODE_COLORS.disabled;
    return `<span class="pill" style="${s}">${escapeHTML(mode || 'disabled')}</span>`;
  }

  // ── Health (from /v1/system/status output text) ────────────────────────────

  function parseHealth(text) {
    const get = (re) => { const m = text.match(re); return m ? m[1] : null; };
    return {
      cpuLoad:       get(/CPU load:\s*([^\n]+)/),
      ramPct:        num(get(/RAM:\s*([0-9.]+)%/)),
      diskPct:       num(get(/Disk \/:\s*([0-9.]+)%/)),
      connections:   get(/Connections:\s*([^\n]+)/),
      conntrack:     get(/Conntrack:\s*([^\n]+)/),
      conntrackPct:  num(get(/Conntrack:\s*\d+\s*\/\s*\d+\s*\(([0-9.]+)%\)/)),
    };
  }

  function renderHealth() {
    const h = state.health || {};
    el.healthGrid.innerHTML = [
      { label: 'CPU load (1m)',  value: h.cpuLoad     || '-',                    pct: null },
      { label: 'RAM',            value: h.ramPct  != null ? `${h.ramPct}%`  : '-', pct: h.ramPct },
      { label: 'Disk /',         value: h.diskPct != null ? `${h.diskPct}%` : '-', pct: h.diskPct },
      { label: 'Connections',    value: h.connections  || '-',                   pct: null },
      { label: 'Conntrack',      value: h.conntrack    || '-',                   pct: h.conntrackPct },
    ].map(k => miniCard(escapeHTML(k.label), escapeHTML(String(k.value)), '', k.pct)).join('');
  }

  function renderTimings() {
    const entries = Object.entries(state.timing || {})
      .filter(([k, v]) => Number.isFinite(Number(v)) && !k.includes('cache_hit'));
    if (!entries.length) {
      el.timingList.innerHTML = '';
      el.timingEmpty.style.display = '';
      return;
    }
    el.timingEmpty.style.display = 'none';
    const max = entries.reduce((m, [, v]) => Math.max(m, Number(v)), 1);
    el.timingList.innerHTML = entries
      .map(([key, value]) => ({ key, value: Number(value), w: Math.max(4, Number(value)*100/max) }))
      .sort((a, b) => b.value - a.value)
      .map(r => `<div class="mini-card">
        <div class="muted">${escapeHTML(r.key)}</div>
        <div><strong>${r.value} ms</strong></div>
        <div class="progress"><span style="width:${r.w}%"></span></div>
      </div>`).join('');
  }

  // ── Nginx / Lua internals ──────────────────────────────────────────────────

  function renderNginxStats() {
    if (!el.nginxStatsGrid) return;
    const d = state.lua;
    if (!d) { el.nginxStatsGrid.innerHTML = '<p class="muted">No data.</p>'; return; }

    const ssl  = d.sslcache  || {};
    const dec  = d.decisions || {};
    const waf  = d.waf       || {};
    const ng   = d.nginx     || {};
    const wk   = ng.worker   || {};
    const bk   = dec.key_breakdown || {};
    const wx   = dec.waf_excludes  || {};

    // ── Section: Shared dict memory ──────────────────────────────────────────
    const dictSection = `
      <div style="grid-column:1/-1">
        <div class="muted" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;margin-bottom:.45rem">
          Shared dict memory
        </div>
        <div class="kpi-grid" style="grid-template-columns:repeat(auto-fill,minmax(260px,1fr))">
          ${dictCard('cfm_decisions', dec)}
          ${dictCard('sslcache', ssl)}
        </div>
      </div>`;

    // ── Section: sslcollector health ─────────────────────────────────────────
    const sslAge = ssl.last_dumpall_age_s;
    const sslAgeWarn = sslAge != null && sslAge > 4000;
    const readyBadge = ssl.ready === '1'
      ? '<span style="color:#87d45b">✓ ready</span>'
      : '<span style="color:#d9516f">✗ not ready</span>';

    const sslHealthSection = `
      <div style="grid-column:1/-1">
        <div class="muted" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;margin:.6rem 0 .45rem">
          sslcollector health
        </div>
        <div class="kpi-grid" style="grid-template-columns:repeat(auto-fill,minmax(200px,1fr))">
          ${miniCard('status', readyBadge, '', null)}
          ${miniCard('version', escapeHTML(ssl.version || '-'), '', null)}
          ${miniCard('exact certs', escapeHTML(String(ssl.exact_hosts ?? '-')), 'hostnames', null)}
          ${miniCard('wildcard certs', escapeHTML(String(ssl.wild_hosts ?? '-')), 'suffixes', null)}
          ${miniCard('last dumpall', escapeHTML(fmtAge(ssl.last_dumpall_age_s)),
              escapeHTML(ssl.last_dumpall_src ? `(${ssl.last_dumpall_src})` : ''),
              null)}
          ${miniCard('last /stats poll', escapeHTML(fmtAge(ssl.last_stats_age_s)), '', null)}
          ${miniCard('snapshot written', escapeHTML(fmtAge(ssl.snapshot_age_s)), '', null)}
          ${miniCard('poll interval', escapeHTML(ssl.poll_interval_s != null
              ? `${ssl.poll_interval_s}s` : '-'),
              ssl.poll_interval_s > 300 ? '⚠ backed off' : '', null)}
          ${ssl.ingest_lock
              ? miniCard('ingest lock', '<span style="color:#ffd27c">active</span>', 'ingesting now', null)
              : ''}
          ${ssl.last_error
              ? miniCard('<span style="color:#d9516f">last error</span>',
                  `<span style="color:#ffc9d3;font-size:.82rem">${escapeHTML(ssl.last_error)}</span>`,
                  escapeHTML(fmtAge(ssl.last_error_age_s)), null)
              : miniCard('last error', '<span style="color:#87d45b">none</span>', '', null)}
        </div>
      </div>`;

    // ── Section: decision cache breakdown ────────────────────────────────────
    const decSection = `
      <div style="grid-column:1/-1">
        <div class="muted" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;margin:.6rem 0 .45rem">
          cfm_decisions key breakdown
        </div>
        <div class="kpi-grid" style="grid-template-columns:repeat(auto-fill,minmax(180px,1fr))">
          ${miniCard('allow-cache entries', escapeHTML(String(bk.decisions ?? '-')),
              `d| keys`, null)}
          ${miniCard('active solved IPs', escapeHTML(String(bk.ok_touches ?? '-')),
              'ok_touch| (≈ active sessions)', null)}
          ${miniCard('POST resumes stashed', escapeHTML(String(bk.post_resumes ?? '-')),
              'pr| keys (90s TTL)', null)}
          ${miniCard('WAF push cooldowns', escapeHTML(String(bk.waf_push_cool ?? '-')),
              'wafpush| (≈ recent WAF events)', null)}
        </div>
      </div>`;

    // ── Section: WAF exclude rules ───────────────────────────────────────────
    const hostRules = Array.isArray(wx.host_rules) ? wx.host_rules : [];
    const pathRules = Array.isArray(wx.path_rules) ? wx.path_rules : [];
    const wxRefresh = wx.refresh_age_s != null ? fmtAge(wx.refresh_age_s) : '-';

    const wafExclSection = (hostRules.length || pathRules.length) ? `
      <div style="grid-column:1/-1">
        <div class="muted" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;margin:.6rem 0 .45rem">
          WAF exclude snapshot
          <span class="muted" style="font-size:.72rem;text-transform:none;margin-left:.4rem">
            refreshed ${escapeHTML(wxRefresh)}
          </span>
        </div>
        <div style="display:grid;gap:.5rem;grid-template-columns:repeat(auto-fill,minmax(260px,1fr))">
          ${hostRules.length ? `<div class="mini-card">
            <div class="muted" style="font-size:.78rem;margin-bottom:.3rem">Host exclusions (${hostRules.length})</div>
            ${hostRules.map(h => `<div style="font-size:.82rem">${escapeHTML(h)}</div>`).join('')}
          </div>` : ''}
          ${pathRules.length ? `<div class="mini-card">
            <div class="muted" style="font-size:.78rem;margin-bottom:.3rem">Path exclusions (${pathRules.length})</div>
            ${pathRules.map(p => `<div style="font-size:.82rem">${escapeHTML(p)}</div>`).join('')}
          </div>` : ''}
        </div>
      </div>` : '';

    // ── Section: WAF rule modes ───────────────────────────────────────────────
    const rules = waf.rules || {};
    const ruleKeys = Object.keys(rules).sort();
    const wafRulesSection = ruleKeys.length ? `
      <div style="grid-column:1/-1">
        <div class="muted" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;margin:.6rem 0 .45rem">
          WAF rule modes
        </div>
        <div class="table-wrap">
          <table class="compact-table" style="width:100%">
            <thead><tr><th>rule</th><th>mode</th></tr></thead>
            <tbody>
              ${ruleKeys.map(k => `<tr>
                <td style="font-family:monospace;font-size:.8rem">${escapeHTML(k)}</td>
                <td>${modeBadge(rules[k])}</td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>` : (waf.note ? `<div style="grid-column:1/-1" class="muted">${escapeHTML(waf.note)}</div>` : '');

    // ── Section: nginx / worker info ─────────────────────────────────────────
    const nginxSection = `
      <div style="grid-column:1/-1">
        <div class="muted" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;margin:.6rem 0 .45rem">
          nginx / worker
        </div>
        <div class="kpi-grid" style="grid-template-columns:repeat(auto-fill,minmax(180px,1fr))">
          ${miniCard('nginx version', escapeHTML(ng.version_str || String(ng.version || '-')), '', null)}
          ${miniCard('prefix', escapeHTML(ng.prefix || '-'), '', null)}
          ${miniCard('workers', escapeHTML(String(wk.count ?? '-')), '', null)}
          ${miniCard('this worker PID', escapeHTML(String(wk.pid || '-')), '', null)}
          ${miniCard('worker id', escapeHTML(String(wk.id ?? '-')), '', null)}
          ${miniCard('worker exiting',
              wk.exiting ? '<span style="color:var(--danger)">yes</span>' : 'no', '', null)}
        </div>
      </div>`;

    el.nginxStatsGrid.innerHTML =
      dictSection + sslHealthSection + decSection +
      (wafExclSection || '') + wafRulesSection + nginxSection;
  }

  // Shared-dict capacity card with usage bar
  function dictCard(name, d) {
    if (!d || d.error) {
      return `<div class="mini-card"><div class="muted">${escapeHTML(name)}</div>
        <div class="muted">unavailable</div></div>`;
    }
    const pct  = Math.min(100, Math.max(0, d.used_pct || 0));
    const kStr = d.keys_capped ? `≥${d.total_keys}` : String(d.total_keys);
    const barStyle = pct > 80 ? 'background:#d9516f' : pct > 60 ? 'background:#f1d64a' : '';
    return `<div class="mini-card">
      <div class="muted">${escapeHTML(name)}</div>
      <div>
        <strong>${fmtBytes(d.used_bytes)}</strong>
        <span class="muted"> / ${fmtBytes(d.capacity_bytes)} &nbsp;(${d.used_pct}%)</span>
      </div>
      <div class="muted" style="font-size:.78rem;margin-top:.15rem">
        ${kStr} keys &nbsp;·&nbsp; ${fmtBytes(d.free_bytes)} free
      </div>
      <div class="progress"><span style="width:${pct}%;${barStyle}"></span></div>
    </div>`;
  }

  async function refreshLuaStats() {
    try {
      state.lua = await fetchLuaStats();
      renderNginxStats();
    } catch (e) {
      if (el.nginxStatsGrid)
        el.nginxStatsGrid.innerHTML =
          `<p class="muted" style="grid-column:1/-1">Lua stats unavailable: ${escapeHTML(e.message)}</p>`;
    }
  }

  // ── Main refresh ───────────────────────────────────────────────────────────

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
      el.sslText.textContent  = JSON.stringify(ssl.stats || {}, null, 2);
    } catch (e) {
      showMsg(`Refresh failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
    // Lua stats are independent — never block the main refresh
    refreshLuaStats();
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
    } catch (e) { showMsg(`Block failed: ${e.message}`); }
  }

  async function unblockIP() {
    try {
      const ip = el.targetIP.value.trim();
      await api('/v1/firewall/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      });
      showMsg(`Unblocked ${ip}`);
      refreshAll();
    } catch (e) { showMsg(`Unblock failed: ${e.message}`); }
  }

  el.refreshBtn.addEventListener('click', refreshAll);
  el.blockBtn.addEventListener('click', blockIP);
  el.unblockBtn.addEventListener('click', unblockIP);

  refreshAll();
})();
