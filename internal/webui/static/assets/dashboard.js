(() => {
  const controller = window.CFMControllerBootstrap.initSharedController({
    onDeferredScopedToken: () => {
      onLateScopedToken().catch((err) => {
        console.error('[cfm-admin dashboard] late token re-init failed', err);
      });
    },
  });


  const state = {
    loading: false,
    health: {},
    lua: null,
    scoped: false,
  };

const el = {
  refreshBtn:        document.getElementById('refreshBtn'),
  blockBtn:          document.getElementById('blockBtn'),
  unblockBtn:        document.getElementById('unblockBtn'),
  targetIP:          document.getElementById('targetIP'),
  ttl:               document.getElementById('ttl'),
  reason:            document.getElementById('reason'),
  actionMsg:         document.getElementById('actionMsg'),
  dnatText:          document.getElementById('dnatText'),
  dnatSummary:       document.getElementById('dnatSummary'),
  sslText:           document.getElementById('sslText'),
  sslGrid:           document.getElementById('sslGrid'),
  securityCard:      document.getElementById('securityCard'),
  securityGrid:      document.getElementById('securityGrid'),
  lastUpdated:       document.getElementById('lastUpdated'),
  autoState:         document.getElementById('autoState'),
  toggleAutoBtn:     document.getElementById('toggleAutoBtn'),
  healthGrid:        document.getElementById('healthGrid'),
  nginxOverviewGrid: document.getElementById('nginxOverviewGrid'),
  cacheOverview:     document.getElementById('cacheOverview'),
  throttleOverview:  document.getElementById('throttleOverview'),
  nginxStatsGrid:    document.getElementById('nginxStatsGrid'),
};

  function setLoading(v) {
    state.loading = Boolean(v);
    el.refreshBtn.disabled = state.loading;
    el.refreshBtn.textContent = state.loading ? 'Refreshing...' : 'Refresh now';
  }

  function showMsg(msg) {
    el.actionMsg.style.display = msg ? '' : 'none';
    el.actionMsg.textContent = msg || '';
  }

  const api = controller.createApiClient({
    basePath: '/cfm-admin/api',
    isScoped: () => false,
  });



  async function loadViewerContext(opts = {}) {
    const tokenBeforeLoadMe = controller.getToken();
    let me = { scoped: false, role: 'admin' };
    try {
      me = await controller.loadMe({ preferScopedToken: true });
      controller.refreshToken();
    } catch (_) {}

    let latestToken = controller.refreshToken();
    const isIdentityScoped = Boolean(me && (me.isScopedMode ?? me.is_scoped_mode ?? me.scoped));
    const computedInitialMode = window.CFMAuthMode?.computeInitialScopeMode?.({
      identity: me,
      token: latestToken,
    }) || 'global';

    if (opts.resolveInitialMode && computedInitialMode === 'scoped' && !isIdentityScoped) {
      try {
        me = await controller.loadMe({ preferScopedToken: true, waitForTokenMs: 0 });
        latestToken = controller.refreshToken();
      } catch (_) {}
    }

    const scoped = Boolean(me && (me.isScopedMode ?? me.is_scoped_mode ?? me.scoped));
    const canWrite = !scoped || String(me.role || '').toLowerCase() !== 'viewer';

    controller.applyScopedChrome({ scoped });

    return {
      scoped,
      canWrite,
      role: String(me.role || ''),
      tokenBeforeLoadMe,
      tokenAfterLoadMe: latestToken,
    };
  }

  async function onLateScopedToken() {
    const prevScoped = Boolean(state.scoped);
    const ctx = await loadViewerContext();
    state.scoped = ctx.scoped;
    if (prevScoped === ctx.scoped) return;
    if (!ctx.canWrite) {
      if (el.blockBtn) el.blockBtn.style.display = 'none';
      if (el.unblockBtn) el.unblockBtn.style.display = 'none';
    }
    await refreshAll();
  }

  async function fetchLuaStats() {
    const res = await fetch('/cfm-admin/lua-stats');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

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
    while (x >= 1024 && i < u.length - 1) {
      x /= 1024;
      i++;
    }
    return `${(x >= 10 || i === 0) ? x.toFixed(0) : x.toFixed(1)} ${u[i]}`;
  }

  function fmtAge(s) {
    if (s == null) return '-';
    const n = Number(s);
    if (!Number.isFinite(n)) return '-';
    if (n < 60) return `${n}s ago`;
    if (n < 3600) return `${Math.floor(n / 60)}m ago`;
    return `${Math.floor(n / 3600)}h ${Math.floor((n % 3600) / 60)}m ago`;
  }

  function num(v) {
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }

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

  const MODE_COLORS = {
    block: 'color:#ffc9d3;border-color:#8f3b4d;background:rgba(217,81,111,.15)',
    challenge: 'color:#ffd27c;border-color:#91651f;background:rgba(170,115,22,.15)',
    logonly: 'color:#8dd0ff;border-color:#2a5f8f;background:rgba(77,163,255,.1)',
    disabled: 'color:var(--muted);border-color:var(--border);background:transparent',
  };

  function modeBadge(mode) {
    const s = MODE_COLORS[mode] || MODE_COLORS.disabled;
    return `<span class="pill" style="${s}">${escapeHTML(mode || 'disabled')}</span>`;
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
    const ng = state.lua?.nginx || {};
    const wk = ng.worker || {};
    const conn = ng.connections || {};

    const items = [
      { label: 'CPU load (1m)', value: h.cpuLoad || '-', pct: null },
      { label: 'RAM', value: h.ramPct != null ? `${h.ramPct}%` : '-', pct: h.ramPct },
      { label: 'Disk /', value: h.diskPct != null ? `${h.diskPct}%` : '-', pct: h.diskPct },
      { label: 'System connections', value: h.connections || '-', pct: null },
      { label: 'Conntrack', value: h.conntrack || '-', pct: h.conntrackPct },
      { label: 'Nginx active', value: conn.active != null ? String(conn.active) : '-', pct: null },
      { label: 'Nginx reading', value: conn.reading != null ? String(conn.reading) : '-', pct: null },
      { label: 'Nginx writing', value: conn.writing != null ? String(conn.writing) : '-', pct: null },
      { label: 'Nginx waiting', value: conn.waiting != null ? String(conn.waiting) : '-', pct: null },
      { label: 'Nginx workers', value: wk.count != null ? String(wk.count) : '-', pct: null },
    ];

    el.healthGrid.innerHTML = items
      .map((k) => miniCard(escapeHTML(k.label), escapeHTML(String(k.value)), '', k.pct))
      .join('');
  }

  function renderNginxOverview() {
    if (!el.nginxOverviewGrid) return;

    const d = state.lua;
    if (!d) {
      el.nginxOverviewGrid.innerHTML = '<p class="muted">No data.</p>';
      return;
    }

    const ng = d.nginx || {};
    const wk = ng.worker || {};
    const conn = ng.connections || {};
    const ssl = d.sslcache || {};
    const dec = d.decisions || {};
    const cache = d.cache || {};

    const sslReady = ssl.ready === '1' ? 'yes' : 'no';
    const sslAge = ssl.last_dumpall_age_s != null ? fmtAge(ssl.last_dumpall_age_s) : '-';
    const lastErr = ssl.last_error ? ssl.last_error : 'none';

    el.nginxOverviewGrid.innerHTML = [
      miniCard('nginx version', escapeHTML(ng.version_str || String(ng.version || '-')), '', null),
      miniCard('workers', escapeHTML(String(wk.count ?? '-')), '', null),
      miniCard('this worker PID', escapeHTML(String(wk.pid ?? '-')), '', null),
      miniCard('worker id', escapeHTML(String(wk.id ?? '-')), '', null),
      miniCard('active', escapeHTML(String(conn.active ?? '-')), '', null),
      miniCard('reading', escapeHTML(String(conn.reading ?? '-')), '', null),
      miniCard('writing', escapeHTML(String(conn.writing ?? '-')), '', null),
      miniCard('waiting', escapeHTML(String(conn.waiting ?? '-')), '', null),
      miniCard('sslcache used', escapeHTML(ssl.used_pct != null ? `${ssl.used_pct}%` : '-'), '', ssl.used_pct),
      miniCard('cfm_decisions used', escapeHTML(dec.used_pct != null ? `${dec.used_pct}%` : '-'), '', dec.used_pct),
      miniCard('cfm_cache_stats used', escapeHTML(cache.used_pct != null ? `${cache.used_pct}%` : '-'), '', cache.used_pct),
      miniCard('sslcollector ready', escapeHTML(sslReady), '', null),
      miniCard('last dumpall', escapeHTML(sslAge), '', null),
      miniCard('last error', escapeHTML(lastErr), '', null),
    ].join('');
  }

function renderCacheOverview() {
  if (!el.cacheOverview) return;

  const cache = state.lua?.cache || null;
  const zones = cache?.zones || {};
  const zs = zones.cfm_static || {};
  const zm = zones.cfm_micro || {};

  function cachePctBar(p) {
    const pct = Number.isFinite(Number(p)) ? Number(p) : 0;
    return `
      <div class="progress" style="margin-top:.25rem">
        <span style="width:${pct}%"></span>
      </div>
    `;
  }



  function row(label, z) {
    const total = z.total ?? 0;
    const cacheable = z.cacheable_total ?? 0;
    const hit = z.hit ?? 0;
    const miss = z.miss ?? 0;
    const bypass = z.bypass ?? 0;
    const stale = z.stale ?? 0;
    const revalidated = z.revalidated ?? 0;

    return `
      <tr>
        <td><code>${escapeHTML(label)}</code></td>
        <td>${escapeHTML(String(total))}</td>
        <td>
          ${escapeHTML(String(hit))} (${escapeHTML(String(z.hit_pct ?? 0))}%)
          ${cachePctBar(z.hit_pct ?? 0)}
        </td>
        <td>${escapeHTML(String(miss))} (${escapeHTML(String(z.miss_pct ?? 0))}%)</td>
        <td>${escapeHTML(String(bypass))} (${escapeHTML(String(z.bypass_pct ?? 0))}%)</td>
        <td>${escapeHTML(String(stale))}</td>
        <td>${escapeHTML(String(revalidated))}</td>
        <td>${escapeHTML(String(cacheable))}</td>
      </tr>
    `;
  }

  if (!cache || cache.error) {
    el.cacheOverview.innerHTML = `
      <table class="compact-table" style="width:100%">
        <thead>
          <tr>
            <th>Zone / path</th>
            <th>Purpose</th>
            <th>TTL / inactivity</th>
            <th>Bypass / notes</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>cfm_static</code></td>
            <td>Static assets (css/js/images/fonts/media)</td>
            <td>cache valid: 5m<br>inactive: 24h</td>
            <td>Background update enabled only for safe static content</td>
          </tr>
          <tr>
            <td><code>cfm_micro</code></td>
            <td>Anonymous dynamic pages</td>
            <td>200: 2s<br>404: 1s<br>inactive: 60m</td>
            <td>Bypassed on challenge traffic and when cookies are present</td>
          </tr>
        </tbody>
      </table>
      <p class="muted" style="margin-top:.65rem">
        Cache telemetry not available yet.
      </p>
    `;
    return;
  }

  el.cacheOverview.innerHTML = `
    <div class="muted" style="margin-bottom:.55rem">
      Total cache-tracked requests: <strong>${escapeHTML(String(cache.total ?? 0))}</strong>
      &nbsp;·&nbsp;
      Last seen: <strong>${escapeHTML(fmtAge(cache.last_seen_age_s))}</strong>
    </div>

    <table class="compact-table" style="width:100%">
      <thead>
        <tr>
          <th>Zone</th>
          <th>Total</th>
          <th>Hit</th>
          <th>Miss</th>
          <th>Bypass</th>
          <th>Stale</th>
          <th>Revalidated</th>
          <th>Cacheable total</th>
        </tr>
      </thead>
      <tbody>
        ${row('cfm_static', zs)}
        ${row('cfm_micro', zm)}
      </tbody>
    </table>

    <p class="muted" style="margin-top:.65rem">
      Hit/Miss percentages are calculated over cacheable responses.
      Bypass percentage is calculated over total tracked requests per zone.
    </p>
  `;
}


function renderThrottleOverview() {
  if (!el.throttleOverview) return;

  const t = state.lua?.throttle?.meta || null;

  if (!t) {
    el.throttleOverview.innerHTML = '<p class="muted">No data.</p>';
    return;
  }

  el.throttleOverview.innerHTML = [
    miniCard('Meta crawler total', escapeHTML(String(t.total ?? 0)), '', null),
    miniCard('Throttled', escapeHTML(String(t.throttled ?? 0)), escapeHTML(`(${t.throttled_pct ?? 0}%)`), t.throttled_pct),
    miniCard('Rejected', escapeHTML(String(t.rejected ?? 0)), escapeHTML(`(${t.rejected_pct ?? 0}%)`), t.rejected_pct),
    miniCard('Delayed', escapeHTML(String(t.delayed ?? 0)), escapeHTML(`(${t.delayed_pct ?? 0}%)`), t.delayed_pct),
    miniCard('HTTP 429', escapeHTML(String(t.http_429 ?? 0)), escapeHTML(`(${t.http_429_pct ?? 0}%)`), t.http_429_pct),
  ].join('');
}




  function renderNginxStats() {
    if (!el.nginxStatsGrid) return;
    const d = state.lua;
    if (!d) {
      el.nginxStatsGrid.innerHTML = '<p class="muted">No data.</p>';
      return;
    }

    const ssl = d.sslcache || {};
    const dec = d.decisions || {};
    const waf = d.waf || {};
    const ng = d.nginx || {};
    const wk = ng.worker || {};
    const conn = ng.connections || {};
    const bk = dec.key_breakdown || {};
    const wx = dec.waf_excludes || {};

const cache = d.cache || {};

const dictSection = `
  <div style="grid-column:1/-1">
    <div class="muted" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;margin-bottom:.45rem">
      Shared dict memory
    </div>
    <div class="kpi-grid" style="grid-template-columns:repeat(auto-fill,minmax(260px,1fr))">
      ${dictCard('cfm_decisions', dec)}
      ${dictCard('sslcache', ssl)}
      ${dictCard('cfm_cache_stats', cache)}
    </div>
  </div>`;

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
          ${miniCard('last dumpall', escapeHTML(fmtAge(ssl.last_dumpall_age_s)), escapeHTML(ssl.last_dumpall_src ? `(${ssl.last_dumpall_src})` : ''), null)}
          ${miniCard('last /stats poll', escapeHTML(fmtAge(ssl.last_stats_age_s)), '', null)}
          ${miniCard('snapshot written', escapeHTML(fmtAge(ssl.snapshot_age_s)), '', null)}
          ${miniCard('poll interval', escapeHTML(ssl.poll_interval_s != null ? `${ssl.poll_interval_s}s` : '-'), ssl.poll_interval_s > 300 ? '⚠ backed off' : '', null)}
          ${ssl.ingest_lock ? miniCard('ingest lock', '<span style="color:#ffd27c">active</span>', 'ingesting now', null) : ''}
          ${ssl.last_error
            ? miniCard('<span style="color:#d9516f">last error</span>', `<span style="color:#ffc9d3;font-size:.82rem">${escapeHTML(ssl.last_error)}</span>`, escapeHTML(fmtAge(ssl.last_error_age_s)), null)
            : miniCard('last error', '<span style="color:#87d45b">none</span>', '', null)}
        </div>
      </div>`;

    const decSection = `
      <div style="grid-column:1/-1">
        <div class="muted" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;margin:.6rem 0 .45rem">
          cfm_decisions key breakdown
        </div>
        <div class="kpi-grid" style="grid-template-columns:repeat(auto-fill,minmax(180px,1fr))">
          ${miniCard('allow-cache entries', escapeHTML(String(bk.decisions ?? '-')), 'd| keys', null)}
          ${miniCard('active solved IPs', escapeHTML(String(bk.ok_touches ?? '-')), 'ok_touch| (≈ active sessions)', null)}
          ${miniCard('POST resumes stashed', escapeHTML(String(bk.post_resumes ?? '-')), 'pr| keys (90s TTL)', null)}
          ${miniCard('WAF push cooldowns', escapeHTML(String(bk.waf_push_cool ?? '-')), 'wafpush| (≈ recent WAF events)', null)}
        </div>
      </div>`;

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
            ${hostRules.map((h) => `<div style="font-size:.82rem">${escapeHTML(h)}</div>`).join('')}
          </div>` : ''}
          ${pathRules.length ? `<div class="mini-card">
            <div class="muted" style="font-size:.78rem;margin-bottom:.3rem">Path exclusions (${pathRules.length})</div>
            ${pathRules.map((p) => `<div style="font-size:.82rem">${escapeHTML(p)}</div>`).join('')}
          </div>` : ''}
        </div>
      </div>` : '';

    const rules = waf.rules || {};
    const ruleKeys = Object.keys(rules).sort();
    const modeCounts = {};
    for (const k of ruleKeys) {
      const m = rules[k] || 'disabled';
      modeCounts[m] = (modeCounts[m] || 0) + 1;
    }
    const modeSummary = Object.entries(modeCounts)
      .sort((a, b) => b[1] - a[1])
      .map(([m, n]) => `${n} ${escapeHTML(m)}`)
      .join(' · ');
    const wafRulesSection = ruleKeys.length ? `
      <div style="grid-column:1/-1">
        <details class="raw-json" style="margin-top:.6rem">
        <summary>WAF rule modes — ${ruleKeys.length} rules (${modeSummary})</summary>
        <div class="table-wrap" style="max-height:420px">
          <table class="compact-table" style="width:100%">
            <thead><tr><th>rule</th><th>mode</th></tr></thead>
            <tbody>
              ${ruleKeys.map((k) => `<tr>
                <td style="font-family:monospace;font-size:.8rem">${escapeHTML(k)}</td>
                <td>${modeBadge(rules[k])}</td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>
        </details>
      </div>` : (waf.note ? `<div style="grid-column:1/-1" class="muted">${escapeHTML(waf.note)}</div>` : '');

    const hasConn = [
      conn.active,
      conn.reading,
      conn.writing,
      conn.waiting,
      conn.accepted,
      conn.handled,
      conn.requests,
    ].some((v) => Number.isFinite(Number(v)));

    const connSection = hasConn ? `
      <div style="grid-column:1/-1">
        <div class="muted" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;margin:.6rem 0 .45rem">
          nginx connections
        </div>
        <div class="kpi-grid" style="grid-template-columns:repeat(auto-fill,minmax(180px,1fr))">
          ${miniCard('active', escapeHTML(String(conn.active ?? '-')), '', null)}
          ${miniCard('reading', escapeHTML(String(conn.reading ?? '-')), '', null)}
          ${miniCard('writing', escapeHTML(String(conn.writing ?? '-')), '', null)}
          ${miniCard('waiting', escapeHTML(String(conn.waiting ?? '-')), '', null)}
          ${miniCard('accepted (total)', escapeHTML(String(conn.accepted ?? '-')), '', null)}
          ${miniCard('handled (total)', escapeHTML(String(conn.handled ?? '-')), '', null)}
          ${miniCard('requests (total)', escapeHTML(String(conn.requests ?? '-')), '', null)}
        </div>
      </div>` : `
      <div style="grid-column:1/-1">
        <div class="muted" style="font-size:.78rem;margin-top:.4rem">
          nginx connection counters unavailable (stub_status variables not exposed by this build)
        </div>
      </div>`;

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
          ${miniCard('worker exiting', wk.exiting ? '<span style="color:var(--danger)">yes</span>' : 'no', '', null)}
        </div>
      </div>`;

    el.nginxStatsGrid.innerHTML =
      dictSection + sslHealthSection + decSection + (wafExclSection || '') + wafRulesSection + connSection + nginxSection;
  }

  function dictCard(name, d) {
    if (!d || d.error) {
      return `<div class="mini-card"><div class="muted">${escapeHTML(name)}</div><div class="muted">unavailable</div></div>`;
    }
    const pct = Math.min(100, Math.max(0, d.used_pct || 0));
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
    renderHealth();
    renderNginxOverview();
    renderCacheOverview();
    renderThrottleOverview();
    renderNginxStats();
  } catch (e) {
    renderHealth();
    renderNginxOverview();
    renderCacheOverview();
    renderThrottleOverview();
    if (el.nginxStatsGrid) {
      el.nginxStatsGrid.innerHTML = `<p class="muted" style="grid-column:1/-1">Lua stats unavailable: ${escapeHTML(e.message)}</p>`;
    }
  }
}


  function linkCard(href, label, value, sub, danger) {
    return `<a class="mini-card" style="text-decoration:none;color:inherit;display:block" href="${href}">
      <div class="muted">${label}</div>
      <div><strong${danger ? ' style="color:var(--danger)"' : ''}>${value}</strong>${sub ? `<span class="muted"> ${sub}</span>` : ''}</div>
    </a>`;
  }

  // Security at a glance: blocked IPs, active challenges, WAF activity,
  // suspicious vhosts — each card deep-links into its page. Admin-only
  // endpoints; the whole card row hides for scoped tokens.
  async function refreshSecurityOverview() {
    if (!el.securityGrid) return;
    if (state.scoped) {
      if (el.securityCard) el.securityCard.style.display = 'none';
      return;
    }
    const safe = (p) => api(p).catch(() => null);
    const [fw, ch, waf, susp] = await Promise.all([
      safe('/v1/firewall/list'),
      safe('/v1/challenge/vhosts?status=active&mode=all&limit=500'),
      safe('/v1/waf/engine/summary?hours=24&limit=1&top=1'),
      safe('/v1/webdet/suspicious?limit=100'),
    ]);
    const rows = (payload, key = 'rows') => (Array.isArray(payload) ? payload : (payload && Array.isArray(payload[key]) ? payload[key] : []));
    const cards = [];
    if (fw) {
      cards.push(linkCard('/cfm-admin/firewall/', 'Blocked IPs', escapeHTML(String(fw.total ?? 0)),
        `${escapeHTML(String(fw.permanent ?? 0))} permanent`, false));
    }
    if (ch) {
      const n = rows(ch).length;
      cards.push(linkCard('/cfm-admin/webdetector/', 'Active challenges', escapeHTML(String(n)), 'vhosts', n > 0));
    }
    if (waf) {
      cards.push(linkCard('/cfm-admin/webdetector/waf/', 'WAF hits (24h)', escapeHTML(String(waf.total_events ?? 0)),
        `${escapeHTML(String(waf.blocked_events ?? 0))} blocked`, Number(waf.blocked_events) > 0));
    }
    if (susp) {
      const n = rows(susp).length;
      cards.push(linkCard('/cfm-admin/webdetector/', 'Suspicious vhosts', escapeHTML(String(n)), 'short window', n > 0));
    }
    el.securityGrid.innerHTML = cards.length ? cards.join('') : '<p class="muted">No security data available.</p>';
  }

  function renderDNAT(dnat) {
    const out = String(dnat?.output || '');
    if (el.dnatText) el.dnatText.textContent = out || '(empty)';
    if (!el.dnatSummary) return;
    if (!out.trim()) {
      el.dnatSummary.textContent = 'No DNAT output.';
      return;
    }
    const lines = out.split('\n').filter((l) => l.trim());
    const status = lines.find((l) => /state|status/i.test(l)) || lines[0] || '';
    el.dnatSummary.textContent = `${status.trim()} · ${lines.length} line(s)`;
  }

  function renderSSLStats(payload) {
    const st = payload?.stats;
    if (el.sslText) el.sslText.textContent = typeof st === 'string' ? st : JSON.stringify(st || {}, null, 2);
    if (!el.sslGrid) return;
    if (!st || typeof st !== 'object') {
      el.sslGrid.innerHTML = '<p class="muted">Collector stats unavailable.</p>';
      return;
    }
    const g = (a, b) => st[a] ?? st[b];
    const bySource = g('BySource', 'by_source') || {};
    const srcSub = Object.keys(bySource).length
      ? Object.entries(bySource).map(([k, v]) => `${escapeHTML(String(k))}:${escapeHTML(String(v))}`).join(' · ')
      : '';
    let genAge = '-';
    const gen = g('GeneratedAt', 'generated_at');
    if (gen) {
      const t = new Date(gen).getTime();
      if (Number.isFinite(t)) genAge = fmtAge(Math.max(0, Math.round((Date.now() - t) / 1000)));
    }
    el.sslGrid.innerHTML = [
      miniCard('exact hosts', escapeHTML(String(g('ExactHosts', 'exact_hosts') ?? '-')), '', null),
      miniCard('wildcard zones', escapeHTML(String(g('WildcardZones', 'wildcard_zones') ?? '-')), '', null),
      miniCard('unique cert pairs', escapeHTML(String(g('UniquePairs', 'unique_pairs') ?? '-')), srcSub, null),
      miniCard('known files', escapeHTML(String(g('KnownFiles', 'known_files') ?? '-')), '', null),
      miniCard('cached TLS', escapeHTML(String(g('CachedTLS', 'cached_tls') ?? '-')), '', null),
      miniCard('generated', escapeHTML(genAge), '', null),
    ].join('');
  }

  async function refreshAll() {
    setLoading(true);
    showMsg('');
    try {
      const [dnat, ssl] = await Promise.all([
        api('/v1/system/dnat'),
        api('/v1/system/ssl/stats'),
      ]);
      state.health = {};
      renderHealth();
      renderNginxOverview();
      renderCacheOverview();
      renderThrottleOverview();
      renderDNAT(dnat);
      renderSSLStats(ssl);
      if (el.lastUpdated) el.lastUpdated.textContent = 'Updated ' + new Date().toLocaleTimeString();
    } catch (e) {
      showMsg(`Refresh failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
    refreshLuaStats();
    refreshSecurityOverview();
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
      await api('/v1/firewall/unblock', {
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

  let autoTimer = null;
  function setAuto(on) {
    if (el.autoState) el.autoState.textContent = on ? 'ON' : 'OFF';
    if (el.toggleAutoBtn) el.toggleAutoBtn.textContent = on ? 'Stop' : 'Start';
    if (autoTimer) { window.clearInterval(autoTimer); autoTimer = null; }
    if (on) autoTimer = window.setInterval(() => { if (!state.loading) refreshAll(); }, 10000);
  }
  el.toggleAutoBtn?.addEventListener('click', () => setAuto(!autoTimer));
  setAuto(true);

  loadViewerContext({ resolveInitialMode: true }).then((ctx) => {
    state.scoped = ctx.scoped;
    controller.noteInitialModeResolved({ isScopedMode: ctx.scoped });
    if (!ctx.canWrite) {
      if (el.blockBtn) el.blockBtn.style.display = 'none';
      if (el.unblockBtn) el.unblockBtn.style.display = 'none';
    }
    refreshAll();
  });
})();
