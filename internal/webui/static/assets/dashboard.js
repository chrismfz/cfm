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
    health: null,       // health.snapshot.v1 payload (admin-only, 1m server cache)
    healthTs: null,     // health.timeseries.v1 payload (1h window, 5m buckets)
    healthError: null,
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
  nodeHealthCard:    document.getElementById('nodeHealthCard'),
  healthGrid:        document.getElementById('healthGrid'),
  healthStatusPill:  document.getElementById('healthStatusPill'),
  healthMeta:        document.getElementById('healthMeta'),
  cacheOverview:     document.getElementById('cacheOverview'),
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
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let x = v, i = 0;
    while (x >= 1024 && i < u.length - 1) {
      x /= 1024;
      i++;
    }
    return `${(x >= 10 || i === 0) ? x.toFixed(0) : x.toFixed(1)} ${u[i]}`;
  }

  function fmtDur(secs) {
    const n = Number(secs);
    if (!Number.isFinite(n) || n <= 0) return '-';
    const d = Math.floor(n / 86400);
    const h = Math.floor((n % 86400) / 3600);
    const m = Math.floor((n % 3600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
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

  function miniCard(label, value, sub, pct, spark) {
    return `<div class="mini-card">
      <div class="muted">${label}</div>
      <div><strong>${value}</strong>${sub ? `<span class="muted"> ${sub}</span>` : ''}</div>
      ${pct != null ? progressBar(pct) : ''}
      ${spark || ''}
    </div>`;
  }

  // Stat-tile trend sparkline: one series per tile (the tile label names it),
  // zero baseline, accent line over a soft area fill. Values feed in from the
  // health timeseries (1h window, 5m buckets ≈ 12 points).
  function sparkline(values, title) {
    const vals = (values || []).map(Number).filter(Number.isFinite);
    if (vals.length < 2) return '';
    const max = Math.max(...vals);
    if (max <= 0) return '';
    const W = 100, H = 26, P = 2;
    const step = W / (vals.length - 1);
    const pts = vals.map((v, i) =>
      `${(i * step).toFixed(1)},${(H - P - (Math.max(0, v) / max) * (H - 2 * P)).toFixed(1)}`);
    const line = `M${pts.join(' L')}`;
    return `<svg class="spark-mini" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img">
      ${title ? `<title>${escapeHTML(title)}</title>` : ''}
      <path class="spark-area" d="${line} L${W},${H} L0,${H} Z"></path>
      <path class="spark-line" d="${line}"></path>
    </svg>`;
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

  // ---- Node health (health.snapshot.v1 from /v1/health/snapshot) ----

  function healthPill(text, tone, title) {
    const cls = tone ? ` ${tone}` : '';
    const t = title ? ` title="${escapeHTML(title)}"` : '';
    return `<span class="pill${cls}"${t}>${text}</span>`;
  }

  function pctTone(p) {
    const v = Number(p);
    if (!Number.isFinite(v)) return '';
    if (v >= 90) return 'danger';
    if (v >= 75) return 'warn';
    return 'ok';
  }

  // Normalized good/neutral vocabularies of the snapshot's summary strings
  // (smart_health, mdadm_health, zfs_health, disk_wearout, mdadm.status).
  function storageTone(v) {
    const s = String(v || '').trim().toLowerCase();
    if (!s) return '';
    if (['ok', 'normal', 'healthy', 'pass', 'online', 'clean'].includes(s)) return 'ok';
    if (['unknown', 'n/a', 'none', 'no raid', 'no active raid'].includes(s)) return '';
    return 'danger';
  }

  function healthSectionHeading(text, extra) {
    return `<div class="muted" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;margin:.7rem 0 .45rem">
      ${escapeHTML(text)}${extra ? `<span class="muted" style="font-size:.72rem;text-transform:none;margin-left:.4rem">${extra}</span>` : ''}
    </div>`;
  }

  function collectHealthIssues(s) {
    const issues = [];
    const push = (tone, text) => issues.push({ tone, text });
    const rt = s.runtime || {};
    const disk = s.disk || {};
    const net = s.network || {};

    if (rt.cfm_daemon_live === false) push('danger', 'CFM daemon not running');
    if (rt.edge_status === 'inactive') push('danger', `edge ${rt.edge_service || '?'} inactive`);
    else if (rt.edge_status === 'degraded') push('warn', `edge ${rt.edge_service || '?'} degraded`);
    const flow = String(rt.challenge_flow_state || '').toUpperCase();
    if (flow === 'FAIL') push('danger', `challenge flow: ${rt.challenge_flow_reason || 'FAIL'}`);
    else if (flow === 'WARN') push('warn', `challenge flow: ${rt.challenge_flow_reason || 'WARN'}`);
    if (rt.ingest_socket_status === 'down') push('warn', 'ingest socket down');
    if (storageTone(disk.smart_health) === 'danger') push('danger', `SMART: ${disk.smart_health}`);
    if (storageTone(disk.disk_wearout) === 'danger') push('warn', `disk wearout: ${disk.disk_wearout}`);
    if (storageTone(disk.mdadm_health) === 'danger') push('danger', `MDADM: ${disk.mdadm_health}`);
    if (storageTone(disk.zfs_health) === 'danger') push('danger', `ZFS: ${disk.zfs_health}`);
    for (const m of (Array.isArray(disk.mounts) ? disk.mounts : [])) {
      const used = num(m.used_pct);
      const inode = num(m.inode_used_pct);
      if (used != null && used >= 90) push('danger', `${m.mount} at ${used.toFixed(1)}%`);
      else if (used != null && used >= 80) push('warn', `${m.mount} at ${used.toFixed(1)}%`);
      if (inode != null && inode >= 90) push('danger', `${m.mount} inodes at ${inode.toFixed(1)}%`);
    }
    const ctPct = num(net.conntrack_usage_pct);
    if (ctPct != null && ctPct >= 90) push('danger', `conntrack at ${ctPct.toFixed(0)}%`);
    else if (ctPct != null && ctPct >= 75) push('warn', `conntrack at ${ctPct.toFixed(0)}%`);
    if (s.error) push('warn', `collector: ${s.error}`);
    return issues;
  }

  function renderHealthHostTiles(s) {
    const host = s.host || {};
    const net = s.network || {};

    const tsPoints = Array.isArray(state.healthTs?.points) ? state.healthTs.points : [];
    const trend = (key, title) => sparkline(tsPoints.map((p) => p[key]), `${title} — last 1h (5m avg)`);

    const pct1 = (v) => {
      const n = num(v);
      return n == null ? '-' : `${n.toFixed(1)}%`;
    };

    const cpuPct = num(host.cpu_percent);
    const cpuSub = host.cpu_percent_source === 'procstat'
      ? `usr ${pct1(host.cpu_user_pct)} · sys ${pct1(host.cpu_system_pct)} · io ${pct1(host.cpu_iowait_pct)}`
      : 'load estimate';

    const load1 = num(host.load_avg_1);
    const threads = num(host.cpu_threads);
    const loadPct = (load1 != null && threads > 0) ? (load1 / threads) * 100 : null;
    const loadSub = `5m ${num(host.load_avg_5)?.toFixed(2) ?? '-'} · 15m ${num(host.load_avg_15)?.toFixed(2) ?? '-'}${threads > 0 ? ` · ${threads} threads` : ''}`;

    const memUsed = num(host.mem_used_bytes);
    const memTotal = num(host.mem_total_bytes);
    const memPct = (memUsed != null && memTotal > 0) ? (memUsed / memTotal) * 100 : null;

    const swapTotal = num(host.swap_total_bytes);
    const swapUsed = num(host.swap_used_bytes);
    const swapPct = (swapTotal > 0 && swapUsed != null) ? (swapUsed / swapTotal) * 100 : null;

    const ctCount = num(net.conntrack_count);
    const ctMax = num(net.conntrack_max);
    const ctPct = num(net.conntrack_usage_pct);

    return `<div class="kpi-grid" style="grid-template-columns:repeat(auto-fill,minmax(200px,1fr))">
      ${miniCard('CPU', cpuPct != null ? escapeHTML(`${cpuPct.toFixed(1)}%`) : '-', escapeHTML(cpuSub), cpuPct, trend('cpu_pct', 'CPU busy %'))}
      ${miniCard('Load avg (1m)', load1 != null ? escapeHTML(load1.toFixed(2)) : '-', escapeHTML(loadSub), loadPct, trend('load1', 'Load avg (1m)'))}
      ${miniCard('RAM', memTotal > 0 ? escapeHTML(`${fmtBytes(memUsed)} / ${fmtBytes(memTotal)}`) : '-', memPct != null ? escapeHTML(`${memPct.toFixed(1)}%`) : '', memPct, trend('ram_used_pct', 'RAM used %'))}
      ${miniCard('Swap', swapTotal > 0 ? escapeHTML(`${fmtBytes(swapUsed)} / ${fmtBytes(swapTotal)}`) : 'none', swapPct != null ? escapeHTML(`${swapPct.toFixed(1)}%`) : '', swapPct, swapTotal > 0 ? trend('swap_used_pct', 'Swap used %') : '')}
      ${miniCard('Conntrack', (ctCount != null && ctMax > 0) ? escapeHTML(`${ctCount} / ${ctMax}`) : '-', ctPct != null ? escapeHTML(`${ctPct.toFixed(1)}%`) : '', ctPct)}
      ${miniCard('Net in', `↓ ${escapeHTML(fmtBytes(net.bandwidth_in_bps))}/s`, '', null, trend('rx_mbps', 'Inbound Mbps'))}
      ${miniCard('Net out', `↑ ${escapeHTML(fmtBytes(net.bandwidth_out_bps))}/s`, '', null, trend('tx_mbps', 'Outbound Mbps'))}
    </div>`;
  }

  function renderHealthRuntimeChips(s) {
    const rt = s.runtime || {};
    const chips = [];
    const chip = (label, value, tone, title) =>
      chips.push(healthPill(`${escapeHTML(label)}: <strong>${escapeHTML(value)}</strong>`, tone, title));

    chip('CFM daemon',
      rt.cfm_daemon_live ? `live${rt.cfm_daemon_pid ? ` · pid ${rt.cfm_daemon_pid}` : ''}` : 'down',
      rt.cfm_daemon_live ? 'ok' : 'danger');

    const onOff = (v) => {
      const val = String(v || 'unknown');
      return { val, tone: val === 'on' ? 'ok' : (val === 'off' ? '' : 'warn') };
    };
    const webDnat = onOff(rt.dnat_enabled);
    chip('Web DNAT', webDnat.val, webDnat.tone, rt.dnat_warning || '');
    const panelDnat = onOff(rt.panel_dnat_enabled);
    chip('Panel DNAT', panelDnat.val, panelDnat.tone);

    const edgeTone = rt.edge_status === 'active' ? 'ok' : (rt.edge_status === 'degraded' ? 'warn' : 'danger');
    chip('Edge', `${rt.edge_service || 'unknown'} · ${rt.edge_status || 'unknown'}`, edgeTone, rt.edge_reason_code || '');
    chip('Upstream', `${rt.upstream_service || 'unknown'} · ${rt.upstream_status || 'unknown'}`,
      rt.upstream_status === 'active' ? 'ok' : '', rt.upstream_reason_code || '');

    const flow = String(rt.challenge_flow_state || 'unknown').toUpperCase();
    chip('Challenge flow', flow,
      flow === 'OK' ? 'ok' : (flow === 'WARN' ? 'warn' : (flow === 'FAIL' ? 'danger' : '')),
      rt.challenge_flow_reason || '');

    const ssl = String(rt.sslcollector_status || '');
    chip('SSL collector', ssl === 'transport' ? 'OK' : (ssl || 'unknown'),
      ssl === 'transport' ? 'ok' : 'danger');

    const ingest = String(rt.ingest_socket_status || 'unknown');
    chip('Ingest', ingest,
      ingest === 'live' ? 'ok' : (ingest === 'listening' ? 'warn' : (ingest === 'down' ? 'danger' : '')),
      rt.ingest_socket_reason || rt.ingest_socket_path || '');

    for (const svc of (Array.isArray(s.services) ? s.services : [])) {
      const tone = svc.active ? 'ok'
        : (svc.name === 'cfm' || svc.enabled) ? 'danger'
        : '';
      chip(svc.name, `${svc.state || 'unknown'}${svc.enabled ? '' : ' · disabled'}`, tone);
    }

    return `<div style="display:flex;flex-wrap:wrap;gap:.3rem .1rem">${chips.join('')}</div>`;
  }

  function renderHealthDisks(s) {
    const disk = s.disk || {};
    const mounts = Array.isArray(disk.mounts) ? disk.mounts : [];
    if (!mounts.length) return '';

    const rows = mounts.map((m) => {
      const used = num(m.used_pct);
      const inode = num(m.inode_used_pct);
      const tone = pctTone(used);
      const usedStyle = tone === 'danger' ? 'color:var(--danger)' : (tone === 'warn' ? 'color:var(--warn)' : '');
      return `<tr>
        <td><code>${escapeHTML(m.mount || '-')}</code></td>
        <td>${escapeHTML(fmtBytes(m.used_bytes))} / ${escapeHTML(fmtBytes(m.total_bytes))}</td>
        <td style="min-width:140px">
          <span style="${usedStyle}">${used != null ? `${used.toFixed(1)}%` : '-'}</span>
          ${used != null ? progressBar(used) : ''}
        </td>
        <td>${inode != null && num(m.total_inodes) > 0 ? `${inode.toFixed(1)}%` : 'n/a'}</td>
      </tr>`;
    }).join('');

    return `${healthSectionHeading('Disks')}
      <div class="table-wrap">
        <table class="compact-table" style="width:100%">
          <thead><tr><th>Mount</th><th>Used / Total</th><th>Use %</th><th>Inodes %</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  }

  function renderHealthStorage(s) {
    const disk = s.disk || {};
    const devs = disk.smart_devices || {};
    const devNames = Object.keys(devs).sort();
    const chips = [
      healthPill(`SMART: <strong>${escapeHTML(disk.smart_health || 'unknown')}</strong>`, storageTone(disk.smart_health)),
      healthPill(`Wearout: <strong>${escapeHTML(disk.disk_wearout || 'unknown')}</strong>`, storageTone(disk.disk_wearout)),
      healthPill(`MDADM: <strong>${escapeHTML(disk.mdadm_health || disk.mdadm?.status || 'unknown')}</strong>`, storageTone(disk.mdadm_health || disk.mdadm?.status)),
      healthPill(`ZFS: <strong>${escapeHTML(disk.zfs_health || 'unknown')}</strong>`, storageTone(disk.zfs_health)),
    ].join('');

    // Always-visible table (was a <details> — the innerHTML rebuild on each
    // auto-refresh reset it to collapsed, hiding the data every 10s).
    let devTable = '';
    if (devNames.length) {
      const rows = devNames.map((name) => {
        const d = devs[name] || {};
        const wear = d.wearout_pct_used != null ? `${d.wearout_pct_used}% used` : 'n/a';
        const health = d.normalized_health || d.health || (d.error ? 'error' : 'unknown');
        return `<tr>
          <td><code>${escapeHTML(name)}</code></td>
          <td>${escapeHTML(d.model || '-')}</td>
          <td>${escapeHTML(d.device_type || '-')}</td>
          <td>${healthPill(escapeHTML(health), storageTone(health), d.error || '')}</td>
          <td>${escapeHTML(wear)}</td>
          <td>${escapeHTML(d.temperature_c ? `${d.temperature_c}°C` : '-')}</td>
        </tr>`;
      }).join('');
      devTable = `<div class="table-wrap" style="margin-top:.45rem">
        <table class="compact-table" style="width:100%">
          <thead><tr><th>Device</th><th>Model</th><th>Type</th><th>Health</th><th>Wearout</th><th>Temp</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
    }

    return `${healthSectionHeading('Storage health')}
      <div style="display:flex;flex-wrap:wrap;gap:.3rem .1rem">${chips}</div>
      ${devTable}`;
  }

  function renderHealth() {
    if (!el.healthGrid) return;
    const s = state.health;

    if (!s) {
      if (state.healthError) {
        el.healthGrid.innerHTML = `<p class="muted">Health snapshot unavailable: ${escapeHTML(state.healthError)}</p>`;
        if (el.healthStatusPill) el.healthStatusPill.innerHTML = healthPill('unavailable', 'warn');
      }
      return;
    }

    const issues = collectHealthIssues(s);
    const worst = issues.some((i) => i.tone === 'danger') ? 'danger' : (issues.length ? 'warn' : 'ok');
    if (el.healthStatusPill) {
      el.healthStatusPill.innerHTML = worst === 'ok'
        ? healthPill('healthy', 'ok')
        : healthPill(`${issues.length} issue${issues.length > 1 ? 's' : ''}`, worst, issues.map((i) => i.text).join(' · '));
    }
    if (el.healthMeta) {
      const host = s.host || {};
      let age = '-';
      const t = new Date(s.collected_at).getTime();
      if (Number.isFinite(t)) age = fmtAge(Math.max(0, Math.round((Date.now() - t) / 1000)));
      const parts = [s.node_id || host.hostname || '', `collected ${age}`];
      if (num(host.uptime_seconds) > 0) parts.push(`up ${fmtDur(host.uptime_seconds)}`);
      if (host.os_pretty_name) parts.push(host.os_pretty_name);
      el.healthMeta.textContent = parts.filter(Boolean).join(' · ');
    }

    const issueBanner = issues.length
      ? `<div style="display:flex;flex-wrap:wrap;gap:.3rem .1rem;margin-bottom:.55rem">
          ${issues.map((i) => healthPill(escapeHTML(i.text), i.tone)).join('')}
        </div>`
      : '';

    el.healthGrid.innerHTML =
      issueBanner +
      renderHealthHostTiles(s) +
      healthSectionHeading('Edge / runtime') +
      renderHealthRuntimeChips(s) +
      renderHealthDisks(s) +
      renderHealthStorage(s);
  }

  async function refreshHealthSnapshot() {
    if (!el.healthGrid) return;
    if (state.scoped) {
      // /v1/health/snapshot is admin-only; hide the card for scoped viewers.
      if (el.nodeHealthCard) el.nodeHealthCard.style.display = 'none';
      return;
    }
    try {
      const [snap, ts] = await Promise.all([
        api('/v1/health/snapshot?cache_ttl=60s'),
        // Trend data for the tile sparklines; best-effort — the card renders
        // fine without it (empty ring store, older daemon).
        api('/v1/health/timeseries?window=1h&step=5m').catch(() => null),
      ]);
      state.health = snap;
      state.healthTs = ts;
      state.healthError = null;
    } catch (e) {
      state.health = null;
      state.healthTs = null;
      state.healthError = e.message;
    }
    renderHealth();
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
    <div class="muted" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;margin:.6rem 0 .45rem">
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

    // One merged nginx section (version/worker identity + live connection
    // gauges). Counter cards whose value the build doesn't expose
    // (accepted/handled/requests without stub_status) are omitted instead
    // of rendering "-" tiles.
    const optCard = (label, v, sub) =>
      Number.isFinite(Number(v)) ? miniCard(label, escapeHTML(String(v)), sub || '', null) : '';
    const hasConn = [conn.active, conn.reading, conn.writing, conn.waiting].some((v) => Number.isFinite(Number(v)));

    const nginxSection = `
      <div style="grid-column:1/-1">
        <div class="muted" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;margin-bottom:.45rem">
          nginx — worker &amp; connections
        </div>
        <div class="kpi-grid" style="grid-template-columns:repeat(auto-fill,minmax(180px,1fr))">
          ${miniCard('version', escapeHTML(ng.version_str || String(ng.version || '-')), '', null)}
          ${miniCard('workers', escapeHTML(String(wk.count ?? '-')), wk.pid ? escapeHTML(`this: pid ${wk.pid} · id ${wk.id ?? '-'}`) : '', null)}
          ${wk.exiting ? miniCard('worker exiting', '<span style="color:var(--danger)">yes</span>', '', null) : ''}
          ${optCard('active', conn.active)}
          ${optCard('reading', conn.reading)}
          ${optCard('writing', conn.writing)}
          ${optCard('waiting', conn.waiting)}
          ${optCard('accepted', conn.accepted, 'total')}
          ${optCard('handled', conn.handled, 'total')}
          ${optCard('requests', conn.requests, 'total')}
        </div>
        ${hasConn ? '' : `<div class="muted" style="font-size:.78rem;margin-top:.4rem">
          nginx connection counters unavailable (stub_status variables not exposed by this build)
        </div>`}
      </div>`;

    el.nginxStatsGrid.innerHTML =
      nginxSection + dictSection + sslHealthSection + decSection + (wafExclSection || '') + wafRulesSection;
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
    renderCacheOverview();
    renderNginxStats();
  } catch (e) {
    renderCacheOverview();
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
      renderCacheOverview();
      renderDNAT(dnat);
      renderSSLStats(ssl);
      if (el.lastUpdated) el.lastUpdated.textContent = 'Updated ' + new Date().toLocaleTimeString();
    } catch (e) {
      showMsg(`Refresh failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
    refreshLuaStats();
    refreshHealthSnapshot();
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
