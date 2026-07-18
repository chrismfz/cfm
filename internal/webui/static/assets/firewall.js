// /cfm-admin/assets/firewall.js
//
// Firewall page — the read/undo side of manual IP blocks. Every Block button
// in the panel writes here-visible state; this page finally shows it:
//
//   GET  /api/v1/firewall/list      — blocked IPs + TTL + comment + GeoIP
//   POST /api/v1/firewall/block     — manual block (same as Quick controls)
//   POST /unblock?ip=…              — cross-layer unblock (nft + WAF planes +
//                                     CSF/Fail2Ban/Imunify background cleanup)
//
// Admin-only endpoints; scoped tokens never see this page's data.

(() => {
  const controller = window.CFMControllerBootstrap.initSharedController({});
  const api = controller.createApiClient({
    basePath: '/cfm-admin/api',
    isScoped: () => false,
  });

  const el = {
    refreshBtn: document.getElementById('refreshBtn'),
    toggleAutoBtn: document.getElementById('toggleAutoBtn'),
    autoState: document.getElementById('autoState'),
    lastUpdated: document.getElementById('lastUpdated'),
    actionMsg: document.getElementById('actionMsg'),
    summary: document.getElementById('fwSummary'),
    search: document.getElementById('fwSearch'),
    onlyPermanent: document.getElementById('fwOnlyPermanent'),
    body: document.getElementById('fwBody'),
    blockIP: document.getElementById('blockIP'),
    blockTTL: document.getElementById('blockTTL'),
    blockReason: document.getElementById('blockReason'),
    blockBtn: document.getElementById('blockBtn'),
  };

  const st = {
    auto: true,
    timer: null,
    rows: [],
    total: 0,
    permanent: 0,
  };

  function escapeHTML(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function flashMsg(text, kind) {
    if (!el.actionMsg) return;
    el.actionMsg.textContent = text || '';
    el.actionMsg.style.display = text ? '' : 'none';
    el.actionMsg.className = 'pill' + (kind ? ' ' + kind : '');
    if (text) {
      window.clearTimeout(flashMsg._t);
      flashMsg._t = window.setTimeout(() => { el.actionMsg.style.display = 'none'; }, 6000);
    }
  }

  function fmtExpires(row) {
    if (row.permanent) return '<span class="pill danger">permanent</span>';
    const secs = Number(row.expires_in_sec || 0);
    if (secs <= 0) return 'expiring…';
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    if (h >= 48) return `${Math.floor(h / 24)}d ${h % 24}h`;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m`;
    return `${secs}s`;
  }

  async function loadAll() {
    try {
      const res = await api('/v1/firewall/list');
      st.rows = Array.isArray(res?.rows) ? res.rows : [];
      st.total = Number(res?.total || 0);
      st.permanent = Number(res?.permanent || 0);
      render();
      if (el.lastUpdated) el.lastUpdated.textContent = 'Updated ' + new Date().toLocaleTimeString();
    } catch (err) {
      console.error('[firewall] load failed', err);
      flashMsg(`load failed: ${err.message || err}`, 'danger');
    }
  }

  function visibleRows() {
    const q = (el.search?.value || '').trim().toLowerCase();
    let rows = st.rows;
    if (el.onlyPermanent?.checked) rows = rows.filter((r) => r.permanent);
    if (!q) return rows;
    return rows.filter((r) =>
      String(r.ip || '').toLowerCase().includes(q)
      || String(r.comment || '').toLowerCase().includes(q)
      || String(r.country || '').toLowerCase().includes(q)
      || String(r.asn_name || '').toLowerCase().includes(q));
  }

  function render() {
    if (el.summary) {
      el.summary.textContent = `${st.total} blocked IP(s) — ${st.permanent} permanent, ${st.total - st.permanent} temporary`;
    }
    if (!el.body) return;
    const rows = visibleRows();
    if (!rows.length) {
      el.body.innerHTML = '<tr><td colspan="6" class="muted">' + (st.total ? 'no rows match the filter' : 'no blocked IPs — all quiet') + '</td></tr>';
      return;
    }
    el.body.innerHTML = rows.map((r) => {
      const cc = r.country ? escapeHTML(r.country) : '-';
      const asn = r.asn ? ` AS${escapeHTML(String(r.asn))}` : '';
      const asnName = r.asn_name ? escapeHTML(r.asn_name) : '';
      return `<tr>
        <td><code>${escapeHTML(r.ip)}</code></td>
        <td>${fmtExpires(r)}</td>
        <td class="truncate" title="${asnName}">${cc}${asn} ${asnName}</td>
        <td class="truncate" title="${escapeHTML(r.comment || '')}">${escapeHTML(r.comment || '-')}</td>
        <td class="actions-cell">
          <a class="btn-quiet btn-sm" href="/cfm-admin/webdetector/forensics/?ip=${encodeURIComponent(r.ip)}#history-card">History</a>
          <button class="btn-danger btn-sm" data-unblock="${escapeHTML(r.ip)}">Unblock</button>
        </td>
      </tr>`;
    }).join('');

    el.body.querySelectorAll('button[data-unblock]').forEach((btn) => {
      btn.addEventListener('click', () => unblockIP(btn.dataset.unblock));
    });
  }

  async function unblockIP(ip) {
    if (!ip) return;
    if (!window.confirm(`Unblock ${ip}?\n\nRemoves it from nft immediately and clears WAF/challenge state; CSF/Fail2Ban/Imunify cleanup runs in the background.`)) return;
    try {
      // /unblock lives at the root (not under /api) — call it through the
      // cfm-admin prefix directly.
      const res = await fetch('/cfm-admin/unblock?ip=' + encodeURIComponent(ip), {
        method: 'POST',
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data?.ok === false) throw new Error(data?.error || `HTTP ${res.status}`);
      flashMsg(`Unblocked ${ip}${data.was_blocked ? '' : ' (was not in nft — cleared other layers)'}`, '');
      await loadAll();
    } catch (err) {
      flashMsg(`Unblock failed for ${ip}: ${err.message || err}`, 'danger');
    }
  }

  async function blockIP() {
    const ip = (el.blockIP?.value || '').trim();
    if (!ip) { flashMsg('Provide an IP to block.', 'warn'); return; }
    const ttl = el.blockTTL?.value ?? '1h';
    if (ttl === '' && !window.confirm(`PERMANENTLY block ${ip}?\n\nA permanent block never expires (it survives restarts).`)) return;
    try {
      await api('/v1/firewall/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, ttl, reason: (el.blockReason?.value || '').trim() || 'firewall page manual block' }),
      });
      flashMsg(`Blocked ${ip}${ttl ? ` for ${ttl}` : ' permanently'}`, '');
      if (el.blockIP) el.blockIP.value = '';
      await loadAll();
    } catch (err) {
      flashMsg(`Block failed for ${ip}: ${err.message || err}`, 'danger');
    }
  }

  function setAuto(on) {
    st.auto = on;
    if (el.autoState) el.autoState.textContent = on ? 'ON' : 'OFF';
    if (el.toggleAutoBtn) el.toggleAutoBtn.textContent = on ? 'Stop' : 'Start';
    if (st.timer) { window.clearInterval(st.timer); st.timer = null; }
    if (on) st.timer = window.setInterval(loadAll, 10000);
  }

  el.refreshBtn?.addEventListener('click', loadAll);
  el.toggleAutoBtn?.addEventListener('click', () => setAuto(!st.auto));
  el.search?.addEventListener('input', render);
  el.onlyPermanent?.addEventListener('change', render);
  el.blockBtn?.addEventListener('click', blockIP);
  el.blockIP?.addEventListener('keydown', (e) => { if (e.key === 'Enter') blockIP(); });

  // ?q= prefills the search (palette deep-link: "Firewall: check 1.2.3.4").
  const q = new URLSearchParams(window.location.search).get('q');
  if (q && el.search) el.search.value = q.trim();

  setAuto(true);
  loadAll();
})();
