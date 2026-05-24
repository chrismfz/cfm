// /cfm-admin/assets/bots.js
//
// Web Bots page — box-wide UA emergency control surface.
// Mirrors the `cfm bots` CLI: live UA top + active emergency rules + the
// throttle/block/allow/undo action buttons. Talks to the same five JSON
// endpoints exposed by the webdetector apiserver:
//
//   GET    /api/v1/webdet/ua-top
//   GET    /api/v1/webdet/ua-emergency
//   POST   /api/v1/webdet/ua-emergency        { ua, action, ttl_seconds, reason, confirm }
//   DELETE /api/v1/webdet/ua-emergency?ua=<name>
//
// Server-side enforces TTL cap (60m), normalizes the UA, and refuses to
// touch verified Google crawlers unless { confirm: true } is in the body.

(() => {
  const controller = window.CFMControllerBootstrap.initSharedController({});
  const api = controller.createApiClient({
    basePath: '/cfm-admin/api',
    isScoped: () => false,
  });

  const el = {
    autoState:       document.getElementById('autoState'),
    refreshBtn:      document.getElementById('refreshBtn'),
    toggleAutoBtn:   document.getElementById('toggleAutoBtn'),
    ttlSelect:       document.getElementById('ttlSelect'),
    reasonInput:     document.getElementById('reasonInput'),
    actionMsg:       document.getElementById('actionMsg'),
    uaTopBody:       document.getElementById('uaTopBody'),
    activeRulesBody: document.getElementById('activeRulesBody'),
  };

  const st = {
    auto: true,
    timer: null,
    topRows: [],
    rulesByUA: Object.create(null),
  };

  // Mirrors IsGoogleVerifiedBot in internal/webdetector/ua_top.go. Used only
  // to surface a warning before the operator clicks — the server enforces
  // the actual block via the 409 conflict response.
  const GOOGLE_VERIFIED = new Set([
    'googlebot',
    'googlebot-image',
    'googlebot-news',
    'googlebot-video',
    'adsbot-google',
    'adsbot-google-mobile',
    'mediapartners-google',
    'storebot-google',
    'feedfetcher-google',
    'googleother',
  ]);

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
      flashMsg._t = window.setTimeout(() => {
        el.actionMsg.style.display = 'none';
      }, 5000);
    }
  }

  function fmtNum(v) {
    if (v == null || Number.isNaN(Number(v))) return '-';
    const n = Number(v);
    if (Math.abs(n) >= 100) return n.toFixed(0);
    return n.toFixed(2);
  }

  function fmtExpiresIn(rfc3339) {
    if (!rfc3339) return '-';
    const exp = new Date(rfc3339).getTime();
    if (!Number.isFinite(exp)) return '-';
    const secs = Math.max(0, Math.round((exp - Date.now()) / 1000));
    if (secs <= 0) return 'expired';
    if (secs < 60) return secs + 's';
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return s ? `${m}m ${s}s` : `${m}m`;
  }

  function readTTLSec() {
    const n = Number(el.ttlSelect?.value);
    return Number.isFinite(n) && n > 0 ? n : 1800;
  }

  function readReason() {
    return (el.reasonInput?.value || '').trim();
  }

  // ── data loading ──────────────────────────────────────────────────────────

  async function loadAll() {
    try {
      const [rows, rules] = await Promise.all([
        api('/api/v1/webdet/ua-top?limit=50'),
        api('/api/v1/webdet/ua-emergency'),
      ]);
      st.topRows = Array.isArray(rows) ? rows : [];
      const byUA = Object.create(null);
      (Array.isArray(rules) ? rules : []).forEach((r) => { byUA[r.ua] = r; });
      st.rulesByUA = byUA;
      renderTop();
      renderRules(Array.isArray(rules) ? rules : []);
    } catch (err) {
      console.error('[bots] load failed', err);
      flashMsg(`load failed: ${err.message || err}`, 'danger');
    }
  }

  // ── render ────────────────────────────────────────────────────────────────

  function renderTop() {
    if (!el.uaTopBody) return;
    if (!st.topRows.length) {
      el.uaTopBody.innerHTML = `<tr><td colspan="8" class="muted">no UA traffic in window</td></tr>`;
      return;
    }
    const rows = st.topRows.map((r, i) => {
      const ua = String(r.ua || '-');
      const isGoogle = GOOGLE_VERIFIED.has(ua);
      const active = st.rulesByUA[ua];
      const activeCell = active
        ? `<span class="pill warn">${escapeHTML(active.action)} · ${escapeHTML(fmtExpiresIn(active.expires_at))}</span>`
        : '<span class="muted">-</span>';
      const googleBadge = isGoogle
        ? ' <span class="pill warn" title="verified Google crawler — confirmation required">G</span>'
        : '';
      return `
        <tr>
          <td>${i + 1}</td>
          <td><strong>${escapeHTML(ua)}</strong>${googleBadge}</td>
          <td>${fmtNum(r.rps)}</td>
          <td>${escapeHTML(String(r.reqs ?? 0))}</td>
          <td>${escapeHTML(String(r.unique_ips ?? 0))}</td>
          <td>${escapeHTML(String(r.vhosts ?? 0))}</td>
          <td>${activeCell}</td>
          <td class="actions-cell">
            <button class="btn-sm" data-act="throttle" data-ua="${escapeHTML(ua)}">throttle</button>
            <button class="btn-sm btn-danger" data-act="block" data-ua="${escapeHTML(ua)}">block</button>
            <button class="btn-sm" data-act="allow" data-ua="${escapeHTML(ua)}">allow</button>
          </td>
        </tr>`;
    });
    el.uaTopBody.innerHTML = rows.join('');
  }

  function renderRules(rules) {
    if (!el.activeRulesBody) return;
    if (!rules.length) {
      el.activeRulesBody.innerHTML = `<tr><td colspan="7" class="muted">no active emergency rules</td></tr>`;
      return;
    }
    el.activeRulesBody.innerHTML = rules.map((r) => `
      <tr>
        <td><strong>${escapeHTML(r.ua)}</strong></td>
        <td>${escapeHTML(r.action)}</td>
        <td>${escapeHTML(fmtExpiresIn(r.expires_at))}</td>
        <td>${escapeHTML(String(r.hits ?? 0))}</td>
        <td>${escapeHTML(r.created_by || '-')}</td>
        <td>${escapeHTML(r.reason || '')}</td>
        <td><button class="btn-sm" data-undo="${escapeHTML(r.ua)}">undo</button></td>
      </tr>`).join('');
  }

  // ── actions ───────────────────────────────────────────────────────────────

  async function applyAction(ua, action, opts = {}) {
    const isGoogle = GOOGLE_VERIFIED.has(ua);
    const confirm = Boolean(opts.confirm);
    if (isGoogle && !confirm) {
      const yes = window.confirm(
        `"${ua}" is a verified Google crawler. Continuing may break SEO ` +
        `(crawl coverage, image search) for the duration of the rule.\n\n` +
        `Are you sure you want to ${action} this UA box-wide?`
      );
      if (!yes) return;
    }
    try {
      const r = await api('/api/v1/webdet/ua-emergency', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ua,
          action,
          ttl_seconds: readTTLSec(),
          reason: readReason(),
          confirm: isGoogle ? true : undefined,
        }),
      });
      flashMsg(`✓ ${r.action} ${r.ua} for ${Math.round((new Date(r.expires_at) - new Date(r.created_at)) / 60000)}m`, 'success');
      await loadAll();
    } catch (err) {
      if (err.status === 409 && err.data?.error === 'google_verified_bot_requires_confirm') {
        // Should be unreachable because we send confirm:true for Google
        // already, but surface defensively.
        flashMsg(`⚠ ${err.data?.message || 'confirmation required'}`, 'warn');
        return;
      }
      flashMsg(`✖ ${err.message || err}`, 'danger');
    }
  }

  async function undoRule(ua) {
    try {
      const r = await api(`/api/v1/webdet/ua-emergency?ua=${encodeURIComponent(ua)}`, {
        method: 'DELETE',
      });
      flashMsg(`✓ undone ${r.ua}`, 'success');
      await loadAll();
    } catch (err) {
      flashMsg(`✖ ${err.message || err}`, 'danger');
    }
  }

  // ── event wiring ──────────────────────────────────────────────────────────

  el.uaTopBody?.addEventListener('click', (ev) => {
    const btn = ev.target.closest('button[data-act]');
    if (!btn) return;
    const ua = btn.getAttribute('data-ua') || '';
    const act = btn.getAttribute('data-act') || '';
    if (!ua || !act) return;
    applyAction(ua, act);
  });

  el.activeRulesBody?.addEventListener('click', (ev) => {
    const btn = ev.target.closest('button[data-undo]');
    if (!btn) return;
    const ua = btn.getAttribute('data-undo') || '';
    if (!ua) return;
    undoRule(ua);
  });

  el.refreshBtn?.addEventListener('click', () => { loadAll(); });

  el.toggleAutoBtn?.addEventListener('click', () => {
    st.auto = !st.auto;
    el.autoState.textContent = st.auto ? 'ON' : 'OFF';
    el.toggleAutoBtn.textContent = st.auto ? 'Stop' : 'Start';
    if (st.auto) startTimer(); else stopTimer();
  });

  function startTimer() {
    stopTimer();
    st.timer = window.setInterval(loadAll, 2500);
  }
  function stopTimer() {
    if (st.timer) { window.clearInterval(st.timer); st.timer = null; }
  }

  // ── bootstrap ─────────────────────────────────────────────────────────────

  (async () => {
    try {
      // Wait briefly for the scoped/admin token to land so the first /ua-top
      // call doesn't return 401.
      if (typeof window.CFMAuthContext?.waitForToken === 'function') {
        await window.CFMAuthContext.waitForToken(450);
      }
    } catch (_) {}
    await loadAll();
    if (st.auto) startTimer();
  })();
})();
