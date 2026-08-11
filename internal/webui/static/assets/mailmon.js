// /cfm-admin/assets/mailmon.js
//
// Mail Monitor page — mail traffic over a window (Mail Monitor stage 1). Reads
// the per-hour counters the mailtraffic collector persists (exim mainlog +
// syslog maillog), with no per-request MTA probe:
//
//   GET /api/v1/mail/traffic?hours=<N>&limit=<N>
//
// Scope-aware and fail-closed server-side: admins see the whole server; a
// scoped cPanel viewer sees only its own domains. Host-wide ("*") and
// local-unix-user rows are admin-only by construction, so the "Local script
// submitters" card is hidden for scoped viewers. `available:false` (collector
// not enabled yet) is surfaced as a note, not an error.

(() => {
  const controller = window.CFMControllerBootstrap.initSharedController({
    onDeferredScopedToken: () => { boot().catch(() => {}); },
  });
  const TOKEN_BOOT_WAIT_MS = 2500;

  function waitForScopedTokenOrTimeout(timeoutMs = TOKEN_BOOT_WAIT_MS) {
    if (controller.getToken()) return Promise.resolve('present');
    return controller.waitForToken(timeoutMs).then((tok) => {
      controller.refreshToken();
      return tok ? 'postmessage' : 'timeout';
    });
  }

  const st = { auto: true, timer: null, isScopedMode: false, booted: false };
  const REFRESH_MS = 30000;

  // The endpoint is read-only and scope-allowed, so there are no admin-only API
  // paths to gate client-side; the server fails closed on its own.
  const api = controller.createApiClient({
    basePath: '/cfm-admin/api',
    isScoped: () => st.isScopedMode,
  });

  const el = {
    meta:          document.getElementById('mmMeta'),
    unavailable:   document.getElementById('mmUnavailable'),
    totals:        document.getElementById('totals'),
    outBody:       document.getElementById('outBody'),
    domBody:       document.getElementById('domBody'),
    localBody:     document.getElementById('localBody'),
    localCard:     document.getElementById('localCard'),
    inBody:        document.getElementById('inBody'),
    authFailBody:  document.getElementById('authFailBody'),
    throttledBody: document.getElementById('throttledBody'),
    overQuotaBody: document.getElementById('overQuotaBody'),
    hoursSel:      document.getElementById('hoursSel'),
    autoState:     document.getElementById('autoState'),
    refreshBtn:    document.getElementById('refreshBtn'),
    toggleAutoBtn: document.getElementById('toggleAutoBtn'),
    actionMsg:     document.getElementById('actionMsg'),
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

  function rows(tbody, items) {
    if (!tbody) return;
    if (!Array.isArray(items) || items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="2" class="muted">(none)</td></tr>';
      return;
    }
    tbody.innerHTML = items
      .map((it) => `<tr><td>${escapeHTML(it.addr)}</td><td>${Number(it.count) || 0}</td></tr>`)
      .join('');
  }

  function pill(label, n) {
    return `<span class="pill" style="margin-right:.4rem">${label}: <strong>${Number(n) || 0}</strong></span>`;
  }

  function renderTotals(t, scoped) {
    const parts = [
      pill('outbound', t.outbound),
      pill('inbound', t.inbound),
      pill('throttled', t.throttled),
      pill('over-quota', t.over_quota),
      pill('auth-fail', t.auth_failed),
    ];
    // Host-wide / local-user counters are admin-only; the server already zeroes
    // them for scoped callers, but hide the pills to avoid a confusing 0.
    if (!scoped) {
      parts.push(pill('local-submit', t.local_submit));
      parts.push(pill('rejected', t.rejected));
    }
    el.totals.innerHTML = parts.join('');
  }

  function render(data) {
    el.unavailable.style.display = 'none';
    const scoped = data.scope === 'scoped';
    // textContent is inherently safe, so no escaping here (window/scope are a
    // server-formatted integer + an enum literal anyway).
    el.meta.textContent = `window ${data.window || ''} · ${data.scope || ''} view`;
    if (el.localCard) el.localCard.style.display = scoped ? 'none' : '';

    renderTotals(data.totals || {}, scoped);
    rows(el.outBody, data.top_outbound_senders);
    rows(el.domBody, data.most_sent_domains);
    rows(el.localBody, data.top_local_submitters);
    rows(el.inBody, data.top_inbound_mailboxes);
    rows(el.authFailBody, data.top_auth_failed);
    rows(el.throttledBody, data.top_throttled);
    rows(el.overQuotaBody, data.top_over_quota);
  }

  function renderUnavailable(note) {
    el.meta.textContent = '';
    el.totals.innerHTML = '';
    [el.outBody, el.domBody, el.localBody, el.inBody, el.authFailBody, el.throttledBody, el.overQuotaBody]
      .forEach((b) => { if (b) b.innerHTML = ''; });
    el.unavailable.style.display = '';
    el.unavailable.textContent = note || 'Mail-traffic collector not enabled yet (no counters collected).';
  }

  function currentHours() {
    const v = parseInt(el.hoursSel && el.hoursSel.value, 10);
    return Number.isFinite(v) && v > 0 ? v : 24;
  }

  async function refresh() {
    try {
      // basePath '/cfm-admin/api' → call path omits the leading /api.
      const data = await api(`/v1/mail/traffic?hours=${currentHours()}&limit=25`);
      if (data && data.available && data.traffic) {
        render(data.traffic);
      } else {
        renderUnavailable(data && data.note);
      }
    } catch (err) {
      flashMsg(err && err.message ? err.message : 'request failed', 'bad');
    }
  }

  function setAuto(on) {
    st.auto = on;
    if (el.autoState) el.autoState.textContent = on ? 'ON' : 'OFF';
    if (el.toggleAutoBtn) el.toggleAutoBtn.textContent = on ? 'Stop' : 'Start';
    window.clearInterval(st.timer);
    if (on) st.timer = window.setInterval(refresh, REFRESH_MS);
  }

  // Resolve admin vs scoped mode (via identity), apply the scoped chrome/badge,
  // then load. Mirrors the shared scope bootstrap the other scope-aware pages use.
  async function boot() {
    if (!controller.getToken()) await waitForScopedTokenOrTimeout(350);
    let me = null;
    try { me = await controller.loadMe({ preferScopedToken: true }); controller.refreshToken(); } catch (_) {}
    const token = controller.refreshToken();
    const mode = window.CFMAuthMode?.computeInitialScopeMode?.({ identity: me, token }) || 'global';
    st.isScopedMode = mode === 'scoped' || Boolean(me && (me.isScopedMode ?? me.is_scoped_mode ?? me.scoped));
    controller.applyScopedChrome({ scoped: st.isScopedMode, scopedLabel: 'Scoped mail view' });
    await refresh();
    if (!st.booted) { setAuto(true); st.booted = true; }
  }

  if (el.refreshBtn) el.refreshBtn.addEventListener('click', refresh);
  if (el.toggleAutoBtn) el.toggleAutoBtn.addEventListener('click', () => setAuto(!st.auto));
  if (el.hoursSel) el.hoursSel.addEventListener('change', refresh);

  boot().catch((err) => { flashMsg(err && err.message ? err.message : 'init failed', 'bad'); });
})();
