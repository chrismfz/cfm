// /cfm-admin/assets/mail.js
//
// Mail queue page — the MTA-agnostic mail-queue breakdown (exim/postfix).
// Admin-only (the nav link hides for scoped viewers; the backend 403s). Reads
// the report the active queue detector publishes each poll — the SAME data as
// `cfm mailtop` and the mail_queue_summary MCP tool, with no per-request MTA
// probe:
//
//   GET /api/v1/system/mail-queue
//
// `available:false` when no queue detector is enabled yet (or first poll
// pending) — surfaced as a note, not an error.

(() => {
  const controller = window.CFMControllerBootstrap.initSharedController({});
  const api = controller.createApiClient({
    basePath: '/cfm-admin/api',
    isScoped: () => false,
  });

  const el = {
    meta:          document.getElementById('mailMeta'),
    headline:      document.getElementById('mailHeadline'),
    unavailable:   document.getElementById('mailUnavailable'),
    ageBuckets:    document.getElementById('ageBuckets'),
    senderBody:    document.getElementById('senderBody'),
    recipientBody: document.getElementById('recipientBody'),
    reasonsBody:   document.getElementById('reasonsBody'),
    oldestBody:    document.getElementById('oldestBody'),
    autoState:     document.getElementById('autoState'),
    refreshBtn:    document.getElementById('refreshBtn'),
    toggleAutoBtn: document.getElementById('toggleAutoBtn'),
    actionMsg:     document.getElementById('actionMsg'),
  };

  const AGE_ORDER = ['<10m', '10m-1h', '1h-6h', '6h-1d', '>1d'];
  const REFRESH_MS = 30000;

  const st = { auto: true, timer: null };

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

  function formatAge(secs) {
    const n = Number(secs) || 0;
    if (n <= 0) return '0s';
    if (n < 60) return `${n}s`;
    if (n < 3600) return `${Math.round(n / 60)}m`;
    if (n < 86400) return `${(n / 3600).toFixed(1)}h`;
    return `${(n / 86400).toFixed(1)}d`;
  }

  function formatSize(b) {
    const n = Number(b) || 0;
    if (n >= 1048576) return `${(n / 1048576).toFixed(1)}M`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)}K`;
    return `${n}B`;
  }

  function rows(tbody, items, render) {
    if (!tbody) return;
    if (!Array.isArray(items) || items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" class="muted">(none)</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(render).join('');
  }

  function renderReport(rep) {
    el.unavailable.style.display = 'none';
    const measured = rep.measured_at ? new Date(rep.measured_at).toLocaleTimeString() : '';
    el.meta.textContent = measured ? `measured ${measured}` : '';

    let head = `mta=${escapeHTML(rep.mta || '?')}  ·  total=${rep.total || 0}  ·  frozen=${rep.frozen || 0}  ·  deferred=${rep.deferred || 0}`;
    if (rep.truncated) head += `  ·  (parsed ${rep.parsed} — listing truncated)`;
    el.headline.textContent = head;

    const buckets = rep.age_buckets || {};
    el.ageBuckets.innerHTML = AGE_ORDER
      .map((k) => `<span class="pill" style="margin-right:.4rem">${k}: <strong>${Number(buckets[k]) || 0}</strong></span>`)
      .join('');

    rows(el.senderBody, rep.top_sender_domains, (d) =>
      `<tr><td>${escapeHTML(d.domain)}</td><td>${Number(d.count) || 0}</td></tr>`);
    rows(el.recipientBody, rep.top_recipient_domains, (d) =>
      `<tr><td>${escapeHTML(d.domain)}</td><td>${Number(d.count) || 0}</td></tr>`);
    rows(el.reasonsBody, rep.defer_reasons, (d) =>
      `<tr><td>${Number(d.count) || 0}</td><td>${escapeHTML(d.category)}</td><td>${escapeHTML(d.reason)}</td></tr>`);
    rows(el.oldestBody, rep.oldest, (m) =>
      `<tr><td>${formatAge(m.age_sec)}</td><td>${formatSize(m.size_bytes)}</td>` +
      `<td>${m.frozen ? '❄' : ''}</td><td>${escapeHTML(m.sender || '<>')}</td>` +
      `<td>${Number(m.recipients) || 0}</td><td>${escapeHTML(m.id)}</td></tr>`);
  }

  function renderUnavailable(note) {
    el.headline.textContent = '';
    el.meta.textContent = '';
    el.ageBuckets.innerHTML = '';
    [el.senderBody, el.recipientBody, el.reasonsBody, el.oldestBody].forEach((b) => { if (b) b.innerHTML = ''; });
    el.unavailable.style.display = '';
    el.unavailable.textContent = note || 'No mail-queue report yet (exim_queues/postfix_queues detector not enabled, or first poll pending).';
  }

  async function refresh() {
    try {
      // basePath is '/cfm-admin/api', so the call path omits the leading /api
      // (→ /cfm-admin/api/v1/system/mail-queue → strips to /api/v1/system/mail-queue).
      const data = await api('/v1/system/mail-queue');
      if (data && data.available && data.report) {
        renderReport(data.report);
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

  if (el.refreshBtn) el.refreshBtn.addEventListener('click', refresh);
  if (el.toggleAutoBtn) el.toggleAutoBtn.addEventListener('click', () => setAuto(!st.auto));

  refresh();
  setAuto(true);
})();
