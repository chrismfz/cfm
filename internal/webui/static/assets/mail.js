// /cfm-admin/assets/mail.js
//
// The Mail page: the live queue and the mail counters in one place, in tabs.
// It replaced two pages (Mail queue, Mail Monitor). Two read-only reports,
// neither a per-request MTA probe:
//
//   GET /api/v1/system/mail-queue           what the queue detector last
//                                           published (as `cfm mailtop`).
//                                           Admin only.
//   GET /api/v1/mail/traffic?hours=&limit=  per-hour counters from the mail
//                                           logs. Scope-aware: a cPanel user
//                                           gets its own domains. For an
//                                           admin it also carries the open
//                                           mail-abuse findings (`abuse`).
//   GET /api/v1/webdet/history/events?type_prefix=mail_
//                                           the findings' history (opened /
//                                           raised / recovered), for the
//                                           Alerts tab. Admin only.
//
// A scoped viewer gets the counters only: the queue is never asked for, and
// the server-wide tables are not drawn (mail-model.js; the daemon is what
// refuses). Each report is held on its own, so one failing or being off
// (`available:false`) never blanks the other, and a failed refresh keeps the
// last read on screen, marked as old.

import {
  WINDOWS, SHOWN, tabsFor, pickTab, pickHours, ageBuckets, tablesFor, tableHint, tableView,
  anomalies, tiles, sourceNote, hasData, queueHeadline, trafficHeadline,
  alertEpisodes, openAlerts, recentEpisodes, alertCount, alertsHeadline, sevPill, fmtWhen,
  episodeState, openKeysOf, historyCovers,
  ALERT_KINDS, ALERT_DAYS, ALERTS_OFF,
} from "./mail-model.js";

(() => {
  const controller = window.CFMControllerBootstrap.initSharedController({
    onDeferredScopedToken: () => { boot().catch(() => {}); },
  });

  function waitForScopedTokenOrTimeout(timeoutMs) {
    if (controller.getToken()) return Promise.resolve('present');
    return controller.waitForToken(timeoutMs).then((tok) => {
      controller.refreshToken();
      return tok ? 'postmessage' : 'timeout';
    });
  }

  const REFRESH_MS = 30000;
  const query = new URLSearchParams(window.location.search);

  const st = {
    auto: true, timer: null, booted: false, modeKnown: false,
    isScopedMode: false,
    tab: query.get('tab') || '',
    hours: pickHours(query.get('hours')),
    expanded: new Set(),
    queue: { state: 'loading' },
    traffic: { state: 'loading' },
    alerts: { state: 'loading' },
    seq: 0,
  };

  const api = controller.createApiClient({
    basePath: '/cfm-admin/api',
    isScoped: () => st.isScopedMode,
  });

  const $ = (id) => document.getElementById(id);
  const el = {
    tiles: $('tiles'), tabs: $('tabs'), actionMsg: $('actionMsg'),
    anomalyCard: $('anomalyCard'), anomalyBody: $('anomalyBody'),
    panel: $('tabPanel'), panelHead: $('panelHead'), panelNote: $('panelNote'),
    ageBar: $('ageBar'), tables: $('tables'),
    hoursSel: $('hoursSel'), autoState: $('autoState'),
    refreshBtn: $('refreshBtn'), toggleAutoBtn: $('toggleAutoBtn'),
  };

  function escapeHTML(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function flashMsg(text) {
    if (!el.actionMsg) return;
    el.actionMsg.textContent = text || '';
    el.actionMsg.style.display = text ? '' : 'none';
    window.clearTimeout(flashMsg._t);
    if (text) flashMsg._t = window.setTimeout(() => { el.actionMsg.style.display = 'none'; }, 6000);
  }

  // The tab and the window live in the address, so a reload or a shared link
  // opens the same view.
  function syncURL() {
    const q = new URLSearchParams(window.location.search);
    q.set('tab', st.tab);
    q.set('hours', String(st.hours));
    try { window.history.replaceState(null, '', window.location.pathname + '?' + q.toString()); } catch (_) {}
  }

  function renderTiles() {
    el.tiles.innerHTML = tiles(st.queue, st.traffic, st.isScopedMode).map((t) =>
      `<button type="button" class="ml-tile" data-tab="${escapeHTML(t.tab)}" title="Open ${escapeHTML(t.tab)}">` +
      `<span class="vp-k">${escapeHTML(t.label)}</span>` +
      `<span class="vp-big">${escapeHTML(t.value)}</span>` +
      `<span class="muted pt-sub">${escapeHTML(t.sub) || '&nbsp;'}</span></button>`).join('');
  }

  function renderTabs() {
    const open = hasData(st.traffic) ? alertCount(st.traffic.data.abuse) : 0;
    el.tabs.innerHTML = tabsFor(st.isScopedMode).map((t) => {
      const badge = t.key === 'alerts' && open > 0 ? ` <span class="pill warn">${open}</span>` : '';
      return `<button type="button" role="tab" class="vp-tab${t.key === st.tab ? ' on' : ''}" ` +
        `aria-selected="${t.key === st.tab ? 'true' : 'false'}" data-tab="${escapeHTML(t.key)}">${escapeHTML(t.label)}${badge}</button>`;
    }).join('');
  }

  // The subject of an alert opens the tab its counters are on.
  function subjectHTML(kind, subject) {
    const tab = (ALERT_KINDS[kind] || {}).tab;
    if (!tab || !subject) return escapeHTML(subject);
    return `<button type="button" class="pt-link" data-tab="${escapeHTML(tab)}" title="Open the ${escapeHTML(tab)} tab">${escapeHTML(subject)}</button>`;
  }

  function sevHTML(sev) {
    return sev ? `<span class="pill ${sevPill(sev)}">${escapeHTML(sev)}</span>` : '';
  }

  function closedCell(ep, openKeys) {
    switch (episodeState(ep, openKeys)) {
      case 'closed': return escapeHTML(fmtWhen(ep.closed));
      case 'open': return '<span class="pill warn">open</span>';
      default: return '<span class="muted" title="no recovery was written, and the last check no longer has it (the check switched off, or its state lost)">not closed</span>';
    }
  }

  // The Alerts tab: what is open now, then the last days' episodes.
  function alertsHTML() {
    const t = hasData(st.traffic) ? st.traffic.data : null;
    const eps = hasData(st.alerts) ? alertEpisodes(st.alerts.data) : [];
    const loading = st.alerts.state === 'loading';
    const open = t ? openAlerts(t.abuse, eps) : [];
    const openRows = open.length
      ? open.map((a) => '<tr>' +
          `<td>${sevHTML(a.severity)}</td><td>${escapeHTML(a.label)}</td><td>${subjectHTML(a.kind, a.subject)}</td>` +
          `<td>${escapeHTML(a.message)}${a.stillOpen ? ' <span class="pill info" title="no longer a finding at the last check, not closed yet">quieter</span>' : ''}</td>` +
          `<td class="pt-r">${escapeHTML(fmtWhen(a.since)) || `<span class="muted">${loading ? '…' : '—'}</span>`}</td></tr>`).join('')
      : '<tr><td colspan="5" class="muted">(none)</td></tr>';
    const openKeys = t ? openKeysOf(t.abuse) : null;
    const recent = recentEpisodes(eps, Date.now() / 1000, ALERT_DAYS, openKeys);
    let histNote = '';
    if (st.alerts.state === 'error') histNote = `<p class="ml-note bad">Could not read the history (${escapeHTML(st.alerts.error || 'request failed')}).</p>`;
    const histRows = recent.length
      ? recent.map((ep) => '<tr>' +
          `<td class="pt-r">${escapeHTML(fmtWhen(ep.opened)) || '<span class="muted">earlier</span>'}</td>` +
          `<td class="pt-r">${closedCell(ep, openKeys)}</td>` +
          `<td>${sevHTML(ep.severity)}</td><td>${escapeHTML((ALERT_KINDS[ep.kind] || {}).label || ep.kind)}</td>` +
          `<td>${subjectHTML(ep.kind, ep.subject)}</td>` +
          `<td>${escapeHTML(ep.message || '')}${ep.closeMessage ? `<div class="muted">${escapeHTML(ep.closeMessage)}</div>` : ''}</td></tr>`).join('')
      : `<tr><td colspan="6" class="muted">${loading ? 'Loading…' : `(none in the last ${ALERT_DAYS} days)`}</td></tr>`;
    return '<div class="mini-card ml-wide"><h3>Open now <span class="top-hint">what the last check found, worst first; the same findings cfm-web pages the team with</span></h3>' +
      '<div class="table-wrap"><table class="mini-table"><thead><tr><th>Severity</th><th>Alert</th><th>Mailbox / user</th><th>What was seen</th><th class="pt-r">Since</th></tr></thead>' +
      `<tbody>${openRows}</tbody></table></div></div>` +
      `<div class="mini-card ml-wide"><h3>Last ${ALERT_DAYS} days <span class="top-hint">each alert from when it opened to how it ended; under it, the message it closed with</span></h3>${histNote}` +
      '<div class="table-wrap"><table class="mini-table"><thead><tr><th class="pt-r">Opened</th><th class="pt-r">Closed</th><th>Severity</th><th>Alert</th><th>Mailbox / user</th><th>What was seen</th></tr></thead>' +
      `<tbody>${histRows}</tbody></table></div></div>`;
  }

  function renderAnomalies() {
    const rows = hasData(st.traffic) ? anomalies(st.traffic.data.anomalies) : [];
    el.anomalyCard.hidden = rows.length === 0;
    el.anomalyBody.innerHTML = rows.map((a) =>
      `<tr><td>${escapeHTML(a.addr)}</td><td><span class="pill warn">${escapeHTML(a.signal)}</span></td>` +
      `<td class="pt-r">${escapeHTML(a.recent)}</td><td class="pt-r">${escapeHTML(a.baseline)}</td><td class="pt-r">${escapeHTML(a.ratio)}</td></tr>`).join('');
  }

  function tableHTML(def, report) {
    const view = tableView(def, report, st.expanded.has(def.key));
    const hint = tableHint(def, st.isScopedMode);
    const head = def.cols.map((c) => `<th${c.t && c.t !== 'flag' ? ' class="pt-r"' : ''}>${escapeHTML(c.h)}</th>`).join('');
    const body = view.rows.length
      ? view.rows.map((r) => '<tr>' + r.map((c) =>
          `<td${c.num ? ' class="pt-r"' : ''}>${c.flag ? `<span class="pill info">${escapeHTML(c.text)}</span>` : escapeHTML(c.text)}</td>`).join('') + '</tr>').join('')
      : `<tr><td colspan="${def.cols.length}" class="muted">(none)</td></tr>`;
    let more = '';
    if (view.hidden > 0) more = `<button type="button" class="pt-link" data-expand="${escapeHTML(def.key)}">Show all ${view.total}</button>`;
    else if (view.total > SHOWN) more = `<button type="button" class="pt-link" data-expand="${escapeHTML(def.key)}">Show the top ${SHOWN}</button>`;
    return `<div class="mini-card${def.wide ? ' ml-wide' : def.mid ? ' ml-mid' : ''}">` +
      `<h3>${escapeHTML(def.title)}${hint ? ` <span class="top-hint">${escapeHTML(hint)}</span>` : ''}</h3>` +
      `<div class="table-wrap"><table class="mini-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>${more}</div>`;
  }

  function renderPanel() {
    if (st.tab === 'alerts') {
      const t = hasData(st.traffic) ? st.traffic.data : null;
      el.panelHead.textContent = alertsHeadline(st.traffic);
      const ran = t && (Array.isArray(t.abuse) || t.abuse_checked_at);
      const note = t && !ran ? { text: ALERTS_OFF, bad: false } : sourceNote('traffic', st.traffic);
      el.panelNote.hidden = !note.text;
      el.panelNote.textContent = note.text;
      el.panelNote.className = 'ml-note' + (note.bad ? ' bad' : ' muted');
      el.ageBar.hidden = true;
      const html = t ? alertsHTML() : '';
      if (html !== st.tablesHTML) { el.tables.innerHTML = html; st.tablesHTML = html; }
      return;
    }
    const kind = st.tab === 'queue' ? 'queue' : 'traffic';
    const src = st[kind];
    const data = hasData(src) ? src.data : null;

    el.panelHead.textContent = !data ? '' : (kind === 'queue' ? queueHeadline(data) : trafficHeadline(data, st.isScopedMode, st.tab));
    const note = sourceNote(kind, src);
    el.panelNote.hidden = !note.text;
    el.panelNote.textContent = note.text;
    el.panelNote.className = 'ml-note' + (note.bad ? ' bad' : ' muted');

    const showAge = kind === 'queue' && !!data;
    el.ageBar.hidden = !showAge;
    el.ageBar.innerHTML = showAge
      ? '<span class="vp-k">Age of the queued messages</span>' + ageBuckets(data.age_buckets).map((b) =>
          `<span class="pill">${escapeHTML(b.label)}: <strong>${b.count.toLocaleString('en-US')}</strong> <span class="muted">${b.pct}%</span></span>`).join('')
      : '';

    // No report, no tables: an empty table would read as "nothing happened".
    // The tables are rebuilt only when they changed, so a refresh that brings
    // the same rows keeps a sideways scroll and the keyboard focus.
    const html = data ? tablesFor(st.tab, st.isScopedMode).map((d) => tableHTML(d, data)).join('') : '';
    if (html !== st.tablesHTML) { el.tables.innerHTML = html; st.tablesHTML = html; }
  }

  function render() {
    // Until the viewer is known (admin or scoped) nothing is drawn: an admin's
    // tabs must not flash in front of a cPanel user.
    if (!st.modeKnown) {
      el.panelNote.hidden = false;
      el.panelNote.className = 'ml-note muted';
      el.panelNote.textContent = 'Loading…';
      return;
    }
    st.tab = pickTab(st.tab, st.isScopedMode);
    renderTiles();
    renderTabs();
    renderAnomalies();
    renderPanel();
  }

  function setTab(key) {
    st.tab = pickTab(key, st.isScopedMode);
    syncURL();
    render();
    if (st.tab === 'alerts' && st.modeKnown && !st.isScopedMode) loadAlertHistory();
  }

  // load one report into its source. A reply from before the mode or the
  // window changed (seq) is dropped.
  async function load(kind, path, pick) {
    const seq = st.seq;
    let next;
    try {
      const reply = await api(path);
      const data = reply && reply.available ? pick(reply) : null;
      next = data && typeof data === 'object'
        ? { state: 'ok', data, at: Date.now() }
        : { state: 'unavailable', note: reply && typeof reply.note === 'string' ? reply.note : '' };
    } catch (err) {
      const prev = st[kind];
      next = { state: 'error', error: err && err.message ? err.message : 'request failed', data: hasData(prev) ? prev.data : null, at: prev.at };
    }
    if (seq !== st.seq) return;
    if ((kind === 'queue' || kind === 'alerts') && st.isScopedMode) return;
    st[kind] = next;
    // The daemon has the last word on who the viewer is: counters it scoped
    // mean a scoped viewer, even when the identity lookup could not say so.
    if (kind === 'traffic' && next.state === 'ok' && next.data.scope === 'scoped' && !st.isScopedMode) {
      st.isScopedMode = true;
      st.queue = { state: 'loading' };
      controller.applyScopedChrome({ scoped: true, scopedLabel: 'Scoped mail view' });
      render();
      syncURL();
      return;
    }
    render();
  }

  // The findings' history: every mail_* row (opened, raised, recovered). A
  // plain list, not a report with `available`; a failure keeps the last read.
  async function loadAlertHistory() {
    const seq = st.seq;
    let next;
    try {
      // Newest first, a page at a time, until the rows reach back past the
      // window (a flapping finding can fill one page), at most 5 pages.
      const rows = [];
      let cursor = '';
      for (let page = 0; page < 5; page++) {
        const reply = await api('/v1/webdet/history/events?type_prefix=mail_&limit=500' + cursor);
        const got = reply && Array.isArray(reply.rows) ? reply.rows : (Array.isArray(reply) ? reply : []);
        rows.push(...got);
        const nx = reply && reply.next;
        if (!nx || historyCovers(got, Date.now() / 1000, ALERT_DAYS)) break;
        cursor = `&before_ts=${encodeURIComponent(nx.before_ts)}&before_id=${encodeURIComponent(nx.before_id)}`;
      }
      next = { state: 'ok', data: rows, at: Date.now() };
    } catch (err) {
      const prev = st.alerts;
      next = { state: 'error', error: err && err.message ? err.message : 'request failed', data: hasData(prev) ? prev.data : null, at: prev.at };
    }
    if (seq !== st.seq || st.isScopedMode) return;
    st.alerts = next;
    render();
  }

  async function refresh() {
    if (!st.modeKnown) return;
    // The open mail-abuse findings sit beside the counters in the reply
    // (admin only); they are kept with them, as one report.
    const jobs = [load('traffic', `/v1/mail/traffic?hours=${st.hours}&limit=25`, (r) => (r.traffic && typeof r.traffic === 'object'
      ? { ...r.traffic, abuse: r.abuse, abuse_checked_at: r.abuse_checked_at }
      : r.traffic))];
    // basePath '/cfm-admin/api' → the call path omits the leading /api.
    if (!st.isScopedMode) {
      jobs.push(load('queue', '/v1/system/mail-queue', (r) => r.report));
      // The history is read only while the Alerts tab is shown: it holds
      // the history store's lock, for nothing the other tabs draw.
      if (st.tab === 'alerts') jobs.push(loadAlertHistory());
    }
    await Promise.all(jobs);
  }

  function setAuto(on) {
    st.auto = on;
    el.autoState.textContent = on ? 'ON' : 'OFF';
    el.toggleAutoBtn.textContent = on ? 'Stop' : 'Start';
    window.clearInterval(st.timer);
    if (on) st.timer = window.setInterval(refresh, REFRESH_MS);
  }

  // Resolve admin vs scoped (by identity), apply the scoped chrome, then load.
  // The queue is asked for only once the viewer is known to be an admin.
  async function boot() {
    if (!controller.getToken()) await waitForScopedTokenOrTimeout(350);
    let me = null;
    try { me = await controller.loadMe({ preferScopedToken: true }); controller.refreshToken(); } catch (_) {}
    const token = controller.refreshToken();
    const mode = window.CFMAuthMode?.computeInitialScopeMode?.({ identity: me, token }) || 'global';
    const scoped = mode === 'scoped' || Boolean(me && (me.isScopedMode ?? me.is_scoped_mode ?? me.scoped));
    if (scoped !== st.isScopedMode || !st.modeKnown) {
      // What was read under the other identity is not this viewer's.
      st.seq++;
      st.queue = { state: 'loading' };
      st.traffic = { state: 'loading' };
      st.alerts = { state: 'loading' };
    }
    st.isScopedMode = scoped;
    st.modeKnown = true;
    controller.applyScopedChrome({ scoped, scopedLabel: 'Scoped mail view' });
    render();
    syncURL();
    await refresh();
    if (!st.booted) { setAuto(true); st.booted = true; }
  }

  el.hoursSel.innerHTML = WINDOWS.map((w) => `<option value="${w.hours}"${w.hours === st.hours ? ' selected' : ''}>${escapeHTML(w.label)}</option>`).join('');
  el.hoursSel.addEventListener('change', () => {
    st.hours = pickHours(el.hoursSel.value);
    st.seq++;
    syncURL();
    refresh();
  });
  el.refreshBtn.addEventListener('click', refresh);
  el.toggleAutoBtn.addEventListener('click', () => setAuto(!st.auto));
  el.tabs.addEventListener('click', (ev) => {
    const b = ev.target.closest('[data-tab]');
    if (b) setTab(b.dataset.tab);
  });
  el.tiles.addEventListener('click', (ev) => {
    const b = ev.target.closest('[data-tab]');
    if (b) setTab(b.dataset.tab);
  });
  el.tables.addEventListener('click', (ev) => {
    const t = ev.target.closest('[data-tab]');
    if (t) { setTab(t.dataset.tab); return; }
    const b = ev.target.closest('[data-expand]');
    if (!b) return;
    const k = b.dataset.expand;
    if (st.expanded.has(k)) st.expanded.delete(k); else st.expanded.add(k);
    renderPanel();
  });

  render();
  boot().catch((err) => { flashMsg(err && err.message ? err.message : 'init failed'); });
})();
