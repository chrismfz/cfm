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
//                                           gets its own domains.
//
// A scoped viewer gets the counters only: the queue is never asked for, and
// the server-wide tables are not drawn (mail-model.js; the daemon is what
// refuses). Each report is held on its own, so one failing or being off
// (`available:false`) never blanks the other, and a failed refresh keeps the
// last read on screen, marked as old.

import {
  WINDOWS, SHOWN, tabsFor, pickTab, pickHours, ageBuckets, tablesFor, tableHint, tableView,
  anomalies, tiles, sourceNote, hasData, queueHeadline, trafficHeadline,
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
    el.tabs.innerHTML = tabsFor(st.isScopedMode).map((t) =>
      `<button type="button" role="tab" class="vp-tab${t.key === st.tab ? ' on' : ''}" ` +
      `aria-selected="${t.key === st.tab ? 'true' : 'false'}" data-tab="${escapeHTML(t.key)}">${escapeHTML(t.label)}</button>`).join('');
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
    if (kind === 'queue' && st.isScopedMode) return;
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

  async function refresh() {
    if (!st.modeKnown) return;
    const jobs = [load('traffic', `/v1/mail/traffic?hours=${st.hours}&limit=25`, (r) => r.traffic)];
    // basePath '/cfm-admin/api' → the call path omits the leading /api.
    if (!st.isScopedMode) jobs.push(load('queue', '/v1/system/mail-queue', (r) => r.report));
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
    const b = ev.target.closest('[data-expand]');
    if (!b) return;
    const k = b.dataset.expand;
    if (st.expanded.has(k)) st.expanded.delete(k); else st.expanded.add(k);
    renderPanel();
  });

  render();
  boot().catch((err) => { flashMsg(err && err.message ? err.message : 'init failed'); });
})();
