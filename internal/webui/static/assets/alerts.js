// Alerts page: the node's alert store (GET /api/v1/alerts, /alerts/summary,
// /alerts/stats). Filters live in the URL hash so a view can be shared.
// Every value from the store is written with textContent, never as HTML: rows
// carry attacker-controlled text (URIs, user agents, PTRs).
(() => {
  const API = '/cfm-admin/api/v1/alerts';
  const FILTER_IDS = {
    hours: 'alertsHours', kind: 'alertsKind', min_severity: 'alertsSeverity', ip: 'alertsIP',
    country: 'alertsCountry', asn: 'alertsASN', vhost: 'alertsVhost', delivery: 'alertsDelivery', q: 'alertsQuery',
  };
  const REFRESH_MS = 15000;
  const ROWS_PER_PAGE = 100;

  // range: a from/to window set by drilling into an hour/day group (overrides
  // the hours select); mode: a ban-mode filter set the same way.
  // pending / pendingAppend: a refresh or a "Load more" asked for while a load
  // was running, run when it finishes.
  const state = {
    category: '', range: null, mode: '', cursor: '', rows: [], timer: null,
    loading: false, pending: false, pendingAppend: false,
  };
  const byId = (id) => document.getElementById(id);

  function request(path) {
    return fetch(path, { credentials: 'same-origin', headers: { Accept: 'application/json' } })
      .then(async (res) => {
        const payload = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(payload.error || `Request failed (${res.status})`);
        return payload;
      });
  }

  function showStatus(msg, ok = true) {
    const el = byId('alertsStatus');
    if (!msg) { el.style.display = 'none'; return; }
    el.style.display = 'block';
    el.textContent = msg;
    el.style.color = ok ? '' : '#f87171';
  }

  // ── filters ↔ URL hash ───────────────────────────────────────────────────
  function readFilters() {
    const f = {};
    for (const [key, id] of Object.entries(FILTER_IDS)) {
      const v = String(byId(id).value || '').trim();
      if (v) f[key] = v;
    }
    if (state.category) f.category = state.category;
    if (state.range) { f.from = String(state.range.from); f.to = String(state.range.to); }
    if (state.mode) f.mode = state.mode;
    const g1 = byId('alertsGroup1').value;
    const g2 = byId('alertsGroup2').value;
    if (g1) f.group_by = g2 && g2 !== g1 ? `${g1},${g2}` : g1;
    return f;
  }

  function writeFilters(f) {
    for (const [key, id] of Object.entries(FILTER_IDS)) {
      byId(id).value = f[key] || (key === 'hours' ? '24' : '');
    }
    state.category = f.category || '';
    const from = Number(f.from); const to = Number(f.to);
    state.range = from > 0 && to > from ? { from, to } : null;
    state.mode = f.mode || '';
    const [g1 = '', g2 = ''] = String(f.group_by || '').split(',');
    byId('alertsGroup1').value = g1;
    byId('alertsGroup2').value = g2;
  }

  function filtersToHash(f) {
    const p = new URLSearchParams(f);
    const s = p.toString();
    if (s !== location.hash.slice(1)) history.replaceState(null, '', s ? `#${s}` : location.pathname);
  }

  function hashToFilters() {
    const f = {};
    for (const [k, v] of new URLSearchParams(location.hash.slice(1))) f[k] = v;
    return f;
  }

  function queryString(f, extra = {}) {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries({ ...f, ...extra })) {
      if (k === 'group_by' && !extra.group_by) continue;
      if (v !== undefined && v !== '') p.set(k, v);
    }
    return p.toString();
  }

  // ── rendering helpers ────────────────────────────────────────────────────
  function el(tag, text, cls) {
    const e = document.createElement(tag);
    if (text !== undefined && text !== null) e.textContent = String(text);
    if (cls) e.className = cls;
    return e;
  }

  function fmtTime(unix) {
    if (!unix) return '—';
    const d = new Date(unix * 1000);
    return d.toLocaleString(undefined, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function fmtTTL(sec) {
    if (!sec) return '';
    if (sec % 86400 === 0) return `${sec / 86400}d`;
    if (sec % 3600 === 0) return `${sec / 3600}h`;
    if (sec % 60 === 0) return `${sec / 60}m`;
    return `${sec}s`;
  }

  function fmtNum(n) { return Number(n || 0).toLocaleString(); }

  function fmtBytes(n) {
    const u = ['B', 'KB', 'MB', 'GB'];
    let v = Number(n || 0); let i = 0;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
  }

  function deliveryPill(d) {
    const cls = d === 'notified' ? 'pill ok' : d === 'send_failed' ? 'pill danger'
      : (d === 'deduped' || d === 'muted' || d === 'below_severity') ? 'pill' : 'pill warn';
    return el('span', d || '—', cls);
  }

  function severityClass(s) {
    return s === 'critical' ? 'pill danger' : s === 'warning' ? 'pill warn' : 'pill info';
  }

  // ── data loads ───────────────────────────────────────────────────────────
  async function loadStats() {
    try {
      const st = await request(`${API}/stats`);
      const days = Math.round((st.max_age_sec || 0) / 86400);
      byId('alertsStoreInfo').textContent = `${fmtNum(st.rows)} stored · ${fmtBytes(st.size_bytes)} · ${days}d`;
      byId('alertsStoreInfo').title = `${st.path}\nwritten since start: ${fmtNum(st.written_since_start)}\ndropped since start: ${fmtNum(st.dropped_since_start)}\nmax rows: ${fmtNum(st.max_rows)}`;
      byId('alertsStoreInfo').className = st.dropped_since_start > 0 ? 'pill warn' : 'pill';
    } catch (e) {
      byId('alertsStoreInfo').textContent = 'store unavailable';
      byId('alertsStoreInfo').className = 'pill danger';
    }
  }

  // One request for the header: tallies, top kind/country and the chip counts
  // (counted without the category filter, so every chip keeps its number).
  async function loadOverview(f) {
    const ov = await request(`${API}/overview?${queryString(f)}`);
    const row = byId('alertsCategoryChips');
    row.replaceChildren();
    let all = 0;
    for (const g of ov.categories || []) all += g.count;
    const allChip = el('button', `All · ${fmtNum(all)}`, `chip${state.category ? '' : ' on'}`);
    allChip.type = 'button';
    allChip.addEventListener('click', () => { state.category = ''; refresh(); });
    row.appendChild(allChip);
    for (const g of ov.categories || []) {
      const cat = g.key.category || 'OTHER';
      const chip = el('button', `${cat} · ${fmtNum(g.count)}`, `chip${state.category === cat ? ' on' : ''}`);
      chip.type = 'button';
      chip.addEventListener('click', () => { state.category = state.category === cat ? '' : cat; refresh(); });
      row.appendChild(chip);
    }
    byId('alertsTotal').textContent = fmtNum(ov.total);
    byId('alertsDistinctIPs').textContent = fmtNum(ov.distinct_ips);
    const k = ov.top_kind;
    byId('alertsTopKind').textContent = k ? `${k.key.kind || '—'} (${fmtNum(k.count)})` : '—';
    const c = ov.top_country;
    byId('alertsTopCountry').textContent = c ? `${c.key.country || '??'} ${c.label ? `· ${c.label}` : ''} (${fmtNum(c.count)})` : '—';
    byId('alertsNotMailed').textContent = fmtNum(ov.not_notified);
  }

  // Chips for the filters that have no input of their own (a drilled-into
  // time bucket, a ban mode); clicking one clears it.
  function renderActiveExtra() {
    const row = byId('alertsActiveExtra');
    row.replaceChildren();
    const add = (text, clear) => {
      const chip = el('button', `${text} ×`, 'chip on');
      chip.type = 'button';
      chip.addEventListener('click', () => { clear(); refresh(); });
      row.appendChild(chip);
    };
    if (state.range) add(`${fmtTime(state.range.from)} – ${fmtTime(state.range.to)}`, () => { state.range = null; });
    if (state.mode) add(`mode: ${state.mode}`, () => { state.mode = ''; });
    row.style.display = row.childElementCount ? '' : 'none';
  }

  async function loadGroups(f) {
    const sum = await request(`${API}/summary?${queryString(f, { group_by: f.group_by, top: '200' })}`);
    const dims = sum.group_by || [];
    const head = byId('alertsGroupsHead');
    const tr = el('tr');
    for (const d of dims) tr.appendChild(el('th', d));
    for (const h of ['Alerts', 'Distinct IPs', 'First', 'Last']) tr.appendChild(el('th', h));
    head.replaceChildren(tr);
    const body = byId('alertsGroupsBody');
    body.replaceChildren();
    for (const g of sum.groups || []) {
      const row = el('tr');
      row.style.cursor = 'pointer';
      for (const d of dims) {
        let v = g.key[d];
        if (d === 'asn' && v === '0') v = '';
        let text = v || '—';
        if ((d === 'asn' || d === 'country') && g.label && dims[0] === d) text = `${v || '—'} · ${g.label}`;
        row.appendChild(el('td', text));
      }
      row.appendChild(el('td', fmtNum(g.count)));
      row.appendChild(el('td', fmtNum(g.distinct_ips)));
      row.appendChild(el('td', fmtTime(g.first_unix)));
      row.appendChild(el('td', fmtTime(g.last_unix)));
      row.addEventListener('click', () => drillInto(dims, g.key));
      body.appendChild(row);
    }
    if (!(sum.groups || []).length) {
      const row = el('tr');
      const td = el('td', 'No alerts match.', 'muted');
      td.colSpan = dims.length + 4;
      row.appendChild(td);
      body.appendChild(row);
    }
    byId('alertsRowsInfo').textContent = sum.truncated ? 'Showing the top 200 groups.' : '';
  }

  // Clicking a group narrows the filters to it and drops back to the rows view.
  function drillInto(dims, key) {
    const map = { kind: 'alertsKind', ip: 'alertsIP', country: 'alertsCountry', asn: 'alertsASN', vhost: 'alertsVhost', delivery: 'alertsDelivery' };
    for (const d of dims) {
      const v = key[d];
      if (d === 'hour' || d === 'day') {
        const from = Math.floor(Date.parse(d === 'day' ? `${v}T00:00:00Z` : v) / 1000);
        if (from > 0) state.range = { from, to: from + (d === 'day' ? 86400 : 3600) };
      } else if (d === 'mode') state.mode = v;
      else if (d === 'category') state.category = v;
      else if (d === 'severity') byId('alertsSeverity').value = v === 'critical' ? 'critical' : v === 'warning' ? 'warning' : '';
      else if (d === 'reason') byId('alertsQuery').value = v;
      // an empty key (ASN: "0") is the group with no value: the API's "-"
      else if (map[d]) byId(map[d]).value = !v || (d === 'asn' && v === '0') ? '-' : v;
    }
    byId('alertsGroup1').value = '';
    byId('alertsGroup2').value = '';
    refresh();
  }

  async function loadRows(f, append) {
    const extra = { limit: String(ROWS_PER_PAGE) };
    if (append && state.cursor) extra.cursor = state.cursor;
    const page = await request(`${API}?${queryString(f, extra)}`);
    if (!append) state.rows = [];
    state.rows.push(...(page.rows || []));
    state.cursor = page.next_cursor || '';
    renderRows();
    byId('alertsMoreBtn').style.display = page.has_more ? '' : 'none';
    byId('alertsRowsInfo').textContent = `${fmtNum(state.rows.length)} shown${page.has_more ? ' (more available)' : ''}`;
  }

  function renderRows() {
    const body = byId('alertsRowsBody');
    body.replaceChildren();
    for (const r of state.rows) {
      const row = el('tr');
      row.style.cursor = 'pointer';
      row.appendChild(el('td', fmtTime(r.ts_unix)));
      const cat = el('td');
      cat.appendChild(el('span', r.category, severityClass(r.severity)));
      row.appendChild(cat);
      row.appendChild(el('td', r.kind));
      row.appendChild(el('td', r.ip || '—'));
      const country = el('td', r.country_iso || '');
      country.title = r.country || '';
      row.appendChild(country);
      row.appendChild(el('td', r.asn || ''));
      row.appendChild(el('td', r.vhost || ''));
      const reason = el('td', r.reason || '');
      reason.style.maxWidth = '28rem';
      reason.style.overflow = 'hidden';
      reason.style.textOverflow = 'ellipsis';
      reason.style.whiteSpace = 'nowrap';
      reason.title = r.reason || '';
      row.appendChild(reason);
      const action = r.mode ? `${r.mode}${r.ttl_sec ? ` ${fmtTTL(r.ttl_sec)}` : ''}` : (r.ttl_sec ? fmtTTL(r.ttl_sec) : '');
      row.appendChild(el('td', action));
      const del = el('td');
      del.appendChild(deliveryPill(r.delivery));
      row.appendChild(del);
      row.addEventListener('click', () => showDetail(r));
      body.appendChild(row);
    }
    if (!state.rows.length) {
      const row = el('tr');
      const td = el('td', 'No alerts match.', 'muted');
      td.colSpan = 10;
      row.appendChild(td);
      body.appendChild(row);
    }
  }

  function showDetail(r) {
    const meta = byId('alertsDetailMeta');
    meta.replaceChildren();
    const fields = [
      ['Time', `${fmtTime(r.ts_unix)} (${r.time})`], ['Kind', r.kind], ['Severity', r.severity || '—'],
      ['IP', r.ip || '—'], ['Country', [r.country, r.country_iso].filter(Boolean).join(' · ') || '—'],
      ['Network', r.asn || '—'], ['PTR', r.ptr || '—'], ['Vhost', r.vhost || '—'], ['Reason', r.reason || '—'],
      ['Action', r.mode ? `${r.mode} ${fmtTTL(r.ttl_sec)}` : (fmtTTL(r.ttl_sec) || '—')], ['Count', r.count || '—'],
      ['Section', r.section || '—'], ['Delivery', r.delivery || '—'], ['Event id', r.event_id || '—'],
    ];
    for (const [k, v] of fields) {
      const card = el('div', null, 'summary-card');
      card.appendChild(el('h4', k));
      card.appendChild(el('div', v, 'value'));
      meta.appendChild(card);
    }
    byId('alertsDetailSamples').textContent = (r.samples || []).join('\n') || '(none)';
    byId('alertsDetailExtra').textContent = r.extra ? JSON.stringify(r.extra, null, 2) : '(none)';
    byId('alertsDetail').style.display = '';
    byId('alertsDetail').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // ── orchestration ────────────────────────────────────────────────────────
  // A refresh asked for while one is loading runs right after it, with the
  // filters as they are then — dropping it left the table showing data for the
  // previous filters under the new selection.
  // stats: the store-size pill reads the whole table, so auto-refresh ticks
  // skip it; it loads on page load and on a manual refresh.
  async function refresh({ append = false, stats = true } = {}) {
    if (state.loading) {
      if (append) state.pendingAppend = true;
      else state.pending = true;
      return;
    }
    state.loading = true;
    const f = readFilters();
    filtersToHash(f);
    renderActiveExtra();
    try {
      if (!append) {
        await Promise.all([stats ? loadStats() : null, loadOverview(f)]);
      }
      const grouped = Boolean(f.group_by);
      byId('alertsGroupsWrap').style.display = grouped ? '' : 'none';
      byId('alertsRowsWrap').style.display = grouped ? 'none' : '';
      if (grouped) {
        state.rows = [];
        byId('alertsMoreBtn').style.display = 'none';
        await loadGroups(f);
      } else {
        await loadRows(f, append);
      }
      showStatus('');
    } catch (e) {
      showStatus(e.message || String(e), false);
    } finally {
      state.loading = false;
      // a full refresh replaces the rows, so it supersedes a pending "Load more"
      if (state.pending) {
        state.pending = false;
        state.pendingAppend = false;
        refresh();
      } else if (state.pendingAppend) {
        state.pendingAppend = false;
        refresh({ append: true });
      }
    }
  }

  function setAutoRefresh(on) {
    clearInterval(state.timer);
    // A tick reloads the first page, so it waits while the operator has paged
    // further with "Load more" rather than throwing those rows away.
    state.timer = on ? setInterval(() => {
      if (!document.hidden && state.rows.length <= ROWS_PER_PAGE) refresh({ stats: false });
    }, REFRESH_MS) : null;
  }

  function init() {
    writeFilters(hashToFilters());
    byId('alertsApplyBtn').addEventListener('click', () => refresh());
    byId('alertsRefreshBtn').addEventListener('click', () => refresh());
    byId('alertsClearBtn').addEventListener('click', () => { writeFilters({}); refresh(); });
    byId('alertsMoreBtn').addEventListener('click', () => refresh({ append: true }));
    byId('alertsDetailClose').addEventListener('click', () => { byId('alertsDetail').style.display = 'none'; });
    byId('alertsAutoRefresh').addEventListener('change', (e) => setAutoRefresh(e.target.checked));
    // picking a window replaces a drilled-into time bucket
    byId('alertsHours').addEventListener('change', () => { state.range = null; refresh(); });
    for (const id of ['alertsSeverity', 'alertsDelivery', 'alertsGroup1', 'alertsGroup2']) {
      byId(id).addEventListener('change', () => refresh());
    }
    for (const id of ['alertsKind', 'alertsIP', 'alertsCountry', 'alertsASN', 'alertsVhost', 'alertsQuery']) {
      byId(id).addEventListener('keydown', (e) => { if (e.key === 'Enter') refresh(); });
    }
    refresh();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
