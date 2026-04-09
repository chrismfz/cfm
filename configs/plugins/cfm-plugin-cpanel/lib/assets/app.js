(() => {
  const TOKEN = window.CFM_TOKEN;
  const MODE = window.CFM_MODE;
  const CURRENT_USER = window.CFM_CURRENT_USER || '';
  const CHALLENGE_SET = window.CFM_CHALLENGE_SET || {};
  const WAF_SET = window.CFM_WAF_SET || {};
  let ownedDomains = Array.isArray(window.CFM_OWNED_DOMAINS) ? window.CFM_OWNED_DOMAINS.filter(Boolean).map(v => String(v).trim().toLowerCase()) : [];
  let topVhostsTimer = null;
  let cpanelVhostTimer = null;

  const q = (sel) => document.querySelector(sel);
  const qa = (sel) => Array.from(document.querySelectorAll(sel));
  const msgEl = q('#msg');
  const tbody = q('#domainsBody');
  const searchEl = q('#search');
  const enabledOnlyEl = q('#enabledOnly');
  const vhostHostEl = q('#vhostHost');
  const webdetBody = q('#webdetBody');
  const suspiciousBody = q('#suspiciousBody');
  const challengeBody = q('#challengeBody');
  const wafOut = q('#wafOut');
  const vhostMeta = q('#vhostMeta');
  const vhostMetrics = q('#vhostMetrics');
  const vhostIPs = q('#vhostIPs');
  const vhostPaths = q('#vhostPaths');

  function esc(s){return String(s ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;');}
  function num(v){const n=Number(v); return Number.isFinite(n)?(Math.round(n*100)/100).toString():'-';}
  function showMsg(text,isError=false){ if(!msgEl) return; msgEl.textContent=text; msgEl.className='msg '+(isError?'err':'ok'); msgEl.classList.remove('hidden'); clearTimeout(showMsg._t); showMsg._t=setTimeout(()=>msgEl.classList.add('hidden'),6000); }
  function stateLabel(state){ return state ? 'WAF OFF / DISABLED' : 'WAF ON / ENABLED'; }
  function challengeStateLabel(state){ return state ? 'CHALLENGE OFF / DISABLED' : 'CHALLENGE ON / ENABLED'; }
  function updateButton(btn, state){ const kind=btn.dataset.kind; btn.dataset.state=state?'1':'0'; btn.textContent=(kind==='waf'?stateLabel(state):challengeStateLabel(state)); btn.classList.toggle('is-disabled', state); btn.classList.toggle('is-enabled', !state); }
  function rowsFrom(obj, key) { return Array.isArray(obj) ? obj : Array.isArray(obj?.rows) ? obj.rows : Array.isArray(obj?.[key]) ? obj[key] : []; }
  function fmtPct(v){ const n=Number(v); return Number.isFinite(n) ? `${num(n)}%` : '-'; }
  function maybePct(v){ const n=Number(v); if (!Number.isFinite(n)) return '-'; return n <= 1 ? `${num(n*100)}%` : `${num(n)}%`; }

  async function ajax(data) {
    const url = new URL(window.location.href);
    url.searchParams.set('ajax','1');
    const res = await fetch(url.toString(), {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json','Accept':'application/json'}, body:JSON.stringify({...data, token:TOKEN})});
    const text = await res.text();
    let json;
    try { json = JSON.parse(text); } catch { throw new Error(text.slice(0,200) || ('HTTP '+res.status)); }
    if (!res.ok || !json || json.ok === false) throw new Error(json?.error || ('HTTP '+res.status));
    return json;
  }
  async function proxyGet(path){ return ajax({op:'proxy_get', path, visible_domains: ownedDomains}); }
  async function proxyPost(path, payload){ return ajax({op:'proxy_post', path, payload, visible_domains: ownedDomains}); }

  function isOwnedDomain(host) { return ownedDomains.includes(String(host || '').trim().toLowerCase()); }

  function buildOwnedDomainSelect() {
    const sel = q('#vhostHost');
    if (!sel) return;
    const current = String(sel.value || '').trim().toLowerCase();
    const options = ['<option value="">Select one of your domains…</option>']
      .concat(ownedDomains.map(d => `<option value="${esc(d)}">${esc(d)}</option>`));
    sel.innerHTML = options.join('');
    if (current && ownedDomains.includes(current)) sel.value = current;
  }

  function applyFilters() {
    const qv = (searchEl?.value || '').trim().toLowerCase();
    const enabledOnly = !!enabledOnlyEl?.checked;
    qa('#domainsTable tbody tr').forEach((tr) => {
      const user = tr.dataset.user || '';
      const domain = tr.dataset.domain || '';
      const matchesSearch = !qv || user.includes(qv) || domain.includes(qv);
      let matchesEnabled = true;
      if (enabledOnly) matchesEnabled = Array.from(tr.querySelectorAll('button.toggle')).some(btn => btn.dataset.state === '0');
      tr.style.display = (matchesSearch && matchesEnabled) ? '' : 'none';
    });
  }

  function buildRow(user, domain) {
    const d = String(domain || '').trim().toLowerCase();
    const chExcluded = !!CHALLENGE_SET[d];
    const wafExcluded = !!WAF_SET[d];
    return `<tr data-user="${esc(String(user).toLowerCase())}" data-domain="${esc(d)}">
      <td>${esc(user)}</td>
      <td>${esc(d)}</td>
      <td><button class="toggle ${chExcluded?'is-disabled':'is-enabled'}" data-kind="challenge" data-domain="${esc(d)}" data-state="${chExcluded?'1':'0'}">${challengeStateLabel(chExcluded)}</button></td>
      <td><button class="toggle ${wafExcluded?'is-disabled':'is-enabled'}" data-kind="waf" data-domain="${esc(d)}" data-state="${wafExcluded?'1':'0'}">${stateLabel(wafExcluded)}</button></td>
    </tr>`;
  }

  async function toggle(btn) {
    const kind = btn.dataset.kind;
    const domain = btn.dataset.domain;
    const currentState = btn.dataset.state === '1';
    const newState = !currentState;
    btn.classList.add('loading');
    try {
      const visibleDomains = qa('#domainsTable tbody tr').map(tr => (tr.dataset.domain || '').trim()).filter(Boolean);
      await ajax({ kind, domain, state:newState, visible_domains:visibleDomains });
      updateButton(btn, newState);
      if (kind === 'challenge') { if (newState) CHALLENGE_SET[domain]=true; else delete CHALLENGE_SET[domain]; }
      if (kind === 'waf') { if (newState) WAF_SET[domain]=true; else delete WAF_SET[domain]; }
      showMsg(`${kind === 'waf' ? 'WAF' : 'Challenge'} updated for ${domain}`);
      applyFilters();
    } catch (err) {
      showMsg(err.message || 'Request failed', true);
    } finally {
      btn.classList.remove('loading');
    }
  }

  async function loadCpanelDomains() {
    if (MODE !== 'cpanel') {
      buildOwnedDomainSelect();
      applyFilters();
      return;
    }

    if (ownedDomains.length) {
      if (tbody) tbody.innerHTML = ownedDomains.slice().sort((a,b)=>a.localeCompare(b)).map((domain)=>buildRow(CURRENT_USER, domain)).join('');
      buildOwnedDomainSelect();
      applyFilters();
      return;
    }

    try {
      const cpsessPrefixMatch = window.location.pathname.match(/^\/cpsess[^/]+\//);
      const cpsessPrefix = cpsessPrefixMatch ? cpsessPrefixMatch[0] : '/';
      const apiUrl = cpsessPrefix + 'execute/DomainInfo/list_domains?hide_temporary_domains=1';
      const res = await fetch(apiUrl, { credentials:'same-origin', headers:{'Accept':'application/json'} });
      const rawText = await res.text();
      let json;
      try { json = JSON.parse(rawText); } catch { throw new Error('Non-JSON response from cPanel UAPI: ' + rawText.slice(0, 160)); }
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const payload = json?.data || json?.result?.data || {};
      const domains = [];
      for (const key of ['main_domain', 'addon_domains', 'parked_domains', 'sub_domains']) {
        const val = payload[key];
        if (typeof val === 'string' && val) domains.push(val.toLowerCase());
        else if (Array.isArray(val)) for (const d of val) if (typeof d === 'string' && d) domains.push(d.toLowerCase());
      }
      ownedDomains = [...new Set(domains.map(d => String(d).trim().toLowerCase()).filter(Boolean))].sort((a,b)=>a.localeCompare(b));
      if (tbody) tbody.innerHTML = ownedDomains.length ? ownedDomains.map(domain => buildRow(CURRENT_USER, domain)).join('') : '<tr><td colspan="4" class="muted">No domains detected for this account yet.</td></tr>';
      buildOwnedDomainSelect();
      applyFilters();
      if (!ownedDomains.length) showMsg('cPanel UAPI returned no domains for this account.', true);
    } catch (err) {
      showMsg('Failed to load domains from cPanel UAPI: ' + (err.message || 'unknown error'), true);
      applyFilters();
    }
  }

  function renderSimpleObject(obj, mapping) {
    const lines = [];
    for (const [label, paths] of mapping) {
      const arr = Array.isArray(paths) ? paths : [paths];
      let value = '-';
      for (const path of arr) {
        const parts = String(path).split('.');
        let cur = obj;
        for (const part of parts) cur = cur?.[part];
        if (cur !== undefined && cur !== null && cur !== '') { value = cur; break; }
      }
      if (typeof value === 'object') value = JSON.stringify(value);
      lines.push(`${label}: ${value}`);
    }
    return lines.join('\n');
  }

  function renderWebdet(top, suspicious, challenged) {
    if (top !== undefined) {
      const topRows = rowsFrom(top, 'rows');
      if (webdetBody) webdetBody.innerHTML = topRows.length ? topRows.slice(0,25).map(row => `
      <tr class="clickable" data-host="${esc(row.host || '')}">
        <td>${esc(row.host || '-')}</td><td>${esc(num(row.rps))}</td><td>${esc(num(row.rps_2xx))}</td><td>${esc(num(row.rps_4xx))}</td><td>${esc(num(row.rps_5xx))}</td><td>${esc(num(row.unique_ips))}</td><td>${esc(num(row.score))}</td>
      </tr>`).join('') : '<tr><td colspan="7" class="muted">No data.</td></tr>';
    }
    if (suspicious !== undefined) {
      const suspRows = rowsFrom(suspicious, 'rows');
      if (suspiciousBody) suspiciousBody.innerHTML = suspRows.length ? suspRows.slice(0,20).map(row => `<tr class="clickable" data-host="${esc(row.host || '')}"><td>${esc(row.host || '-')}</td><td>${esc(num(row.score))}</td><td>${esc(num(row.rps))}</td><td>${esc((row.reasons || []).join(', '))}</td></tr>`).join('') : '<tr><td colspan="4" class="muted">No suspicious vhosts.</td></tr>';
    }
    if (challenged !== undefined) {
      const chRows = rowsFrom(challenged, 'rows');
      if (challengeBody) challengeBody.innerHTML = chRows.length ? chRows.slice(0,20).map(row => `<tr class="clickable" data-host="${esc(row.host || '')}"><td>${esc(row.host || '-')}</td><td>${esc(row.mode || '-')}</td><td>${esc(num(row.uniq_ip || row.unique_ips))}</td><td>${esc((row.reasons || []).join(', '))}</td></tr>`).join('') : '<tr><td colspan="4" class="muted">No active challenged vhosts.</td></tr>';
    }
  }

  function renderWaf(summary) {
    if (!wafOut) return;
    const s = summary?.data || summary || {};
    const lines = [
      `Window: last ${s.hours ?? '-'}h`,
      `Events: ${num(s.total_events)}`,
      `Hosts: ${num(s.unique_hosts)}`,
      `IPs: ${num(s.unique_ips)}`,
      `Blocked: ${num(s.blocked_events)}`,
      ''
    ];
    const rules = Array.isArray(s.top_rules) ? s.top_rules : [];
    if (rules.length) {
      lines.push('Top rules:');
      for (const r of rules.slice(0, 12)) lines.push(`- ${r.key || '-'} (${num(r.count)})`);
    } else {
      lines.push('No WAF rule summary available.');
    }
    wafOut.textContent = lines.join('\n');
  }

  async function loadVhost(host) {
    if (!host) return;
    host = String(host).trim().toLowerCase();
    if (MODE === 'cpanel' && !isOwnedDomain(host)) {
      vhostMeta.textContent = 'This host is not in your allowed domain list.';
      showMsg('That host is not allowed for this cPanel account.', true);
      return;
    }
    vhostHostEl.value = host;
    vhostMeta.textContent = 'Loading ' + host + ' ...';
    try {
      const data = await proxyGet(`v1/webdet/drilldown?host=${encodeURIComponent(host)}&top=25`);
      const short = data?.short || data || {};
      const long = data?.long || {};
      const rps = long.rps ?? short.rps;
      const errRatio = long.err_ratio ?? short.err_ratio;
      const botRatio = long.bot_ratio ?? short.bot_ratio ?? short.bot_pct;
      const uniqueIps = long.unique_ips ?? short.unique_ips ?? (Array.isArray(short.top_ips) ? short.top_ips.length : undefined);
      const shortScore = short.short_score ?? short.score ?? long.score;
      const kpis = [
        ['Host', host],
        ['RPS', num(rps)],
        ['Short score', num(shortScore)],
        ['Err ratio', maybePct(errRatio)],
        ['Bot ratio', maybePct(botRatio)],
        ['Unique IPs', num(uniqueIps)]
      ];
      if (vhostMetrics) vhostMetrics.innerHTML = kpis.map(([label,value])=>`<div class="kpi"><div class="label">${esc(label)}</div><div class="value">${esc(value)}</div></div>`).join('');
      const topIPs = Array.isArray(data?.enriched_top_ips) ? data.enriched_top_ips : (Array.isArray(short.enriched_top_ips) ? short.enriched_top_ips : []);
      const fallbackTopIPs = Array.isArray(short.top_ips) ? short.top_ips : [];
      const topPaths = Array.isArray(short.top_paths) ? short.top_paths : [];
      if (vhostIPs) {
        if (topIPs.length) {
          vhostIPs.innerHTML = topIPs.slice(0,20).map(r=>{
            const meta = [r.ptr, r.asn ? `AS${r.asn}` : '', r.asn_name, r.country].filter(Boolean).join(' · ');
            return `<div class="list-row"><span><span class="code">${esc(r.ip || r.key || '-')}</span>${meta ? `<div class="muted">${esc(meta)}</div>` : ''}</span><span>${esc(num(r.count || r.value || r.req))}</span></div>`;
          }).join('');
        } else {
          vhostIPs.innerHTML = fallbackTopIPs.length ? fallbackTopIPs.slice(0,20).map(r=>`<div class="list-row"><span class="code">${esc(r.key || r.ip || '-')}</span><span>${esc(num(r.value || r.req || r.count))}</span></div>`).join('') : '<div class="muted">No IP data.</div>';
        }
      }
      if (vhostPaths) vhostPaths.innerHTML = topPaths.length ? topPaths.slice(0,20).map(r=>`<div class="list-row"><span class="code">${esc(r.key || r.path || '-')}</span><span>${esc(num(r.value || r.req || r.count))}</span></div>`).join('') : '<div class="muted">No path data.</div>';
      const reasons = Array.isArray(long.reasons) ? long.reasons : [];
      vhostMeta.innerHTML = `${esc(host)}${reasons.length ? ' · ' + esc(reasons.join(', ')) : ''}`;
    } catch (err) {
      vhostMeta.textContent = 'Failed to load vhost drilldown: ' + (err.message || 'unknown error');
    }
  }

  function hasAnyUsefulValue(obj, paths) {
    for (const path of paths) {
      const parts = String(path).split('.');
      let cur = obj;
      for (const part of parts) cur = cur?.[part];
      if (cur !== undefined && cur !== null && cur !== '') return true;
    }
    return false;
  }

  async function refreshTopVhostsOnly() {
    if (MODE !== 'whm') return;
    try {
      const top = await proxyGet('v1/webdet/top-short?limit=20');
      renderWebdet(top, undefined, undefined);
    } catch (err) {
      if (webdetBody) webdetBody.innerHTML = '<tr><td colspan="7" class="muted">Failed to load top vhosts.</td></tr>';
    }
  }

  async function refreshDashboard() {
    if (MODE !== 'whm') return;

    const jobs = [
      proxyGet('v1/webdet/top-short?limit=20'),
      proxyGet('v1/webdet/suspicious?limit=20'),
      proxyGet('v1/challenge/vhosts?status=active&mode=all&limit=50'),
      proxyGet('v1/waf/engine/summary?hours=24&limit=100&top=10&enrich=1'),
    ];

    const [topRes, suspiciousRes, challengedRes, wafRes] = await Promise.allSettled(jobs);

    let hadError = false;

    if (topRes.status === 'fulfilled' && suspiciousRes.status === 'fulfilled' && challengedRes.status === 'fulfilled') {
      renderWebdet(topRes.value, suspiciousRes.value, challengedRes.value);
    } else {
      hadError = true;
      if (webdetBody) webdetBody.innerHTML = '<tr><td colspan="7" class="muted">Failed to load top vhosts.</td></tr>';
      if (suspiciousBody) suspiciousBody.innerHTML = '<tr><td colspan="4" class="muted">Failed to load suspicious hosts.</td></tr>';
      if (challengeBody) challengeBody.innerHTML = '<tr><td colspan="4" class="muted">Failed to load active challenge hosts.</td></tr>';
    }

    if (wafRes.status === 'fulfilled') {
      renderWaf(wafRes.value);
    } else {
      hadError = true;
      if (wafOut) wafOut.textContent = 'Failed to load WAF summary.';
    }

    if (hadError) {
      showMsg('Some WHM dashboard sections failed to load, but the page stayed usable.', true);
    }
  }

  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button.toggle');
    if (btn) { if (!btn.classList.contains('loading')) toggle(btn); return; }
    const hostRow = e.target.closest('[data-host]');
    if (hostRow && hostRow.dataset.host) loadVhost(hostRow.dataset.host);
  });
  q('#refreshDashboard')?.addEventListener('click', refreshDashboard);
  q('#loadVhostBtn')?.addEventListener('click', ()=>loadVhost((vhostHostEl?.value || '').trim()));
  q('#challengeHostBtn')?.addEventListener('click', async ()=>{ const host=(vhostHostEl?.value||'').trim(); if(!host) return; try{ await proxyPost('v1/challenge/vhost/add',{host,ttl:'30m',reason:'cpanel-ui'}); showMsg('Challenge enabled for '+host); refreshDashboard(); } catch(err){ showMsg(err.message||'challenge failed',true);} });
  q('#unchallengeHostBtn')?.addEventListener('click', async ()=>{ const host=(vhostHostEl?.value||'').trim(); if(!host) return; try{ await proxyPost('v1/challenge/vhost/remove',{host}); showMsg('Challenge removed for '+host); refreshDashboard(); } catch(err){ showMsg(err.message||'unchallenge failed',true);} });
  searchEl?.addEventListener('input', applyFilters);
  enabledOnlyEl?.addEventListener('change', applyFilters);
  loadCpanelDomains().then(() => {
    if (MODE === 'whm') {
      refreshDashboard();
      topVhostsTimer = window.setInterval(refreshTopVhostsOnly, 5000);
      window.addEventListener('beforeunload', () => { if (topVhostsTimer) window.clearInterval(topVhostsTimer); }, { once: true });
    } else if (ownedDomains.length) {
      vhostHostEl.value = ownedDomains[0];
      loadVhost(ownedDomains[0]);
      cpanelVhostTimer = window.setInterval(() => {
        const host = (vhostHostEl?.value || '').trim();
        if (host) loadVhost(host);
      }, 5000);
      window.addEventListener('beforeunload', () => { if (cpanelVhostTimer) window.clearInterval(cpanelVhostTimer); }, { once: true });
    }
  });
})();
