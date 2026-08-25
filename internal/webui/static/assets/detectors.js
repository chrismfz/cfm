import { lookupDetectorKeySchema, normalizeSchemaValue } from './detector-key-schema.js';
import { runtimeBadge } from './runtime-badge.js';
import { coverageBadge, coverageSummaryItems, unitStateText } from './detector-coverage.js';

const state = { original: null, draft: null, path: '', dirty: false, modes: {}, examples: [], exampleKind: 'core', inlineValidation: { bySection: {}, global: [] }, runtime: { sections: [], summary: {}, inventory: {} }, coverage: null, catalog: [], configExists: true };
const byId = (id) => document.getElementById(id);
const RUNTIME_REFRESH_INTERVAL_MS = 30_000;
const RUNTIME_SKIP_NOTICE_THRESHOLD = 3;
const runtimeRefreshState = { inFlight: false, consecutiveSkips: 0, refreshAfterEditing: false };

function clone(v){ return JSON.parse(JSON.stringify(v)); }
function setStatus(msg,bad=false){ const el=byId('detectorsStatus'); el.textContent=msg; el.style.color=bad?'#f87171':'#93c5fd'; }
function setDirty(v){ state.dirty=v; byId('detectorsDirty').textContent=v?'Unsaved':'Saved'; }
function setLeniencyFeedback(msg,bad=false){ const el=byId('detectorsLeniencyModalFeedback'); el.textContent=msg; el.style.color=bad?'#f87171':'#93c5fd'; }
function safeText(v){ return String(v??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'); }
function fmtDate(v){ if(!v) return 'never'; const d=new Date(v); return Number.isNaN(d.getTime())?'never':d.toLocaleString(); }

function setRuntimeSummary(summary, inventory){
  const el = byId('detectorsRuntimeSummary');
  if(!el) return;
  const c = inventory?.counts || {};
  const fallback = summary || {};
  const loaded = Number.isFinite(c.loaded) ? c.loaded : (fallback.loaded_types||0);
  const configured = Number.isFinite(c.configured) ? c.configured : (fallback.configured_sections||0);
  const enabled = Number.isFinite(c.enabled) ? c.enabled : (fallback.enabled_sections||0);
  const active = Number.isFinite(c.active) ? c.active : (fallback.active_sections||0);
  el.textContent = `Loaded ${loaded} detector types, configured ${configured} sections, enabled ${enabled}, active ${active}`;
}

function renderInventoryLists(inventory){
  const inv = inventory || {};
  const missing = Array.isArray(inv.missing_config_for_available) ? inv.missing_config_for_available : [];
  const unknown = Array.isArray(inv.unknown_sections) ? inv.unknown_sections : [];

  const missingList = byId('detectorsMissingConfigList');
  const unknownList = byId('detectorsUnknownSectionsList');
  const missingCount = byId('detectorsMissingConfigCount');
  const unknownCount = byId('detectorsUnknownSectionsCount');
  const warning = byId('detectorsInventoryWarning');

  if(missingCount) missingCount.textContent = String(missing.length);
  if(unknownCount) unknownCount.textContent = String(unknown.length);

  if(missingList){
    missingList.innerHTML = '';
    if(missing.length===0){
      missingList.innerHTML = '<li class="muted">None</li>';
    }else{
      missing.forEach((name)=>{ const li=document.createElement('li'); li.textContent=String(name); missingList.appendChild(li); });
    }
  }
  if(unknownList){
    unknownList.innerHTML = '';
    if(unknown.length===0){
      unknownList.innerHTML = '<li class="muted">None</li>';
    }else{
      unknown.forEach((name)=>{ const li=document.createElement('li'); li.textContent=String(name); unknownList.appendChild(li); });
    }
  }

  if(warning){
    // The Daemon-coverage card below is the authoritative "does this matter
    // on this host?" view — keep this inventory line informational.
    if(missing.length && unknown.length){
      warning.textContent = `Inventory: ${missing.length} type(s) with no section, ${unknown.length} unknown section(s) — see Daemon coverage for what matters on this host.`;
      warning.style.color = '#9ca3af';
    } else if(missing.length){
      warning.textContent = `Inventory: ${missing.length} detector type(s) have no config section — usually because the daemon is not on this host. Check Daemon coverage below.`;
      warning.style.color = '#9ca3af';
    } else if(unknown.length){
      warning.textContent = `Config has ${unknown.length} unknown section(s) — likely a typo or an older binary.`;
      warning.style.color = '#fca5a5';
    } else {
      warning.textContent = 'Inventory clean: every available detector type has a section.';
      warning.style.color = '#9ca3af';
    }
  }
}

function renderCoverage(){
  const body = byId('detectorsCoverageBody');
  const summaryEl = byId('detectorsCoverageSummary');
  if(!body) return;

  if(summaryEl){
    summaryEl.innerHTML = '';
    (coverageSummaryItems(state.coverage?.summary)).forEach((item)=>{
      const pill = document.createElement('span');
      pill.className = item.cls;
      pill.title = item.title || '';
      pill.textContent = item.label;
      summaryEl.appendChild(pill);
    });
  }

  body.innerHTML = '';
  const types = Array.isArray(state.coverage?.types) ? state.coverage.types : [];
  if(types.length === 0){
    body.innerHTML = '<tr><td colspan="5" class="muted">Coverage unavailable (endpoint unreachable or older binary).</td></tr>';
    return;
  }
  types.forEach((t)=>{
    const badge = coverageBadge(t.verdict);
    const sections = Array.isArray(t.sections) ? t.sections : [];
    const enabledCount = sections.filter((s)=>s.enabled).length;
    const sectionsText = sections.length ? `${enabledCount}/${sections.length} enabled` : '—';
    const unitsText = Array.isArray(t.units)
      ? (t.units.map(unitStateText).join(', ') || '—')
      : '—';
    const noteParts = [];
    if(t.note) noteParts.push(t.note);
    const probeNotes = sections.filter((s)=>s.enabled && !s.source_probe_ok);
    if(probeNotes.length) noteParts.push(`log source not found for: ${probeNotes.map((s)=>s.section).join(', ')}`);
    const tr = document.createElement('tr');
    tr.innerHTML = `<td><div class="detector-section-title">${safeText(t.type)}</div><div class="muted" style="margin-top:2px">${safeText(t.title||'')}</div></td>`+
      `<td><span class="${badge.cls}" title="${safeText(badge.title)}">${safeText(badge.label)}</span></td>`+
      `<td>${safeText(sectionsText)}</td>`+
      `<td class="muted">${safeText(unitsText)}</td>`+
      `<td class="muted">${safeText(noteParts.join(' — '))}</td>`;
    body.appendChild(tr);
  });
}

async function refreshRuntimeStatus(){
  if(runtimeRefreshState.inFlight) return;
  runtimeRefreshState.inFlight = true;
  try{
    // Coverage rides the same edit-aware refresh loop as runtime status; its
    // failure must never take the status view down (allSettled, not all).
    const [statusRes, coverageRes] = await Promise.allSettled([
      api('/api/v1/detectors/status'),
      api('/api/v1/detectors/coverage'),
    ]);
    if(statusRes.status === 'fulfilled'){
      state.runtime = statusRes.value || { sections: [], summary: {}, inventory: {} };
    }else{
      setStatus(`Runtime status unavailable: ${statusRes.reason?.message || 'error'}`, true);
    }
    state.coverage = coverageRes.status === 'fulfilled' ? (coverageRes.value || null) : null;
    renderRuntimeOnly();
  }finally {
    runtimeRefreshState.inFlight = false;
  }
}

function isElementVisible(el){
  return Boolean(el) && el.style.display !== 'none' && el.getClientRects().length > 0;
}

function isDirectTextEditModalOpen(){
  return Array.from(document.querySelectorAll('.modal-backdrop')).some((modal)=>{
    if(!isElementVisible(modal)) return false;
    return modal.querySelector('input, textarea, [contenteditable=""], [contenteditable="true"]') !== null;
  });
}

function isUserEditing(){
  const active = document.activeElement;
  const tag = String(active?.tagName || '').toLowerCase();
  if(tag === 'input' || tag === 'textarea') return true;
  if(active?.isContentEditable) return true;
  return isDirectTextEditModalOpen();
}

function setRuntimePauseNotice(show){
  const summary = byId('detectorsRuntimeSummary');
  if(!summary) return;
  let note = byId('detectorsRuntimePauseNote');
  if(!note){
    note = document.createElement('div');
    note.id = 'detectorsRuntimePauseNote';
    note.className = 'muted';
    note.style.marginTop = '6px';
    summary.insertAdjacentElement('afterend', note);
  }
  note.textContent = show ? 'Runtime updates paused while editing' : '';
  note.style.display = show ? 'block' : 'none';
}

function triggerRuntimeRefreshAfterEditing(){
  if(!runtimeRefreshState.refreshAfterEditing || isUserEditing()) return;
  runtimeRefreshState.refreshAfterEditing = false;
  runtimeRefreshState.consecutiveSkips = 0;
  setRuntimePauseNotice(false);
  refreshRuntimeStatus();
}

function refreshRuntimeStatusIfSafe(){
  if(isUserEditing()){
    runtimeRefreshState.consecutiveSkips += 1;
    runtimeRefreshState.refreshAfterEditing = true;
    if(runtimeRefreshState.consecutiveSkips >= RUNTIME_SKIP_NOTICE_THRESHOLD){
      setRuntimePauseNotice(true);
    }
    return;
  }
  runtimeRefreshState.consecutiveSkips = 0;
  setRuntimePauseNotice(false);
  refreshRuntimeStatus();
}

async function api(path,opt={}){ const r=await fetch(`/cfm-admin${path}`,{credentials:'include',headers:{'Content-Type':'application/json'},...opt}); const j=await r.json().catch(()=>({})); if(!r.ok) throw new Error(j.error||`HTTP ${r.status}`); return j; }

function allSectionNames(){
  const names = new Set();
  [...(state.draft.core||[]), ...(state.draft.leniency||[]), ...(state.draft.advanced||[])].forEach((sec)=>{
    const name = (sec?.name||'').trim();
    if(name) names.add(name.toLowerCase());
  });
  return names;
}

function detectorMeta(sectionName){
  const key = String(sectionName||'').trim().toLowerCase();
  return (state.catalog||[]).find((m)=>String(m.type_key||'').toLowerCase()===key) || null;
}

function uniqueCoreSectionName(base){
  const names = allSectionNames();
  if(!names.has(String(base).toLowerCase())) return base;
  let i=2;
  while(names.has(`${base}_${i}`.toLowerCase())) i++;
  return `${base}_${i}`;
}

function addCoreFromTemplate(typeKey, template){
  const name = uniqueCoreSectionName(typeKey);
  const keys = clone(template||{});
  if(!Object.prototype.hasOwnProperty.call(keys,'ENABLED')) keys.ENABLED = '0';
  if(!Object.prototype.hasOwnProperty.call(keys,'BLOCK')) keys.BLOCK = 'dryrun';
  state.draft.core = state.draft.core || [];
  state.draft.core.push({ name, kind: 'core', enabled: ['1','true','yes','on'].includes(String(keys.ENABLED).toLowerCase()), keys });
  renderConfigEditors();
  setDirty(true);
  setStatus(`Added detector section ${name}`);
}

function addLeniencyCompanion(baseName){
  const sectionName = `${baseName}.leniency`;
  const names = allSectionNames();
  if(names.has(sectionName.toLowerCase())){ setStatus(`Leniency section ${sectionName} already exists`, true); return; }
  state.draft.leniency = state.draft.leniency || [];
  state.draft.leniency.push({ name: sectionName, kind: 'leniency', keys: { MATCH_COUNTRY: '', MATCH_ASN: '', BLOCK: '30m', BLOCK_COOLDOWN: '1h', SEND_TO_API: '0' } });
  renderConfigEditors();
  setDirty(true);
  setStatus(`Added leniency companion ${sectionName}`);
}

function refreshCatalogUI(){
  const typeSel = byId('detectorsCatalogType');
  const presetSel = byId('detectorsPresetSelect');
  if(typeSel){
    typeSel.innerHTML = '';
    (state.catalog||[]).forEach((m)=>{ const opt=document.createElement('option'); opt.value=m.type_key; opt.textContent=`${m.type_key} — ${m.title||m.type_key}`; typeSel.appendChild(opt); });
  }
  if(presetSel){
    presetSel.innerHTML = '<option value="">Select preset…</option>';
    (state.catalog||[]).forEach((m)=> (m.example_presets||[]).forEach((p)=>{ const opt=document.createElement('option'); opt.value=`${m.type_key}::${p.id}`; opt.textContent=`${m.type_key} / ${p.title||p.id}`; presetSel.appendChild(opt); }));
  }
}

function openLeniencyModal(){
  const coreSections = (state.draft.core||[]).filter((sec)=>String(sec?.name||'').trim() !== '');
  if(coreSections.length===0){ setStatus('Add at least one core detector before creating leniency sections.', true); return; }
  const baseSel = byId('detectorsLeniencyBase'); baseSel.innerHTML='';
  coreSections.forEach((sec)=>{ const opt=document.createElement('option'); opt.value=sec.name; opt.textContent=sec.name; baseSel.appendChild(opt); });
  byId('detectorsLeniencySectionName').value='';
  byId('detectorsLeniencyMatchCountry').value='';
  byId('detectorsLeniencyMatchASN').value='';
  byId('detectorsLeniencyBlock').value='30m';
  byId('detectorsLeniencyBlockCooldown').value='1h';
  byId('detectorsLeniencySendToAPI').value='0';
  setLeniencyFeedback('Create a starter leniency block and adjust values as needed.');
  byId('detectorsLeniencyModal').style.display='flex';
}

function confirmAddLeniency(){
  const base = byId('detectorsLeniencyBase').value.trim();
  const manual = byId('detectorsLeniencySectionName').value.trim();
  const sectionName = manual || `${base}.leniency`;
  const dupes = allSectionNames();
  if(!sectionName){ setLeniencyFeedback('Section name is required.', true); return; }
  if(dupes.has(sectionName.toLowerCase())){ setLeniencyFeedback(`Section "${sectionName}" already exists. Choose a different name.`, true); return; }
  const keys = {
    MATCH_COUNTRY: byId('detectorsLeniencyMatchCountry').value.trim(),
    MATCH_ASN: byId('detectorsLeniencyMatchASN').value.trim(),
    BLOCK: byId('detectorsLeniencyBlock').value.trim() || '30m',
    BLOCK_COOLDOWN: byId('detectorsLeniencyBlockCooldown').value.trim() || '1h',
    SEND_TO_API: byId('detectorsLeniencySendToAPI').value.trim() || '0',
  };
  state.draft.leniency = state.draft.leniency || [];
  state.draft.leniency.push({ name: sectionName, kind: 'leniency', keys });
  byId('detectorsLeniencyModal').style.display='none';
  renderConfigEditors();
  setDirty(true);
  setStatus(`Added leniency section ${sectionName}`);
}

function normalizeSafeBlockValue(v){
  const raw = String(v||'').trim();
  const mode = raw.toLowerCase();
  if(!mode) return 'dryrun';
  if(['0','no','off','dryrun','alert','permanent','perm'].includes(mode)) return mode;
  if(parseDurationStrict(raw)) return raw;
  return 'dryrun';
}

function uniqueSectionName(baseName, kind){
  const clean = String(baseName||'').trim() || (kind === 'leniency' ? 'example.leniency' : 'example_detector');
  const names = allSectionNames();
  if(!names.has(clean.toLowerCase())) return clean;
  let idx = 2;
  while(names.has(`${clean}_${idx}`.toLowerCase())) idx++;
  return `${clean}_${idx}`;
}

function sanitizeExampleKeys(keys, opt={}){
  const safeInsert = opt.safeInsert === true;
  const next = clone(keys||{});
  if(safeInsert && Object.prototype.hasOwnProperty.call(next,'BLOCK')) next.BLOCK = normalizeSafeBlockValue(next.BLOCK);
  if(Object.prototype.hasOwnProperty.call(next,'SEND_TO_API') && String(next.SEND_TO_API).trim()==='') next.SEND_TO_API = '0';
  return next;
}

function insertExample(example, kind, opt={}){
  const safeInsert = opt.safeInsert !== false;
  const secName = uniqueSectionName(example.section || example.id, kind);
  const keys = sanitizeExampleKeys(example.keys || {}, { safeInsert });
  if(kind === 'core'){
    keys.ENABLED = '0';
    state.draft.core = state.draft.core || [];
    state.draft.core.push({ name: secName, kind: 'core', enabled: false, keys });
  } else {
    state.draft.leniency = state.draft.leniency || [];
    state.draft.leniency.push({ name: secName, kind: 'leniency', keys });
  }
  byId('detectorsExamplesModal').style.display='none';
  renderConfigEditors();
  setDirty(true);
  setStatus(`Inserted template "${example.title}" as ${secName}${safeInsert?' (safe insert)':''}`);
}

async function copyExampleConfig(example, kind){
  const section = uniqueSectionName(example.section || example.id, kind);
  const keys = sanitizeExampleKeys(example.keys || {}, { safeInsert: false });
  const payload = { section, kind, keys };
  const text = JSON.stringify(payload, null, 2);
  try{
    await navigator.clipboard.writeText(text);
    setStatus(`Copied ${example.title || example.id} example config`);
  } catch(_){
    setStatus('Clipboard unavailable in this browser context', true);
  }
}

function openExamplesModal(kind){
  state.exampleKind = kind;
  const items = (state.examples || []).filter((ex)=>ex.kind === kind);
  byId('detectorsExamplesTitle').textContent = kind === 'leniency' ? 'Insert leniency template/example' : 'Insert core template/example';
  const list = byId('detectorsExamplesList');
  list.innerHTML = '';
  if(items.length === 0){
    list.innerHTML = '<p class="muted">No matching examples found in detectors.conf metadata comments.</p>';
    byId('detectorsExamplesModal').style.display='flex';
    return;
  }
  items.forEach((ex)=>{
    const card = document.createElement('div');
    card.className = 'summary-card';
    card.innerHTML = `<h4 style="margin-top:0">${safeText(ex.title || ex.id)}</h4><p class="muted" style="margin:4px 0 8px 0">Source section: <code>${safeText(ex.section || '-')}</code></p><p class="muted" style="margin:0 0 10px 0">${safeText(ex.preview || 'No preview')}</p><div class="toolbar wrap"><button type="button" data-action="insert-safe">Insert safely</button><button type="button" class="btn-quiet" data-action="insert-raw">Insert as-is</button><button type="button" class="btn-quiet" data-action="copy">Copy example config</button></div>`;
    card.querySelector('[data-action="insert-safe"]').addEventListener('click', ()=>insertExample(ex, kind, { safeInsert: true }));
    card.querySelector('[data-action="insert-raw"]').addEventListener('click', ()=>insertExample(ex, kind, { safeInsert: false }));
    card.querySelector('[data-action="copy"]').addEventListener('click', ()=>copyExampleConfig(ex, kind));
    list.appendChild(card);
  });
  byId('detectorsExamplesModal').style.display='flex';
}

function parseDurationStrict(v){
  const s = normalizeSchemaValue(v);
  if(!s) return false;
  if(!/^[-+]?\d/.test(s)) return false;
  // detectors.conf extends Go durations with a days unit ("7d", "1d12h") —
  // mirror the server's detconf.ParseCfgDuration by expanding Nd -> N*24h.
  const expanded = s.replace(/(\d+(?:\.\d+)?)d/g, (_, n) => `${Number(n) * 24}h`);
  const re = /^[-+]?((\d+(\.\d+)?)(ns|us|µs|ms|s|m|h))+$/;
  return re.test(expanded);
}

function parsePositiveNumber(v){
  const n = Number.parseFloat(String(v ?? '').trim());
  return Number.isFinite(n) ? n : null;
}

function isThresholdKey(k){
  const u = String(k||'').toUpperCase();
  return u.includes('THRESHOLD') || u.endsWith('_LIMIT') || u.endsWith('_MAX') || u.includes('SCORE_MIN');
}

function isPermanentBlock(v){
  return ['permanent', 'perm'].includes(String(v||'').trim().toLowerCase());
}

function detectorTypeFromSectionName(sectionName){
  const name = String(sectionName || '').trim().toLowerCase();
  if(!name) return '';
  return name.split('.')[0].split('_')[0];
}

function regexSourceForJS(raw){
  return String(raw||'').replaceAll(/\(\?P<([a-zA-Z_][a-zA-Z0-9_]*)>/g, '(?<$1>');
}

function validateRegexLine(raw){
  const value = String(raw||'').trim();
  if(!value) return { ok: false, message: 'Regex is empty' };
  try{
    new RegExp(regexSourceForJS(value));
    return { ok: true, message: '' };
  }catch(err){
    return { ok: false, message: err?.message || 'Invalid regex' };
  }
}

function collectLocalValidation(){
  const errs = [];
  const bySection = {};
  const global = [];
  const push = (section, msg) => {
    if(section){
      bySection[section] = bySection[section] || [];
      bySection[section].push(msg);
    } else {
      global.push(msg);
    }
  };

  for(const [k,v] of Object.entries(state.draft.global||{})){
    const schema = lookupDetectorKeySchema(k);
    const trimmed = String(v||'').trim();
    if(schema?.type === 'duration' && trimmed!=='' && !parseDurationStrict(v)){
      errs.push({ path:`global.${k}`, message:'invalid duration format', expected:'duration, e.g. 30s, 5m, 1h30m, 7d' });
      push(null, `global.${k}: invalid duration format (expected e.g. 30s, 5m, 1h30m, 7d)`);
    } else if(schema?.type === 'duration_or_enum' && trimmed!==''){
      const low = normalizeSchemaValue(trimmed).toLowerCase();
      const allowed = (schema.allowed||[]).some((item)=>String(item).toLowerCase() === low);
      if(!allowed && !parseDurationStrict(trimmed)){
        errs.push({ path:`global.${k}`, message:'invalid block mode', expected:'named mode or duration, e.g. dryrun, 30m or 7d' });
        push(null, `global.${k}: invalid block mode (expected dryrun/permanent/etc or duration like 30m / 7d)`);
      }
    }
  }
  [...(state.draft.core||[]),...(state.draft.leniency||[])].forEach((sec)=>{
    const sectionName = sec.name || '(unnamed)';
    let lowestThreshold = null;
    for(const [k,v] of Object.entries(sec.keys||{})){
      const schema = lookupDetectorKeySchema(k);
      const trimmed = String(v||'').trim();
      if(schema?.type === 'duration' && trimmed!=='' && !parseDurationStrict(v)){
        errs.push({ path:`${sec.name}.${k}`, message:'invalid duration format', expected:'duration, e.g. 30s, 5m, 1h30m, 7d' });
        push(sectionName, `${k}: invalid duration format`);
      } else if(schema?.type === 'duration_or_enum' && trimmed!==''){
        const low = normalizeSchemaValue(trimmed).toLowerCase();
        const allowed = (schema.allowed||[]).some((item)=>String(item).toLowerCase() === low);
        if(!allowed && !parseDurationStrict(trimmed)){
          errs.push({ path:`${sec.name}.${k}`, message:'invalid block mode', expected:'named mode or duration, e.g. dryrun, 30m or 7d' });
          push(sectionName, `${k}: invalid block mode (use dryrun/permanent/etc or duration like 30m / 7d)`);
        }
      } else if(schema?.type === 'regex_multiline'){
        const lines = String(v||'').split('\n');
        lines.forEach((line, idx)=>{
          const verdict = validateRegexLine(line);
          if(!verdict.ok){
            errs.push({ path:`${sec.name}.${k}[${idx}]`, message:verdict.message, expected:'a non-empty compileable regex' });
            push(sectionName, `${k} line ${idx+1}: ${verdict.message}`);
          }
        });
      }
      if(isThresholdKey(k)){
        const n = parsePositiveNumber(v);
        if(n !== null && (lowestThreshold === null || n < lowestThreshold)) lowestThreshold = n;
      }
    }
    if(isPermanentBlock(sec.keys?.BLOCK) && lowestThreshold !== null && lowestThreshold <= 2){
      push(sectionName, 'Risky combo: BLOCK=permanent with very low threshold (<=2). Use dryrun/timed block first.');
    }
  });
  return { errs, bySection, global };
}

function highRiskHelpForKey(key){
  const upper = String(key||'').toUpperCase();
  if(upper === 'BLOCK') return 'High risk: permanent blocking can lock out legitimate senders. Start with dryrun, then timed block.';
  if(upper === 'BLOCK_COOLDOWN') return 'High risk: very long cooldown may repeatedly re-block less often, very short cooldown can hammer retries.';
  if(isThresholdKey(upper)) return 'Threshold sensitivity: lower values increase detections and false positives. Tune gradually.';
  return '';
}

function riskBadgesForSection(sec){
  const badges = [];
  const lowestThreshold = Object.entries(sec.keys||{})
    .filter(([k])=>isThresholdKey(k))
    .map(([,v])=>parsePositiveNumber(v))
    .filter((v)=>v !== null);
  const minThreshold = lowestThreshold.length ? Math.min(...lowestThreshold) : null;
  if(isPermanentBlock(sec.keys?.BLOCK) && minThreshold !== null && minThreshold <= 2){
    badges.push('Permanent block + low threshold');
  }
  if(String(sec.keys?.BLOCK||'').trim().toLowerCase() === 'dryrun'){
    badges.push('Dryrun (safe)');
  }
  return badges;
}

function buildTypedControl(key, value, onChange){
  const schema = lookupDetectorKeySchema(key);
  const raw = String(value ?? '');
  const normalized = normalizeSchemaValue(raw);
  if(!schema) return null;
  const wrap = document.createElement('div');
  wrap.style.marginBottom = '8px';
  const riskHelp = highRiskHelpForKey(key);
  const keyLabel = riskHelp ? `${key} <span title="${safeText(riskHelp)}" style="cursor:help;color:#fbbf24;font-weight:700">ⓘ</span>` : key;
  const help = schema.help ? `<div class="muted" style="font-size:11px">${schema.help}${schema.examples?.length?` Example: ${schema.examples.join(', ')}`:''}</div>` : '';
  if(schema.type === 'bool'){
    wrap.innerHTML = `<label class="muted">${keyLabel}</label><select class="input input-wide"><option value="1">true (1)</option><option value="0">false (0)</option></select>${help}`;
    const sel = wrap.querySelector('select');
    const low = normalized.toLowerCase();
    sel.value = ['1','yes','true','on'].includes(low) ? '1' : '0';
    sel.addEventListener('change',(e)=>onChange(e.target.value));
    return wrap;
  }
  if(schema.allowed?.length){
    if(schema.type === 'duration_or_enum'){
      const suggestions = Array.from(new Set([...(schema.allowed||[]), '30m', '1h', '24h', '1h30m']));
      const listId = `detectors-${String(key).toLowerCase().replace(/[^a-z0-9_-]/g,'-')}-duration-suggestions`;
      wrap.innerHTML = `<label class="muted">${keyLabel}</label><input type="text" class="input input-wide" list="${listId}" value="${raw.replaceAll('"','&quot;')}"><datalist id="${listId}">${suggestions.map((s)=>`<option value="${safeText(s)}"></option>`).join('')}</datalist><div class="muted" style="font-size:11px">duration, e.g. 30m, 24h, 1h30m, 7d</div>${help}`;
      const input = wrap.querySelector('input');
      const inlineState = document.createElement('div');
      inlineState.className = 'muted';
      inlineState.style.fontSize = '11px';
      inlineState.style.minHeight = '16px';
      inlineState.style.marginTop = '2px';
      wrap.appendChild(inlineState);
      const allowedMap = new Map((schema.allowed||[]).map((v)=>[String(v).toLowerCase(), v]));
      const renderInline = (nextRaw)=>{
        const next = String(nextRaw||'').trim();
        if(!next){
          inlineState.textContent='';
          inlineState.style.color = '';
          return;
        }
        if(allowedMap.has(next.toLowerCase()) || parseDurationStrict(next)){
          inlineState.textContent='';
          inlineState.style.color = '';
          return;
        }
        inlineState.textContent = 'Invalid value: use a listed mode or duration, e.g. 30m, 24h, 1h30m, 7d';
        inlineState.style.color = '#fca5a5';
      };
      renderInline(raw);
      input.addEventListener('input',(e)=>{ renderInline(e.target.value); onChange(e.target.value); });
      return wrap;
    }
    const opts = schema.allowed.map((o)=>`<option value="${o}">${o}</option>`).join('');
    wrap.innerHTML = `<label class="muted">${keyLabel}</label><select class="input input-wide"><option value="">-- select --</option>${opts}</select>${help}`;
    const sel = wrap.querySelector('select');
    const candidate = normalized.toLowerCase();
    const match = schema.allowed.find((v)=>v.toLowerCase()===candidate);
    if(match) sel.value = match;
    if(schema.type === 'duration_or_enum' && !match && normalized){
      const opt = document.createElement('option');
      opt.value = normalized;
      opt.textContent = normalized;
      sel.appendChild(opt);
      sel.value = normalized;
    }
    sel.addEventListener('change',(e)=>onChange(e.target.value));
    return wrap;
  }
  if(schema.type === 'regex_multiline'){
    wrap.innerHTML = `<label class="muted">${keyLabel}</label><textarea class="input input-wide" style="min-height:100px;font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">${safeText(raw)}</textarea>${help}`;
    const ta = wrap.querySelector('textarea');
    const inlineState = document.createElement('div');
    inlineState.style.marginTop = '4px';
    inlineState.style.fontSize = '11px';
    inlineState.className = 'muted';
    wrap.appendChild(inlineState);
    const renderInline = (nextRaw)=>{
      const lines = String(nextRaw||'').split('\n');
      const problems = lines
        .map((line, idx)=>({ idx, line, verdict: validateRegexLine(line) }))
        .filter((item)=>String(item.line).trim() !== '' ? !item.verdict.ok : true);
      if(problems.length === 0){
        inlineState.textContent = '';
        inlineState.style.color = '';
        return;
      }
      inlineState.innerHTML = problems
        .slice(0, 6)
        .map((item)=>`Line ${item.idx + 1}: ${safeText(item.verdict.message)}`)
        .join('<br>');
      inlineState.style.color = '#fca5a5';
    };
    renderInline(raw);
    ta.addEventListener('input',(e)=>{ renderInline(e.target.value); onChange(e.target.value); });
    return wrap;
  }
  const inputType = schema.type === 'int' ? 'number' : 'text';
  wrap.innerHTML = `<label class="muted">${keyLabel}</label><input type="${inputType}" class="input input-wide" value="${raw.replaceAll('"','&quot;')}">${help}`;
  wrap.querySelector('input').addEventListener('input',(e)=>onChange(e.target.value));
  return wrap;
}

function renderSectionEditor(container, sec){
  const sectionKey = sec.name || crypto.randomUUID();
  state.modes[sectionKey] = state.modes[sectionKey] || 'form';
  container.innerHTML = '';
  const toolbar = document.createElement('div');
  toolbar.className = 'toolbar wrap';
  toolbar.style.marginBottom='8px';
  toolbar.innerHTML = `<span class="pill">${state.modes[sectionKey]==='form'?'Form mode':'JSON mode'}</span><button type="button" class="btn-quiet">${state.modes[sectionKey]==='form'?'JSON mode':'Form mode'}</button>`;
  toolbar.querySelector('button').addEventListener('click',()=>{ state.modes[sectionKey]=state.modes[sectionKey]==='form'?'json':'form'; renderConfigEditors(); });
  container.appendChild(toolbar);

  if(state.modes[sectionKey] === 'json'){
    const ta = document.createElement('textarea'); ta.className='input'; ta.style.width='100%'; ta.style.minHeight='110px'; ta.value = JSON.stringify(sec.keys||{},null,2);
    ta.addEventListener('input',(e)=>{ try{ sec.keys=JSON.parse(e.target.value); setDirty(true); }catch(_){ } });
    container.appendChild(ta);
    return;
  }

  const known = document.createElement('div');
  const advanced = document.createElement('details');
  advanced.innerHTML = '<summary>Advanced / Custom keys</summary>';
  const advBody = document.createElement('div');
  advBody.style.marginTop='6px';

  Object.entries(sec.keys||{}).forEach(([k,v])=>{
    const typed = buildTypedControl(k, v, (next)=>{ sec.keys[k]=String(next); if(k==='ENABLED') sec.enabled = ['1','yes','true','on'].includes(String(next).toLowerCase()); setDirty(true); });
    if(typed){ known.appendChild(typed); }
    else {
      const row = document.createElement('div'); row.style.marginBottom='8px';
      row.innerHTML = `<label class="muted">${k}</label><input class="input input-wide" value="${String(v??'').replaceAll('"','&quot;')}">`;
      row.querySelector('input').addEventListener('input',(e)=>{ sec.keys[k]=e.target.value; setDirty(true); });
      advBody.appendChild(row);
    }
  });
  if(known.children.length===0){ known.innerHTML = '<p class="muted">No known schema keys in this section. Use custom keys below.</p>'; }
  if(advBody.children.length===0){ advBody.innerHTML = '<p class="muted">No custom keys.</p>'; }
  advanced.appendChild(advBody);
  container.appendChild(known);
  container.appendChild(advanced);
}

function renderRuntimeOnly(){
  setRuntimeSummary(state.runtime.summary, state.runtime.inventory);
  renderInventoryLists(state.runtime.inventory);
  renderCoverage();

  const runtimeBySection = new Map((state.runtime.sections||[]).map((s)=>[String(s.section||''), s]));
  const coreRows = document.querySelectorAll('#detectorsCoreBody tr[data-section]');
  coreRows.forEach((tr)=>{
    const sectionName = tr.getAttribute('data-section') || '';
    const sec = (state.draft.core||[]).find((item)=>String(item?.name||'')===sectionName);
    if(!sec) return;
    const runtime = runtimeBySection.get(sectionName);
    const status = runtimeBadge(sec, runtime);
    const badgeEl = tr.querySelector('[data-runtime-badge]');
    const detailEl = tr.querySelector('[data-runtime-detail]');
    if(badgeEl){
      badgeEl.textContent = status.label;
      badgeEl.title = status.reason || '';
      badgeEl.style.background = status.color;
      badgeEl.style.color = '#111827';
    }
    if(detailEl){
      if(runtime){
        detailEl.textContent = `runs=${runtime.runs||0}, fail=${runtime.failures||0}, timeout=${runtime.timeouts||0}, last run=${fmtDate(runtime.last_run_at)}${runtime.last_error?`, err=${runtime.last_error}`:''}`;
        detailEl.style.display = '';
      } else {
        detailEl.textContent = '';
        detailEl.style.display = 'none';
      }
    }
  });
}

function renderConfigEditors(){
  const localValidation = collectLocalValidation();
  state.inlineValidation = { bySection: localValidation.bySection, global: localValidation.global };
  const g=byId('detectorsGlobal'); g.innerHTML='';
  Object.entries(state.draft.global||{}).forEach(([k,v])=>{ const d=document.createElement('div'); d.innerHTML=`<label class="muted">${k}</label><input class="input input-wide" value="${String(v).replaceAll('"','&quot;')}"/>`; d.querySelector('input').addEventListener('input',e=>{state.draft.global[k]=e.target.value; setDirty(true);}); g.appendChild(d); });

  const core=byId('detectorsCoreBody'); core.innerHTML='';
  const runtimeBySection = new Map((state.runtime.sections||[]).map((s)=>[String(s.section||''), s]));
  (state.draft.core||[]).forEach((sec)=>{ const runtime = runtimeBySection.get(String(sec.name||'')); const status = runtimeBadge(sec, runtime); const badges = riskBadgesForSection(sec).map((b)=>`<span class="pill" style="margin-left:6px">${safeText(b)}</span>`).join(''); const validation = (state.inlineValidation.bySection[sec.name||'']||[]).map((e)=>`<div class="muted" style="color:#fca5a5">${safeText(e)}</div>`).join(''); const meta = detectorMeta(sec.name) || detectorMeta(detectorTypeFromSectionName(sec.name)); const leniencyHint = (meta?.leniency_supported && !allSectionNames().has(`${String(sec.name||'')}.leniency`.toLowerCase())) ? `<button type="button" class="btn-quiet" data-leniency-for="${safeText(sec.name)}" style="margin-left:8px">Add leniency companion</button>` : ''; const customWarning = String(meta?.type_key||'').toLowerCase()==='custom' ? `<div class="muted" style="margin-top:6px;padding:8px;border:1px solid #fbbf24;background:#422006;color:#fde68a;border-radius:6px">⚠️ Test regex against real sample lines before enabling permanent block.</div>` : ''; const tr=document.createElement('tr'); tr.classList.add('detector-row'); tr.setAttribute('data-section', String(sec.name||'')); tr.innerHTML=`<td><div class="detector-section-title">${safeText(sec.name)}</div>${badges}${leniencyHint}${customWarning}${validation?`<div style="margin-top:6px">${validation}</div>`:''}<div class="muted" style="margin-top:4px;display:none" data-runtime-detail></div></td><td><span class="pill" data-runtime-badge style="background:${status.color};color:#111827" title="${safeText(status.reason)}">${safeText(status.label)}</span></td><td><input type="checkbox" ${sec.enabled?'checked':''}></td><td><div data-editor-host></div></td>`;
    tr.querySelector('input').addEventListener('change',e=>{sec.enabled=e.target.checked; sec.keys.ENABLED=e.target.checked?'1':'0'; setDirty(true); renderConfigEditors();});
    const leniencyBtn = tr.querySelector('[data-leniency-for]');
    if(leniencyBtn) leniencyBtn.addEventListener('click',()=>addLeniencyCompanion(sec.name));
    renderSectionEditor(tr.querySelector('[data-editor-host]'), sec);
    core.appendChild(tr);
  });

  const len=byId('detectorsLeniencyBody'); len.innerHTML='';
  (state.draft.leniency||[]).forEach((sec)=>{ const badges = riskBadgesForSection(sec).map((b)=>`<span class="pill" style="margin-left:6px">${safeText(b)}</span>`).join(''); const validation = (state.inlineValidation.bySection[sec.name||'']||[]).map((e)=>`<div class="muted" style="color:#fca5a5">${safeText(e)}</div>`).join(''); const tr=document.createElement('tr'); tr.classList.add('detector-row'); tr.setAttribute('data-section', String(sec.name||'')); tr.innerHTML=`<td><div class="detector-section-title">${safeText(sec.name)}</div>${badges}${validation?`<div style="margin-top:6px">${validation}</div>`:''}</td><td><div data-editor-host></div></td>`; renderSectionEditor(tr.querySelector('[data-editor-host]'), sec); len.appendChild(tr); });

  const adv=byId('detectorsAdvanced'); adv.innerHTML='';
  (state.draft.advanced||[]).forEach((sec)=>{ const box=document.createElement('div'); box.className='summary-card'; box.innerHTML=`<h4>${sec.name}</h4><textarea class="input" style="width:100%;min-height:140px"></textarea>`; const ta=box.querySelector('textarea'); ta.value=(sec.raw_lines||[]).join('\n'); ta.addEventListener('input',e=>{sec.raw_lines=e.target.value.split('\n'); setDirty(true);}); adv.appendChild(box); });

  renderRuntimeOnly();
}

function buildCatalogDefaultsConfig(){
  const core = (state.catalog||[]).map((m)=>({ name: m.type_key, kind: 'core', enabled: false, keys: { ENABLED: '0', BLOCK: 'dryrun', ...(m.defaults_template||{}) } }));
  return { global: { DEFAULT_EVERY: '30s', DEFAULT_WINDOW: '10m', DEFAULT_COOLDOWN: '20m' }, core, leniency: [], advanced: [], examples: [] };
}

async function load(){
  const [j, c] = await Promise.all([api('/api/v1/detectors/config'), api('/api/v1/detectors/catalog')]);
  state.original=clone(j.config); state.draft=clone(j.config); state.path=j.path||''; state.examples=clone(j.config?.examples||[]); state.configExists = j.exists !== false; state.catalog = clone(c.catalog||[]); state.modes={};
  refreshCatalogUI();
  byId('detectorsInitCard').style.display = state.configExists ? 'none' : 'block';
  renderOverlayNotice(j.overlay_files||[]);
  renderConfigEditors(); setDirty(false); setStatus(`Loaded ${state.path}`); await Promise.all([refreshBackups(), refreshRuntimeStatus()]);
}

// Overlay notice: this editor reads/writes the BASE detectors.conf, while the
// daemon runs base + /etc/cfm/detectors.d overlays merged. When overlays
// exist, say so — otherwise an edit that an overlay overrides looks like it
// "didn't take". Built with textContent (XSS-safe).
function renderOverlayNotice(files){
  const el = byId('detectorsOverlayNotice');
  if(!el) return;
  if(!files.length){ el.style.display='none'; el.textContent=''; return; }
  el.style.display='block';
  el.textContent = `${files.length} overlay file(s) in detectors.d override values shown here: ${files.join(', ')} — this editor edits the BASE file; the daemon runs the merged view (see the Source resolution card for the effective sources).`;
}

async function refreshBackups(){ const j=await api('/api/v1/detectors/backups'); const ul=byId('detectorsBackupsList'); ul.innerHTML=''; (j.backups||[]).forEach((b)=>{ const li=document.createElement('li'); li.textContent=`${b.id} (${b.size} bytes)`; ul.appendChild(li); }); }

async function saveFlow(){
  const localValidation = collectLocalValidation();
  state.inlineValidation = { bySection: localValidation.bySection, global: localValidation.global };
  renderConfigEditors();
  if(localValidation.errs.length){
    const ul=byId('detectorsValidationErrors'); ul.innerHTML='';
    localValidation.errs.forEach((e)=>{ const li=document.createElement('li'); li.textContent=`${e.path}: ${e.message}. Expected: ${e.expected}`; ul.appendChild(li); });
    byId('detectorsValidationModal').style.display='flex';
    return;
  }
  const v=await api('/api/v1/detectors/validate',{method:'POST',body:JSON.stringify({config:state.draft})});
  if(!v.ok){ const ul=byId('detectorsValidationErrors'); ul.innerHTML=''; (v.errors||[]).forEach(e=>{const li=document.createElement('li'); li.textContent=`${e.Path||e.path}: ${e.Message||e.message}${e.Expected||e.expected?` (Expected: ${e.Expected||e.expected})`:''}`; ul.appendChild(li);}); byId('detectorsValidationModal').style.display='flex'; return; }
  const p=await api('/api/v1/detectors/preview',{method:'POST',body:JSON.stringify({config:state.draft})});
  byId('detectorsDiff').textContent=p.diff||''; byId('detectorsSaveModal').style.display='flex';
}

// Source-resolution dry run (GET /api/v1/detectors/source-resolution): which
// log source each section would tail right now, per the daemon's shared
// resolver. On-demand only — the endpoint runs journalctl/systemctl/docker
// probes, so it is fetched once at page open and via the Re-run button, never
// on the auto-refresh interval. Rows are built with textContent (XSS-safe).
async function refreshSourceResolution(){
  const body = byId('detectorsSrcResolveBody');
  const note = byId('detectorsSrcResolveNote');
  if(!body) return;
  if(note) note.textContent = 'Resolving…';
  try{
    const j = await api('/api/v1/detectors/source-resolution');
    body.innerHTML='';
    (j.rows||[]).forEach((r)=>{
      const tr=document.createElement('tr');
      const td=(t)=>{ const c=document.createElement('td'); c.textContent=t; tr.appendChild(c); return c; };
      td(r.section);
      td(r.enabled?'yes':'no');
      const srcCell=document.createElement('td');
      const pill=document.createElement('span');
      pill.className='pill';
      if(r.would_disable){ pill.classList.add('danger'); pill.textContent='self-disable'; }
      else if(r.provisional){ pill.classList.add('warn'); pill.textContent=`${r.kind} · provisional`; }
      else pill.textContent=r.kind||'';
      srcCell.appendChild(pill);
      tr.appendChild(srcCell);
      td(r.target||'');
      td([r.reason, r.note].filter(Boolean).join(' · ')).className='muted';
      body.appendChild(tr);
    });
    if(note) note.textContent = `${(j.rows||[]).length} sections · dry run, nothing changed`;
  }catch(e){
    if(note) note.textContent = `Unavailable: ${e.message}`;
  }
}

function init(){
  byId('detectorsSaveBtn').onclick=saveFlow;
  byId('detectorsSrcResolveBtn').onclick=refreshSourceResolution;
  byId('detectorsDiscardBtn').onclick=()=>{ state.draft=clone(state.original); renderConfigEditors(); setDirty(false); setStatus('Draft reverted'); };
  byId('detectorsReloadBtn').onclick=async()=>{ await api('/api/v1/detectors/reload',{method:'POST'}); setStatus('Detectors reload requested'); await refreshRuntimeStatus(); };
  byId('detectorsConfirmSave').onclick=async()=>{ await api('/api/v1/detectors/config',{method:'PUT',body:JSON.stringify({config:state.draft})}); byId('detectorsSaveModal').style.display='none'; setStatus('Saved detectors config'); await load(); };
  byId('detectorsCancelSave').onclick=()=>byId('detectorsSaveModal').style.display='none';
  byId('detectorsValidationClose').onclick=()=>byId('detectorsValidationModal').style.display='none';
  byId('detectorsAddLeniencyBtn').onclick=openLeniencyModal;
  byId('detectorsAddCatalogBtn').onclick=()=>{ const type = byId('detectorsCatalogType').value; const meta = (state.catalog||[]).find((m)=>m.type_key===type); if(!meta){ setStatus('Select a detector type first.', true); return; } addCoreFromTemplate(type, meta.defaults_template||{}); };
  byId('detectorsCreatePresetBtn').onclick=()=>{ const v = byId('detectorsPresetSelect').value; if(!v){ setStatus('Select a preset first.', true); return; } const [type,presetID]=v.split('::'); const meta = (state.catalog||[]).find((m)=>m.type_key===type); const preset = (meta?.example_presets||[]).find((p)=>p.id===presetID); if(!meta || !preset){ setStatus('Preset not found.', true); return; } addCoreFromTemplate(type, { ...(meta.defaults_template||{}), ...(preset.template||{}) }); };
  byId('detectorsAddCoreFromExampleBtn').onclick=()=>openExamplesModal('core');
  byId('detectorsAddLeniencyFromExampleBtn').onclick=()=>openExamplesModal('leniency');
  byId('detectorsLeniencyConfirm').onclick=confirmAddLeniency;
  byId('detectorsLeniencyCancel').onclick=()=>byId('detectorsLeniencyModal').style.display='none';
  byId('detectorsExamplesClose').onclick=()=>byId('detectorsExamplesModal').style.display='none';
  byId('detectorsRefreshBackups').onclick=refreshBackups;
  byId('detectorsRestoreBtn').onclick=async()=>{ const id=byId('detectorsRestoreID').value.trim(); if(!id)return; await api('/api/v1/detectors/backups/restore',{method:'POST',body:JSON.stringify({id,reload:true})}); setStatus(`Restored ${id}`); await load(); };
  byId('detectorsInitFromCatalogBtn').onclick=()=>{ state.draft = buildCatalogDefaultsConfig(); renderConfigEditors(); setDirty(true); setStatus('Initialized draft from catalog defaults. Review and save.'); };
  window.addEventListener('beforeunload',(e)=>{ if(!state.dirty) return; e.preventDefault(); e.returnValue=''; });
  document.addEventListener('focusout',()=>window.setTimeout(triggerRuntimeRefreshAfterEditing, 0));
  document.addEventListener('visibilitychange',()=>{ if(!document.hidden) triggerRuntimeRefreshAfterEditing(); });
  window.setInterval(refreshRuntimeStatusIfSafe, RUNTIME_REFRESH_INTERVAL_MS);
  load().catch((e)=>setStatus(e.message,true));
  refreshSourceResolution().catch(()=>{});
}

if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',init,{once:true}); else init();
