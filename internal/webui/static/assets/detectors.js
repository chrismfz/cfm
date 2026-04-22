import { lookupDetectorKeySchema, normalizeSchemaValue } from './detector-key-schema.js';

const state = { original: null, draft: null, path: '', dirty: false, modes: {}, examples: [], exampleKind: 'core', inlineValidation: { bySection: {}, global: [] }, runtime: { sections: [], summary: {}, inventory: {} } };
const byId = (id) => document.getElementById(id);

function clone(v){ return JSON.parse(JSON.stringify(v)); }
function setStatus(msg,bad=false){ const el=byId('detectorsStatus'); el.textContent=msg; el.style.color=bad?'#f87171':'#93c5fd'; }
function setDirty(v){ state.dirty=v; byId('detectorsDirty').textContent=v?'Unsaved':'Saved'; }
function setLeniencyFeedback(msg,bad=false){ const el=byId('detectorsLeniencyModalFeedback'); el.textContent=msg; el.style.color=bad?'#f87171':'#93c5fd'; }
function safeText(v){ return String(v??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'); }
function fmtDate(v){ if(!v) return 'never'; const d=new Date(v); return Number.isNaN(d.getTime())?'never':d.toLocaleString(); }

function runtimeBadge(sec, runtime){
  if(!runtime || !sec?.enabled) return {color:'#9ca3af', label:'disabled', reason:'Section is disabled.'};
  const successes = Math.max(0, Number(runtime.runs||0)-Number(runtime.failures||0));
  const lastSuccessAt = runtime.last_success_at ? new Date(runtime.last_success_at) : null;
  const recentSuccess = lastSuccessAt && (Date.now() - lastSuccessAt.getTime()) <= (20*60*1000);
  const repeatedFailures = Number(runtime.failures||0) >= 3;
  const timeoutStreak = Number(runtime.timeouts||0) >= 2;
  if(runtime.init_ok === false || repeatedFailures || timeoutStreak || (runtime.last_error||'').toLowerCase().includes('timeout')){
    return {color:'#ef4444', label:'error', reason:runtime.last_error || 'Init failure/repeated failures/timeouts.'};
  }
  if(runtime.active && recentSuccess && runtime.source_probe_ok){
    return {color:'#22c55e', label:'healthy', reason:`Recent success at ${fmtDate(runtime.last_success_at)}.`};
  }
  if(!runtime.source_probe_ok){
    return {color:'#f59e0b', label:'waiting', reason:runtime.source_probe_message || 'No source activity yet.'};
  }
  return {color:'#f59e0b', label:'warming', reason:successes===0?'Enabled but no successful runs yet.':'Waiting for fresh successful run.'};
}

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
    if(missing.length || unknown.length){
      warning.textContent = `Config drift detected: ${missing.length} missing config type(s), ${unknown.length} unknown section(s).`;
      warning.style.color = '#fca5a5';
    } else {
      warning.textContent = 'No detector config drift detected.';
      warning.style.color = '#86efac';
    }
  }
}

async function refreshRuntimeStatus(){
  try{
    const j = await api('/api/v1/detectors/status');
    state.runtime = j || { sections: [], summary: {}, inventory: {} };
    setRuntimeSummary(state.runtime.summary, state.runtime.inventory);
    renderInventoryLists(state.runtime.inventory);
    render();
  }catch(e){
    setStatus(`Runtime status unavailable: ${e.message}`, true);
  }
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
  render();
  setDirty(true);
  setStatus(`Added leniency section ${sectionName}`);
}

function normalizeSafeBlockValue(v){
  const mode = String(v||'').trim().toLowerCase();
  if(!mode) return 'dryrun';
  if(['0','no','off','dryrun','alert'].includes(mode)) return mode;
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

function sanitizeExampleKeys(keys){
  const next = clone(keys||{});
  if(Object.prototype.hasOwnProperty.call(next,'BLOCK')) next.BLOCK = normalizeSafeBlockValue(next.BLOCK);
  if(Object.prototype.hasOwnProperty.call(next,'SEND_TO_API') && String(next.SEND_TO_API).trim()==='') next.SEND_TO_API = '0';
  return next;
}

function insertExample(example, kind){
  const secName = uniqueSectionName(example.section || example.id, kind);
  const keys = sanitizeExampleKeys(example.keys || {});
  if(kind === 'core'){
    keys.ENABLED = '0';
    state.draft.core = state.draft.core || [];
    state.draft.core.push({ name: secName, kind: 'core', enabled: false, keys });
  } else {
    state.draft.leniency = state.draft.leniency || [];
    state.draft.leniency.push({ name: secName, kind: 'leniency', keys });
  }
  byId('detectorsExamplesModal').style.display='none';
  render();
  setDirty(true);
  setStatus(`Inserted template "${example.title}" as ${secName}`);
}

async function copyExampleConfig(example, kind){
  const section = uniqueSectionName(example.section || example.id, kind);
  const keys = sanitizeExampleKeys(example.keys || {});
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
    card.innerHTML = `<h4 style="margin-top:0">${safeText(ex.title || ex.id)}</h4><p class="muted" style="margin:4px 0 8px 0">Source section: <code>${safeText(ex.section || '-')}</code></p><p class="muted" style="margin:0 0 10px 0">${safeText(ex.preview || 'No preview')}</p><div class="toolbar wrap"><button type="button" data-action="insert">Insert safely</button><button type="button" class="btn-quiet" data-action="copy">Copy example config</button></div>`;
    card.querySelector('[data-action="insert"]').addEventListener('click', ()=>insertExample(ex, kind));
    card.querySelector('[data-action="copy"]').addEventListener('click', ()=>copyExampleConfig(ex, kind));
    list.appendChild(card);
  });
  byId('detectorsExamplesModal').style.display='flex';
}

function parseDurationStrict(v){
  const s = normalizeSchemaValue(v);
  if(!s) return false;
  if(!/^[-+]?\d/.test(s)) return false;
  const re = /^[-+]?((\d+(\.\d+)?)(ns|us|µs|ms|s|m|h))+$/;
  return re.test(s);
}

function isDurationFamilyKey(k){
  const u = String(k||'').toUpperCase();
  return ['EVERY','TIMEOUT','COOLDOWN','WINDOW','TTL'].some((t)=>u.includes(t)) || u.includes('BLOCK');
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
    if(isDurationFamilyKey(k) && String(v||'').trim()!=='' && !parseDurationStrict(v)){
      errs.push({ path:`global.${k}`, message:'invalid duration format', expected:'Go duration, e.g. 30s, 5m, 1h30m' });
      push(null, `global.${k}: invalid duration format (expected Go duration e.g. 30s, 5m, 1h30m)`);
    }
  }
  [...(state.draft.core||[]),...(state.draft.leniency||[])].forEach((sec)=>{
    const sectionName = sec.name || '(unnamed)';
    let lowestThreshold = null;
    for(const [k,v] of Object.entries(sec.keys||{})){
      if(isDurationFamilyKey(k) && String(v||'').trim()!=='' && !parseDurationStrict(v)){
        errs.push({ path:`${sec.name}.${k}`, message:'invalid duration format', expected:'Go duration, e.g. 30s, 5m, 1h30m' });
        push(sectionName, `${k}: invalid duration format`);
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
  toolbar.querySelector('button').addEventListener('click',()=>{ state.modes[sectionKey]=state.modes[sectionKey]==='form'?'json':'form'; render(); });
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

function render(){
  const localValidation = collectLocalValidation();
  state.inlineValidation = { bySection: localValidation.bySection, global: localValidation.global };
  const g=byId('detectorsGlobal'); g.innerHTML='';
  Object.entries(state.draft.global||{}).forEach(([k,v])=>{ const d=document.createElement('div'); d.innerHTML=`<label class="muted">${k}</label><input class="input input-wide" value="${String(v).replaceAll('"','&quot;')}"/>`; d.querySelector('input').addEventListener('input',e=>{state.draft.global[k]=e.target.value; setDirty(true);}); g.appendChild(d); });

  const core=byId('detectorsCoreBody'); core.innerHTML='';
  const runtimeBySection = new Map((state.runtime.sections||[]).map((s)=>[String(s.section||''), s]));
  (state.draft.core||[]).forEach((sec)=>{ const runtime = runtimeBySection.get(String(sec.name||'')); const status = runtimeBadge(sec, runtime); const badges = riskBadgesForSection(sec).map((b)=>`<span class="pill" style="margin-left:6px">${safeText(b)}</span>`).join(''); const validation = (state.inlineValidation.bySection[sec.name||'']||[]).map((e)=>`<div class="muted" style="color:#fca5a5">${safeText(e)}</div>`).join(''); const detail = runtime ? `<div class="muted" style="margin-top:4px">runs=${runtime.runs||0}, fail=${runtime.failures||0}, timeout=${runtime.timeouts||0}, last run=${safeText(fmtDate(runtime.last_run_at))}${runtime.last_error?`, err=${safeText(runtime.last_error)}`:''}</div>` : ''; const tr=document.createElement('tr'); tr.innerHTML=`<td>${safeText(sec.name)}${badges}${validation?`<div style="margin-top:6px">${validation}</div>`:''}${detail}</td><td><span class="pill" style="background:${status.color};color:#111827" title="${safeText(status.reason)}">${safeText(status.label)}</span></td><td><input type="checkbox" ${sec.enabled?'checked':''}></td><td><div></div></td>`;
    tr.querySelector('input').addEventListener('change',e=>{sec.enabled=e.target.checked; sec.keys.ENABLED=e.target.checked?'1':'0'; setDirty(true); render();});
    renderSectionEditor(tr.querySelector('div'), sec);
    core.appendChild(tr);
  });

  const len=byId('detectorsLeniencyBody'); len.innerHTML='';
  (state.draft.leniency||[]).forEach((sec)=>{ const badges = riskBadgesForSection(sec).map((b)=>`<span class="pill" style="margin-left:6px">${safeText(b)}</span>`).join(''); const validation = (state.inlineValidation.bySection[sec.name||'']||[]).map((e)=>`<div class="muted" style="color:#fca5a5">${safeText(e)}</div>`).join(''); const tr=document.createElement('tr'); tr.innerHTML=`<td>${safeText(sec.name)}${badges}${validation?`<div style="margin-top:6px">${validation}</div>`:''}</td><td><div></div></td>`; renderSectionEditor(tr.querySelector('div'), sec); len.appendChild(tr); });

  const adv=byId('detectorsAdvanced'); adv.innerHTML='';
  (state.draft.advanced||[]).forEach((sec)=>{ const box=document.createElement('div'); box.className='summary-card'; box.innerHTML=`<h4>${sec.name}</h4><textarea class="input" style="width:100%;min-height:140px"></textarea>`; const ta=box.querySelector('textarea'); ta.value=(sec.raw_lines||[]).join('\n'); ta.addEventListener('input',e=>{sec.raw_lines=e.target.value.split('\n'); setDirty(true);}); adv.appendChild(box); });
}

async function load(){ const j=await api('/api/v1/detectors/config'); state.original=clone(j.config); state.draft=clone(j.config); state.path=j.path||''; state.examples=clone(j.config?.examples||[]); state.modes={}; render(); setDirty(false); setStatus(`Loaded ${state.path}`); await Promise.all([refreshBackups(), refreshRuntimeStatus()]); }

async function refreshBackups(){ const j=await api('/api/v1/detectors/backups'); const ul=byId('detectorsBackupsList'); ul.innerHTML=''; (j.backups||[]).forEach((b)=>{ const li=document.createElement('li'); li.textContent=`${b.id} (${b.size} bytes)`; ul.appendChild(li); }); }

async function saveFlow(){
  const localValidation = collectLocalValidation();
  state.inlineValidation = { bySection: localValidation.bySection, global: localValidation.global };
  render();
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

function init(){
  byId('detectorsSaveBtn').onclick=saveFlow;
  byId('detectorsDiscardBtn').onclick=()=>{ state.draft=clone(state.original); render(); setDirty(false); setStatus('Draft reverted'); };
  byId('detectorsReloadBtn').onclick=async()=>{ await api('/api/v1/detectors/reload',{method:'POST'}); setStatus('Detectors reload requested'); await refreshRuntimeStatus(); };
  byId('detectorsConfirmSave').onclick=async()=>{ await api('/api/v1/detectors/config',{method:'PUT',body:JSON.stringify({config:state.draft})}); byId('detectorsSaveModal').style.display='none'; setStatus('Saved detectors config'); await load(); };
  byId('detectorsCancelSave').onclick=()=>byId('detectorsSaveModal').style.display='none';
  byId('detectorsValidationClose').onclick=()=>byId('detectorsValidationModal').style.display='none';
  byId('detectorsAddLeniencyBtn').onclick=openLeniencyModal;
  byId('detectorsAddCoreFromExampleBtn').onclick=()=>openExamplesModal('core');
  byId('detectorsAddLeniencyFromExampleBtn').onclick=()=>openExamplesModal('leniency');
  byId('detectorsLeniencyConfirm').onclick=confirmAddLeniency;
  byId('detectorsLeniencyCancel').onclick=()=>byId('detectorsLeniencyModal').style.display='none';
  byId('detectorsExamplesClose').onclick=()=>byId('detectorsExamplesModal').style.display='none';
  byId('detectorsRefreshBackups').onclick=refreshBackups;
  byId('detectorsRestoreBtn').onclick=async()=>{ const id=byId('detectorsRestoreID').value.trim(); if(!id)return; await api('/api/v1/detectors/backups/restore',{method:'POST',body:JSON.stringify({id,reload:true})}); setStatus(`Restored ${id}`); await load(); };
  window.addEventListener('beforeunload',(e)=>{ if(!state.dirty) return; e.preventDefault(); e.returnValue=''; });
  window.setInterval(()=>{ refreshRuntimeStatus(); }, 10000);
  load().catch((e)=>setStatus(e.message,true));
}

if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',init,{once:true}); else init();
