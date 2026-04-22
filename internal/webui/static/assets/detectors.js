import { lookupDetectorKeySchema, normalizeSchemaValue } from './detector-key-schema.js';

const state = { original: null, draft: null, path: '', dirty: false, modes: {}, examples: [], exampleKind: 'core' };
const byId = (id) => document.getElementById(id);

function clone(v){ return JSON.parse(JSON.stringify(v)); }
function setStatus(msg,bad=false){ const el=byId('detectorsStatus'); el.textContent=msg; el.style.color=bad?'#f87171':'#93c5fd'; }
function setDirty(v){ state.dirty=v; byId('detectorsDirty').textContent=v?'Unsaved':'Saved'; }
function setLeniencyFeedback(msg,bad=false){ const el=byId('detectorsLeniencyModalFeedback'); el.textContent=msg; el.style.color=bad?'#f87171':'#93c5fd'; }
function safeText(v){ return String(v??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'); }

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
    card.innerHTML = `<h4 style="margin-top:0">${safeText(ex.title || ex.id)}</h4><p class="muted" style="margin:4px 0 8px 0">Source section: <code>${safeText(ex.section || '-')}</code></p><p class="muted" style="margin:0 0 10px 0">${safeText(ex.preview || 'No preview')}</p><button type="button">Insert safely</button>`;
    card.querySelector('button').addEventListener('click', ()=>insertExample(ex, kind));
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

function collectDurationErrors(){
  const errs = [];
  for(const [k,v] of Object.entries(state.draft.global||{})){
    if(isDurationFamilyKey(k) && String(v||'').trim()!=='' && !parseDurationStrict(v)){
      errs.push({ path:`global.${k}`, message:'invalid duration format', expected:'Go duration, e.g. 30s, 5m, 1h30m' });
    }
  }
  [...(state.draft.core||[]),...(state.draft.leniency||[])].forEach((sec)=>{
    for(const [k,v] of Object.entries(sec.keys||{})){
      if(isDurationFamilyKey(k) && String(v||'').trim()!=='' && !parseDurationStrict(v)){
        errs.push({ path:`${sec.name}.${k}`, message:'invalid duration format', expected:'Go duration, e.g. 30s, 5m, 1h30m' });
      }
    }
  });
  return errs;
}

function buildTypedControl(key, value, onChange){
  const schema = lookupDetectorKeySchema(key);
  const raw = String(value ?? '');
  const normalized = normalizeSchemaValue(raw);
  if(!schema) return null;
  const wrap = document.createElement('div');
  wrap.style.marginBottom = '8px';
  const help = schema.help ? `<div class="muted" style="font-size:11px">${schema.help}${schema.examples?.length?` Example: ${schema.examples.join(', ')}`:''}</div>` : '';
  if(schema.type === 'bool'){
    wrap.innerHTML = `<label class="muted">${key}</label><select class="input input-wide"><option value="1">true (1)</option><option value="0">false (0)</option></select>${help}`;
    const sel = wrap.querySelector('select');
    const low = normalized.toLowerCase();
    sel.value = ['1','yes','true','on'].includes(low) ? '1' : '0';
    sel.addEventListener('change',(e)=>onChange(e.target.value));
    return wrap;
  }
  if(schema.allowed?.length){
    const opts = schema.allowed.map((o)=>`<option value="${o}">${o}</option>`).join('');
    wrap.innerHTML = `<label class="muted">${key}</label><select class="input input-wide"><option value="">-- select --</option>${opts}</select>${help}`;
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
  wrap.innerHTML = `<label class="muted">${key}</label><input type="${inputType}" class="input input-wide" value="${raw.replaceAll('"','&quot;')}">${help}`;
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
  const g=byId('detectorsGlobal'); g.innerHTML='';
  Object.entries(state.draft.global||{}).forEach(([k,v])=>{ const d=document.createElement('div'); d.innerHTML=`<label class="muted">${k}</label><input class="input input-wide" value="${String(v).replaceAll('"','&quot;')}"/>`; d.querySelector('input').addEventListener('input',e=>{state.draft.global[k]=e.target.value; setDirty(true);}); g.appendChild(d); });

  const core=byId('detectorsCoreBody'); core.innerHTML='';
  (state.draft.core||[]).forEach((sec)=>{ const tr=document.createElement('tr'); tr.innerHTML=`<td>${sec.name}</td><td><input type="checkbox" ${sec.enabled?'checked':''}></td><td><div></div></td>`;
    tr.querySelector('input').addEventListener('change',e=>{sec.enabled=e.target.checked; sec.keys.ENABLED=e.target.checked?'1':'0'; setDirty(true); render();});
    renderSectionEditor(tr.querySelector('div'), sec);
    core.appendChild(tr);
  });

  const len=byId('detectorsLeniencyBody'); len.innerHTML='';
  (state.draft.leniency||[]).forEach((sec)=>{ const tr=document.createElement('tr'); tr.innerHTML=`<td>${sec.name}</td><td><div></div></td>`; renderSectionEditor(tr.querySelector('div'), sec); len.appendChild(tr); });

  const adv=byId('detectorsAdvanced'); adv.innerHTML='';
  (state.draft.advanced||[]).forEach((sec)=>{ const box=document.createElement('div'); box.className='summary-card'; box.innerHTML=`<h4>${sec.name}</h4><textarea class="input" style="width:100%;min-height:140px"></textarea>`; const ta=box.querySelector('textarea'); ta.value=(sec.raw_lines||[]).join('\n'); ta.addEventListener('input',e=>{sec.raw_lines=e.target.value.split('\n'); setDirty(true);}); adv.appendChild(box); });
}

async function load(){ const j=await api('/api/v1/detectors/config'); state.original=clone(j.config); state.draft=clone(j.config); state.path=j.path||''; state.examples=clone(j.config?.examples||[]); state.modes={}; render(); setDirty(false); setStatus(`Loaded ${state.path}`); await refreshBackups(); }

async function refreshBackups(){ const j=await api('/api/v1/detectors/backups'); const ul=byId('detectorsBackupsList'); ul.innerHTML=''; (j.backups||[]).forEach((b)=>{ const li=document.createElement('li'); li.textContent=`${b.id} (${b.size} bytes)`; ul.appendChild(li); }); }

async function saveFlow(){
  const localDurationErrors = collectDurationErrors();
  if(localDurationErrors.length){
    const ul=byId('detectorsValidationErrors'); ul.innerHTML='';
    localDurationErrors.forEach((e)=>{ const li=document.createElement('li'); li.textContent=`${e.path}: ${e.message}. Expected: ${e.expected}`; ul.appendChild(li); });
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
  byId('detectorsReloadBtn').onclick=async()=>{ await api('/api/v1/detectors/reload',{method:'POST'}); setStatus('Detectors reload requested'); };
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
  load().catch((e)=>setStatus(e.message,true));
}

if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',init,{once:true}); else init();
