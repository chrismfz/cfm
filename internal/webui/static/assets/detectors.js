const state = { original: null, draft: null, path: '', dirty: false };
const byId = (id) => document.getElementById(id);

function clone(v){ return JSON.parse(JSON.stringify(v)); }
function setStatus(msg,bad=false){ const el=byId('detectorsStatus'); el.textContent=msg; el.style.color=bad?'#f87171':'#93c5fd'; }
function setDirty(v){ state.dirty=v; byId('detectorsDirty').textContent=v?'Unsaved':'Saved'; }

async function api(path,opt={}){ const r=await fetch(`/cfm-admin${path}`,{credentials:'include',headers:{'Content-Type':'application/json'},...opt}); const j=await r.json().catch(()=>({})); if(!r.ok) throw new Error(j.error||`HTTP ${r.status}`); return j; }

function render(){
  const g=byId('detectorsGlobal'); g.innerHTML='';
  Object.entries(state.draft.global||{}).forEach(([k,v])=>{ const d=document.createElement('div'); d.innerHTML=`<label class="muted">${k}</label><input class="input input-wide" value="${String(v).replaceAll('"','&quot;')}"/>`; d.querySelector('input').addEventListener('input',e=>{state.draft.global[k]=e.target.value; setDirty(true);}); g.appendChild(d); });

  const core=byId('detectorsCoreBody'); core.innerHTML='';
  (state.draft.core||[]).forEach((sec,idx)=>{ const tr=document.createElement('tr'); tr.innerHTML=`<td>${sec.name}</td><td><input type="checkbox" ${sec.enabled?'checked':''}></td><td><textarea class="input" style="width:100%;min-height:90px">${JSON.stringify(sec.keys,null,2)}</textarea></td>`;
    tr.querySelector('input').addEventListener('change',e=>{sec.enabled=e.target.checked; sec.keys.ENABLED=e.target.checked?'1':'0'; setDirty(true);});
    tr.querySelector('textarea').addEventListener('input',e=>{ try{ sec.keys=JSON.parse(e.target.value); setDirty(true);}catch(_){} });
    core.appendChild(tr);
  });

  const len=byId('detectorsLeniencyBody'); len.innerHTML='';
  (state.draft.leniency||[]).forEach((sec)=>{ const tr=document.createElement('tr'); tr.innerHTML=`<td>${sec.name}</td><td><textarea class="input" style="width:100%;min-height:90px">${JSON.stringify(sec.keys,null,2)}</textarea></td>`; tr.querySelector('textarea').addEventListener('input',e=>{ try{ sec.keys=JSON.parse(e.target.value); setDirty(true);}catch(_){} }); len.appendChild(tr); });

  const adv=byId('detectorsAdvanced'); adv.innerHTML='';
  (state.draft.advanced||[]).forEach((sec)=>{ const box=document.createElement('div'); box.className='summary-card'; box.innerHTML=`<h4>${sec.name}</h4><textarea class="input" style="width:100%;min-height:140px"></textarea>`; const ta=box.querySelector('textarea'); ta.value=(sec.raw_lines||[]).join('\n'); ta.addEventListener('input',e=>{sec.raw_lines=e.target.value.split('\n'); setDirty(true);}); adv.appendChild(box); });
}

async function load(){ const j=await api('/api/v1/detectors/config'); state.original=clone(j.config); state.draft=clone(j.config); state.path=j.path||''; render(); setDirty(false); setStatus(`Loaded ${state.path}`); await refreshBackups(); }

async function refreshBackups(){ const j=await api('/api/v1/detectors/backups'); const ul=byId('detectorsBackupsList'); ul.innerHTML=''; (j.backups||[]).forEach((b)=>{ const li=document.createElement('li'); li.textContent=`${b.id} (${b.size} bytes)`; ul.appendChild(li); }); }

async function saveFlow(){
  const v=await api('/api/v1/detectors/validate',{method:'POST',body:JSON.stringify({config:state.draft})});
  if(!v.ok){ const ul=byId('detectorsValidationErrors'); ul.innerHTML=''; (v.errors||[]).forEach(e=>{const li=document.createElement('li'); li.textContent=`${e.Path||e.path}: ${e.Message||e.message}`; ul.appendChild(li);}); byId('detectorsValidationModal').style.display='flex'; return; }
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
  byId('detectorsRefreshBackups').onclick=refreshBackups;
  byId('detectorsRestoreBtn').onclick=async()=>{ const id=byId('detectorsRestoreID').value.trim(); if(!id)return; await api('/api/v1/detectors/backups/restore',{method:'POST',body:JSON.stringify({id,reload:true})}); setStatus(`Restored ${id}`); await load(); };
  window.addEventListener('beforeunload',(e)=>{ if(!state.dirty) return; e.preventDefault(); e.returnValue=''; });
  load().catch((e)=>setStatus(e.message,true));
}

if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',init,{once:true}); else init();
