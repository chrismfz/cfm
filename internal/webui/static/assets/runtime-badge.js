const RECENT_WINDOW_MS = 20 * 60 * 1000;

function fmtDate(v){
  if(!v) return 'never';
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? 'never' : d.toLocaleString();
}

function parseTs(v){
  if(!v) return null;
  const d = new Date(v);
  if(Number.isNaN(d.getTime())) return null;
  return d.getTime();
}

export function runtimeBadge(sec, runtime, opts = {}){
  if(!runtime || !sec?.enabled) return {color:'#9ca3af', label:'disabled', reason:'Section is disabled.'};

  const nowMs = Number.isFinite(opts.nowMs) ? Number(opts.nowMs) : Date.now();
  const failures = Math.max(0, Number(runtime.failures || 0));
  const timeouts = Math.max(0, Number(runtime.timeouts || 0));
  const successes = Math.max(0, Number(runtime.runs || 0) - failures);

  const lastRunTs = parseTs(runtime.last_run_at);
  const lastSuccessTs = parseTs(runtime.last_success_at);
  const recentSuccess = lastSuccessTs !== null && (nowMs - lastSuccessTs) <= RECENT_WINDOW_MS;
  const hasLastError = String(runtime.last_error || '').trim().length > 0;
  const recentError = hasLastError && lastRunTs !== null && (nowMs - lastRunTs) <= RECENT_WINDOW_MS;
  const recentTimeoutStreak = timeouts >= 2 && lastRunTs !== null && (nowMs - lastRunTs) <= RECENT_WINDOW_MS;

  if(runtime.init_ok === false || recentError || recentTimeoutStreak){
    let reason = runtime.last_error || (runtime.init_ok === false ? 'Initialization failed.' : 'Recent repeated timeouts/errors.');
    if(failures >= 3) reason += ` Lifetime failures=${failures}.`;
    return {color:'#ef4444', label:'error', reason};
  }

  if(runtime.active && recentSuccess && runtime.source_probe_ok){
    let reason = `Recent success at ${fmtDate(runtime.last_success_at)}.`;
    if(failures >= 3) reason += ` Lifetime failures=${failures}.`;
    return {color:'#22c55e', label:'healthy', reason};
  }

  if(!runtime.source_probe_ok){
    let reason = runtime.source_probe_message || 'No source activity yet.';
    if(failures >= 3) reason += ` Lifetime failures=${failures}.`;
    return {color:'#f59e0b', label:'waiting', reason};
  }

  let reason = successes === 0 ? 'Enabled but no successful runs yet.' : 'Waiting for fresh successful run.';
  if(failures >= 3) reason += ` Lifetime failures=${failures}.`;
  return {color:'#f59e0b', label:'warming', reason};
}
