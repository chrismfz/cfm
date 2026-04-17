(() => {
  const q = (id) => document.getElementById(id);
  const el = {
    refreshBtn: q('refreshBtn'),
    livePayload: q('livePayload'),
    durationSec: q('durationSec'),
    startCaptureBtn: q('startCaptureBtn'),
    captureMsg: q('captureMsg'),
    captureID: q('captureID'),
    loadCaptureBtn: q('loadCaptureBtn'),
    exportJSONBtn: q('exportJSONBtn'),
    exportTextBtn: q('exportTextBtn'),
    capturePayload: q('capturePayload'),
  };

  async function api(path, opts = {}) {
    const res = await fetch(`/cfm-admin/api${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...opts,
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(text || `HTTP ${res.status}`);
    }
    return text;
  }

  async function loadLive() {
    const payload = await api('/v1/debug/live');
    el.livePayload.textContent = payload;
  }

  async function startCapture() {
    const duration = Number(el.durationSec.value || 20);
    const payload = await api('/v1/debug/capture', {
      method: 'POST',
      body: JSON.stringify({ duration_sec: duration }),
    });
    el.capturePayload.textContent = payload;
    try {
      const parsed = JSON.parse(payload);
      if (parsed?.id) el.captureID.value = parsed.id;
      el.captureMsg.textContent = `Capture ${parsed.id} status: ${parsed.status}`;
    } catch {
      el.captureMsg.textContent = 'Capture request sent.';
    }
  }

  async function loadCapture() {
    const id = String(el.captureID.value || '').trim();
    if (!id) {
      el.captureMsg.textContent = 'Enter a capture ID first.';
      return;
    }
    const payload = await api(`/v1/debug/capture/${encodeURIComponent(id)}`);
    el.capturePayload.textContent = payload;
  }

  async function exportCapture(format) {
    const id = String(el.captureID.value || '').trim();
    if (!id) {
      el.captureMsg.textContent = 'Enter a capture ID first.';
      return;
    }
    const payload = await api(`/v1/debug/export?id=${encodeURIComponent(id)}&format=${format}`);
    el.capturePayload.textContent = payload;
  }

  async function safeRun(fn) {
    try {
      await fn();
      el.captureMsg.textContent = '';
    } catch (err) {
      console.error(err);
      el.captureMsg.textContent = String(err.message || err);
    }
  }

  el.refreshBtn?.addEventListener('click', () => safeRun(loadLive));
  el.startCaptureBtn?.addEventListener('click', () => safeRun(startCapture));
  el.loadCaptureBtn?.addEventListener('click', () => safeRun(loadCapture));
  el.exportJSONBtn?.addEventListener('click', () => safeRun(() => exportCapture('json')));
  el.exportTextBtn?.addEventListener('click', () => safeRun(() => exportCapture('txt')));

  safeRun(loadLive);
})();
