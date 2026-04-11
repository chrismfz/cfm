(() => {
  if (window.CFMAuthContext) return;

  const TOKEN_RE = /^[0-9a-f]{64}$/;
  const state = { token: '', source: 'none', changes: new Set(), waiters: [] };

  function parseOrigin(value) {
    if (typeof value !== 'string') return '';
    const trimmed = value.trim();
    if (!trimmed) return '';
    try { return new URL(trimmed, window.location.origin).origin; } catch (_) { return ''; }
  }

  function getInjectedExpectedOrigin() {
    const fromGlobal =
      window.__CFM_EXPECTED_ORIGIN__ ||
      window.__CFM_TOKEN_EXPECTED_ORIGIN__ ||
      window.CFM_EXPECTED_ORIGIN;
    const fromDataset =
      document.documentElement?.dataset?.cfmExpectedOrigin ||
      document.body?.dataset?.cfmExpectedOrigin;
    const fromMeta = document.querySelector('meta[name="cfm-expected-origin"]')?.getAttribute('content');
    let fromQuery = '';
    try {
      fromQuery = new URL(window.location.href).searchParams.get('cfmExpectedOrigin') || '';
    } catch (_) {}
    return (
      parseOrigin(fromGlobal) ||
      parseOrigin(fromDataset) ||
      parseOrigin(fromMeta) ||
      parseOrigin(fromQuery)
    );
  }

  function getAllowedOrigins() {
    const allowed = new Set();
    const add = (v) => { const o = parseOrigin(v); if (o) allowed.add(o); };
    const injectedExpectedOrigin = getInjectedExpectedOrigin();
    if (injectedExpectedOrigin) add(injectedExpectedOrigin);
    add(window.location.origin);
    return allowed;
  }

  function notifyWaiters() {
    const token = state.token;
    while (state.waiters.length) {
      const resolve = state.waiters.shift();
      try { resolve(token); } catch (_) {}
    }
  }

  function emitChange(prevToken, meta) {
    state.changes.forEach((cb) => {
      try {
        cb({ token: state.token, previousToken: prevToken, source: state.source, modeChanged: !prevToken && !!state.token, ...meta });
      } catch (_) {}
    });
  }

  function setToken(token, source, meta = {}) {
    if (typeof token !== 'string' || !TOKEN_RE.test(token)) return false;
    const prevToken = state.token;
    if (prevToken === token) return true;
    state.token = token;
    state.source = source;
    notifyWaiters();
    emitChange(prevToken, meta);
    return true;
  }

  function readTokenFromURL() {
    try {
      const u = new URL(window.location.href);
      const t = (u.searchParams.get('token') || '').trim();
      if (!TOKEN_RE.test(t)) return;
      if (setToken(t, 'url')) {
        u.searchParams.delete('token');
        window.history.replaceState({}, '', u.toString());
      }
    } catch (_) {}
  }

  function initPostMessageListener() {
    const injectedExpectedOrigin = getInjectedExpectedOrigin();
    const allowedOrigins = getAllowedOrigins();
    const expectParent = window.parent && window.parent !== window;
    window.addEventListener('message', function onTokenMsg(evt) {
      if (!evt || typeof evt.origin !== 'string') return;
      const expectedOrigin = injectedExpectedOrigin || window.location.origin;
      if (injectedExpectedOrigin && evt.origin !== injectedExpectedOrigin) {
        console.warn(
          '[cfm-auth] rejecting postMessage: origin mismatch (received=%s expected=%s)',
          evt.origin,
          expectedOrigin
        );
        return;
      }
      if (!allowedOrigins.has(evt.origin)) {
        console.warn(
          '[cfm-auth] rejecting postMessage: origin mismatch (received=%s expected=%s)',
          evt.origin,
          expectedOrigin
        );
        return;
      }
      if (expectParent && evt.source !== window.parent) return;
      const tok = evt.data && evt.data.cfmToken;
      if (!setToken(tok, 'postMessage', { origin: evt.origin })) return;
      try {
        if (expectParent) window.parent.postMessage({ cfmTokenAck: true, path: 'postMessage' }, evt.origin);
      } catch (_) {}
    });
  }

  function waitForToken(timeoutMs = 1200) {
    if (state.token) return Promise.resolve(state.token);
    return new Promise((resolve) => {
      const done = () => resolve(state.token || '');
      state.waiters.push(done);
      if (timeoutMs > 0) {
        window.setTimeout(() => {
          const idx = state.waiters.indexOf(done);
          if (idx >= 0) state.waiters.splice(idx, 1);
          done();
        }, timeoutMs);
      }
    });
  }

  async function loadMe(opts = {}) {
    const preferScopedToken = opts.preferScopedToken !== false;
    const waitMs = Number(opts.waitForTokenMs) > 0 ? Number(opts.waitForTokenMs) : 0;
    if (waitMs > 0 && !state.token) await waitForToken(waitMs);
    const headers = { Accept: 'application/json' };
    const authz = window.CFMSharedConstants?.buildBearerHeader?.(state.token);
    if (preferScopedToken && authz) headers.Authorization = authz;
    const mePath = window.CFMSharedConstants?.TOKENS_ME_PATH;
    const res = await fetch(mePath, { credentials: 'same-origin', headers });
    if (!res.ok) throw new Error(`v1/tokens/me -> HTTP ${res.status}`);
    return res.json();
  }

  function onAuthContextChanged(cb) {
    if (typeof cb !== 'function') return () => {};
    state.changes.add(cb);
    return () => state.changes.delete(cb);
  }

  function shouldUseBootstrapCookiePath() {
    return window.location.pathname === '/cfm-admin' || window.location.pathname.startsWith('/cfm-admin/');
  }

  readTokenFromURL();
  initPostMessageListener();

  window.CFMAuthContext = {
    getToken: () => state.token,
    getSource: () => state.source,
    waitForToken,
    loadMe,
    onAuthContextChanged,
    shouldUseBootstrapCookiePath,
  };
})();
