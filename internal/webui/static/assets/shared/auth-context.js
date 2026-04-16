(() => {
  if (window.CFMAuthContext) return;

  const TOKEN_RE = /^[0-9a-f]{64}$/;
  const EXPECTED_PARENT_ORIGIN_PARAM = 'cfmExpectedOrigin';
  const EXPECTED_PARENT_ORIGIN_STORAGE_KEY = 'cfm:expectedParentOrigin';
  const URL_TOKEN_COMPAT_FLAG = 'enableLegacyUrlTokenTransport';
  const state = { token: '', source: 'none', changes: new Set(), waiters: [] };

  function parseOrigin(value) {
    if (typeof value !== 'string') return '';
    const trimmed = value.trim();
    if (!trimmed) return '';
    try { return new URL(trimmed, window.location.origin).origin; } catch (_) { return ''; }
  }

  function parseLocationURL() {
    try { return new URL(window.location.href); } catch (_) { return null; }
  }

  function getExpectedOriginFromQuery(parsedURL) {
    if (!parsedURL || !parsedURL.searchParams) return '';
    return parseOrigin(parsedURL.searchParams.get(EXPECTED_PARENT_ORIGIN_PARAM) || '');
  }

  function readStoredExpectedParentOrigin() {
    try {
      const raw = window.sessionStorage.getItem(EXPECTED_PARENT_ORIGIN_STORAGE_KEY) || '';
      return parseOrigin(raw);
    } catch (_) {
      return '';
    }
  }

  function storeExpectedParentOrigin(origin) {
    if (!origin) return;
    try { window.sessionStorage.setItem(EXPECTED_PARENT_ORIGIN_STORAGE_KEY, origin); } catch (_) {}
  }

  function getAllowedOrigins(expectedParentOrigin) {
    const allowed = new Set();
    const add = (v) => { const o = parseOrigin(v); if (o) allowed.add(o); };
    if (expectedParentOrigin) add(expectedParentOrigin);
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

  function readTokenFromURL(parsedURL) {
    if (!parsedURL || !parsedURL.searchParams) return false;
    const compatFlag = window.CFMFeatureFlags?.[URL_TOKEN_COMPAT_FLAG] === true;
    if (!compatFlag) return false;
    const t = (parsedURL.searchParams.get('token') || '').trim();
    if (!TOKEN_RE.test(t)) return false;
    console.warn(
      '[cfm-auth] DEPRECATED: URL token transport is enabled via feature flag "%s". This mode is unsupported in production.',
      URL_TOKEN_COMPAT_FLAG
    );
    return setToken(t, 'url');
  }

  function cleanupBootstrapQueryParams(parsedURL, keys = []) {
    if (!parsedURL || !parsedURL.searchParams || !Array.isArray(keys) || !keys.length) return;
    let dirty = false;
    keys.forEach((k) => {
      if (parsedURL.searchParams.has(k)) {
        parsedURL.searchParams.delete(k);
        dirty = true;
      }
    });
    if (!dirty) return;
    try { window.history.replaceState({}, '', parsedURL.toString()); } catch (_) {}
  }

  function initPostMessageListener(expectedParentOrigin) {
    const allowedOrigins = getAllowedOrigins(expectedParentOrigin);
    const expectParent = window.parent && window.parent !== window;
    window.addEventListener('message', function onTokenMsg(evt) {
      if (!evt || typeof evt.origin !== 'string') return;
      const expectedOrigin = expectedParentOrigin || window.location.origin;
      const allowlist = Array.from(allowedOrigins.values());
      if (expectedParentOrigin && evt.origin !== expectedParentOrigin) {
        console.warn(
          '[cfm-auth] rejecting postMessage origin (received=%s allowlist=%o)',
          evt.origin,
          allowlist
        );
        return;
      }
      if (!allowedOrigins.has(evt.origin)) {
        console.warn(
          '[cfm-auth] rejecting postMessage origin (received=%s allowlist=%o)',
          evt.origin,
          allowlist
        );
        return;
      }
      if (expectParent && evt.source !== window.parent) return;
      console.debug('[cfm-auth] accepted postMessage origin=%s expected=%s', evt.origin, expectedOrigin);
      const tok = evt.data && evt.data.cfmToken;
      if (!setToken(tok, 'postMessage', { origin: evt.origin })) return;
      try {
        window.dispatchEvent(new CustomEvent('cfm:token_ready', { detail: state.token }));
      } catch (_) {}
      try {
        if (expectParent) {
          const seq = Number(evt?.data?.loadSeq || 0);
          const ackPayload = { cfmTokenAck: true, path: 'postMessage', ackSeq: seq || 0, loadSeq: seq || 0 };
          window.parent.postMessage(ackPayload, evt.origin);
          console.debug('[cfm-auth] ACK sent origin=%s ackSeq=%d loadSeq=%d', evt.origin, ackPayload.ackSeq, ackPayload.loadSeq);
        }
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

  const bootstrapURL = parseLocationURL();
  const tokenAcceptedFromURL = readTokenFromURL(bootstrapURL);
  if (tokenAcceptedFromURL) {
    try { window.dispatchEvent(new CustomEvent('cfm:token_ready', { detail: state.token })); } catch (_) {}
  }
  const expectedParentOriginFromURL = getExpectedOriginFromQuery(bootstrapURL);
  if (expectedParentOriginFromURL) storeExpectedParentOrigin(expectedParentOriginFromURL);
  const expectedParentOrigin = expectedParentOriginFromURL || readStoredExpectedParentOrigin();
  initPostMessageListener(expectedParentOrigin);
  cleanupBootstrapQueryParams(
    bootstrapURL,
    [
      ...(tokenAcceptedFromURL ? ['token'] : []),
      EXPECTED_PARENT_ORIGIN_PARAM,
    ]
  );

  window.CFMAuthContext = {
    getToken: () => state.token,
    getSource: () => state.source,
    waitForToken,
    loadMe,
    onAuthContextChanged,
    shouldUseBootstrapCookiePath,
  };
})();
