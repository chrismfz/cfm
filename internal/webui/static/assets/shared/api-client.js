(() => {
  function normalizePath(path) {
    const raw = String(path || '').trim();
    if (!raw) return '/';
    return raw.startsWith('/') ? raw : `/${raw}`;
  }

  function normalizeAdminOnlyPaths(adminOnlyPaths) {
    if (!adminOnlyPaths) return new Set();
    if (adminOnlyPaths instanceof Set) return new Set([...adminOnlyPaths].map(normalizePath));
    if (Array.isArray(adminOnlyPaths)) return new Set(adminOnlyPaths.map(normalizePath));
    return new Set();
  }

  async function parseResponseJSON(res) {
    if (res.status === 204) return {};
    const contentType = String(res.headers.get('content-type') || '').toLowerCase();
    const text = await res.text();
    if (!text) return {};
    if (contentType.includes('application/json')) {
      try { return JSON.parse(text); } catch (_) { return { raw: text }; }
    }
    try { return JSON.parse(text); } catch (_) { return { raw: text }; }
  }

  function makeApiError({ message, status, path, data, cause }) {
    const err = new Error(message || 'api request failed');
    err.name = 'ApiClientError';
    err.status = Number(status) || 0;
    err.path = path || '';
    err.data = data;
    if (cause) err.cause = cause;
    return err;
  }

  function createApiClient({ basePath, getToken, isScoped, adminOnlyPaths, retryAuthRace } = {}) {
    const resolvedBase = String(basePath || '').replace(/\/+$/, '');
    const resolvedGetToken = typeof getToken === 'function' ? getToken : () => '';
    const resolvedIsScoped = typeof isScoped === 'function' ? isScoped : () => Boolean(isScoped);
    const blockedPaths = normalizeAdminOnlyPaths(adminOnlyPaths);

    return async function request(path, opts = {}) {
      const normalizedPath = normalizePath(path);
      const reqOpts = { credentials: 'same-origin', ...opts };
      const retryOnAuthRace = Boolean(reqOpts.retryAuthRace ?? retryAuthRace);
      delete reqOpts.retryAuthRace;

      if (resolvedIsScoped() && blockedPaths.has(normalizedPath)) {
        throw makeApiError({
          message: `Scoped mode blocks admin endpoint: ${normalizedPath}`,
          status: 403,
          path: normalizedPath,
          data: { error: 'scoped_mode_admin_endpoint_blocked' },
        });
      }

      const runFetch = async () => {
        const headers = { ...(reqOpts.headers || {}) };
        const token = String(resolvedGetToken() || '').trim();
        if (token) headers.Authorization = `Bearer ${token}`;
        const res = await fetch(`${resolvedBase}${normalizedPath}`, { ...reqOpts, headers });
        const data = await parseResponseJSON(res);
        if (!res.ok || data?.ok === false) {
          throw makeApiError({
            message: data?.error || data?.message || `HTTP ${res.status}`,
            status: res.status,
            path: normalizedPath,
            data,
          });
        }
        return data;
      };

      const hadToken = Boolean(String(resolvedGetToken() || '').trim());
      try {
        return await runFetch();
      } catch (err) {
        const status = Number(err?.status || 0);
        if (!retryOnAuthRace || hadToken || ![401, 403].includes(status) || typeof window.CFMAuthContext?.waitForToken !== 'function') {
          throw err;
        }
        await window.CFMAuthContext.waitForToken(450);
        const hasTokenNow = Boolean(String(resolvedGetToken() || '').trim());
        if (!hasTokenNow) throw err;
        return runFetch();
      }
    };
  }

  window.CFMApiClient = { createApiClient };
  window.createApiClient = createApiClient;
})();
