(() => {
  function defaultAdminOnlyMatcher(href) {
    return href === '/cfm-admin/' || href.includes('/webdetector/controls/') || href.includes('/governor/');
  }

  function createFallbackAuthContext() {
    return {
      getToken: () => '',
      waitForToken: async () => '',
      onAuthContextChanged: () => () => {},
      loadMe: async ({ preferScopedToken = true } = {}) => {
        const headers = { Accept: 'application/json' };
        if (preferScopedToken && window.CFMAuthContext?.getToken?.()) {
          headers.Authorization = `Bearer ${window.CFMAuthContext.getToken()}`;
        }
        const res = await fetch('/cfm-admin/api/v1/tokens/me', { credentials: 'same-origin', headers });
        if (!res.ok) throw new Error(`v1/tokens/me -> HTTP ${res.status}`);
        return res.json();
      },
    };
  }

  function initSharedController({ onModeChanged, onDeferredScopedToken } = {}) {
    const authCtx = window.CFMAuthContext || createFallbackAuthContext();
    let scopedToken = authCtx.getToken();
    const transitionTracker = window.CFMAuthMode?.createDeferredScopedTransitionTracker?.();

    function maybeHandleDeferredScopedToken(evt) {
      const hasTokenNow = Boolean(authCtx.getToken());
      const shouldHandle = transitionTracker
        ? transitionTracker.shouldHandleDeferredScopedToken({ event: evt, hasTokenNow })
        : (evt?.modeChanged && hasTokenNow);
      if (shouldHandle && typeof onDeferredScopedToken === 'function') onDeferredScopedToken(evt);
    }

    authCtx.onAuthContextChanged((evt) => {
      scopedToken = authCtx.getToken();
      maybeHandleDeferredScopedToken(evt);
      if (evt && evt.modeChanged && typeof onModeChanged === 'function') {
        onModeChanged(evt);
      }
    });

    const createApiClient = window.CFMApiClient?.createApiClient || window.createApiClient;

    return {
      authCtx,
      getToken: () => scopedToken,
      refreshToken: () => {
        scopedToken = authCtx.getToken();
        return scopedToken;
      },
      waitForToken: (timeoutMs = 1200) => authCtx.waitForToken(timeoutMs),
      loadMe: (opts = {}) => authCtx.loadMe(opts),
      noteInitialModeResolved: ({ isScopedMode = false } = {}) => {
        transitionTracker?.noteInitialModeResolved({ isScopedMode, tokenPresent: Boolean(scopedToken) });
      },
      createApiClient: ({ basePath, isScoped, adminOnlyPaths, retryAuthRace = true } = {}) => createApiClient({
        basePath,
        getToken: () => scopedToken,
        isScoped,
        adminOnlyPaths,
        retryAuthRace,
      }),
      applyScopedChrome: ({
        scoped = false,
        navSelector = '.top-nav',
        adminOnlyMatcher = defaultAdminOnlyMatcher,
        badgeSelector = '.topbar .meta',
        scopedLabel = 'Scoped view',
        globalLabel = 'Global view',
      } = {}) => {
        const uiScope = window.CFMUiScope || {};
        uiScope.applyScopedNavFiltering?.({ navSelector, scoped, adminOnlyMatcher });
        const badge = uiScope.applyScopedBadge?.({ selector: badgeSelector, scopedLabel, globalLabel });
        if (badge) badge.textContent = scoped ? scopedLabel : globalLabel;
        return badge;
      },
    };
  }

  window.CFMControllerBootstrap = { initSharedController };
})();
