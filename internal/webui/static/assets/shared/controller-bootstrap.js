(() => {
  function defaultAdminOnlyMatcher(href) {
    return href === '/cfm-admin/' || href.includes('/webdetector/controls/') || href.includes('/governor/');
  }

  function initSharedController({ onModeChanged, onDeferredScopedToken } = {}) {
    const authCtx = window.CFMAuthContext;
    if (!authCtx) throw new Error('CFMAuthContext is required before initializing controllers');

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

    const createApiClient = window.CFMApiClient?.createApiClient;
    if (typeof createApiClient !== 'function') throw new Error('CFMApiClient.createApiClient is required before initializing controllers');

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
        scopedLabel,
        globalLabel,
      } = {}) => {
        const labels = window.CFMSharedConstants?.SCOPE_LABELS || {};
        const resolvedScopedLabel = scopedLabel || labels.scoped;
        const resolvedGlobalLabel = globalLabel || labels.global;

        const uiScope = window.CFMUiScope || {};
        uiScope.applyScopedNavFiltering?.({ navSelector, scoped, adminOnlyMatcher });
        const badge = uiScope.applyScopedBadge?.({ selector: badgeSelector, scopedLabel: resolvedScopedLabel, globalLabel: resolvedGlobalLabel });
        if (badge) badge.textContent = scoped ? resolvedScopedLabel : resolvedGlobalLabel;
        return badge;
      },
    };
  }

  window.CFMControllerBootstrap = { initSharedController };
})();
