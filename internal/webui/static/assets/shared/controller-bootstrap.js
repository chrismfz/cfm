(() => {
  // Nav items a scoped (per-vhost cPanel/DA) user must NOT see: they are
  // server-wide/admin-only (global dashboard, global UA-emergency "Web Bots",
  // notifier/detectors config, settings, debug). Everything else (WebDetector,
  // Vhost live/Forensics, WAF engine, Vhost controls, MySQL governor) is
  // scope-filtered server-side and stays visible. Backends already fail-closed
  // (403) on these paths; this just hides the dead links from scoped users.
  const ADMIN_ONLY_NAV_PATHS = new Set([
    '/cfm-admin',                    // Dashboard (global stats + global block/unblock)
    '/cfm-admin/health',             // Health history — box-wide metrics (admin-only endpoints)
    '/cfm-admin/mail',               // Mail queue — box-wide queue report (admin-only endpoint)
    '/cfm-admin/webdetector/bots',   // Web Bots — global UA emergency controls
    '/cfm-admin/webdetector/tokens', // API tokens — admin-only issuance/revocation
    '/cfm-admin/notifier',
    '/cfm-admin/detectors',
    '/cfm-admin/settings',
    '/cfm-admin/debug',
  ]);

  function defaultAdminOnlyMatcher(href) {
    let path = String(href || '').split(/[?#]/, 1)[0].replace(/\/+$/, '');
    if (path === '') path = '/cfm-admin';
    return ADMIN_ONLY_NAV_PATHS.has(path);
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
