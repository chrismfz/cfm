(() => {
  function computeInitialScopeMode({ identity, token }) {
    if (identity && identity.scoped === true) return 'scoped';
    if (typeof token === 'string' && token.trim()) return 'scoped';
    return 'global';
  }

  function createDeferredScopedTransitionTracker() {
    let initialModeResolved = false;
    let initialScopedMode = false;
    let initialTokenPresent = false;
    let deferredScopedTokenHandled = false;

    return {
      noteInitialModeResolved({ isScopedMode = false, tokenPresent = false } = {}) {
        initialModeResolved = true;
        initialScopedMode = Boolean(isScopedMode);
        initialTokenPresent = Boolean(tokenPresent);
      },
      shouldHandleDeferredScopedToken({ event, hasTokenNow }) {
        if (!event || !event.modeChanged) return false;
        if (!initialModeResolved || initialScopedMode || initialTokenPresent) return false;
        if (!hasTokenNow || deferredScopedTokenHandled) return false;
        deferredScopedTokenHandled = true;
        return true;
      },
    };
  }

  const api = {
    computeInitialScopeMode,
    createDeferredScopedTransitionTracker,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (typeof window !== 'undefined') {
    window.CFMAuthMode = api;
  }
})();
