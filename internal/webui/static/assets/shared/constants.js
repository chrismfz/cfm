(() => {
  const TOKENS_ME_PATH = '/cfm-admin/api/v1/tokens/me';
  const BEARER_PREFIX = 'Bearer ';
  const SCOPE_LABELS = {
    scoped: 'Scoped view',
    global: 'Global view',
  };

  function buildBearerHeader(token) {
    const trimmed = String(token || '').trim();
    return trimmed ? `${BEARER_PREFIX}${trimmed}` : '';
  }

  window.CFMSharedConstants = {
    TOKENS_ME_PATH,
    BEARER_PREFIX,
    SCOPE_LABELS,
    buildBearerHeader,
  };
})();
