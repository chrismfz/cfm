(() => {
  function isElement(value) {
    return Boolean(value && typeof value === 'object' && value.nodeType === 1);
  }

  function resolveElement(selector) {
    if (isElement(selector)) return selector;
    if (typeof selector === 'string' && selector.trim()) return document.querySelector(selector);
    return null;
  }

  function applyScopedBadge({ selector, scopedLabel, globalLabel } = {}) {
    const container = resolveElement(selector);
    if (!container) return null;

    let badge = container.querySelector('.scoped-badge');
    if (!badge) {
      badge = document.createElement('span');
      badge.className = 'pill scoped-badge';
      container.prepend(badge);
    }

    const labels = window.CFMSharedConstants?.SCOPE_LABELS || {};
    const resolvedScopedLabel = scopedLabel || labels.scoped || '';
    const resolvedGlobalLabel = globalLabel || labels.global || '';

    badge.textContent = resolvedScopedLabel;
    badge.dataset.scopedLabel = resolvedScopedLabel;
    badge.dataset.globalLabel = resolvedGlobalLabel;
    return badge;
  }

  function applyScopedNavFiltering({ navSelector, adminOnlyMatcher, scoped = false } = {}) {
    const nav = resolveElement(navSelector);
    if (!nav) return null;
    const matcher = typeof adminOnlyMatcher === 'function'
      ? adminOnlyMatcher
      : (href) => {
          const path = String(href || '').split(/[?#]/, 1)[0];
          return path === '/cfm-admin' || path === '/cfm-admin/';
        };

    nav.querySelectorAll('a[href]').forEach((anchor) => {
      const href = anchor.getAttribute('href') || '';
      const adminOnly = matcher(href, anchor);
      anchor.style.display = scoped && adminOnly ? 'none' : '';
    });
    return nav;
  }

  window.CFMUiScope = {
    applyScopedBadge,
    applyScopedNavFiltering,
  };
})();
