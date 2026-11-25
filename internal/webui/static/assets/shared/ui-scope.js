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
    // The authoritative admin-only nav list lives in controller-bootstrap.js
    // (defaultAdminOnlyMatcher) and is always passed in by applyScopedChrome.
    // Do NOT keep a divergent copy here: a stale duplicate previously disagreed
    // with the real list and misled a scope audit. If no matcher is supplied,
    // hide nothing — backends still fail-closed (403) on admin-only paths.
    const matcher = typeof adminOnlyMatcher === 'function' ? adminOnlyMatcher : () => false;

    nav.querySelectorAll('a[href]').forEach((anchor) => {
      const href = anchor.getAttribute('href') || '';
      const adminOnly = matcher(href, anchor);
      anchor.style.display = scoped && adminOnly ? 'none' : '';
    });
    // A group whose every page is hidden loses its heading too (a scoped user
    // has nothing under "Overview").
    nav.querySelectorAll('.nav-group-title').forEach((title) => {
      let any = false;
      for (let n = title.nextElementSibling; n && !n.classList.contains('nav-group-title'); n = n.nextElementSibling) {
        if (n.matches('a[href]') && n.style.display !== 'none') { any = true; break; }
      }
      title.style.display = any ? '' : 'none';
    });
    return nav;
  }

  window.CFMUiScope = {
    applyScopedBadge,
    applyScopedNavFiltering,
  };
})();
