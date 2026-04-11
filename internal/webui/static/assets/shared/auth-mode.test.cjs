const test = require('node:test');
const assert = require('node:assert/strict');

const {
  computeInitialScopeMode,
  createDeferredScopedTransitionTracker,
} = require('./auth-mode.js');

test('first load with admin session only resolves global mode', () => {
  const mode = computeInitialScopeMode({ identity: { scoped: false, role: 'admin' }, token: '' });
  assert.equal(mode, 'global');
});

test('first load with scoped token resolves scoped mode', () => {
  const mode = computeInitialScopeMode({ identity: { scoped: true, role: 'viewer' }, token: 'abc' });
  assert.equal(mode, 'scoped');
});

test('late token arrival after initial global triggers one deferred transition', () => {
  const tracker = createDeferredScopedTransitionTracker();
  tracker.noteInitialModeResolved({ isScopedMode: false, tokenPresent: false });

  const first = tracker.shouldHandleDeferredScopedToken({
    event: { modeChanged: true },
    hasTokenNow: true,
  });
  assert.equal(first, true);

  const second = tracker.shouldHandleDeferredScopedToken({
    event: { modeChanged: true },
    hasTokenNow: true,
  });
  assert.equal(second, false);
});
