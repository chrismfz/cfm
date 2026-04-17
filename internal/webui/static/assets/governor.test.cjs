const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function createElement() {
  return {
    style: {},
    dataset: {},
    value: '',
    textContent: '',
    innerHTML: '',
    disabled: false,
    addEventListener() {},
    removeAttribute() {},
    prepend() {},
    remove() {},
    querySelector() { return null; },
    querySelectorAll() { return []; },
    appendChild() {},
    scrollIntoView() {},
  };
}

function okJson(data) {
  return {
    ok: true,
    status: 200,
    headers: { get: () => 'application/json' },
    text: async () => JSON.stringify(data),
  };
}

test('startup with token + /v1/tokens/me 401 uses scoped refresh and skips admin endpoints', async () => {
  const governorPath = path.resolve(__dirname, 'governor.js');
  const source = fs.readFileSync(governorPath, 'utf8');
  const ids = new Map();
  const getEl = (id) => {
    if (!ids.has(id)) ids.set(id, createElement());
    return ids.get(id);
  };

  const fetchCalls = [];
  const token = 'scoped-token-present';
  const adminPathPattern = /\/v1\/mysql\/(state|kills|locks|processlist)(?:[?#]|$)/;

  const context = {
    window: {},
    document: {
      getElementById: (id) => getEl(id),
      createElement: () => createElement(),
    },
    console: { info() {}, error() {}, warn() {}, log() {} },
    URLSearchParams,
    Date,
    setInterval: () => 1,
    clearInterval: () => {},
    fetch: async (url) => {
      fetchCalls.push(String(url));
      if (adminPathPattern.test(String(url))) {
        throw new Error(`admin endpoint called in guarded scenario: ${url}`);
      }
      if (String(url).includes('/api/v1/mysql/user-summary')) {
        return okJson({ ok: true, ts: 1, users: [] });
      }
      if (String(url).includes('/api/v1/mysql/user-history')) {
        return okJson({ ok: true, ts: 1, window: '1h', sample_count: 0, users: [] });
      }
      if (String(url).includes('/api/v1/mysql/user-kills')) {
        return okJson({ ok: true, kills: [] });
      }
      return okJson({ ok: true });
    },
  };
  context.window = context;
  context.window.confirm = () => true;
  context.window.echarts = null;
  context.window.CFMAuthMode = {
    computeInitialScopeMode: ({ identity, token: t }) => {
      if (identity && (identity.scoped === true || identity.isScopedMode === true || identity.is_scoped_mode === true)) return 'scoped';
      return String(t || '').trim() ? 'scoped' : 'global';
    },
  };
  context.window.CFMControllerBootstrap = {
    initSharedController: () => ({
      getToken: () => token,
      waitForToken: async () => token,
      refreshToken: () => token,
      loadMe: async () => {
        throw new Error('v1/tokens/me -> HTTP 401');
      },
      noteInitialModeResolved() {},
      applyScopedChrome() {},
      createApiClient: ({ basePath }) => async (reqPath) => context.fetch(`${basePath}${reqPath}`),
    }),
  };

  vm.runInNewContext(source, context, { filename: governorPath });
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(fetchCalls.some((url) => url.includes('/api/v1/mysql/user-summary')), true);
  assert.equal(fetchCalls.some((url) => url.includes('/api/v1/mysql/user-history')), true);
  assert.equal(fetchCalls.some((url) => url.includes('/api/v1/mysql/user-kills')), true);
  assert.equal(fetchCalls.some((url) => adminPathPattern.test(url)), false);
});
