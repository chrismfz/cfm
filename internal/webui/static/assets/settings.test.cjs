const test = require('node:test');
const assert = require('node:assert/strict');

const {
  normalizeCode,
  updatePassword,
  startTotpEnrollment,
  confirmTotpEnrollment,
  regenerateRecoveryCodes,
  getRecoveryCodes,
  mountSettingsPage,
} = require('./settings.js');

test('normalizeCode strips non-digits and truncates to 6', () => {
  assert.equal(normalizeCode('1a2b3c4d5e6f7'), '123456');
});

test('updatePassword prefers goauth self endpoint then falls back to cfm endpoint', async () => {
  const calls = [];
  global.fetch = async (url) => {
    calls.push(url);
    if (url === '/cfm-admin/me/password') {
      return { ok: false, status: 404, json: async () => ({ error: 'not found' }) };
    }
    if (url === '/cfm-admin/api/v1/me/password') {
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    }
    throw new Error(`unexpected url ${url}`);
  };

  const out = await updatePassword({ currentPassword: 'old-password', newPassword: 'new-password-123' });
  assert.equal(out.endpoint, '/cfm-admin/api/v1/me/password');
  assert.deepEqual(calls, ['/cfm-admin/me/password', '/cfm-admin/api/v1/me/password']);
});

test('start/confirm/regenerate mfa happy path', async () => {
  const calls = [];
  global.fetch = async (url) => {
    calls.push(url);
    if (url.endsWith('/start')) {
      return { ok: true, status: 200, json: async () => ({ otpauth_uri: 'otpauth://totp/Example?secret=ABC123' }) };
    }
    if (url.endsWith('/confirm')) {
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    }
    if (url.endsWith('/regenerate')) {
      return { ok: true, status: 200, json: async () => ({ codes: ['A1-B2-C3'] }) };
    }
    throw new Error(`unexpected url ${url}`);
  };

  const started = await startTotpEnrollment();
  assert.equal(started.otpauth_uri, 'otpauth://totp/Example?secret=ABC123');

  const confirmed = await confirmTotpEnrollment({ code: '12-34 56' });
  assert.equal(confirmed.ok, true);

  const regenerated = await regenerateRecoveryCodes({ password: 'current-password' });
  assert.deepEqual(getRecoveryCodes(regenerated), ['A1-B2-C3']);

  assert.deepEqual(calls, [
    '/cfm-admin/mfa/totp/enroll/start',
    '/cfm-admin/mfa/totp/enroll/confirm',
    '/cfm-admin/mfa/recovery/regenerate',
  ]);
});

test('getRecoveryCodes supports both current and legacy response fields', () => {
  assert.deepEqual(getRecoveryCodes({ codes: ['X1-Y2-Z3'] }), ['X1-Y2-Z3']);
  assert.deepEqual(getRecoveryCodes({ recovery_codes: ['A1-B2-C3'] }), ['A1-B2-C3']);
  assert.deepEqual(getRecoveryCodes({}), []);
});

test('mountSettingsPage displays returned recovery codes from current payload field', async () => {
  const elements = createSettingsDOM();
  elements.reauthPassword.value = 'current-password';

  global.document = {
    getElementById: (id) => elements[id] || null,
  };

  global.fetch = async (url) => {
    if (url.endsWith('/regenerate')) {
      return { ok: true, status: 200, json: async () => ({ codes: ['CODE-1', 'CODE-2'] }) };
    }
    throw new Error(`unexpected url ${url}`);
  };

  mountSettingsPage();
  await elements.regenRecoveryBtn.handlers.click();

  assert.equal(elements.recoveryCodes.textContent, 'CODE-1\nCODE-2');
});

test('mountSettingsPage displays returned recovery codes from legacy payload field', async () => {
  const elements = createSettingsDOM();
  elements.reauthPassword.value = 'current-password';

  global.document = {
    getElementById: (id) => elements[id] || null,
  };

  global.fetch = async (url) => {
    if (url.endsWith('/regenerate')) {
      return { ok: true, status: 200, json: async () => ({ recovery_codes: ['LEGACY-1', 'LEGACY-2'] }) };
    }
    throw new Error(`unexpected url ${url}`);
  };

  mountSettingsPage();
  await elements.regenRecoveryBtn.handlers.click();

  assert.equal(elements.recoveryCodes.textContent, 'LEGACY-1\nLEGACY-2');
});

test('startTotpEnrollment still supports legacy qr_svg-only payloads', async () => {
  global.fetch = async (url) => {
    if (url.endsWith('/start')) {
      return { ok: true, status: 200, json: async () => ({ qr_svg: '<svg>legacy</svg>' }) };
    }
    throw new Error(`unexpected url ${url}`);
  };

  const started = await startTotpEnrollment();
  assert.equal(started.qr_svg, '<svg>legacy</svg>');
});

test('unauthorized API responses bubble as errors', async () => {
  global.fetch = async () => ({ ok: false, status: 401, json: async () => ({ error: 'unauthorized' }) });
  await assert.rejects(() => startTotpEnrollment(), /unauthorized/);
});

function createSettingsDOM() {
  const createElement = () => {
    const handlers = {};
    return {
      value: '',
      textContent: '',
      innerHTML: '',
      style: {},
      handlers,
      addEventListener: (event, handler) => {
        handlers[event] = handler;
      },
    };
  };

  return {
    settingsStatus: createElement(),
    totpQRSurface: createElement(),
    recoveryCodes: createElement(),
    changePasswordBtn: createElement(),
    currentPassword: createElement(),
    newPassword: createElement(),
    startTotpBtn: createElement(),
    confirmTotpBtn: createElement(),
    totpCode: createElement(),
    regenRecoveryBtn: createElement(),
    reauthPassword: createElement(),
  };
}
