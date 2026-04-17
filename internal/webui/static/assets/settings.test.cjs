const test = require('node:test');
const assert = require('node:assert/strict');

const {
  normalizeCode,
  updatePassword,
  startTotpEnrollment,
  confirmTotpEnrollment,
  regenerateRecoveryCodes,
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
      return { ok: true, status: 200, json: async () => ({ qr_svg: '<svg>qr</svg>' }) };
    }
    if (url.endsWith('/confirm')) {
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    }
    if (url.endsWith('/regenerate')) {
      return { ok: true, status: 200, json: async () => ({ recovery_codes: ['A1-B2-C3'] }) };
    }
    throw new Error(`unexpected url ${url}`);
  };

  const started = await startTotpEnrollment();
  assert.equal(started.qr_svg, '<svg>qr</svg>');

  const confirmed = await confirmTotpEnrollment({ code: '12-34 56' });
  assert.equal(confirmed.ok, true);

  const regenerated = await regenerateRecoveryCodes({ password: 'current-password' });
  assert.deepEqual(regenerated.recovery_codes, ['A1-B2-C3']);

  assert.deepEqual(calls, [
    '/cfm-admin/mfa/totp/enroll/start',
    '/cfm-admin/mfa/totp/enroll/confirm',
    '/cfm-admin/mfa/recovery/regenerate',
  ]);
});

test('unauthorized API responses bubble as errors', async () => {
  global.fetch = async () => ({ ok: false, status: 401, json: async () => ({ error: 'unauthorized' }) });
  await assert.rejects(() => startTotpEnrollment(), /unauthorized/);
});
