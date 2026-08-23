const test = require('node:test');
const assert = require('node:assert/strict');

const api = require('./settings.js');
const { configDriftView } = api;

test('configDriftView reports clean configs', () => {
  const v = configDriftView({
    ok: true,
    detectors_conf: {
      name: 'detectors.conf',
      stock_found: true,
      live_found: true,
      report: { missing_sections: [], missing_keys: [], extra_sections: [], extra_keys: [], value_diffs: 3 },
    },
    cfm_conf: {
      name: 'cfm.conf',
      stock_found: true,
      live_found: true,
      report: { missing_keys: [], stock_keys: 40, live_keys: 40 },
    },
  });
  assert.equal(v.total, 0);
  assert.equal(v.headlineTone, 'ok');
  assert.match(v.headline, /No drift/);
});

test('configDriftView lists detectors missing sections and keys as warnings', () => {
  const v = configDriftView({
    ok: true,
    detectors_conf: {
      name: 'detectors.conf',
      stock_found: true,
      live_found: true,
      report: {
        missing_sections: ['waf_security'],
        missing_keys: [{ section: 'challenge_cookie_discard', key: 'MIN_SOLVES' }],
        extra_sections: ['cpanel'],
        extra_keys: [],
        value_diffs: 1,
      },
    },
    cfm_conf: { name: 'cfm.conf', stock_found: true, live_found: true, report: { missing_keys: [], stock_keys: 40, live_keys: 40 } },
  });
  assert.equal(v.total, 2);
  assert.equal(v.headlineTone, 'warn');
  const det = v.files.find((f) => f.name === 'detectors.conf');
  assert.equal(det.tone, 'warn');
  assert.ok(det.lines.some((l) => l.text.includes('waf_security')));
  assert.ok(det.lines.some((l) => l.text.includes('MIN_SOLVES') && l.text.includes('challenge_cookie_discard')));
  assert.ok(det.lines.some((l) => /differ in VALUE/.test(l.text)));
});

test('configDriftView handles the flat cfm.conf missing-keys shape', () => {
  const v = configDriftView({
    ok: true,
    detectors_conf: { name: 'detectors.conf', stock_found: false },
    cfm_conf: {
      name: 'cfm.conf',
      stock_found: true,
      live_found: true,
      report: { missing_keys: ['MCP'], stock_keys: 41, live_keys: 40 },
    },
  });
  assert.equal(v.total, 1);
  const cfm = v.files.find((f) => f.name === 'cfm.conf');
  assert.equal(cfm.tone, 'warn');
  assert.ok(cfm.lines.some((l) => l.text.includes('MCP')));
});

test('configDriftView degrades gracefully: no stock file, unreadable live, bad payload', () => {
  const noStock = configDriftView({ ok: true, detectors_conf: { name: 'detectors.conf', stock_found: false, note: 'stock reference not found' } });
  const detBlock = noStock.files.find((f) => f.name === 'detectors.conf');
  assert.equal(detBlock.tone, 'muted');
  assert.ok(detBlock.lines[0].text.includes('not found'));

  const errLive = configDriftView({
    ok: true,
    detectors_conf: { name: 'detectors.conf', stock_found: true, error: 'parse live: boom' },
    cfm_conf: { name: 'cfm.conf', stock_found: false },
  });
  const detErr = errLive.files.find((f) => f.name === 'detectors.conf');
  assert.equal(detErr.tone, 'warn');
  assert.ok(detErr.lines.some((l) => l.text.includes('boom')));

  const empty = configDriftView(null);
  assert.ok(empty.headline.length > 0);
  assert.deepEqual(empty.files.map((f) => f.missingTotal), [0, 0]);
});
