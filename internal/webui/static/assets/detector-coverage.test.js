import test from 'node:test';
import assert from 'node:assert/strict';

import { coverageBadge, coverageSummaryItems, unitStateText } from './detector-coverage.js';

test('coverageBadge maps every server verdict to the right pill class', () => {
  const cases = {
    ok: 'pill ok',
    gap: 'pill danger',
    disabled: 'pill warn',
    dormant: 'pill warn',
    absent: 'pill', // muted — informational by design
    na: 'pill info',
  };
  for (const [verdict, cls] of Object.entries(cases)) {
    const badge = coverageBadge(verdict);
    assert.equal(badge.cls, cls, `verdict ${verdict}`);
    assert.ok(badge.label && typeof badge.title === 'string', `verdict ${verdict} label/title`);
  }
});

test('absent verdict must not look like an error', () => {
  const badge = coverageBadge('absent');
  assert.ok(!badge.cls.includes('danger'));
  assert.ok(!badge.cls.includes('warn'));
});

test('unknown verdict degrades to a neutral pill, never throws', () => {
  for (const v of [undefined, null, '', 'something-new']) {
    const badge = coverageBadge(v);
    assert.equal(badge.cls, 'pill');
    assert.ok(badge.label.length > 0);
  }
});

test('coverageSummaryItems covers all six buckets with counts', () => {
  const items = coverageSummaryItems({ types_total: 19, ok: 4, gaps: 1, disabled: 0, dormant: 2, absent: 7, event_driven: 5 });
  const byKey = Object.fromEntries(items.map((i) => [i.key, i]));
  assert.deepEqual(
    Object.keys(byKey).sort(),
    ['absent', 'disabled', 'dormant', 'event_driven', 'gaps', 'ok'].sort()
  );
  assert.equal(byKey.gaps.count, 1);
  assert.equal(byKey.gaps.cls, 'pill danger');
  assert.equal(byKey.event_driven.cls, 'pill info');
  assert.equal(byKey.absent.cls, 'pill');
  assert.ok(byKey.ok.label.includes('OK: 4'));
});

test('coverageSummaryItems tolerates a missing summary object', () => {
  const items = coverageSummaryItems(null);
  assert.equal(items.length, 6);
  assert.ok(items.every((i) => i.count === 0));
});

test('unitStateText renders the three daemon states', () => {
  assert.equal(unitStateText({ unit: 'postfix', found: true, active: true }), 'postfix: running');
  assert.equal(unitStateText({ unit: 'postfix', found: true, active: false }), 'postfix: stopped');
  assert.equal(unitStateText({ unit: 'pvedaemon', found: false }), 'pvedaemon: not installed');
  assert.equal(unitStateText(null), '?: not installed');
});
