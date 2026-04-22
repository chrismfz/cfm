import test from 'node:test';
import assert from 'node:assert/strict';
import { runtimeBadge } from './runtime-badge.js';

const NOW = Date.parse('2026-04-22T12:00:00Z');

test('old failures with recent success is not error', () => {
  const sec = { enabled: true };
  const runtime = {
    runs: 25,
    failures: 8,
    timeouts: 0,
    init_ok: true,
    active: true,
    source_probe_ok: true,
    last_success_at: new Date(NOW - (5 * 60 * 1000)).toISOString(),
    last_run_at: new Date(NOW - (2 * 60 * 1000)).toISOString(),
    last_error: '',
  };
  const badge = runtimeBadge(sec, runtime, { nowMs: NOW });
  assert.notEqual(badge.label, 'error');
  assert.equal(badge.label, 'healthy');
});

test('init failure is error', () => {
  const sec = { enabled: true };
  const runtime = {
    runs: 1,
    failures: 1,
    timeouts: 0,
    init_ok: false,
    active: false,
    source_probe_ok: true,
    last_run_at: new Date(NOW - (1 * 60 * 1000)).toISOString(),
    last_error: 'bad regex',
  };
  const badge = runtimeBadge(sec, runtime, { nowMs: NOW });
  assert.equal(badge.label, 'error');
});

test('repeated recent timeouts is error', () => {
  const sec = { enabled: true };
  const runtime = {
    runs: 7,
    failures: 2,
    timeouts: 2,
    init_ok: true,
    active: true,
    source_probe_ok: true,
    last_run_at: new Date(NOW - (3 * 60 * 1000)).toISOString(),
    last_error: 'run timeout',
  };
  const badge = runtimeBadge(sec, runtime, { nowMs: NOW });
  assert.equal(badge.label, 'error');
});
