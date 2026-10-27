// node --test internal/webui/static/assets/webdet/challenge-lockdown.test.js
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  LOCKDOWN_TTL_CHOICES,
  lockdownActive,
  lockdownLabel,
  lockdownLeft,
  lockdownRequest,
  lockdownUntil,
} from "./challenge-lockdown.js";

const now = Date.parse("2026-10-27T12:00:00Z");

test("reads the expiry from a status object and from a controls row", () => {
  assert.equal(lockdownUntil({ lockdown: true, lockdown_until: "2026-10-27T12:30:00Z" }).toISOString(), "2026-10-27T12:30:00.000Z");
  assert.equal(lockdownUntil({ challenge_lockdown_until: "2026-10-27T12:30:00Z" }).toISOString(), "2026-10-27T12:30:00.000Z");
  assert.equal(lockdownUntil({ lockdown: false, lockdown_until: null }), null);
  assert.equal(lockdownUntil({ lockdown_until: "nonsense" }), null);
  assert.equal(lockdownUntil(null), null);
});

test("active / left / label follow the clock, an expired lockdown is none", () => {
  const s = { lockdown_until: "2026-10-27T13:05:00Z" };
  assert.equal(lockdownActive(s, now), true);
  assert.equal(lockdownLeft(s, now), "1h05m");
  assert.equal(lockdownLabel(s, now), "LOCKDOWN · 1h05m left");
  assert.equal(lockdownLeft({ lockdown_until: "2026-10-27T12:20:00Z" }, now), "20m");
  const gone = { lockdown_until: "2026-10-27T11:59:00Z" };
  assert.equal(lockdownActive(gone, now), false);
  assert.equal(lockdownLabel(gone, now), "");
});

test("the request: lift, lock an armed vhost in place, or arm both", () => {
  assert.deepEqual(lockdownRequest("a.gr", { manual_active: true }, false),
    { path: "v1/challenge/vhost/lockdown", body: { host: "a.gr", lockdown: false } });
  assert.deepEqual(lockdownRequest("a.gr", { manual_active: true }, true, "1h"),
    { path: "v1/challenge/vhost/lockdown", body: { host: "a.gr", lockdown: true, ttl: "1h" } });
  // An automatic challenge, or none, is armed manually with the lockdown.
  for (const st of [{ auto_active: true }, {}, null]) {
    assert.deepEqual(lockdownRequest("a.gr", st, true, "30m"), {
      path: "v1/challenge/vhost/add",
      body: { host: "a.gr", ttl: "30m", reason: "panic-lockdown", lockdown: true, lockdown_ttl: "30m" },
    });
  }
});

test("the duration choices stay within the daemon's 6h cap", () => {
  const src = readFileSync(new URL("../../../../webdetector/vhost_lockdown.go", import.meta.url), "utf8");
  const m = src.match(/maxLockdownTTL\s*=\s*(\d+)\s*\*\s*time\.Hour/);
  assert.ok(m, "maxLockdownTTL not found in vhost_lockdown.go");
  const maxH = Number(m[1]);
  const toH = (v) => (v.endsWith("h") ? Number(v.slice(0, -1)) : Number(v.slice(0, -1)) / 60);
  for (const c of LOCKDOWN_TTL_CHOICES) assert.ok(toH(c.value) <= maxH, `${c.value} exceeds ${maxH}h`);
  assert.equal(toH(LOCKDOWN_TTL_CHOICES[LOCKDOWN_TTL_CHOICES.length - 1].value), maxH, "the last choice is the maximum");
});
