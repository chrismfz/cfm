// node --test internal/webui/static/assets/webdet/challenge-tier.test.js
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  TIER_SOURCE_LABELS,
  tierButtonTitle,
  effectiveTier,
  tierSourceLabel,
  tierButtonLabel,
  tierPinned,
  tierSuffix,
  tierSwitchIsPin,
  tierSwitchRequest,
  tierSwitchRequests,
  tierSwitchTarget,
  tierTitle,
  tierUnpinRequest,
  tierUnpinnable,
} from "./challenge-tier.js";

const autoV2 = { auto_active: true, rung: "v2", rung_source: "auto", rung_trigger: "suspicious_vhost" };
const autoV1 = { auto_active: true, rung: "", rung_source: "auto", rung_trigger: "vhost_config" };
const pinnedV1 = { auto_active: true, rung: "", rung_source: "pin", rung_trigger: "suspicious_vhost", rung_pin: "v1" };
const manualV2 = { manual_active: true, rung: "v2", rung_source: "manual", rung_pin: "v1" };
const manualV1 = { manual_active: true, rung: "", rung_source: "manual" };

test("effective tier follows the daemon's resolved rung", () => {
  assert.equal(effectiveTier(autoV2), "v2");
  assert.equal(effectiveTier(autoV1), "v1");
  assert.equal(effectiveTier(pinnedV1), "v1");
  assert.equal(effectiveTier(undefined), "v1");
});

test("an automatic challenge switches by PIN, a manual arm in place", () => {
  assert.equal(tierSwitchTarget(autoV2), "v1");
  assert.deepEqual(tierSwitchRequest("a.gr", autoV2, "v1"), { path: "v1/challenge/vhost/tier", body: { host: "a.gr", rung: "v1" } });
  assert.equal(tierButtonLabel(autoV2), "→ v1 (pin)");

  assert.equal(tierSwitchTarget(manualV2), "v1");
  assert.deepEqual(tierSwitchRequest("a.gr", manualV2, "v1"), { path: "v1/challenge/vhost/rung", body: { host: "a.gr", rung: "v1" } });
  assert.equal(tierButtonLabel(manualV2), "→ v1");
  assert.equal(tierSwitchTarget(manualV1), "v2");

  assert.deepEqual(tierUnpinRequest("a.gr"), { path: "v1/challenge/vhost/tier", body: { host: "a.gr", rung: "auto" } });
});

test("a wildcard row gets no tier button (the daemon refuses wildcard pins and v2 arms)", () => {
  assert.equal(tierSwitchTarget(autoV2, "*.example.com"), "");
  assert.equal(tierButtonLabel(autoV2, "*.example.com"), "");
  assert.equal(tierSwitchTarget(manualV1, "*.example.com"), "");
  assert.equal(tierSwitchTarget(autoV2, "shop.example.com"), "v1");
});

test("a manual v1 arm under an automatic v2 drops back by PIN, not by re-tiering the arm", () => {
  const s = { manual_active: true, auto_active: true, rung: "v2", rung_source: "auto", rung_trigger: "suspicious_vhost" };
  assert.equal(tierSwitchTarget(s, "a.gr"), "v1");
  assert.deepEqual(tierSwitchRequest("a.gr", s, "v1"), { path: "v1/challenge/vhost/tier", body: { host: "a.gr", rung: "v1" } });
  assert.equal(tierButtonLabel(s, "a.gr"), "→ v1 (pin)");
});

test("a customer sees no pin controls on the operator's pin", () => {
  const locked = { ...pinnedV1, rung_pin_locked: true, rung_unpin_locked: true };
  assert.equal(tierSwitchTarget(locked, "a.gr"), "");
  assert.ok(!tierUnpinnable(locked));
  // A www-only tenant under its OWN apex pin (apex out of its scope): it may
  // set a www pin, not clear the apex's.
  const apexOutOfScope = { ...pinnedV1, rung_unpin_locked: true };
  assert.equal(tierSwitchTarget(apexOutOfScope, "www.a.gr"), "v2");
  assert.ok(!tierUnpinnable(apexOutOfScope));
  assert.ok(tierUnpinnable(pinnedV1));
  // A parked pin (no automatic challenge now) is still removable.
  assert.ok(tierUnpinnable({ rung_pin: "v1" }));
  assert.ok(!tierUnpinnable({}));
  assert.match(tierTitle(locked), /server operator/);
});

test("no pin button when the daemon resolved no automatic source", () => {
  // The store says auto-active, but the resolver saw no source (e.g. the
  // bridge entry already lapsed): a pin would change nothing.
  assert.equal(tierSwitchTarget({ auto_active: true, rung: "", rung_source: "" }), "");
  assert.equal(tierSwitchTarget({ auto_active: true, rung_source: "pin", rung_pin: "v1" }), "v2");
  assert.ok(tierSwitchIsPin(autoV2));
  assert.ok(!tierSwitchIsPin(manualV1));
});

test("nothing to switch when nothing challenges the host", () => {
  assert.equal(tierSwitchTarget({}), "");
  assert.equal(tierSwitchTarget(null), "");
  // A parked pin with no challenge is not switchable from the row.
  assert.equal(tierSwitchTarget({ rung_pin: "v2" }), "");
  assert.equal(tierButtonLabel({}), "");
});

test("the pill says v2 and pinned; plain automatic v1 adds nothing", () => {
  assert.equal(tierSuffix(autoV2), " · v2");
  assert.equal(tierSuffix(autoV1), "");
  assert.equal(tierSuffix(pinnedV1), " · v1 pinned");
  assert.equal(tierSuffix(manualV2), " · v2");
  assert.ok(tierPinned(pinnedV1));
  assert.ok(!tierPinned(autoV2));
});

test("the title names what decided the tier", () => {
  assert.match(tierTitle(autoV2), /automatic: suspicious_vhost/);
  assert.match(tierTitle(autoV1), /not armed/);
  assert.match(tierTitle(pinnedV1), /pinned by an operator/);
  assert.match(tierTitle(manualV2), /manual challenge.*v1 pin is parked/);
  assert.equal(tierTitle({}), "");
});

test("the page labels exactly the Go automatic sources", () => {
  const go = readFileSync(new URL("../../../../webdetector/challenge_v2_auto.go", import.meta.url), "utf8");
  const fn = go.slice(go.indexOf("func ChallengeV2AutoVhostSources()"));
  const body = fn.slice(0, fn.indexOf("\n}\n"));
  const consts = [...body.matchAll(/autoV2\w+/g)].map((m) => m[0]);
  const values = consts.map((c) => {
    const m = go.match(new RegExp(c + String.raw`\s*=\s*"([^"]+)"`));
    assert.ok(m, `constant ${c} not found`);
    return m[1];
  });
  assert.deepEqual([...values].sort(), Object.keys(TIER_SOURCE_LABELS).sort());
  assert.equal(tierSourceLabel("nope"), "an automatic source");
});

test("a manual v2 arm over an automatic v2 drops to v1 in one click: re-tier + pin", () => {
  const s = { manual_active: true, rung: "v2", rung_source: "manual", rung_auto: "v2", rung_trigger: "under_attack" };
  assert.deepEqual(tierSwitchRequests("a.gr", s, "v1"), [
    { path: "v1/challenge/vhost/rung", body: { host: "a.gr", rung: "v1" } },
    { path: "v1/challenge/vhost/tier", body: { host: "a.gr", rung: "v1" } },
  ]);
  assert.match(tierButtonTitle(s, "a.gr"), /AND pin/);
  // A customer who may not pin gets only the re-tier, and is told v2 stays.
  const locked = { ...s, rung_pin_locked: true };
  assert.equal(tierSwitchRequests("a.gr", locked, "v1").length, 1);
  assert.match(tierButtonTitle(locked, "a.gr"), /stay at v2/);
  // No automatic v2 underneath: one call.
  assert.equal(tierSwitchRequests("a.gr", { ...s, rung_auto: "" }, "v1").length, 1);
});
