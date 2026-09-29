// node --test internal/webui/static/assets/webdet/challenge-tier.test.js
import test from "node:test";
import assert from "node:assert/strict";
import {
  effectiveTier,
  tierButtonLabel,
  tierPinned,
  tierSuffix,
  tierSwitchRequest,
  tierSwitchTarget,
  tierTitle,
  tierUnpinRequest,
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
