import { test } from "node:test";
import assert from "node:assert/strict";
import { enabled, toggleable, matched, state, KINDS } from "./controls-model.js";

// /api/v1/webdet/vhosts rows (webdetVhostControlRow).
const PLAIN = {
  host: "shop.gr", challenge_enabled: true, waf_enabled: true, http3_enabled: false,
  challenge_toggleable: true, waf_toggleable: true, http3_toggleable: true,
  clam_enabled: true, clam_toggleable: true, clam_override_present: false,
  clam_mode_inline: false, clam_mode_toggleable: true, clam_mode_override_present: false,
};
const pick = (st) => [st.word, st.caption, st.tone, st.locked];

test("field readers: an absent field reads false, as the table always did", () => {
  for (const k of KINDS) {
    assert.equal(enabled({}, k), false, k);
    assert.equal(toggleable({}, k), false, k);
  }
  assert.equal(matched({ waf_matched_exclude: " *.shop.gr " }, "waf"), "*.shop.gr");
  assert.equal(matched({ clam_enabled: true }, "clam"), "");
  assert.equal(enabled(null, "waf"), false);
});

test("challenge and WAF: on is quiet, off is loud and says why", () => {
  assert.deepEqual(pick(state(PLAIN, "waf")), ["On", "", "ok", false]);
  const here = { ...PLAIN, waf_enabled: false, waf_matched_exclude: "shop.gr", waf_toggleable: true };
  assert.deepEqual(pick(state(here, "waf")), ["Off", "excluded here", "danger", false]);
  const wide = { ...PLAIN, challenge_enabled: false, challenge_matched_exclude: "*.gr", challenge_toggleable: false };
  assert.deepEqual(pick(state(wide, "challenge")), ["Off", "by *.gr", "danger", true]);
});

test("HTTP/3: an opt-in; off is the quiet default", () => {
  assert.deepEqual(pick(state(PLAIN, "http3")), ["Off", "default", "muted", false]);
  const own = { ...PLAIN, http3_enabled: true, http3_matched_optin: "shop.gr" };
  assert.deepEqual(pick(state(own, "http3")), ["On", "opted in", "info", false]);
  const wild = { ...PLAIN, http3_enabled: true, http3_matched_optin: "*.shop.gr", http3_toggleable: false };
  assert.deepEqual(pick(state(wild, "http3")), ["On", "by *.shop.gr", "info", true]);
});

test("ClamAV and its mode", () => {
  assert.deepEqual(pick(state(PLAIN, "clam")), ["On", "node default", "ok", false]);
  assert.deepEqual(pick(state({ ...PLAIN, clam_enabled: false, clam_override_present: true }, "clam")), ["Off", "override", "muted", false]);
  assert.deepEqual(pick(state({ ...PLAIN, clam_enabled: false, clam_toggleable: false }, "clam")), ["Off", "ClamAV off on this node", "muted", true]);
  assert.deepEqual(pick(state(PLAIN, "clammode")), ["Async", "node default · notify only", "muted", false]);
  assert.deepEqual(pick(state({ ...PLAIN, clam_mode_inline: true, clam_mode_override_present: true }, "clammode")), ["Inline", "override · upload waits", "warn", false]);
  assert.deepEqual(pick(state({ ...PLAIN, clam_mode_toggleable: false }, "clammode")), ["N/A", "not scanned", "muted", true]);
});

test("the switch position is the row's enabled flag for every kind", () => {
  for (const k of KINDS) {
    const row = { ...PLAIN };
    assert.equal(state(row, k).on, enabled(row, k), k);
  }
});
