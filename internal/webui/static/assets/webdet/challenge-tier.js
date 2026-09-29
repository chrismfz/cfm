// Challenge tier (v1 / v2) helpers shared by the challenge and controls pages.
//
// `s` is a vhost challenge status as the daemon reports it — the per-host
// status endpoint (v1/challenge/vhost/status) or a row of v1/challenge/vhosts:
//   { manual_active, auto_active, rung, rung_source, rung_trigger, rung_pin }
// rung / rung_source / rung_trigger / rung_pin come from the SAME resolver the
// verify gate enforces (challengeV2VhostTier, challenge_v2_auto.go), so the
// page shows exactly the tier the solves are held to:
//   rung_source "manual" = a manual arm's own tier
//               "pin"    = an operator tier pin on an automatic challenge
//               "auto"   = CHALLENGE_V2_AUTO_VHOST (rung_trigger names the
//                          source: suspicious_vhost, uniqpaths_short,
//                          vhost_config, under_attack)
// Switching: a manual arm is re-tiered in place (v1/challenge/vhost/rung,
// expiry kept); an automatic challenge is PINNED (v1/challenge/vhost/tier) —
// "→ v1" is the emergency drop-back, "auto" hands the tier back to the knob.

// TIER_SOURCE_LABELS: the automatic sources (Go: ChallengeV2AutoVhostSources,
// challenge_v2_auto.go — pinned by challenge-tier.test.js) and how the page
// names them.
export const TIER_SOURCE_LABELS = {
  suspicious_vhost: "the traffic scorer",
  uniqpaths_short: "the unique-paths burst detector",
  vhost_config: "the CHALLENGE_VHOST list",
  under_attack: "Under-Attack Mode",
};

export function tierSourceLabel(trigger) {
  return TIER_SOURCE_LABELS[trigger] || "an automatic source";
}

export function effectiveTier(s) {
  return s && s.rung === "v2" ? "v2" : "v1";
}

// isManual: the tier is DECIDED by a manual arm (rung_source "manual"), so a
// switch re-tiers that arm. manual_active alone is not enough: a manual v1 arm
// under an automatic v2 resolves to rung_source auto/pin, and re-tiering the
// arm (already v1) would change nothing — the way down there is a v1 pin.
// Rows from a daemon without rung_source fall back to manual_active.
function isManual(s) {
  if (!s) return false;
  if (s.rung_source) return s.rung_source === "manual";
  return Boolean(s.manual_active);
}

// tierSwitchIsPin: whether the switch for this host is a PIN (an automatic
// challenge) rather than an in-place re-tier of a manual arm. The ONE
// manual-vs-pin matcher — tierSwitchRequest and every label use it.
export function tierSwitchIsPin(s) {
  return !isManual(s);
}

// tierSwitchTarget: the tier a one-click switch would move this host to, or
// "" when nothing challenges it (a pin alone changes nothing to switch), or
// for a wildcard row (e.g. a CHALLENGE_VHOST `*.example.com` entry): the
// daemon refuses both a wildcard pin and a wildcard v2 arm (the verify-side
// lookup is exact + www only), so the button would always fail. Pass the
// row's host to get that check.
export function tierSwitchTarget(s, host) {
  if (!s) return "";
  if (String(host || "").includes("*")) return "";
  if (isManual(s)) return effectiveTier(s) === "v2" ? "v1" : "v2";
  // A pin only acts on an AUTOMATIC source the daemon can see
  // (rung_source auto|pin): a row the store calls auto-active but whose
  // tier resolved to no source would take a pin that changes nothing.
  if (s.rung_source !== "auto" && s.rung_source !== "pin") return "";
  // The operator's pin, seen by a customer token: the write would 403.
  if (s.rung_pin_locked) return "";
  return effectiveTier(s) === "v2" ? "v1" : "v2";
}

// tierSwitchRequest: the API call that switches host to `to`.
export function tierSwitchRequest(host, s, to) {
  if (!tierSwitchIsPin(s)) return { path: "v1/challenge/vhost/rung", body: { host, rung: to } };
  return { path: "v1/challenge/vhost/tier", body: { host, rung: to } };
}

// tierAlsoPinsV1: switching a manual v2 arm to v1 leaves the host at v2 when
// an automatic source also holds it there (rung_auto "v2") — the switch then
// pins the automatic tier to v1 as well, when the caller may.
export function tierAlsoPinsV1(s, to) {
  return Boolean(s && to === "v1" && !tierSwitchIsPin(s) && s.rung_auto === "v2" && !s.rung_pin_locked);
}

// companionPinTTL: the v1 pin that accompanies a manual v2→v1 switch lives as
// long as the manual arm it accompanies (never a forgotten permanent opt-out
// of the node default); 24h when the arm's expiry is unknown.
export function companionPinTTL(s, nowMs = Date.now()) {
  const exp = s && s.expires_at ? Date.parse(s.expires_at) : NaN;
  if (!Number.isFinite(exp)) return "24h";
  const secs = Math.ceil((exp - nowMs) / 1000);
  return `${Math.max(secs, 60)}s`;
}

// tierSwitchRequests: every call the one-click switch makes, in order.
export function tierSwitchRequests(host, s, to, nowMs = Date.now()) {
  const reqs = [tierSwitchRequest(host, s, to)];
  if (tierAlsoPinsV1(s, to)) {
    reqs.push({ path: "v1/challenge/vhost/tier", body: { host, rung: "v1", ttl: companionPinTTL(s, nowMs) } });
  }
  return reqs;
}

// tierUnpinRequest: hands an automatic challenge's tier back to the knob.
export function tierUnpinRequest(host) {
  return { path: "v1/challenge/vhost/tier", body: { host, rung: "auto" } };
}

export function tierPinned(s) {
  return Boolean(s && s.rung_source === "pin");
}

// tierUnpinnable: the "↺ auto" control — a pin exists (deciding the tier
// now, or parked: no automatic challenge right now, or outranked by a manual
// v2 arm — it would silently decide the NEXT automatic challenge, so it must
// be removable from here too) and the caller may clear it
// (rung_unpin_locked: a customer looking at the operator's pin, or at an
// apex pin outside its scope).
export function tierUnpinnable(s) {
  return Boolean(s && (s.rung_pin || s.rung_source === "pin")) && !s.rung_unpin_locked;
}

// tierSuffix: the short tag the mode pill carries (" · v2", " · v1 pinned").
// A plain automatic v1 adds nothing, as before auto-v2 existed.
export function tierSuffix(s) {
  if (!s) return "";
  const t = effectiveTier(s);
  if (tierPinned(s)) return ` · ${t} pinned`;
  return t === "v2" ? " · v2" : "";
}

// tierTitle: the hover text explaining the tier and what decided it.
export function tierTitle(s) {
  if (!s || !s.rung_source) return "";
  const t = effectiveTier(s) === "v2"
    ? "v2 (solves must also pass the passive humanity check)"
    : "v1 (plain challenge)";
  let why;
  switch (s.rung_source) {
    case "manual": why = "set on the manual challenge"; break;
    case "pin": why = `pinned by an operator (automatic source: ${s.rung_trigger || "?"})`; break;
    default: why = `automatic: ${s.rung_trigger || "?"} is in CHALLENGE_V2_AUTO_VHOST` +
      (effectiveTier(s) === "v2" ? "" : " — not armed");
  }
  let out = `Tier ${t} — ${why}`;
  if (s.rung_pin_locked) out += ". The pin was set by the server operator — ask them to change it.";
  if (s.rung_pin && s.rung_source !== "pin") out += `. A ${s.rung_pin} pin is parked here (applies to automatic challenges only).`;
  return out;
}

// tierButtonLabel / tierButtonTitle: the switch button beside the pill.
export function tierButtonLabel(s, host) {
  const to = tierSwitchTarget(s, host);
  if (!to) return "";
  return isManual(s) ? `→ ${to}` : `→ ${to} (pin)`;
}

export function tierButtonTitle(s, host) {
  const to = tierSwitchTarget(s, host);
  if (!to) return "";
  if (isManual(s)) {
    if (tierAlsoPinsV1(s, to)) {
      return "Switch this manual challenge to plain v1 AND pin the automatic tier to v1 for as long as the arm lasts — an automatic source also holds it at v2 (keeps the arm's expiry)";
    }
    if (to === "v1" && s.rung_auto === "v2") {
      return "Switch this manual challenge to v1 — solves stay at v2 while the automatic source holds it (the pin is the operator's)";
    }
    return to === "v1"
      ? "Switch this manual challenge back to plain v1 (keeps its expiry)"
      : "Switch this manual challenge to v2: solves must also pass the passive humanity check (keeps its expiry)";
  }
  return to === "v1"
    ? "Pin this vhost's automatic challenges to plain v1 (the emergency drop-back): stays until you unpin it (a customer's pin expires after 24h)"
    : "Pin this vhost's automatic challenges to v2: solves must also pass the passive humanity check; stays until you unpin it (a customer's pin expires after 24h)";
}
