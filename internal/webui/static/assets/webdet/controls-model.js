// /cfm-admin/assets/webdet/controls-model.js
//
// Pure model for the Vhost controls table's toggles (feature-controls.js):
// one switch per protection per host, worded as a short state ("On", "Off",
// "Inline"…) plus a muted caption saying what decided it ("by *.example.com",
// "node default", "excluded here"). The table used to show the whole thing
// as one upper-case button label ("OFF / MATCHED BY PATTERN"), seven columns
// across hundreds of rows.
//
// The verdicts are the daemon's /api/v1/webdet/vhosts row
// (webdetVhostControlRow): enabled, toggleable, the matched exclude / opt-in
// and the ClamAV override flags. This file only words them.

const str = (v) => (v === undefined || v === null ? "" : String(v));

export const KINDS = Object.freeze(["challenge", "waf", "http3", "clam", "clammode"]);

// enabled / toggleable / matched read the row's own fields per kind (an
// absent field reads false, as the table always did).
const ENABLED_KEY = Object.freeze({ challenge: "challenge_enabled", waf: "waf_enabled", http3: "http3_enabled", clam: "clam_enabled", clammode: "clam_mode_inline" });
const TOGGLE_KEY = Object.freeze({ challenge: "challenge_toggleable", waf: "waf_toggleable", http3: "http3_toggleable", clam: "clam_toggleable", clammode: "clam_mode_toggleable" });
// clam / clammode: exact-match overrides only, no pattern to surface.
const MATCHED_KEY = Object.freeze({ challenge: "challenge_matched_exclude", waf: "waf_matched_exclude", http3: "http3_matched_optin" });

export function enabled(row, kind) {
  const k = ENABLED_KEY[kind];
  return Boolean(k && row && row[k]);
}

export function toggleable(row, kind) {
  const k = TOGGLE_KEY[kind];
  return Boolean(k && row && row[k]);
}

export function matched(row, kind) {
  const k = MATCHED_KEY[kind];
  return k && row ? str(row[k]).trim() : "";
}

// state is one switch: { on, word, caption, tone, locked }.
//   on      — the switch position (what a click flips);
//   word    — the short state ("On", "Off", "Inline", "Async", "N/A");
//   caption — what decided it, muted under the switch ("" when nothing to say);
//   tone    — ok | danger | info | warn | muted: how loud the cell is (a
//             protection turned OFF is the loud one, an opt-in left off is not);
//   locked  — a click cannot change it here (a wider entry or a node switch
//             decides it; the title says where).
export function state(row, kind) {
  const host = str(row && row.host).toLowerCase();
  const on = enabled(row, kind);
  const canToggle = toggleable(row, kind);
  const m = matched(row, kind);
  const by = m && m !== host ? `by ${m}` : "";
  switch (kind) {
    case "challenge":
    case "waf":
      if (on) return { on, word: "On", caption: "", tone: "ok", locked: false };
      return { on, word: "Off", caption: canToggle ? "excluded here" : (by || "excluded by a pattern"), tone: "danger", locked: !canToggle };
    case "http3":
      if (on) return { on, word: "On", caption: by || "opted in", tone: "info", locked: !canToggle };
      return { on, word: "Off", caption: "default", tone: "muted", locked: !canToggle };
    case "clam": {
      if (!canToggle && !on) return { on, word: "Off", caption: "ClamAV off on this node", tone: "muted", locked: true };
      const why = row && row.clam_override_present ? "override" : "node default";
      return on
        ? { on, word: "On", caption: why, tone: "ok", locked: false }
        : { on, word: "Off", caption: why, tone: "muted", locked: false };
    }
    case "clammode": {
      if (!canToggle) return { on: false, word: "N/A", caption: "not scanned", tone: "muted", locked: true };
      const why = row && row.clam_mode_override_present ? "override" : "node default";
      return on
        ? { on, word: "Inline", caption: `${why} · upload waits`, tone: "warn", locked: false }
        : { on, word: "Async", caption: `${why} · notify only`, tone: "muted", locked: false };
    }
  }
  return { on: false, word: "?", caption: "", tone: "muted", locked: true };
}
