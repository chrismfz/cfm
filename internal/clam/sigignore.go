package clam

import (
	"path/filepath"
	"strings"
	"sync"
)

// Signature-trust layer (CLAM_SIG_IGNORE + the per-vhost store): an ignored
// signature's infected verdict is DOWNGRADED to log-only — still logged and
// published to history (flagged), but no CLAM/INFECTED notification and no
// quarantine copy. Hunting-grade third-party YARA rules are FP-prone by
// design; without this layer their hits cost spurious critical alerts today
// and would 403 legitimate uploads once inline mode exists.
//
// Two sources, checked in order:
//   1. the baseline config globs (Config.SigIgnore, from CLAM_SIG_IGNORE);
//   2. the runtime lookup registered by webdetector (global + per-vhost store
//      entries, editable via API/CLI/UI with no reload).
//
// Like SetScanEventSink, the lookup is a single settable hook (replace, not
// append) because the engine is rebuilt on config reload.

var (
	sigLookupMu sync.RWMutex
	sigLookup   func(host, sig string) (bool, string)
)

// SetSigIgnoreLookup registers (replacing any prior) the runtime signature-
// ignore lookup. fn returns whether (host, sig) is ignored and a short label
// of the matching entry for the log line. Pass nil to detach.
func SetSigIgnoreLookup(fn func(host, sig string) (bool, string)) {
	sigLookupMu.Lock()
	sigLookup = fn
	sigLookupMu.Unlock()
}

// SigGlobMatch is a case-insensitive filepath.Match on a signature name.
// A malformed pattern never matches (reject it at the API/config edge, not
// here). Exported so the webdetector store uses THIS matcher — a second copy
// could drift from what the scanner actually enforces.
func SigGlobMatch(pattern, sig string) bool {
	ok, err := filepath.Match(strings.ToLower(pattern), strings.ToLower(sig))
	return err == nil && ok
}

// sigIgnored reports whether an infected verdict for sig on host must be
// downgraded to log-only, and the source of the decision ("config:<pattern>"
// or the store label). Must never panic — it runs on the scanner worker.
func (m *Manager) sigIgnored(host, sig string) (bool, string) {
	if m == nil || strings.TrimSpace(sig) == "" {
		return false, ""
	}
	for _, pat := range m.cfg.SigIgnore {
		if SigGlobMatch(pat, sig) {
			return true, "config:" + pat
		}
	}
	sigLookupMu.RLock()
	fn := sigLookup
	sigLookupMu.RUnlock()
	if fn == nil {
		return false, ""
	}
	ignored, by := false, ""
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				logf("[clam] sig-ignore lookup panic host=%s sig=%s err=%v", host, sig, rec)
				ignored, by = false, ""
			}
		}()
		ignored, by = fn(host, sig)
	}()
	return ignored, by
}
