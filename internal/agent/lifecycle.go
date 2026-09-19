package agent

import (
	"time"

	cfgpkg "cfm/internal/config"
	"cfm/internal/firewall"
)

// Lifecycle owns the start/update lifecycle of the API agent Runner.
// Create once with NewLifecycle, then call ApplyConfig on every daemon tick
// after config is parsed. It starts the runner on first valid config and
// updates credentials live when URL/token change — no restart needed.
type Lifecycle struct {
	// wired at construction — never change
	version string
	be      firewall.Backend
	cfgDir  string

	// internal state
	runner  *Runner
	lastKey string // "URL|TOKEN" — detects credential changes
	fpSink  func([]FingerprintPolicyRow)
}

// SetFingerprintPolicySink wires the fingerprint-policy pull's destination
// (see fppolicy_pull.go). Callable before or after the Runner exists; the
// sink is (re)applied whenever ApplyConfig touches the Runner.
func (l *Lifecycle) SetFingerprintPolicySink(fn func([]FingerprintPolicyRow)) {
	l.fpSink = fn
	if l.runner != nil {
		l.runner.SetFingerprintPolicySink(fn)
	}
}

// NewLifecycle returns a ready-to-use Lifecycle.
// version is the daemon build version string (e.g. "1.2.3").
// be and cfgDir are passed through to the Runner for unblock operations.
func NewLifecycle(version string, be firewall.Backend, cfgDir string) *Lifecycle {
	return &Lifecycle{
		version: version,
		be:      be,
		cfgDir:  cfgDir,
	}
}

// ApplyConfig starts or updates the agent runner based on cfg.API.
// Safe to call on every tick — it is a no-op when URL and token are unchanged.
// If URL or token are empty, the agent is not started (no API configured).
func (l *Lifecycle) ApplyConfig(cfg *cfgpkg.Config) {
	if cfg == nil || cfg.API.URL == "" || cfg.API.AuthToken == "" {
		return
	}

	key := cfg.API.URL + "|" + cfg.API.AuthToken
	if key == l.lastKey && l.runner != nil {
		return // no-op: credentials unchanged
	}

	ac := Config{
		BaseURL:  cfg.API.URL,
		Token:    cfg.API.AuthToken,
		Version:  l.version,
		Interval: 20 * time.Second,
	}

	if l.runner == nil {
		// first time — create, wire, start
		l.runner = New(ac)
		l.runner.SetBackend(l.be)
		l.runner.SetConfigDir(l.cfgDir)
		l.runner.SetFingerprintPolicySink(l.fpSink)
		l.runner.Start()
	} else {
		// credentials changed — hot-update, no restart needed
		l.runner.Update(ac)
		l.runner.SetBackend(l.be)
		l.runner.SetConfigDir(l.cfgDir)
	}

	l.lastKey = key
}

// Stop cleanly shuts down the runner. Call on daemon exit.
func (l *Lifecycle) Stop() {
	if l.runner != nil {
		l.runner.Stop()
		l.runner = nil
	}
}
