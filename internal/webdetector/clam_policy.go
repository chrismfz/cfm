package webdetector

import "sync/atomic"

// Global ClamAV upload-scan policy, mirrored from the main config (cfm.conf)
// into this package so the vhost-controls API can compute the effective
// per-vhost scan state without re-reading cfm.conf. cmd/cfm applySystemConfig
// calls SetClamScanPolicy on every config (re)load — the same place the rendered
// edge config (cfm_clamav_config.lua) is written — so the UI stays consistent
// with what the edge actually enforces.
//
// The edge decision (cfm_clamav.lua) is:
//
//	scan(host) = globallyEnabled && (scanDefault XOR host-in-override)
//
// where globallyEnabled = CLAMD_ENABLED && CLAMD_NGINX_HOOK_ENABLED and the
// override set is matched by EXACT hostname (no suffix/wildcard expansion).
var (
	clamGloballyEnabledFlag atomic.Bool
	clamScanDefaultFlag     atomic.Bool
	clamInlineDefaultFlag   atomic.Bool
)

// SetClamScanPolicy records the global ClamAV scan policy for the vhost-controls
// API. globallyEnabled is (CLAMD_ENABLED && CLAMD_NGINX_HOOK_ENABLED); scanDefault
// is CLAM_SCAN_DEFAULT; inlineDefault is (CLAM_SCAN_MODE == "inline") — the mode
// a vhost gets unless flipped by the mode-override store. Safe for concurrent
// use; called on every config reload.
func SetClamScanPolicy(globallyEnabled, scanDefault, inlineDefault bool) {
	clamGloballyEnabledFlag.Store(globallyEnabled)
	clamScanDefaultFlag.Store(scanDefault)
	clamInlineDefaultFlag.Store(inlineDefault)
}

// clamScanPolicy returns the current (globallyEnabled, scanDefault) policy.
func clamScanPolicy() (globallyEnabled, scanDefault bool) {
	return clamGloballyEnabledFlag.Load(), clamScanDefaultFlag.Load()
}

// clamInlineDefault reports whether the global scan mode is inline.
func clamInlineDefault() bool {
	return clamInlineDefaultFlag.Load()
}
