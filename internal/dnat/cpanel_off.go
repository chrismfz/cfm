package dnat

import (
	"strings"

	"cfm/internal/edgeengine"
	"cfm/internal/firewall"
)

// panelListenerChallengeConfigPaths: each edge engine's live copy (detection
// order, from edgeengine.Profiles), then the repo template. A var so tests
// point it elsewhere.
var panelListenerChallengeConfigPaths = func() []string {
	var out []string
	for _, p := range edgeengine.Profiles {
		out = append(out, p.ConfPath("cfm-panel-listeners.conf"))
	}
	return append(out, "configs/cfm-panel-listeners.conf.in")
}()

type panelOffResult struct {
	FirewallChanges []string
	AllowlistError  error
}

var (
	panelDeleteRedirectTableFn = func() error {
		if backend := defaultPanelBackend(); backend != nil {
			return backend.PanelDNATOff()
		}
		return nil
	}
	panelRemoveAllowlistFn            = removePanelAllowlist
	panelPersistChallengeEnabledFn    = persistPanelChallengeEnabled
	panelApplyChallengeModeToPathsFn  = applyPanelChallengeModeToPaths
	panelReloadPanelListenerServiceFn = reloadPanelListenerService
	panelSetFirewallHealthFn          = setPanelFirewallHealth
	panelGetFirewallHealthFn          = getPanelFirewallHealth
)

func panelOff() ([]string, error) {
	res, err := panelOffWithOptionsAndBackend(true, nil)
	return res.FirewallChanges, err
}

func panelOffWithBackend(backend firewall.Backend) (panelOffResult, error) {
	return panelOffWithOptionsAndBackend(true, backend)
}

func panelOffWithOptions(autoRemoveAllowlist bool) (panelOffResult, error) {
	return panelOffWithOptionsAndBackend(autoRemoveAllowlist, nil)
}

func panelOffWithOptionsAndBackend(autoRemoveAllowlist bool, backend firewall.Backend) (panelOffResult, error) {
	result := panelOffResult{}
	health := panelGetFirewallHealthFn()
	if backend != nil {
		_ = backend.PanelDNATOff()
	} else {
		_ = panelDeleteRedirectTableFn()
	}

	if autoRemoveAllowlist {
		changes, err := removePanelAllowlistWithBackend(backend)
		if panelRemoveAllowlistFn != nil && backend == nil {
			changes, err = panelRemoveAllowlistFn()
		}
		result.FirewallChanges = changes
		if err != nil {
			result.AllowlistError = err
			panelSetFirewallHealthFn("FAILED", err.Error(), health.Attempted)
			return result, err
		}
	}

	panelSetFirewallHealthFn("OK", "", health.Attempted)
	_ = panelPersistChallengeEnabledFn(false)
	_ = panelApplyChallengeModeToPathsFn("off", panelListenerChallengeConfigPaths)
	_ = panelReloadPanelListenerServiceFn()
	return result, nil
}

// panelOffPreserveIntent tears down the cPanel DNAT nft table (and optionally
// the allowlist) without touching the persisted intent, the listener
// challenge-mode config, or reloading angie/openresty. It is used by the
// failsafe so a transient edge breakage doesn't require manual re-enable
// once the edge recovers — the failsafe's Recover path can flip DNAT back
// ON immediately because the listener is still in forced mode.
func panelOffPreserveIntent(autoRemoveAllowlist bool) (panelOffResult, error) {
	result := panelOffResult{}
	health := panelGetFirewallHealthFn()
	_ = panelDeleteRedirectTableFn()
	if autoRemoveAllowlist {
		changes, err := panelRemoveAllowlistFn()
		result.FirewallChanges = changes
		if err != nil {
			result.AllowlistError = err
			panelSetFirewallHealthFn("FAILED", err.Error(), health.Attempted)
			return result, err
		}
	}
	panelSetFirewallHealthFn("OK", "", health.Attempted)
	return result, nil
}

func panelOffFirewallSummary(changes []string) string {
	if len(changes) == 0 {
		return "no allowlist changes"
	}
	return strings.Join(changes, ", ")
}
