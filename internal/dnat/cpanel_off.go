package dnat

import "strings"

var panelListenerChallengeConfigPaths = []string{
	"/etc/angie/cfm-panel-listeners.conf",
	"/usr/local/openresty/nginx/conf/cfm-panel-listeners.conf",
	"configs/cfm-panel-listeners.conf.in",
}

type panelOffResult struct {
	FirewallChanges []string
	AllowlistError  error
}

var (
	panelDeleteRedirectTableFn        = func() error { return execCommand("nft", "delete", "table", "inet", "cfm_panel_redirect").Run() }
	panelRemoveAllowlistFn            = removePanelAllowlist
	panelPersistChallengeEnabledFn    = persistPanelChallengeEnabled
	panelApplyChallengeModeToPathsFn  = applyPanelChallengeModeToPaths
	panelReloadPanelListenerServiceFn = reloadPanelListenerService
	panelSetFirewallHealthFn          = setPanelFirewallHealth
	panelGetFirewallHealthFn          = getPanelFirewallHealth
)

func panelOff() ([]string, error) {
	res, err := panelOffWithOptions(true)
	return res.FirewallChanges, err
}

func panelOffWithOptions(autoRemoveAllowlist bool) (panelOffResult, error) {
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
	_ = panelPersistChallengeEnabledFn(false)
	_ = panelApplyChallengeModeToPathsFn("off", panelListenerChallengeConfigPaths)
	_ = panelReloadPanelListenerServiceFn()
	return result, nil
}

func panelOffFirewallSummary(changes []string) string {
	if len(changes) == 0 {
		return "no allowlist changes"
	}
	return strings.Join(changes, ", ")
}
