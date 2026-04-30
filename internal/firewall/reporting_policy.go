package firewall

import cfgpkg "cfm/internal/config"

// ShouldReportBlock returns whether a block event should be sent to the API
// based on source and current config policy.
func ShouldReportBlock(cfg *cfgpkg.Config, source string) bool {
	if cfg == nil {
		return false
	}
	switch source {
	case "detector":
		return cfg.API.DetectorsSend || cfg.API.AutoBlockSend
	case "autoblock":
		return cfg.API.AutoBlockSend
	case "manual":
		return cfg.API.ManualBlockSend
	default:
		return false
	}
}
