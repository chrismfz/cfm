package dnat

import (
	"cfm/internal/firewall"
	"context"
	"fmt"
	"time"
)

// RestoreOnStartup re-applies the persisted DNAT intent for the given scope
// when the cfm daemon starts. It refuses to re-enable DNAT until the edge
// proxy (angie/openresty) is actually healthy (TCP listening AND
// /__ssl_debug returns 200 over both http and https). This avoids the
// classic "DNAT was on, system rebooted, edge isn't up yet, all traffic
// drops" failure mode.
//
// The function blocks until intent is honored or the wait deadline expires,
// so callers typically run it in a goroutine. On timeout the failsafe loop
// will pick up the recovery as soon as the edge starts serving traffic.
func RestoreOnStartup(ctx context.Context, scope DNATScope, backend firewall.Backend) {
	if backend == nil {
		return
	}
	enabled, present := LoadIntent(scope)
	if !present || !enabled {
		return
	}

	waitTotal := time.Duration(getenvInt("CFM_DNAT_STARTUP_WAIT_MS", 60000)) * time.Millisecond
	step := time.Duration(getenvInt("CFM_DNAT_STARTUP_STEP_MS", 2000)) * time.Millisecond
	if step <= 0 {
		step = 2 * time.Second
	}

	ports := WebEdgePorts()
	if scope == ScopeCPanel {
		ports = CPanelEdgePorts()
	}

	deadline := time.Now().Add(waitTotal)
	var lastReason string
	for {
		on, _ := scopeStatus(scope, backend)
		if on {
			return
		}
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		ok, reason := probeEdgeHealthy(probeCtx, scope, ports)
		cancel()
		if ok {
			if err := scopeEnable(scope, backend); err != nil {
				LogTransition(scope, "OFF", "startup", fmt.Sprintf("enable failed: %v", err))
				return
			}
			LogTransition(scope, "ON", "startup", "")
			return
		}
		lastReason = reason
		if time.Now().After(deadline) {
			LogTransition(scope, "OFF", "startup-timeout", lastReason)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(step):
		}
	}
}

func scopeStatus(scope DNATScope, backend firewall.Backend) (bool, error) {
	if scope == ScopeCPanel {
		on, _, err := backend.PanelDNATStatus()
		return on, err
	}
	return backend.DNATStatus("inet", "cfm_redirect")
}

func scopeEnable(scope DNATScope, backend firewall.Backend) error {
	if scope == ScopeCPanel {
		if err := backend.PanelDNATOn(getenvInt("NFT_PANEL_DNAT_PRIORITY", -101)); err != nil {
			return err
		}
		// PanelDNATOn only reinstalls the redirect table; the input-chain
		// accept rules live separately and must be reasserted here so
		// redirected traffic isn't dropped by the firewall after a reboot.
		_, err := backend.EnsurePanelDNATAccepts()
		return err
	}
	// backend.DNATOn already calls ensureScopedDNATAccepts internally, so
	// the web path needs no extra accept reassert here.
	return backend.DNATOn("inet", "cfm_redirect", getenvInt("HTTP_PORT", 9080), getenvInt("HTTPS_PORT", 9043))
}
