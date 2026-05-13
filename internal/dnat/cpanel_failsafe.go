package dnat

import (
	"cfm/internal/firewall"
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type panelFailSafeState struct {
	Enabled          bool
	ConsecutiveFails int
	LastActionAt     time.Time
	LastActionReason string
}

var (
	panelFailSafeMu sync.Mutex
	panelFailSafe   = panelFailSafeState{}
)

func getPanelFailSafeState() panelFailSafeState {
	panelFailSafeMu.Lock()
	defer panelFailSafeMu.Unlock()
	return panelFailSafe
}

func setPanelFailSafeCounter(v int) {
	panelFailSafeMu.Lock()
	defer panelFailSafeMu.Unlock()
	panelFailSafe.ConsecutiveFails = v
}

func setPanelFailSafeAction(reason string) {
	panelFailSafeMu.Lock()
	defer panelFailSafeMu.Unlock()
	panelFailSafe.LastActionAt = time.Now().UTC()
	panelFailSafe.LastActionReason = reason
}

var panelStatusFn = panelStatus
var panelProbeFn = probePanelTargets
var panelOffFn = panelOffPreserveIntent

func newPanelDNATFailSafeTarget(backend firewall.Backend) dnatFailSafeTarget {
	every := time.Duration(getenvInt("CFM_PANEL_FAILSAFE_INTERVAL_MS", 2000)) * time.Millisecond
	failNeed := getenvInt("CFM_PANEL_FAILSAFE_CONSECUTIVE_FAILS", 3)
	recoverOK := getenvInt("CFM_PANEL_FAILSAFE_RECOVER_OK", 5)
	probeTimeout := time.Duration(getenvInt("CFM_PANEL_FAILSAFE_PROBE_TIMEOUT_MS", 2000)) * time.Millisecond
	autoRemoveAllowlist := strings.EqualFold(strings.TrimSpace(os.Getenv("CFM_PANEL_FAILSAFE_AUTO_REMOVE_ALLOWLIST")), "1") || strings.EqualFold(strings.TrimSpace(os.Getenv("CFM_PANEL_FAILSAFE_AUTO_REMOVE_ALLOWLIST")), "true")

	probe := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		defer cancel()
		// Combine the panel listener TCP probe with the canonical Lua-aware
		// healthz on 9080/9043. Either failure mode (panel port down, or
		// edge Lua broken) trips the failsafe.
		if err := panelProbeFn(probeTimeout); err != nil {
			recordProbe(ScopeCPanel, false, err.Error())
			return err
		}
		ok, reason := probeEdgeHealthy(ctx, ScopeCPanel, []EdgePort{
			{Port: getenvInt("HTTP_PORT", 9080), TLS: false, Healthz: true},
			{Port: getenvInt("HTTPS_PORT", 9043), TLS: true, Healthz: true},
		})
		if ok {
			return nil
		}
		return fmt.Errorf("%s", reason)
	}

	return dnatFailSafeTarget{
		Name:             "cpanel",
		LogPrefix:        "[dnat:cpanel]",
		Interval:         every,
		FailureThreshold: failNeed,
		StatusCheck: func() (bool, error) {
			on, _, err := panelStatusFn()
			return on, err
		},
		HealthProbe: probe,
		Cleanup: func(failCount int, probeErr error) {
			offResult, offErr := panelOffFn(autoRemoveAllowlist)
			reason := fmt.Sprintf("auto-disabled after %d consecutive probe failures: %v", failCount, probeErr)
			if autoRemoveAllowlist {
				if offErr != nil {
					reason += "; allowlist removal failed: " + offErr.Error()
				} else {
					reason += "; allowlist removed: " + panelOffFirewallSummary(offResult.FirewallChanges)
				}
			} else {
				reason += "; allowlist removal skipped"
			}
			setPanelFirewallHealth("AUTO_FAILSAFE", reason, true)
			setPanelFailSafeAction(reason)
			LogTransition(ScopeCPanel, "OFF", "failsafe-off", reason)
		},
		UpdateFailCount: setPanelFailSafeCounter,
		IntentCheck: func() bool {
			enabled, present := LoadIntent(ScopeCPanel)
			return present && enabled
		},
		RecoverThreshold: recoverOK,
		Recover: func(_ int) {
			if backend == nil {
				LogTransition(ScopeCPanel, "OFF", "failsafe-recover", "no backend")
				return
			}
			priority := getenvInt("NFT_PANEL_DNAT_PRIORITY", -101)
			if err := backend.PanelDNATOn(priority); err != nil {
				LogTransition(ScopeCPanel, "OFF", "failsafe-recover", fmt.Sprintf("enable failed: %v", err))
				return
			}
			setPanelFirewallHealth("OK", "", true)
			LogTransition(ScopeCPanel, "ON", "failsafe-recover", "")
		},
	}
}

func StartPanelFailSafe(ctx context.Context, backend firewall.Backend) {
	panelFailSafeMu.Lock()
	panelFailSafe.Enabled = true
	panelFailSafeMu.Unlock()

	startDNATFailSafe(ctx, newPanelDNATFailSafeTarget(backend))
}

var panelProbePorts = []int{12082, 12083, 12086, 12087, 12095, 12096, 12222}
var panelProbeDialContextFn = func(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func probePanelTargets(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type probeResult struct {
		addr string
		err  error
	}

	results := make(chan probeResult, len(panelProbePorts))
	for _, p := range panelProbePorts {
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(p))
		go func(address string) {
			c, err := panelProbeDialContextFn(ctx, "tcp", address)
			if err != nil {
				results <- probeResult{addr: address, err: err}
				return
			}
			_ = c.Close()
			results <- probeResult{addr: address}
		}(addr)
	}

	failed := make([]string, 0)
	for range panelProbePorts {
		r := <-results
		if r.err != nil {
			failed = append(failed, fmt.Sprintf("%s (%v)", r.addr, r.err))
		}
	}
	if len(failed) > 0 {
		sort.Strings(failed)
		return fmt.Errorf("panel probe failed for %d/%d targets: %s", len(failed), len(panelProbePorts), strings.Join(failed, "; "))
	}
	return nil
}
