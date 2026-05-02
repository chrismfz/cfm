package dnat

import (
	"cfm/internal/firewall"
	"cfm/internal/logging"
	"context"
	"fmt"
	"net"
	"os"
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
var panelDisableTableFn = func() error { return execCommand("nft", "delete", "table", "inet", "cfm_panel_redirect").Run() }

func StartPanelFailSafe(ctx context.Context, _ firewall.Backend) {
	every := time.Duration(getenvInt("CFM_PANEL_FAILSAFE_INTERVAL_MS", 2000)) * time.Millisecond
	failNeed := getenvInt("CFM_PANEL_FAILSAFE_CONSECUTIVE_FAILS", 3)
	probeTimeout := time.Duration(getenvInt("CFM_PANEL_FAILSAFE_PROBE_TIMEOUT_MS", 300)) * time.Millisecond
	autoRemoveAllowlist := strings.EqualFold(strings.TrimSpace(os.Getenv("CFM_PANEL_FAILSAFE_AUTO_REMOVE_ALLOWLIST")), "1") || strings.EqualFold(strings.TrimSpace(os.Getenv("CFM_PANEL_FAILSAFE_AUTO_REMOVE_ALLOWLIST")), "true")

	panelFailSafeMu.Lock()
	panelFailSafe.Enabled = true
	panelFailSafeMu.Unlock()

	t := time.NewTicker(every)
	go func() {
		defer t.Stop()
		failCount := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				on, _, err := panelStatusFn()
				if err != nil {
					logging.Logf("[dnat:cpanel:failsafe] status check failed: %v", err)
					continue
				}
				if !on {
					failCount = 0
					setPanelFailSafeCounter(0)
					continue
				}
				probeErr := panelProbeFn(probeTimeout)
				if probeErr == nil {
					failCount = 0
					setPanelFailSafeCounter(0)
					continue
				}
				failCount++
				setPanelFailSafeCounter(failCount)
				if failCount < failNeed {
					continue
				}
				on2, _, _ := panelStatusFn()
				if on2 {
					_ = panelDisableTableFn()
					reason := fmt.Sprintf("auto-disabled after %d consecutive probe failures: %v", failCount, probeErr)
					if autoRemoveAllowlist {
						if changes, err := removePanelAllowlist(); err != nil {
							reason += "; allowlist removal failed: " + err.Error()
						} else {
							reason += "; allowlist removed: " + strings.Join(changes, ", ")
						}
					}
					setPanelFirewallHealth("AUTO_FAILSAFE", reason, true)
					setPanelFailSafeAction(reason)
					logging.Logf("[dnat:cpanel:failsafe] %s", reason)
				}
				failCount = 0
				setPanelFailSafeCounter(0)
			}
		}
	}()
}

var panelProbePorts = []int{12082, 12083, 12086, 12087, 12095, 12096, 12222}

func probePanelTargets(timeout time.Duration) error {
	for _, p := range panelProbePorts {
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(p))
		c, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return fmt.Errorf("%s down: %w", addr, err)
		}
		_ = c.Close()
	}
	return nil
}
