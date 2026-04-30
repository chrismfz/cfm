//go:build linux

package nftlib

import (
	"fmt"
	"time"

	"cfm/internal/logging"
)

func (b *Backend) logPhase(phase, status string, duration time.Duration, err error, extra string) {
	msg := fmt.Sprintf("[firewall] engine=nftlib phase=%s status=%s duration=%s", phase, status, duration)
	if err != nil {
		msg += fmt.Sprintf(" error=%q", err.Error())
	} else {
		msg += ` error=""`
	}
	if extra != "" {
		msg += " " + extra
	}
	logging.Logf("%s", msg)
}
