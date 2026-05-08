//go:build linux

package nftlib

import (
	"fmt"
	"time"

	"cfm/internal/config"
)

func (b *Backend) ApplySMTPBlock(cfg *config.SMTPBlockConfig) (err error) {
	start := time.Now()
	enabled := cfg != nil && cfg.Enabled
	b.logPhase("ApplySMTPBlock", "start", 0, nil, fmt.Sprintf("enabled=%t", enabled))
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("ApplySMTPBlock", st, time.Since(start), err, fmt.Sprintf("enabled=%t", enabled))
	}()
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	if !b.chainExistsCLI("smtpblock") {
		if err := b.nftExec(
			"add chain inet cfm smtpblock { type filter hook output priority -100; policy accept; }",
		); err != nil {
			return err
		}
	}
	_ = b.nftExec("flush chain inet cfm smtpblock")
	return b.nftExec("add rule inet cfm smtpblock drop")
}
