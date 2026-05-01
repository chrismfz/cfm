//go:build linux

// internal/firewall/nft/dnat.go

package nft

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Defaults: keep same as your script expectations.
func dnatDefaults(fam, tbl string) (string, string) {
	fam = strings.TrimSpace(fam)
	tbl = strings.TrimSpace(tbl)
	if fam == "" {
		fam = "inet"
	}
	if tbl == "" {
		tbl = "cfm_redirect"
	}
	return fam, tbl
}

func (b *Backend) dnatTableExists(fam, tbl string) bool {
	// Reuse existing helper that runs "nft -f -" and returns output/error.
	_, err := b.nftOut(fmt.Sprintf("list table %s %s", fam, tbl))
	return err == nil
}

func (b *Backend) DNATStatus(fam, tbl string) (bool, error) {
	fam, tbl = dnatDefaults(fam, tbl)
	return b.dnatTableExists(fam, tbl), nil
}

func (b *Backend) DNATShow(fam, tbl string) (string, error) {
	fam, tbl = dnatDefaults(fam, tbl)
	return b.nftOut(fmt.Sprintf("list table %s %s", fam, tbl))
}

func dnatScript(fam, tbl string, httpPort, httpsPort int, priority int) string {
	// 1:1 with your dnatALL.sh heredoc
	return fmt.Sprintf(`table %s %s {
  chain prerouting {
    type nat hook prerouting priority %d; policy accept;

    iif "lo" accept

    tcp dport 80  dnat to :%d
    tcp dport 443 dnat to :%d
    udp dport 443 dnat to :%d
  }
}
`, fam, tbl, priority, httpPort, httpsPort, httpsPort)
}

func (b *Backend) DNATOn(fam, tbl string, httpPort, httpsPort int) (err error) {
	start := time.Now()
	b.logPhase("DNATOn", "start", 0, nil, fmt.Sprintf("http_port=%d https_port=%d", httpPort, httpsPort))
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("DNATOn", st, time.Since(start), err, fmt.Sprintf("http_port=%d https_port=%d", httpPort, httpsPort))
	}()
	fam, tbl = dnatDefaults(fam, tbl)

	if httpPort <= 0 || httpsPort <= 0 {
		return fmt.Errorf("invalid ports: http=%d https=%d", httpPort, httpsPort)
	}

	// Idempotent
	if b.dnatTableExists(fam, tbl) {
		return nil
	}

	// Reuse your multi-line nft expression runner
	return b.nftExpr(dnatScript(fam, tbl, httpPort, httpsPort, b.dnatPriority()))
}

func (b *Backend) DNATOff(fam, tbl string) (err error) {
	start := time.Now()
	b.logPhase("DNATOff", "start", 0, nil, "")
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("DNATOff", st, time.Since(start), err, "")
	}()
	fam, tbl = dnatDefaults(fam, tbl)

	// Idempotent
	if !b.dnatTableExists(fam, tbl) {
		return nil
	}

	// Reuse your single-expression runner (auto adds ;)
	return b.nftCmd(fmt.Sprintf("delete table %s %s", fam, tbl))
}

func getenvInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func (b *Backend) dnatPriority() int {
	if b != nil && b.cfg != nil && b.cfg.NFT.DNATPriority != 0 {
		return b.cfg.NFT.DNATPriority
	}
	return getenvInt("NFT_DNAT_PRIORITY", -99)
}
