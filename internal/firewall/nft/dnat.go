//go:build linux
// internal/firewall/nft/dnat.go

package nft

import (
	"fmt"
	"strings"
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

func dnatScript(fam, tbl string, httpPort, httpsPort int) string {
	// 1:1 with your dnatALL.sh heredoc
	return fmt.Sprintf(`table %s %s {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;

    iif "lo" accept

    tcp dport 80  dnat to :%d
    tcp dport 443 dnat to :%d
    udp dport 443 dnat to :%d
  }
}
`, fam, tbl, httpPort, httpsPort, httpsPort)
}

func (b *Backend) DNATOn(fam, tbl string, httpPort, httpsPort int) error {
	fam, tbl = dnatDefaults(fam, tbl)

	if httpPort <= 0 || httpsPort <= 0 {
		return fmt.Errorf("invalid ports: http=%d https=%d", httpPort, httpsPort)
	}

	// Idempotent
	if b.dnatTableExists(fam, tbl) {
		return nil
	}

	// Reuse your multi-line nft expression runner
	return b.nftExpr(dnatScript(fam, tbl, httpPort, httpsPort))
}

func (b *Backend) DNATOff(fam, tbl string) error {
	fam, tbl = dnatDefaults(fam, tbl)

	// Idempotent
	if !b.dnatTableExists(fam, tbl) {
		return nil
	}

	// Reuse your single-expression runner (auto adds ;)
	return b.nftCmd(fmt.Sprintf("delete table %s %s", fam, tbl))
}
