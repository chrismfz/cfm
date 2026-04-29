//go:build linux

// Challenge redirect and DNAT methods delegate to the embedded nft.Backend.
// These methods manage complex DNAT prerouting rules; native nftlib
// implementations will replace them in a later phase.
package nftlib

func (b *Backend) SetChallengeRedirectEnabled(enabled bool) {
	b.cli.SetChallengeRedirectEnabled(enabled)
}

func (b *Backend) CleanupChallengeRedirect() error {
	return b.cli.CleanupChallengeRedirect()
}

func (b *Backend) EnsureChallengeRedirect(httpListen, httpsListen string) error {
	return b.cli.EnsureChallengeRedirect(httpListen, httpsListen)
}

func (b *Backend) DNATStatus(family, table string) (bool, error) {
	return b.cli.DNATStatus(family, table)
}

func (b *Backend) DNATShow(family, table string) (string, error) {
	return b.cli.DNATShow(family, table)
}

func (b *Backend) DNATOn(family, table string, httpPort, httpsPort int) error {
	return b.cli.DNATOn(family, table, httpPort, httpsPort)
}

func (b *Backend) DNATOff(family, table string) error {
	return b.cli.DNATOff(family, table)
}
