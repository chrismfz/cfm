package nftlib

const (
	floodChainName     = "flood"
	throttledSetV4Name = "throttled_v4"
	throttledSetV6Name = "throttled_v6"
	scannerSetV4Name   = "port_scanners_v4"
	scannerSetV6Name   = "port_scanners_v6"
	blockSetName       = "block_v4"
	allowSetName       = "allow_v4"
	ignoreSetName      = "ignore_v4"
	feedSetName        = "block_ext_v4_hosts"
)

func (b *Backend) FloodChainName() string { return floodChainName }

func (b *Backend) ThrottledSetNames() []string { return []string{throttledSetV4Name, throttledSetV6Name} }

func (b *Backend) ScannerSetNames() []string { return []string{scannerSetV4Name, scannerSetV6Name} }

func (b *Backend) CardinalitySetNames() map[string]string {
	return map[string]string{
		"block":     blockSetName,
		"allow":     allowSetName,
		"ignore":    ignoreSetName,
		"feed":      feedSetName,
	}
}
