//go:build linux

package dnat

import (
	"cfm/internal/firewall"
	"cfm/internal/firewall/nft"
)

func defaultPanelBackend() firewall.Backend { return nft.New() }
