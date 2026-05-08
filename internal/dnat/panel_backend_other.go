//go:build !linux

package dnat

import "cfm/internal/firewall"

func defaultPanelBackend() firewall.Backend { return nil }
