package firewall

// PanelDNATMapping describes one cPanel/DirectAdmin panel DNAT port mapping.
type PanelDNATMapping struct {
	From int
	To   int
}

// PanelDNATMappings returns the stable panel DNAT mapping set in nft rule order.
func PanelDNATMappings() []PanelDNATMapping {
	return []PanelDNATMapping{
		{From: 2082, To: 12082},
		{From: 2083, To: 12083},
		{From: 2086, To: 12086},
		{From: 2087, To: 12087},
		{From: 2095, To: 12095},
		{From: 2096, To: 12096},
		{From: 2222, To: 12222},
	}
}
