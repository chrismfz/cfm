package config

import (
	"fmt"
	"strings"
)

func (c *Config) Summary() []string {
	var lines []string

	// --- Logging & API (χωρίς να διαρρέει token)
	apiURL := c.API.URL
	if apiURL == "" { apiURL = "-" }
	logFile := c.Logging.File
	if logFile == "" { logFile = "-" }
	lines = append(lines,
		fmt.Sprintf("api_url=%s auth_token=%t", apiURL, c.API.AuthToken != ""),
		fmt.Sprintf("log_stdout=%t log_file=%s", c.Logging.Stdout, logFile),
	)

	// --- NFT
	lines = append(lines, fmt.Sprintf("nft_input_priority=%d", c.NFT.InputPriority))

	// --- Ports
	lines = append(lines, fmt.Sprintf(
		"ports: tcp_in=%d ranges, tcp_out=%d, udp_in=%d, udp_out=%d",
		len(c.Ports.TCPIn), len(c.Ports.TCPOut), len(c.Ports.UDPIn), len(c.Ports.UDPOut),
	))

	// --- Connlimit
	clTot, clTCP, clUDP := 0, 0, 0
	for _, r := range c.Connlimit.Rules {
		clTot++
		if r.Proto == "udp" { clUDP++ } else { clTCP++ }
	}
	lines = append(lines, fmt.Sprintf("connlimit: rules=%d (tcp=%d udp=%d)", clTot, clTCP, clUDP))

	// --- PortFlood
	pfTot, pfTCP, pfUDP := 0, 0, 0
	for _, r := range c.PortFlood.Rules {
		pfTot++
		if r.Proto == "udp" { pfUDP++ } else { pfTCP++ }
	}
	lines = append(lines, fmt.Sprintf("portflood: rules=%d (tcp=%d udp=%d)", pfTot, pfTCP, pfUDP))

	// --- PacketRate
	mode := c.PacketRate.Mode
	if mode == "" { mode = "syn" }
	lines = append(lines, fmt.Sprintf("pkt_rate: rate=%d pps burst=%d mode=%s",
		c.PacketRate.Rate, c.PacketRate.Burst, mode))

	// --- Throttle
	src := "-"
	if len(c.Throttle.Sources) > 0 {
		src = strings.Join(c.Throttle.Sources, ",")
	}
	lines = append(lines, fmt.Sprintf(
		"throttle: enabled=%t window=%ds hits=%d mode=%s ttl=%ds set_ttl=%ds sources=[%s]",
		c.Throttle.Enabled, c.Throttle.WindowSec, c.Throttle.Hits, c.Throttle.Mode,
		c.Throttle.TTLSeconds, c.Throttle.SetTTL, src,
	))

// -- tweaks
// 
lines = append(lines, fmt.Sprintf(
	"sys_tweaks: enable=%t persist=%t ct[perGB=%d min=%d max=%d] strict=%t synR=%d synAckR=%d fin=%d tw=%d finw=%d closew=%d rp_filter=%d redir(acc=%t,send=%t)",
	c.SystemTweaks.Enable, c.SystemTweaks.Persist,
	c.SystemTweaks.CTPerGB, c.SystemTweaks.CTMin, c.SystemTweaks.CTMax,
	c.SystemTweaks.TCPLooseStrict,
	c.SystemTweaks.TCPSynRetries, c.SystemTweaks.TCPSynAckRetries, c.SystemTweaks.TCPFinTimeout,
	c.SystemTweaks.CTTimeWait, c.SystemTweaks.CTFinWait, c.SystemTweaks.CTCloseWait,
	c.SystemTweaks.RPFilter, c.SystemTweaks.AcceptRedirects, c.SystemTweaks.SendRedirects,
))


lines = append(lines, fmt.Sprintf(
  "hardening: badflags=%t new=%d/s burst=%d icmp=%d/s burst=%d",
  c.Hardening.BlockBadTCPFlags, c.Hardening.NewRate, c.Hardening.NewBurst,
  c.Hardening.ICMPRate, c.Hardening.ICMPBurst,
))




	// --- Portscan
	psOnly := "-"
	if len(c.Portscan.OnlyPorts) > 0 {
		psOnly = fmt.Sprintf("%d ranges", len(c.Portscan.OnlyPorts))
	}
	psPorts := "-"
	if len(c.Portscan.Ports) > 0 {
		psPorts = fmt.Sprintf("%d ports", len(c.Portscan.Ports))
	}
	lines = append(lines, fmt.Sprintf(
		"portscan: enabled=%t interval=%ds mode=%s ttl=%ds limit=%d diversity=%d track_tcp=%t track_udp=%t only=%s focus=%s",
		c.Portscan.Enabled, c.Portscan.Interval, c.Portscan.Mode, c.Portscan.TTLSeconds,
		c.Portscan.Limit, c.Portscan.Diversity, c.Portscan.TrackTCP, c.Portscan.TrackUDP,
		psOnly, psPorts,
	))

	return lines
}
