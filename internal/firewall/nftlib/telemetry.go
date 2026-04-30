//go:build linux

package nftlib

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	cfgpkg "cfm/internal/config"
	"cfm/internal/firewall/autoblock"
	"cfm/internal/logging"
	"cfm/internal/notify"

	"github.com/google/nftables"
)

const (
	psPairsV4    = "ps_pairs_v4"
	psPairsV6    = "ps_pairs_v6"
	psPairsUDPV4 = "ps_pairs_udp_v4"
	psPairsUDPV6 = "ps_pairs_udp_v6"
)

// DumpFloodCounters logs flood counter deltas (non-blocking, overlap-guarded).
func (b *Backend) DumpFloodCounters() {
	b.floodDumpMu.Lock()
	if b.floodDumpRunning {
		b.floodDumpMu.Unlock()
		return
	}
	b.floodDumpRunning = true
	b.floodDumpMu.Unlock()

	go func() {
		defer func() {
			b.floodDumpMu.Lock()
			b.floodDumpRunning = false
			b.floodDumpMu.Unlock()
		}()
		b.dumpFloodCountersOnce()
	}()
}

func (b *Backend) dumpFloodCountersOnce() {
	b.mu.Lock()
	t, err := b.lookupTable()
	b.mu.Unlock()
	if err != nil {
		_ = b.EnsureBase()
		logging.Logf("[flood] cannot get table: %v", err)
		return
	}

	objs, err := b.conn.GetObjects(t)
	if err != nil {
		logging.Logf("[flood] cannot list counters: %v", err)
		return
	}

	wantedExact := map[string]struct{}{
		"badflags_drop": {},
		"newrate_v4":    {},
		"newrate_v6":    {},
		"icmp_v4":       {},
		"icmp_v6":       {},
	}
	isWanted := func(name string) bool {
		if _, ok := wantedExact[name]; ok {
			return true
		}
		return strings.HasPrefix(name, "connlimit_") ||
			strings.HasPrefix(name, "portflood_") ||
			strings.HasPrefix(name, "synrate_") ||
			strings.HasPrefix(name, "ppsrate_")
	}

	for _, obj := range objs {
		c, ok := obj.(*nftables.CounterObj)
		if !ok || !isWanted(c.Name) {
			continue
		}
		pkts := c.Packets
		prev := b.last[c.Name]
		if pkts > prev {
			delta := pkts - prev
			logging.Logf("[flood] %-24s packets %d (+%d) reason=%s",
				c.Name, pkts, delta, autoblock.ReasonForName(c.Name))
		}
		b.last[c.Name] = pkts
	}

	if b.cfg != nil && b.cfg.Throttle.Enabled {
		b.dumpThrottledIPsNative()
	}
}

// DumpThrottledIPs logs and evaluates throttled IPs for auto-block.
func (b *Backend) DumpThrottledIPs() {
	b.dumpThrottledIPsNative()
}

func (b *Backend) dumpThrottledIPsNative() {
	uniq4 := map[string]struct{}{}
	uniq6 := map[string]struct{}{}

	record := func(setName string) {
		ips := b.getSetIPStrings(setName)
		if len(ips) == 0 {
			return
		}
		rsn := autoblock.ReasonForName(setName)
		for _, ip := range ips {
			if prev, ok := b.ab.Reasons[ip]; !ok || prev == "" ||
				strings.HasPrefix(prev, "General throttle") || prev == "Auto-block" || prev == "unknown" {
				b.ab.Reasons[ip] = rsn
			}
			if autoblock.ParseIPFam(ip) == 4 {
				uniq4[ip] = struct{}{}
			} else if autoblock.ParseIPFam(ip) == 6 {
				uniq6[ip] = struct{}{}
			}
		}
	}

	var srcs []string
	if b.cfg != nil && len(b.cfg.Throttle.Sources) > 0 {
		srcs = b.cfg.Throttle.Sources
	} else {
		env := strings.TrimSpace(os.Getenv("THROTTLE_SOURCES"))
		if env == "" {
			env = "syn,portflood,pps,new,icmp,ack"
		}
		for _, t := range strings.Split(env, ",") {
			srcs = append(srcs, t)
		}
	}
	enabled := make(map[string]bool, len(srcs))
	for _, t := range srcs {
		k := strings.ToLower(strings.TrimSpace(t))
		if k != "" {
			enabled[k] = true
		}
	}

	if enabled["syn"] {
		record("th_syn_v4")
		record("th_syn_v6")
	}
	if enabled["pps"] {
		record("th_pps_v4")
		record("th_pps_v6")
	}
	if enabled["new"] {
		record("th_new_v4")
		record("th_new_v6")
	}
	if enabled["icmp"] {
		record("th_icmp_v4")
		record("th_icmp_v6")
	}
	if enabled["portflood"] {
		names, _ := b.listSetsByPrefix("th_pf_")
		for _, s := range names {
			record(s)
		}
	}
	if enabled["connlimit"] {
		names, _ := b.listSetsByPrefix("th_connlimit_")
		for _, s := range names {
			record(s)
		}
	}

	if b.cfg != nil && b.cfg.Throttle.Enabled {
		var v4, v6 []string
		for ip := range uniq4 {
			v4 = append(v4, ip)
		}
		for ip := range uniq6 {
			v6 = append(v6, ip)
		}
		b.ab.Eval(v4, v6, b.cfg.Throttle, b.autoBlockAction)
	}
}

// getSetIPStrings retrieves all IP elements from a named set via netlink,
// filtering out self IPs.
func (b *Backend) getSetIPStrings(setName string) []string {
	b.mu.Lock()
	set, err := b.lookupSet(setName)
	b.mu.Unlock()
	if err != nil {
		return nil
	}
	elems, err := b.conn.GetSetElements(set)
	if err != nil {
		return nil
	}
	var ips []string
	for _, e := range elems {
		if e.IntervalEnd {
			continue
		}
		ip := keyToIP(e.Key)
		if ip == nil {
			continue
		}
		s := ip.String()
		if b.selfResolver.Contains(s) {
			continue
		}
		ips = append(ips, s)
	}
	return ips
}

// autoBlockAction is nftlib's BlockAction: uses b.AddBlock (native netlink, no subprocess).
func (b *Backend) autoBlockAction(ip, fam, reason string, tc cfgpkg.ThrottleConfig) error {
	if reason == "" {
		reason = "Auto-block"
	}

	const ignoreNotifyCooldown = 90 * time.Second

	if skip, why := b.shouldSkipAutoBlock(ip); skip {
		extraLabel := b.enrichLabel(ip)
		logIP := ip + extraLabel
		ignReason := why
		if ignReason == "" {
			ignReason = "matched allow/ignore policy"
		}
		if time.Since(b.lastIgnoredAt[ip]) >= ignoreNotifyCooldown {
			logging.Logf("[autoblock][ignored] %s %s reason=%s", fam, logIP, ignReason)
			note := reason
			if ignReason != "" {
				note += " | " + ignReason
			}
			b.emitAutoBlockNotify(ip, fam, "ignored", note, 0, tc.Hits, tc.WindowSec)
			b.lastIgnoredAt[ip] = time.Now()
		}
		return nil
	}

	if tc.CooldownSec > 0 {
		if t, ok := b.lastAutoBlockAt[ip]; ok {
			if time.Since(t) < time.Duration(tc.CooldownSec)*time.Second {
				return nil
			}
		}
	}

	extraLabel := b.enrichLabel(ip)
	logIP := ip + extraLabel
	cleanExtra := strings.TrimSpace(strings.TrimPrefix(extraLabel, "—"))
	cleanExtra = strings.TrimLeft(cleanExtra, "–— ")
	comment := reason
	if cleanExtra != "" {
		comment += " | " + cleanExtra
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("autoBlockAction: invalid IP %q", ip)
	}

	switch tc.Mode {
	case "alert", "dryrun":
		logging.Logf("[dryrun] %s %s -> would block_%s (ttl=%ds, hits>=%d in %ds) reason=%s",
			fam, logIP, fam, tc.TTLSeconds, tc.Hits, tc.WindowSec, reason)
		return nil

	case "ttl":
		ttl := tc.TTLSeconds
		if ttl <= 0 {
			ttl = 3600
		}
		d := time.Duration(ttl) * time.Second
		if err := b.AddBlock(parsedIP, comment, &d); err != nil {
			return err
		}
		logging.Logf("[autoblock] %s %s -> block_%s ttl=%ds (hits>=%d in %ds) reason=%s",
			fam, logIP, fam, ttl, tc.Hits, tc.WindowSec, reason)
		b.lastAutoBlockAt[ip] = time.Now()
		_ = b.ReportBlock(ip, comment, "autoblock", "ttl", ttl)
		b.emitAutoBlockNotify(ip, fam, "ttl", reason, ttl, tc.Hits, tc.WindowSec)
		return nil

	default: // "permanent"
		if err := b.AddBlock(parsedIP, comment, nil); err != nil {
			return err
		}
		logging.Logf("[autoblock] %s %s -> block_%s permanent (hits>=%d in %ds) reason=%s",
			fam, logIP, fam, tc.Hits, tc.WindowSec, reason)
		b.lastAutoBlockAt[ip] = time.Now()
		_ = b.appendToDenyFile(ip, comment)
		_ = b.ReportBlock(ip, comment, "autoblock", "permanent", 0)
		b.emitAutoBlockNotify(ip, fam, "permanent", reason, 0, tc.Hits, tc.WindowSec)
		return nil
	}
}

// shouldSkipAutoBlock returns (true, reason) if ip is in ignore/allow sets.
func (b *Backend) shouldSkipAutoBlock(ip string) (bool, string) {
	f := autoblock.ParseIPFam(ip)
	if f == 0 {
		return false, ""
	}

	var hostSets, netSets []string
	if f == 6 {
		hostSets = []string{"ignore_v6", "allow_v6", "allow_dyn_v6"}
		netSets = []string{"ignore_v6_nets", "allow_v6_nets"}
	} else {
		hostSets = []string{"ignore_v4", "allow_v4", "allow_dyn_v4"}
		netSets = []string{"ignore_v4_nets", "allow_v4_nets"}
	}

	for _, s := range hostSets {
		ok, _ := b.HasElem(s, ip)
		if ok {
			if strings.HasPrefix(s, "ignore_") {
				return true, "in ignore list"
			}
			return true, "already allowed"
		}
	}
	for _, s := range netSets {
		ok, _ := b.HasElem(s, ip)
		if ok {
			if strings.HasPrefix(s, "ignore_") {
				return true, "in ignore CIDR"
			}
			return true, "allowed by CIDR"
		}
	}

	// Union sets maintained by RebuildExternalUnions cover all feed-sourced allows.
	var extHostSet, extNetSet string
	if f == 6 {
		extHostSet, extNetSet = "allow_ext_v6_hosts", "allow_ext_v6_nets"
	} else {
		extHostSet, extNetSet = "allow_ext_v4_hosts", "allow_ext_v4_nets"
	}
	if ok, _ := b.HasElem(extHostSet, ip); ok {
		return true, "already allowed (feed)"
	}
	if ok, _ := b.HasElem(extNetSet, ip); ok {
		return true, "allowed by CIDR (feed)"
	}

	return false, ""
}

func (b *Backend) appendToDenyFile(ip, reason string) error {
	if strings.TrimSpace(b.cfgDir) == "" {
		return nil
	}
	dir := filepath.Clean(b.cfgDir)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	fp := filepath.Join(dir, "cfm.deny")
	// #nosec G304 -- path is operator-supplied config directory, not user input
	f, err := os.OpenFile(fp, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	_, err = f.WriteString(fmt.Sprintf("%s # autoblock: %s at %s\n", ip, reason, ts))
	return err
}

func (b *Backend) enrichLabel(ip string) string {
	if b.enr == nil {
		return ""
	}
	r := b.enr.Lookup(ip)
	var parts []string
	if r.PTR != "" {
		parts = append(parts, r.PTR)
	}
	if r.ASN > 0 {
		if r.ASNName != "" {
			parts = append(parts, fmt.Sprintf("AS%d %s", r.ASN, r.ASNName))
		} else {
			parts = append(parts, fmt.Sprintf("AS%d", r.ASN))
		}
	}
	if r.City != "" || r.Country != "" {
		if r.City != "" {
			parts = append(parts, fmt.Sprintf("%s, %s", r.City, r.Country))
		} else {
			parts = append(parts, r.Country)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "  —  " + strings.Join(parts, " | ")
}

func (b *Backend) emitAutoBlockNotify(ip, fam, mode, reason string, ttlSeconds, hits, window int) {
	ev := notify.Event{
		Kind:     reason,
		SrcIP:    ip,
		Reason:   reason,
		TTL:      time.Duration(ttlSeconds) * time.Second,
		Count:    hits,
		Section:  "autoblock",
		When:     time.Now(),
		Severity: "warning",
		Extra: map[string]string{
			"family": fam,
			"mode":   mode,
			"window": fmt.Sprintf("%ds", window),
		},
	}
	if b.enr != nil {
		r := b.enr.Lookup(ip)
		ev.PTR = r.PTR
		if r.ASN > 0 {
			if r.ASNName != "" {
				ev.ASN = fmt.Sprintf("AS%d %s", r.ASN, r.ASNName)
			} else {
				ev.ASN = fmt.Sprintf("AS%d", r.ASN)
			}
		}
		if r.City != "" && r.Country != "" {
			ev.Country = r.City + ", " + r.Country
		} else {
			ev.Country = r.Country
		}
	}
	notify.Enqueue(ev)
}

// LoadPortScanner runs port-scan detection in a non-blocking goroutine.
func (b *Backend) LoadPortScanner() {
	b.portScanMu.Lock()
	if b.portScanRunning {
		b.portScanMu.Unlock()
		return
	}
	b.portScanRunning = true
	b.portScanMu.Unlock()

	go func() {
		defer func() {
			b.portScanMu.Lock()
			b.portScanRunning = false
			b.portScanMu.Unlock()
		}()
		b.loadPortScannerOnce()
	}()
}

func (b *Backend) loadPortScannerOnce() {
	if err := b.EnsureBase(); err != nil {
		return
	}
	b.ensurePortscanSetsNative()

	if b.cfg == nil {
		return
	}
	ps := b.cfg.Portscan
	if !ps.Enabled || ps.Interval <= 0 || ps.Limit <= 0 {
		return
	}

	tcp, udp := b.dumpPortscanPairsNative()

	counts := map[string]int{}
	addCounts := func(m map[string]map[int]struct{}) {
		for ip, ports := range m {
			counts[ip] += len(ports)
		}
	}
	if ps.TrackTCP {
		addCounts(tcp)
	}
	if ps.TrackUDP {
		addCounts(udp)
	}

	tc := cfgpkg.ThrottleConfig{
		WindowSec:  ps.Interval,
		Hits:       1,
		Mode:       "ttl",
		TTLSeconds: ps.TTLSeconds,
	}
	if strings.ToLower(ps.Mode) == "permanent" {
		tc.Mode = "permanent"
	}

	var v4, v6 []string
	for ip, n := range counts {
		if n < ps.Limit {
			continue
		}
		reason := fmt.Sprintf("portscan (%d distinct ports)", n)
		var some []int
		if ps.TrackTCP {
			for p := range tcp[ip] {
				some = append(some, p)
			}
		}
		if ps.TrackUDP {
			for p := range udp[ip] {
				some = append(some, p)
			}
		}
		if len(some) > 0 {
			for i := 0; i < len(some); i++ {
				for j := i + 1; j < len(some); j++ {
					if some[j] < some[i] {
						some[i], some[j] = some[j], some[i]
					}
				}
			}
			if len(some) > 6 {
				some = some[:6]
			}
			var parts []string
			for _, p := range some {
				parts = append(parts, strconv.Itoa(p))
			}
			reason = fmt.Sprintf("%s: %s", reason, strings.Join(parts, ","))
		}
		b.ab.Reasons[ip] = reason
		if autoblock.ParseIPFam(ip) == 4 {
			v4 = append(v4, ip)
		} else if autoblock.ParseIPFam(ip) == 6 {
			v6 = append(v6, ip)
		}
	}

	keep4 := make([]string, 0, len(v4))
	for _, s := range v4 {
		if !b.selfResolver.Contains(s) {
			keep4 = append(keep4, s)
		} else {
			delete(b.ab.Reasons, s)
		}
	}
	v4 = keep4
	keep6 := make([]string, 0, len(v6))
	for _, s := range v6 {
		if !b.selfResolver.Contains(s) {
			keep6 = append(keep6, s)
		} else {
			delete(b.ab.Reasons, s)
		}
	}
	v6 = keep6

	mode := strings.ToLower(ps.Mode)
	if mode == "alert" || mode == "log" || mode == "test" {
		for _, ip := range v4 {
			logging.Logf("[portscan] possible port scan v4 %s%s %s", ip, b.enrichLabel(ip), b.ab.Reasons[ip])
		}
		for _, ip := range v6 {
			logging.Logf("[portscan] possible port scan v6 %s%s %s", ip, b.enrichLabel(ip), b.ab.Reasons[ip])
		}
		return
	}

	switch mode {
	case "ttl", "temporary":
		tc.Mode = "ttl"
		tc.TTLSeconds = ps.TTLSeconds
	default:
		tc.Mode = "permanent"
	}

	if len(v4) > 0 || len(v6) > 0 {
		b.ab.Eval(v4, v6, tc, b.autoBlockAction)
	}
}

// ensurePortscanSetsNative creates the ps_pairs_* concat sets via netlink.
func (b *Backend) ensurePortscanSetsNative() {
	table := &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}
	concatV4 := nftables.MustConcatSetType(nftables.TypeIPAddr, nftables.TypeInetService)
	concatV6 := nftables.MustConcatSetType(nftables.TypeIP6Addr, nftables.TypeInetService)

	sets := []struct {
		name    string
		keyType nftables.SetDatatype
	}{
		{psPairsV4, concatV4},
		{psPairsV6, concatV6},
		{psPairsUDPV4, concatV4},
		{psPairsUDPV6, concatV6},
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range sets {
		if err := b.conn.AddSet(&nftables.Set{
			Table:         table,
			Name:          s.name,
			KeyType:       s.keyType,
			HasTimeout:    true,
			Concatenation: true,
		}, nil); err != nil {
			logging.Logf("[portscan] ensurePortscanSetsNative queue %s: %v", s.name, err)
		}
	}
	if err := b.conn.Flush(); err != nil && !isAlreadyExists(err) {
		logging.Logf("[portscan] ensurePortscanSetsNative flush: %v", err)
	}
}

// dumpPortscanPairsNative reads the ps_pairs_* sets via netlink and decodes
// the concat keys (IP . port) back to a map[ip]map[port]struct{}.
func (b *Backend) dumpPortscanPairsNative() (tcp, udp map[string]map[int]struct{}) {
	parseSet := func(setName string, v6 bool) map[string]map[int]struct{} {
		m := map[string]map[int]struct{}{}

		b.mu.Lock()
		set, err := b.lookupSet(setName)
		b.mu.Unlock()
		if err != nil {
			return m
		}

		elems, err := b.conn.GetSetElements(set)
		if err != nil {
			return m
		}

		for _, e := range elems {
			if e.IntervalEnd {
				continue
			}
			ip, port, ok := decodeConcatIPPort(e.Key, v6)
			if !ok {
				continue
			}
			s := ip.String()
			if _, exists := m[s]; !exists {
				m[s] = map[int]struct{}{}
			}
			m[s][port] = struct{}{}
		}
		return m
	}

	tcp = map[string]map[int]struct{}{}
	udp = map[string]map[int]struct{}{}
	mergeInto := func(src, dst map[string]map[int]struct{}) {
		for ip, ports := range src {
			if _, ok := dst[ip]; !ok {
				dst[ip] = map[int]struct{}{}
			}
			for p := range ports {
				dst[ip][p] = struct{}{}
			}
		}
	}
	mergeInto(parseSet(psPairsV4, false), tcp)
	mergeInto(parseSet(psPairsV6, true), tcp)
	mergeInto(parseSet(psPairsUDPV4, false), udp)
	mergeInto(parseSet(psPairsUDPV6, true), udp)
	return tcp, udp
}

// decodeConcatIPPort decodes a concat set key (ipv4_addr . inet_service or
// ipv6_addr . inet_service) back to an IP and port number.
//
// The nftables kernel pads each concat component to 4-byte alignment, so:
//   - ipv4_addr . inet_service → 4 + 4 = 8 bytes (port in bytes[4:6])
//   - ipv6_addr . inet_service → 16 + 4 = 20 bytes (port in bytes[16:18])
func decodeConcatIPPort(key []byte, v6 bool) (net.IP, int, bool) {
	if v6 {
		if len(key) < 20 {
			return nil, 0, false
		}
		ip := make(net.IP, 16)
		copy(ip, key[0:16])
		port := int(binary.BigEndian.Uint16(key[16:18]))
		return ip, port, true
	}
	if len(key) < 8 {
		return nil, 0, false
	}
	ip := make(net.IP, 4)
	copy(ip, key[0:4])
	port := int(binary.BigEndian.Uint16(key[4:6]))
	return ip, port, true
}
