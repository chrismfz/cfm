package health

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

// probeTopTalkers returns enriched "top N IPs" currently connected to local TCP port `port`
// in the given TCP states (e.g., ["SYN_RECV","ESTABLISHED"]).
func (d *Detector) probeTopTalkers(port int, states []string, topN int) []string {
	if topN <= 0 { topN = 10 }
	if len(states) == 0 { states = []string{"SYN_RECV", "ESTABLISHED"} }

	stateMask := map[uint8]bool{}
	for _, s := range states { if st, ok := tcpStateCode(s); ok { stateMask[st] = true } }

	counts := map[string]int{}

	readProc := func(path string, v6 bool) {
		f, err := os.Open(path)
		if err != nil { return }
		defer f.Close()
		sc := bufio.NewScanner(f)
		if sc.Scan() { /* skip header */ }
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			// sl local_address rem_address st ...
			fields := strings.Fields(line)
			if len(fields) < 4 { continue }
			localHex := fields[1]
			remHex   := fields[2]
			stHex    := fields[3]

			_, lpPort := parseAddr(localHex, v6)
			rpIP, _      := parseAddr(remHex, v6)
			if lpPort != port { continue }

			st, err := strconv.ParseUint(stHex, 16, 8)
			if err != nil { continue }
			if !stateMask[uint8(st)] { continue }

			if ip := rpIP.String(); ip != "" && ip != "0.0.0.0" && ip != "::" {
				counts[ip]++
			}
		}
	}

	readProc("/proc/net/tcp", false)
	readProc("/proc/net/tcp6", true)

	// sort by count desc
	type kv struct{ ip string; n int }
	agg := make([]kv, 0, len(counts))
	for ip, n := range counts { agg = append(agg, kv{ip, n}) }
	sort.Slice(agg, func(i, j int) bool { 
		if agg[i].n == agg[j].n { return agg[i].ip < agg[j].ip }
		return agg[i].n > agg[j].n
	})
	if len(agg) > topN { agg = agg[:topN] }

	out := make([]string, 0, len(agg))
	for _, t := range agg {
		// decorate with ASN/Country/PTR like other detectors
		label := d.decorateIP(t.ip)
		out = append(out, fmt.Sprintf("%s  conns=%d", label, t.n))
	}
	return out
}






// probeSynRecvTalkers returns top remote IPs across ALL local ports in SYN_RECV.
func (d *Detector) probeSynRecvTalkers(topN int) []string {
	if topN <= 0 { topN = 10 }
	counts := map[string]int{}
	readProc := func(path string, v6 bool) {
		f, err := os.Open(path)
		if err != nil { return }
		defer f.Close()
		sc := bufio.NewScanner(f)
		if sc.Scan() { /* skip header */ }
		for sc.Scan() {
			fields := strings.Fields(strings.TrimSpace(sc.Text()))
			if len(fields) < 4 { continue }
			remHex := fields[2]
			stHex  := fields[3]
			st, err := strconv.ParseUint(stHex, 16, 8)
			if err != nil || uint8(st) != 0x03 { // 0x03 = SYN_RECV
				continue
			}
			rpIP, _ := parseAddr(remHex, v6)
			if ip := rpIP.String(); ip != "" && ip != "0.0.0.0" && ip != "::" {
				counts[ip]++
			}
		}
	}
	readProc("/proc/net/tcp", false)
	readProc("/proc/net/tcp6", true)

	type kv struct{ ip string; n int }
	agg := make([]kv, 0, len(counts))
	for ip, n := range counts { agg = append(agg, kv{ip, n}) }
	sort.Slice(agg, func(i, j int) bool {
		if agg[i].n == agg[j].n { return agg[i].ip < agg[j].ip }
		return agg[i].n > agg[j].n
	})
	if len(agg) > topN { agg = agg[:topN] }

	out := make([]string, 0, len(agg))
	for _, t := range agg {
		label := d.decorateIP(t.ip)
		out = append(out, fmt.Sprintf("%s  conns=%d", label, t.n))
	}
	return out
}








// parseAddr converts the /proc hex address into net.IP + port.
func parseAddr(hexPair string, v6 bool) (ip net.IP, port int) {
	parts := strings.Split(hexPair, ":")
	if len(parts) != 2 { return nil, 0 }
	phex := parts[1]
	pv, _ := strconv.ParseUint(phex, 16, 16)
	port = int(pv)

	if v6 {
		// IPv6 is 32 hex chars, little-endian 32-bit words reversed
		h := parts[0]
		if len(h) != 32 { return net.IPv6zero, port }
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 16 { return net.IPv6zero, port }
		// bytes are little endian per 32-bit word; reverse per 4-byte chunk
		for i := 0; i < 16; i += 4 {
			for a, bidx := 0, 3; a < bidx; a, bidx = a+1, bidx-1 {
				b[i+a], b[i+bidx] = b[i+bidx], b[i+a]
			}
		}
		ip = net.IP{b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]}
		return ip, port
	}

	// IPv4 is 8 hex chars, little-endian
	h := parts[0]
	if len(h) != 8 { return net.IPv4zero, port }
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 4 { return net.IPv4zero, port }
	ip = net.IPv4(b[3], b[2], b[1], b[0])
	return ip, port
}

func tcpStateCode(name string) (uint8, bool) {
	switch strings.ToUpper(name) {
	case "ESTABLISHED": return 0x01, true
	case "SYN_SENT":    return 0x02, true
	case "SYN_RECV":    return 0x03, true
	case "FIN_WAIT1":   return 0x04, true
	case "FIN_WAIT2":   return 0x05, true
	case "TIME_WAIT":   return 0x06, true
	case "CLOSE":       return 0x07, true
	case "CLOSE_WAIT":  return 0x08, true
	case "LAST_ACK":    return 0x09, true
	case "LISTEN":      return 0x0A, true
	case "CLOSING":     return 0x0B, true
	default: return 0, false
	}
}


// Top PIDs by number of matching sockets (optionally filtered by local port; -1 = any)
// states like []string{"ESTABLISHED"}; returns lines "nginx (pid 1234) conns=17"
func (d *Detector) probeTopPIDsByConn(portFilter int, states []string, topN int) []string {
	if topN <= 0 { topN = 10 }
	stateMask := map[uint8]bool{}
	for _, s := range states { if st, ok := tcpStateCode(s); ok { stateMask[st] = true } }

	// collect inodes for sockets we care about
	inodes := map[string]struct{}{}
	addInodes := func(path string, v6 bool) {
		f, err := os.Open(path); if err != nil { return }
		defer f.Close()
		sc := bufio.NewScanner(f)
		if sc.Scan() { /* skip header */ }
		for sc.Scan() {
			fields := strings.Fields(strings.TrimSpace(sc.Text()))
			if len(fields) < 10 { continue }
			localHex := fields[1]
			stHex    := fields[3]
			inode    := fields[9] // /proc/net/tcp inode column

			_, lpPort := parseAddr(localHex, v6)
			if portFilter >= 0 && lpPort != portFilter { continue }

			st, err := strconv.ParseUint(stHex, 16, 8)
			if err != nil { continue }
			if !stateMask[uint8(st)] { continue }

			inodes[inode] = struct{}{}
		}
	}
	addInodes("/proc/net/tcp", false)
	addInodes("/proc/net/tcp6", true)
	if len(inodes) == 0 { return nil }

	// map inode -> pid by scanning /proc/*/fd
	type rec struct{ pid int; name string }
	counts := map[int]int{}
	names  := map[int]string{}

	pdirs, _ := os.ReadDir("/proc")
	for _, de := range pdirs {
		if !de.IsDir() { continue }
		pid, err := strconv.Atoi(de.Name()); if err != nil { continue }

		fdDir := "/proc/" + de.Name() + "/fd"
		fds, err := os.ReadDir(fdDir); if err != nil { continue }

		for _, fd := range fds {
			link, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil { continue }
			// look for socket:[inode]
			if !strings.HasPrefix(link, "socket:[") { continue }
			in := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if _, ok := inodes[in]; ok {
				counts[pid]++
			}
		}

		if counts[pid] > 0 {
			// lazily load name
			if nm, ok := names[pid]; !ok || nm == "" {
				if b, err := os.ReadFile("/proc/" + de.Name() + "/comm"); err == nil {
					names[pid] = strings.TrimSpace(string(b))
				}
			}
		}
	}

	if len(counts) == 0 { return nil }

	// rank
	type kv struct{ pid, n int }
	agg := make([]kv, 0, len(counts))
	for p, n := range counts { agg = append(agg, kv{p, n}) }
	sort.Slice(agg, func(i, j int) bool {
		if agg[i].n == agg[j].n { return agg[i].pid < agg[j].pid }
		return agg[i].n > agg[j].n
	})
	if len(agg) > topN { agg = agg[:topN] }

	var out []string
	for _, t := range agg {
		name := names[t.pid]
		if name == "" { name = "pid" }
		out = append(out, fmt.Sprintf("%s (pid %d)  conns=%d", name, t.pid, t.n))
	}
	return out
}

// ESTABLISHED talkers across ALL local ports (unlike probeSynRecvTalkers which is SYN_RECV-only)
func (d *Detector) probeTalkersAllPorts(states []string, topN int) []string {
	if topN <= 0 { topN = 10 }
	stateMask := map[uint8]bool{}
	for _, s := range states { if st, ok := tcpStateCode(s); ok { stateMask[st] = true } }

	counts := map[string]int{}
	add := func(path string, v6 bool) {
		f, err := os.Open(path); if err != nil { return }
		defer f.Close()
		sc := bufio.NewScanner(f)
		if sc.Scan() { /* skip header */ }
		for sc.Scan() {
			fields := strings.Fields(strings.TrimSpace(sc.Text()))
			if len(fields) < 4 { continue }
			remHex := fields[2]
			stHex  := fields[3]
			st, err := strconv.ParseUint(stHex, 16, 8)
			if err != nil { continue }
			if !stateMask[uint8(st)] { continue }

			rpIP, _ := parseAddr(remHex, v6)
			if ip := rpIP.String(); ip != "" && ip != "0.0.0.0" && ip != "::" {
				counts[ip]++
			}
		}
	}
	add("/proc/net/tcp", false)
	add("/proc/net/tcp6", true)

	if len(counts) == 0 { return nil }

	type kv struct{ ip string; n int }
	agg := make([]kv, 0, len(counts))
	for ip, n := range counts { agg = append(agg, kv{ip, n}) }
	sort.Slice(agg, func(i, j int) bool {
		if agg[i].n == agg[j].n { return agg[i].ip < agg[j].ip }
		return agg[i].n > agg[j].n
	})
	if len(agg) > topN { agg = agg[:topN] }

	out := make([]string, 0, len(agg))
	for _, t := range agg {
		label := d.decorateIP(t.ip)
		out = append(out, fmt.Sprintf("%s  conns=%d", label, t.n))
	}
	return out
}
