package mailruntime

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
)

// DefaultSMTPPorts are the inbound SMTP listener ports whose ESTABLISHED socket
// count approximates the current inbound SMTP session count that Exim's
// smtp_accept_max caps: 25 (smtp), 465 (smtps), 587 (submission).
var DefaultSMTPPorts = map[int]bool{25: true, 465: true, 587: true}

// CountEstablishedOnPorts counts ESTABLISHED TCP sockets whose LOCAL port is in
// ports, reading one /proc/net/tcp{,6} stream. Keying on the LOCAL port counts
// INBOUND sessions only: a client connecting to our :25/:465/:587 has that as
// its local port here, whereas an outbound delivery uses an ephemeral local port
// (the remote is :25), so it is not counted. The /proc/net/tcp line format is a
// stable kernel interface; this mirrors the reader in the health detector, keyed
// by port instead of aggregate state. State "01" is ESTABLISHED.
func CountEstablishedOnPorts(r io.Reader, ports map[int]bool) int {
	if len(ports) == 0 {
		return 0
	}
	br := bufio.NewReader(r)
	_, _ = br.ReadString('\n') // skip the header row
	count := 0
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			fields := strings.Fields(line)
			// fields[1]=local_address "HEXIP:HEXPORT", fields[3]=state hex.
			if len(fields) >= 4 && fields[3] == "01" {
				if p, ok := localPortHex(fields[1]); ok && ports[p] {
					count++
				}
			}
		}
		if err != nil {
			break
		}
	}
	return count
}

// localPortHex extracts the port from a /proc/net/tcp "HEXIP:HEXPORT" local
// address (IPv4 or IPv6 — the port is always the final colon-separated hex).
func localPortHex(addr string) (int, bool) {
	i := strings.LastIndexByte(addr, ':')
	if i < 0 || i+1 >= len(addr) {
		return 0, false
	}
	n, err := strconv.ParseInt(addr[i+1:], 16, 32)
	if err != nil || n <= 0 {
		return 0, false
	}
	return int(n), true
}

// SMTPEstablished counts inbound ESTABLISHED SMTP sockets on the given local
// ports across both /proc/net/tcp and /proc/net/tcp6. A missing/unreadable file
// contributes 0 (a v6-less or restricted host still yields the v4 count) rather
// than failing the whole read.
func SMTPEstablished(ports map[int]bool) int {
	total := 0
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		total += CountEstablishedOnPorts(f, ports)
		_ = f.Close()
	}
	return total
}
