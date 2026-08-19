package mailruntime

import (
	"strings"
	"testing"
)

// A /proc/net/tcp fixture (real column layout). Ports in hex: 25=0019,
// 587=024B, 465=01D1, ephemeral 50000=C350. State 01=ESTABLISHED, 0A=LISTEN,
// 06=TIME_WAIT.
const procNetTCPFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0019 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1000 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0019 0200A8C0:1234 01 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:024B 0300A8C0:5678 01 00000000:00000000 00:00000000 00000000     0        0 1002 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:01D1 0400A8C0:9ABC 01 00000000:00000000 00:00000000 00000000     0        0 1003 1 0000000000000000 20 4 30 10 -1
   4: 0100007F:C350 0500A8C0:0019 01 00000000:00000000 00:00000000 00000000     0        0 1004 1 0000000000000000 20 4 30 10 -1
   5: 0100007F:0019 0600A8C0:DEAD 06 00000000:00000000 00:00000000 00000000     0        0 1005 1 0000000000000000 20 4 30 10 -1
`

func TestCountEstablishedOnPorts(t *testing.T) {
	// Only lines 1,2,3: ESTABLISHED with a local SMTP port. Line 0 is LISTEN,
	// line 4 is an outbound delivery (local ephemeral, remote :25), line 5 is
	// TIME_WAIT.
	got := CountEstablishedOnPorts(strings.NewReader(procNetTCPFixture), DefaultSMTPPorts)
	if got != 3 {
		t.Fatalf("CountEstablishedOnPorts = %d, want 3", got)
	}
}

func TestCountEstablishedOnPortsSubset(t *testing.T) {
	// Only port 25 → just line 1 (line 5 on :25 is TIME_WAIT, not established).
	got := CountEstablishedOnPorts(strings.NewReader(procNetTCPFixture), map[int]bool{25: true})
	if got != 1 {
		t.Fatalf("port 25 only = %d, want 1", got)
	}
}

func TestCountEstablishedOnPortsEmptyPortSet(t *testing.T) {
	if got := CountEstablishedOnPorts(strings.NewReader(procNetTCPFixture), nil); got != 0 {
		t.Fatalf("empty port set = %d, want 0", got)
	}
}

func TestLocalPortHex(t *testing.T) {
	tests := []struct {
		addr string
		want int
		ok   bool
	}{
		{"0100007F:0019", 25, true},
		{"0100007F:024B", 587, true},
		{"00000000000000000000000001000000:01BB", 443, true}, // IPv6 local addr
		{"0100007F:0000", 0, false},                          // port 0 → not valid
		{"noconlon", 0, false},
		{"0100007F:ZZZZ", 0, false}, // non-hex
	}
	for _, tc := range tests {
		got, ok := localPortHex(tc.addr)
		if ok != tc.ok || got != tc.want {
			t.Errorf("localPortHex(%q) = (%d,%v), want (%d,%v)", tc.addr, got, ok, tc.want, tc.ok)
		}
	}
}
