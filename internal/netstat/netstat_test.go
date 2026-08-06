package netstat

import (
	"reflect"
	"testing"
)

func TestGroupListeners(t *testing.T) {
	raw := []Listener{
		// named on :53 across many specific IPs → collapses to one group,
		// sampled + more count.
		{Proto: "udp", Addr: "1.1.1.1", Port: 53, Comm: "named", PID: 9},
		{Proto: "udp", Addr: "1.1.1.2", Port: 53, Comm: "named", PID: 9},
		{Proto: "udp", Addr: "1.1.1.3", Port: 53, Comm: "named", PID: 9},
		{Proto: "udp", Addr: "1.1.1.4", Port: 53, Comm: "named", PID: 9},
		{Proto: "udp", Addr: "1.1.1.5", Port: 53, Comm: "named", PID: 9},
		{Proto: "udp", Addr: "1.1.1.6", Port: 53, Comm: "named", PID: 9},
		{Proto: "udp", Addr: "1.1.1.7", Port: 53, Comm: "named", PID: 9},
		{Proto: "udp", Addr: "1.1.1.8", Port: 53, Comm: "named", PID: 9},
		// wildcard bind subsumes any specific address in the same group.
		{Proto: "tcp", Addr: "0.0.0.0", Port: 443, Comm: "litespeed", PID: 5},
		{Proto: "tcp", Addr: "1.2.3.4", Port: 443, Comm: "litespeed", PID: 5},
		// a lone listener.
		{Proto: "tcp", Addr: "127.0.0.1", Port: 6060, Comm: "cfm", PID: 2},
		// duplicate address in a group must not double-count.
		{Proto: "tcp", Addr: "127.0.0.1", Port: 6060, Comm: "cfm", PID: 2},
	}
	got := groupListeners(raw)
	if len(got) != 3 {
		t.Fatalf("groups = %d, want 3", len(got))
	}
	// sorted by port: 53, 443, 6060
	dns := got[0]
	if dns.Port != 53 || dns.Comm != "named" || dns.Count != 8 {
		t.Fatalf("dns group wrong: %+v", dns)
	}
	if len(dns.Addrs) != sampleAddrs || dns.More != 8-sampleAddrs {
		t.Fatalf("dns sample = %d addrs, more=%d; want %d, %d", len(dns.Addrs), dns.More, sampleAddrs, 8-sampleAddrs)
	}
	ls := got[1]
	if ls.Port != 443 || !reflect.DeepEqual(ls.Addrs, []string{"0.0.0.0"}) || ls.Count != 2 || ls.More != 0 {
		t.Fatalf("litespeed group should report only the wildcard: %+v", ls)
	}
	cfm := got[2]
	if cfm.Port != 6060 || cfm.Count != 1 || !reflect.DeepEqual(cfm.Addrs, []string{"127.0.0.1"}) {
		t.Fatalf("cfm group wrong (dup addr must collapse): %+v", cfm)
	}
}

func TestParseSSLine(t *testing.T) {
	cases := []struct {
		name              string
		line              string
		v4, v6            string
		wantOK            bool
		proto, addr, comm string
		port, pid         int
	}{
		{
			name: "tcp v4 with process", line: `LISTEN 0 4096 127.0.0.1:6060 0.0.0.0:* users:(("cfm",pid=123,fd=8))`,
			v4: "tcp", v6: "tcp6", wantOK: true, proto: "tcp", addr: "127.0.0.1", port: 6060, comm: "cfm", pid: 123,
		},
		{
			name: "tcp v6 brackets", line: `LISTEN 0 511 [::]:443 [::]:* users:(("litespeed",pid=1254197,fd=6))`,
			v4: "tcp", v6: "tcp6", wantOK: true, proto: "tcp6", addr: "::", port: 443, comm: "litespeed", pid: 1254197,
		},
		{
			name: "udp v4", line: `UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("named",pid=9,fd=4))`,
			v4: "udp", v6: "udp6", wantOK: true, proto: "udp", addr: "0.0.0.0", port: 53, comm: "named", pid: 9,
		},
		{
			name: "wildcard addr", line: `LISTEN 0 128 *:111 *:* users:(("rpcbind",pid=1,fd=4))`,
			v4: "tcp", v6: "tcp6", wantOK: true, proto: "tcp", addr: "*", port: 111, comm: "rpcbind", pid: 1,
		},
		{
			name: "no process attribution", line: `LISTEN 0 128 0.0.0.0:22 0.0.0.0:*`,
			v4: "tcp", v6: "tcp6", wantOK: true, proto: "tcp", addr: "0.0.0.0", port: 22, comm: "", pid: 0,
		},
		{name: "blank", line: "   ", v4: "tcp", v6: "tcp6", wantOK: false},
		{name: "short", line: "LISTEN 0", v4: "tcp", v6: "tcp6", wantOK: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseSSLine(c.line, c.v4, c.v6)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if !c.wantOK {
				return
			}
			if got.Proto != c.proto || got.Addr != c.addr || got.Port != c.port || got.Comm != c.comm || got.PID != c.pid {
				t.Fatalf("got %+v, want proto=%s addr=%s port=%d comm=%s pid=%d", got, c.proto, c.addr, c.port, c.comm, c.pid)
			}
		})
	}
}
