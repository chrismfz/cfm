package netstat

import "testing"

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
