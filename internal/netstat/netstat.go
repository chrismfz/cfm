// Package netstat lists listening sockets (the `ss -tlnp` / `ss -ulnp` view):
// which address:port is open and which process owns it. It backs the read-only
// MCP tool `listening_ports` / GET /api/v1/system/listeners — the "is the edge/
// daemon/panel actually listening, and who owns :443?" check.
//
// It shells out to iproute2's `ss` (already relied on by the health collector)
// rather than scanning /proc/net/* + /proc/<pid>/fd, which is O(pids×fds) and
// slow on a busy shared host. Only listening sockets and the owning COMM+pid are
// returned — never connection payloads or peer lists.
package netstat

import (
	"context"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Listener struct {
	Proto string `json:"proto"` // tcp | tcp6 | udp | udp6
	Addr  string `json:"addr"`  // local bind address
	Port  int    `json:"port"`
	Comm  string `json:"comm"` // owning process name ("" if ss couldn't attribute)
	PID   int    `json:"pid"`
}

// PortGroup is one (proto, port, owning-process) collapsed across all the bind
// addresses it listens on. A shared host binds a service on every IP alias
// (e.g. named on :53 across hundreds of addresses); the operator-relevant fact
// is "named owns :53 on N addresses", not N near-identical rows — so we group
// and keep a bounded address sample.
type PortGroup struct {
	Proto string   `json:"proto"`
	Port  int      `json:"port"`
	Comm  string   `json:"comm"`
	PID   int      `json:"pid"`
	Count int      `json:"count"`           // distinct bind addresses in this group
	Addrs []string `json:"addrs"`           // the wildcard bind(s), else a bounded sample of specific addresses
	More  int      `json:"more,omitempty"`  // addresses beyond the sample (Count-len(Addrs)) when not wildcard
}

const ssTimeout = 5 * time.Second

// sampleAddrs bounds how many specific bind addresses a non-wildcard group lists.
const sampleAddrs = 6

// Listeners returns listening TCP/UDP sockets grouped by (proto, port, owning
// process). Grouping keeps the output bounded on hosts with many IP aliases
// (see PortGroup).
func Listeners(ctx context.Context) ([]PortGroup, error) {
	cctx, cancel := context.WithTimeout(ctx, ssTimeout)
	defer cancel()

	raw := make([]Listener, 0, 128)
	// -H no header, -t/-u tcp/udp, -l listening, -n numeric, -p process.
	for _, spec := range []struct{ flag, tcpProto, v6Proto string }{
		{"-Htlnp", "tcp", "tcp6"},
		{"-Hulnp", "udp", "udp6"},
	} {
		lines, err := runSS(cctx, spec.flag)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			if l, ok := parseSSLine(line, spec.tcpProto, spec.v6Proto); ok {
				raw = append(raw, l)
			}
		}
	}
	return groupListeners(raw), nil
}

// isWildcardAddr reports whether a bind address covers all local addresses, so
// the specific-address list is redundant.
func isWildcardAddr(a string) bool {
	return a == "0.0.0.0" || a == "::" || a == "*"
}

// groupListeners collapses per-socket listeners into per-(proto,port,comm,pid)
// groups. Separated from exec so it is unit-tested. Within a group: if any bind
// is a wildcard, only the wildcard(s) are reported (they subsume the rest);
// otherwise a bounded sample of distinct specific addresses plus a `more` count.
func groupListeners(raw []Listener) []PortGroup {
	type key struct {
		proto string
		port  int
		comm  string
		pid   int
	}
	order := make([]key, 0, 64)
	seenKey := map[key]bool{}
	addrs := map[key][]string{}     // insertion-ordered distinct addresses
	seenAddr := map[key]map[string]bool{}
	for _, l := range raw {
		k := key{l.Proto, l.Port, l.Comm, l.PID}
		if !seenKey[k] {
			seenKey[k] = true
			order = append(order, k)
			seenAddr[k] = map[string]bool{}
		}
		if !seenAddr[k][l.Addr] {
			seenAddr[k][l.Addr] = true
			addrs[k] = append(addrs[k], l.Addr)
		}
	}

	out := make([]PortGroup, 0, len(order))
	for _, k := range order {
		all := addrs[k]
		g := PortGroup{Proto: k.proto, Port: k.port, Comm: k.comm, PID: k.pid, Count: len(all)}
		var wilds []string
		for _, a := range all {
			if isWildcardAddr(a) {
				wilds = append(wilds, a)
			}
		}
		if len(wilds) > 0 {
			g.Addrs = wilds
		} else if len(all) > sampleAddrs {
			g.Addrs = append([]string(nil), all[:sampleAddrs]...)
			g.More = len(all) - sampleAddrs
		} else {
			g.Addrs = all
		}
		out = append(out, g)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].Comm < out[j].Comm
	})
	return out
}

// ssPath resolves the ss binary, falling back to the usual sbin locations for a
// daemon whose PATH may not include them.
func ssPath() string {
	if p, err := exec.LookPath("ss"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/sbin/ss", "/sbin/ss", "/usr/bin/ss"} {
		if fi, err := exec.Command(p, "-h").CombinedOutput(); err == nil || len(fi) > 0 {
			return p
		}
	}
	return "ss"
}

func runSS(ctx context.Context, flag string) ([]string, error) {
	raw, err := exec.CommandContext(ctx, ssPath(), flag).Output()
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n"), nil
}

// parseSSLine parses one `ss -H -tlnp`/`-ulnp` row. v4Proto/v6Proto pick the
// label by whether the local address is IPv6. Returns ok=false for blank/
// unparseable rows.
//
// Row shape (fields are whitespace-separated):
//
//	LISTEN 0 4096 127.0.0.1:6060 0.0.0.0:* users:(("cfm",pid=123,fd=8))
//	UNCONN 0 0    0.0.0.0:53     0.0.0.0:* users:(("named",pid=9,fd=4))
func parseSSLine(line, v4Proto, v6Proto string) (Listener, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return Listener{}, false
	}
	local := fields[3]
	addr, port, ok := splitHostPort(local)
	if !ok {
		return Listener{}, false
	}
	proto := v4Proto
	if strings.Contains(addr, ":") || strings.HasPrefix(local, "[") {
		proto = v6Proto
	}
	l := Listener{Proto: proto, Addr: addr, Port: port}
	if i := strings.Index(line, "users:(("); i >= 0 {
		l.Comm, l.PID = parseProcInfo(line[i:])
	}
	return l, true
}

// splitHostPort splits ss's "addr:port" where addr may be IPv4, [IPv6], * or ::.
func splitHostPort(s string) (addr string, port int, ok bool) {
	c := strings.LastIndexByte(s, ':')
	if c < 0 || c == len(s)-1 {
		return "", 0, false
	}
	p, err := strconv.Atoi(s[c+1:])
	if err != nil {
		return "", 0, false
	}
	addr = strings.Trim(s[:c], "[]")
	return addr, p, true
}

// parseProcInfo pulls the first comm + pid from users:(("comm",pid=N,fd=M),…).
func parseProcInfo(s string) (comm string, pid int) {
	if q1 := strings.IndexByte(s, '"'); q1 >= 0 {
		if q2 := strings.IndexByte(s[q1+1:], '"'); q2 >= 0 {
			comm = s[q1+1 : q1+1+q2]
		}
	}
	if i := strings.Index(s, "pid="); i >= 0 {
		rest := s[i+4:]
		j := 0
		for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
			j++
		}
		if j > 0 {
			pid, _ = strconv.Atoi(rest[:j])
		}
	}
	return comm, pid
}
