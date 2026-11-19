package originrealip

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
)

// v6BindCheck is `cfm realip v6-bindcheck tcp:9080 tcp:9043 udp:9043`, run by
// scripts/cfm-edge-listen-v6.sh (as root) before it lets the edge listen on
// IPv6: it binds (and, for tcp, listens on) [::]:PORT IPv6-only, as nginx's
// `listen [::]:PORT` does, and closes it at once. /proc/net/tcp6 cannot show
// this: a socket that is bound and never listens (or that connected out from
// a bound port) is absent or not LISTEN there, yet it makes the edge's bind
// fail with EADDRINUSE, and `nginx -t` does not bind, so the edge's start
// would fail, IPv4 included. Exit 0 every port bindable, 1 one is taken (the
// reason printed), 2 cannot tell (no IPv6, a bad argument).
func v6BindCheck(args []string, w io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(w, "usage: cfm realip v6-bindcheck tcp:PORT|udp:PORT ...")
		return 2
	}
	for _, a := range args {
		proto, ps, ok := strings.Cut(a, ":")
		port, err := strconv.Atoi(ps)
		if !ok || err != nil || port < 1 || port > 65535 || (proto != "tcp" && proto != "udp") {
			fmt.Fprintf(w, "bad argument %q\n", a)
			return 2
		}
		addr := net.JoinHostPort("::", ps)
		if err := v6Bind(proto, addr); err != nil {
			if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) {
				fmt.Fprintf(w, "cannot bind %s [::]:%d: %v\n", proto, port, err)
				return 2
			}
			fmt.Fprintf(w, "IPv6 %s port %d is taken: %v\n", proto, port, err)
			return 1
		}
	}
	fmt.Fprintln(w, "ok")
	return 0
}

// v6Bind: Go's tcp6 / udp6 listeners are IPv6-only (IPV6_V6ONLY=1) and set
// SO_REUSEADDR for tcp, like nginx's listen [::]:PORT, so the edge's own
// IPv4 0.0.0.0:PORT does not conflict and a test seam can swap it.
var v6Bind = func(proto, addr string) error {
	if proto == "tcp" {
		ln, err := net.Listen("tcp6", addr)
		if err != nil {
			return err
		}
		return ln.Close()
	}
	pc, err := net.ListenPacket("udp6", addr)
	if err != nil {
		return err
	}
	return pc.Close()
}
