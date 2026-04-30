// Package selfip provides a goroutine-safe resolver that reports whether
// a given IP string belongs to the local machine.
//
// It is engine-neutral: both the nft (cli) and nftlib (netlink) backends
// use it so neither depends on the other to answer self-IP questions.
package selfip

import (
	"net"
	"strings"
	"sync"
)

// Resolver reports whether an IP belongs to the local host.
// It is safe for concurrent use. The IP set is lazily populated on the
// first Contains call and can be refreshed explicitly with Refresh.
type Resolver struct {
	mu   sync.RWMutex
	ips  map[string]struct{}
	once sync.Once
}

// New returns a ready Resolver.
func New() *Resolver {
	return &Resolver{ips: make(map[string]struct{})}
}

// Contains reports whether s is a local IP address: loopback, link-local
// unicast, or bound to an active network interface.
func (r *Resolver) Contains(s string) bool {
	r.once.Do(r.Refresh)
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	r.mu.RLock()
	_, ok := r.ips[ip.String()]
	r.mu.RUnlock()
	return ok
}

// Refresh re-enumerates local network interfaces and updates the cache.
// Safe to call from any goroutine; callers serialise externally if needed.
func (r *Resolver) Refresh() {
	fresh := collectLocalIPs()
	r.mu.Lock()
	r.ips = fresh
	r.mu.Unlock()
}

// LocalIPs returns a snapshot of the current non-loopback, non-link-local
// IP strings bound to active interfaces. IPv4 addresses are in dotted-quad
// form (4-byte canonical); IPv6 in compressed form.
func (r *Resolver) LocalIPs() []string {
	r.once.Do(r.Refresh)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.ips))
	for ip := range r.ips {
		out = append(out, ip)
	}
	return out
}

// collectLocalIPs enumerates all non-loopback IPs on active interfaces.
func collectLocalIPs() map[string]struct{} {
	m := make(map[string]struct{})
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil || ip == nil || ip.IsLoopback() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				m[v4.String()] = struct{}{}
			} else {
				m[ip.String()] = struct{}{}
			}
		}
	}
	return m
}
