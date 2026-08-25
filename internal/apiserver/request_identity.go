package apiserver

import (
	"net"
	"net/http"

	"cfm/internal/reqident"
)

// RequestPeer is the canonical identity of one control-plane request. Forwarded
// identity and scheme are trusted only across the explicit loopback edge hop.
// The trust rules live in the shared internal/reqident package (also consumed by
// the challenge server); RequestPeer adds the apiserver-specific Entry
// classification (which listener the request arrived on) on top.
type RequestPeer struct {
	ImmediateIP  net.IP
	ClientIP     net.IP
	TrustedProxy bool
	Scheme       string
	Entry        string
}

func requestPeer(r *http.Request) RequestPeer {
	p := reqident.FromRequest(r)
	peer := RequestPeer{
		ImmediateIP:  p.ImmediateIP,
		ClientIP:     p.ClientIP,
		TrustedProxy: p.TrustedProxy,
		Scheme:       p.Scheme,
		Entry:        "other",
	}
	if r == nil {
		return peer
	}
	// Entry is "edge" when a loopback hop presented forwarded identity — whether
	// it resolved to a canonical client IP (TrustedProxy) or failed closed on an
	// ambiguous/malformed one. Otherwise the request arrived directly on a known
	// listener port (6060/6061) or somewhere unrecognized ("other").
	if p.ImmediateIP != nil && p.ImmediateIP.IsLoopback() && (p.TrustedProxy || reqident.HasForwardedClientIdentity(r)) {
		peer.Entry = "edge"
	} else {
		peer.Entry = requestListenerEntry(r)
	}
	return peer
}

func requestListenerEntry(r *http.Request) string {
	if r == nil {
		return "other"
	}
	addr, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if addr == nil {
		return "other"
	}
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "other"
	}
	switch port {
	case "6060", "6061":
		return port
	default:
		return "other"
	}
}

// realIPFromRequest returns one validated client IP string, never arbitrary
// forwarded text. Thin wrapper over the shared identity rule.
func realIPFromRequest(r *http.Request) string {
	return reqident.ClientIPString(r)
}
