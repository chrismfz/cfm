package apiserver

import (
	"net"
	"net/http"
	"strings"
)

// RequestPeer is the canonical identity of one control-plane request. Forwarded
// identity and scheme are trusted only across the explicit loopback edge hop.
type RequestPeer struct {
	ImmediateIP  net.IP
	ClientIP     net.IP
	TrustedProxy bool
	Scheme       string
	Entry        string
}

func requestPeer(r *http.Request) RequestPeer {
	peer := RequestPeer{Scheme: "http", Entry: "other"}
	if r == nil {
		return peer
	}
	if r.TLS != nil {
		peer.Scheme = "https"
	}

	peer.ImmediateIP = remoteIP(r.RemoteAddr)
	peer.ClientIP = peer.ImmediateIP
	if peer.ImmediateIP != nil && peer.ImmediateIP.IsLoopback() {
		if forwarded := trustedForwardedClientIP(r); forwarded != nil {
			peer.ClientIP = forwarded
			peer.TrustedProxy = true
			peer.Entry = "edge"
			if scheme := canonicalForwardedScheme(r.Header.Get("X-Forwarded-Proto")); scheme != "" {
				peer.Scheme = scheme
			}
		} else if hasForwardedClientIdentity(r) {
			// A proxy-marked request with an ambiguous/malformed client address
			// must fail closed rather than inheriting loopback's trust.
			peer.ClientIP = nil
		}
	}
	if !peer.TrustedProxy {
		peer.Entry = requestListenerEntry(r)
	}
	return peer
}

func hasForwardedClientIdentity(r *http.Request) bool {
	if r == nil {
		return false
	}
	return strings.TrimSpace(r.Header.Get("X-Real-IP")) != "" ||
		strings.TrimSpace(r.Header.Get("X-Forwarded-For")) != ""
}

func remoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.Trim(strings.TrimSpace(remoteAddr), "[]")
	}
	return net.ParseIP(host)
}

func trustedForwardedClientIP(r *http.Request) net.IP {
	if r == nil {
		return nil
	}
	if raw := strings.TrimSpace(r.Header.Get("X-Real-IP")); raw != "" {
		if strings.Contains(raw, ",") {
			return nil
		}
		return net.ParseIP(raw)
	}
	raw := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if raw == "" || strings.Contains(raw, ",") {
		return nil
	}
	return net.ParseIP(raw)
}

func canonicalForwardedScheme(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if strings.Contains(raw, ",") {
		return ""
	}
	switch raw {
	case "http", "https":
		return raw
	default:
		return ""
	}
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

func realIPFromRequest(r *http.Request) string {
	if ip := requestPeer(r).ClientIP; ip != nil {
		return ip.String()
	}
	return ""
}
