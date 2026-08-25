package apiserver

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
)

// RequestPeer is the canonical identity of one control-plane request. Forwarded
// identity and scheme are trusted only across the explicit loopback edge hop.
type RequestPeer struct {
	ImmediateIP  net.IP
	ClientIP     net.IP
	TrustedProxy bool
	Scheme       string
	// Entry is a SEMANTIC listener tag, not a literal port: "edge" (forwarded over
	// the loopback edge hop), "6060" (the primary plaintext HTTP listener),
	// "6061" (the TLS listener), or "other". The "6060"/"6061" tags track the
	// CONFIGURED PORT/TLS_PORT (see setListenerPorts), so classification stays
	// correct when an operator runs the control plane on non-default ports.
	Entry string
}

// configuredHTTPPort / configuredTLSPort hold the control plane's actual listener
// ports so requestListenerEntry classifies a request by the listener it truly
// arrived on rather than hardcoded 6060/6061 (audit Step 5 follow-up: otherwise a
// non-default PORT made every request "other" and silently disabled
// AdminTransportRedirect). Zero means "unset" → the historical 6060/6061 defaults.
var (
	configuredHTTPPort atomic.Int32
	configuredTLSPort  atomic.Int32
)

// setListenerPorts records the configured control-plane ports. Called once from
// Start() before the listeners begin serving, so the store happens-before every
// per-request read.
func setListenerPorts(httpPort, tlsPort int) {
	configuredHTTPPort.Store(int32(httpPort))
	configuredTLSPort.Store(int32(tlsPort))
}

func httpListenerPort() int {
	if p := configuredHTTPPort.Load(); p > 0 {
		return int(p)
	}
	return 6060
}

func tlsListenerPort() int {
	if p := configuredTLSPort.Load(); p > 0 {
		return int(p)
	}
	return 6061
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
			peer.Entry = "edge"
		}
	}
	if peer.Entry != "edge" {
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
	p, err := strconv.Atoi(port)
	if err != nil {
		return "other"
	}
	// Map the ACTUAL listener port to its semantic tag. TLS is checked first only
	// as a deterministic tiebreak for the historical default (6060 HTTP / 6061 TLS)
	// and the unset fallback below; a genuine PORT==TLS_PORT collision is decided by
	// which http.Server wins the bind (the loser fails and stays down, see Start()),
	// not by this ordering.
	switch p {
	case tlsListenerPort():
		return "6061"
	case httpListenerPort():
		return "6060"
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
