package apiserver

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

type requestIdentityAddr string

func (a requestIdentityAddr) Network() string { return "tcp" }
func (a requestIdentityAddr) String() string  { return string(a) }

func withLocalAddr(r *http.Request, addr string) *http.Request {
	ctx := context.WithValue(r.Context(), http.LocalAddrContextKey, net.Addr(requestIdentityAddr(addr)))
	return r.WithContext(ctx)
}

func TestRequestPeerEntryTopologies(t *testing.T) {
	edge := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/system/status", nil)
	edge.RemoteAddr = "127.0.0.1:41000"
	edge.Header.Set("X-Real-IP", "203.0.113.10")
	edge.Header.Set("X-Forwarded-For", "8.8.8.8, 203.0.113.10")
	edge.Header.Set("X-Forwarded-Proto", "https")
	got := requestPeer(edge)
	if got.ClientIP.String() != "203.0.113.10" || got.ImmediateIP.String() != "127.0.0.1" || got.Entry != "edge" || got.Scheme != "https" {
		t.Fatalf("edge identity = %+v", got)
	}

	directHTTP := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/system/status", nil)
	directHTTP.RemoteAddr = "198.51.100.20:42000"
	directHTTP.Header.Set("X-Real-IP", "8.8.8.8")
	directHTTP.Header.Set("X-Forwarded-Proto", "https")
	directHTTP = withLocalAddr(directHTTP, "0.0.0.0:6060")
	got = requestPeer(directHTTP)
	if got.ClientIP.String() != "198.51.100.20" || got.Entry != "6060" || got.Scheme != "http" || got.TrustedProxy {
		t.Fatalf("direct 6060 identity = %+v", got)
	}

	directTLS := httptest.NewRequest(http.MethodGet, "https://localhost/api/v1/system/status", nil)
	directTLS.RemoteAddr = "198.51.100.21:43000"
	directTLS.Header.Set("X-Forwarded-Proto", "http")
	directTLS = withLocalAddr(directTLS, "0.0.0.0:6061")
	got = requestPeer(directTLS)
	if got.ClientIP.String() != "198.51.100.21" || got.Entry != "6061" || got.Scheme != "https" || got.TrustedProxy {
		t.Fatalf("direct 6061 identity = %+v", got)
	}
}

func TestRequestPeerRejectsNonCanonicalForwardedChainWithoutRealIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	r.RemoteAddr = "127.0.0.1:41000"
	r.Header.Set("X-Forwarded-For", "8.8.8.8, 203.0.113.10")
	got := requestPeer(r)
	if got.TrustedProxy || got.ClientIP != nil {
		t.Fatalf("ambiguous XFF must not become client identity: %+v", got)
	}
}
