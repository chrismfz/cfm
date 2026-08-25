package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStripCookieSecureAttr(t *testing.T) {
	cases := []struct{ in, want string }{
		{"cfm-sid=abc; Path=/; HttpOnly; Secure; SameSite=Lax", "cfm-sid=abc; Path=/; HttpOnly; SameSite=Lax"},
		{"cfm-sid=abc; Secure", "cfm-sid=abc"},
		{"cfm-sid=abc; secure", "cfm-sid=abc"}, // case-insensitive attribute
		{"cfm-sid=abc; Path=/", "cfm-sid=abc; Path=/"},
		{"cfm-sid=Secure-looking-value; Path=/; Secure", "cfm-sid=Secure-looking-value; Path=/"}, // value not stripped
	}
	for _, c := range cases {
		if got := stripCookieSecureAttr(c.in); got != c.want {
			t.Fatalf("stripCookieSecureAttr(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSessionCookieFallbackName(t *testing.T) {
	if got := sessionCookieFallbackName("cfm-sid"); got != "cfm-sid-http-fallback" {
		t.Fatalf("fallback name = %q", got)
	}
}

// setCookieHandler simulates goauth writing a Secure session cookie.
func setCookieHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", name+"=VALUE; Path=/; HttpOnly; Secure; SameSite=Lax")
		w.Header().Add("Set-Cookie", "other=x; Path=/") // an unrelated cookie must pass through
		w.WriteHeader(http.StatusOK)
	}
}

func degradedReq() *http.Request {
	// direct external :6060, no forwarded identity -> Entry "6060", Scheme "http".
	r := httptest.NewRequest(http.MethodGet, "http://host:6060/cfm-admin/", nil)
	r.RemoteAddr = "198.51.100.5:5000"
	return withLocalAddr(r, "0.0.0.0:6060")
}

func setCookies(rr *httptest.ResponseRecorder) []string { return rr.Result().Header["Set-Cookie"] }

func TestSessionCookieTransport_DegradedRewritesSetCookie(t *testing.T) {
	h := SessionCookieTransportMiddleware("cfm-sid")(setCookieHandler("cfm-sid"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, degradedReq())

	var sawFallback, sawOther bool
	for _, c := range setCookies(rr) {
		if strings.HasPrefix(c, "cfm-sid-http-fallback=VALUE") {
			sawFallback = true
			if strings.Contains(strings.ToLower(c), "secure") {
				t.Fatalf("fallback cookie must not be Secure: %q", c)
			}
		}
		if strings.HasPrefix(c, "cfm-sid=") {
			t.Fatalf("canonical Secure cookie must not be emitted over plaintext: %q", c)
		}
		if strings.HasPrefix(c, "other=") {
			sawOther = true
		}
	}
	if !sawFallback {
		t.Fatalf("degraded window must emit the non-Secure fallback cookie; got %v", setCookies(rr))
	}
	if !sawOther {
		t.Fatal("unrelated cookies must pass through untouched")
	}
}

func TestSessionCookieTransport_NonDegradedPassthrough(t *testing.T) {
	// Edge (loopback peer + forwarded https) -> Entry "edge", Scheme "https": native
	// Secure cfm-sid must stand, no rewrite.
	edge := httptest.NewRequest(http.MethodGet, "http://host/cfm-admin/", nil)
	edge.RemoteAddr = "127.0.0.1:41000"
	edge.Header.Set("X-Real-IP", "203.0.113.9")
	edge.Header.Set("X-Forwarded-Proto", "https")
	edge = withLocalAddr(edge, "0.0.0.0:6060")

	h := SessionCookieTransportMiddleware("cfm-sid")(setCookieHandler("cfm-sid"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, edge)

	var sawSecureCanonical bool
	for _, c := range setCookies(rr) {
		if strings.HasPrefix(c, "cfm-sid=VALUE") && strings.Contains(c, "Secure") {
			sawSecureCanonical = true
		}
		if strings.Contains(c, "http-fallback") {
			t.Fatalf("non-degraded path must not translate to the fallback cookie: %q", c)
		}
	}
	if !sawSecureCanonical {
		t.Fatalf("edge must keep the native Secure cfm-sid; got %v", setCookies(rr))
	}
}

func TestSessionCookieTransport_RenamesRequestCookie(t *testing.T) {
	// A degraded request carrying the fallback cookie must be seen downstream under
	// the canonical name so goauth reads the shared session.
	var seen string
	h := SessionCookieTransportMiddleware("cfm-sid")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("cfm-sid"); err == nil {
			seen = c.Value
		}
		w.WriteHeader(http.StatusOK)
	}))
	r := degradedReq()
	r.Header.Set("Cookie", "cfm-sid-http-fallback=SESSVAL; other=y")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if seen != "SESSVAL" {
		t.Fatalf("downstream saw cfm-sid=%q, want SESSVAL (renamed from fallback)", seen)
	}
}

func TestSessionCookieTransport_DropsInjectedCanonicalCookie(t *testing.T) {
	// Both a forged canonical cookie and the real fallback present: the injected
	// canonical must be dropped and the fallback must win (no session shadowing).
	var seen string
	h := SessionCookieTransportMiddleware("cfm-sid")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("cfm-sid"); err == nil {
			seen = c.Value
		}
		w.WriteHeader(http.StatusOK)
	}))
	r := degradedReq()
	r.Header.Set("Cookie", "cfm-sid=INJECTED; cfm-sid-http-fallback=REALSESSION")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if seen != "REALSESSION" {
		t.Fatalf("downstream saw cfm-sid=%q, want REALSESSION (injected canonical dropped, fallback wins)", seen)
	}
}

func TestSessionCookieTransport_RewritesOnNoWrite(t *testing.T) {
	// A handler that sets Set-Cookie but never writes a response (mimics SCS's
	// post-handler commit path) must still have the cookie rewritten to the fallback.
	h := SessionCookieTransportMiddleware("cfm-sid")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "cfm-sid=VALUE; Path=/; HttpOnly; Secure; SameSite=Lax")
		// deliberately no WriteHeader / Write
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, degradedReq())
	var sawFallback bool
	for _, c := range setCookies(rr) {
		if strings.HasPrefix(c, "cfm-sid-http-fallback=VALUE") {
			sawFallback = true
		}
		if strings.HasPrefix(c, "cfm-sid=") {
			t.Fatalf("no-write commit path must still be rewritten: %q", c)
		}
	}
	if !sawFallback {
		t.Fatalf("no-write path must rewrite to the fallback; got %v", setCookies(rr))
	}
}

func TestSessionCookieTransport_SpoofedXFPStaysDegraded(t *testing.T) {
	// A direct :6060 external client spoofing X-Forwarded-Proto: https must NOT be
	// treated as https (XFP is trusted only from a loopback edge peer), so the
	// translation still applies and no Secure cookie is emitted over plaintext.
	r := httptest.NewRequest(http.MethodGet, "http://host:6060/cfm-admin/", nil)
	r.RemoteAddr = "198.51.100.5:5000"
	r.Header.Set("X-Forwarded-Proto", "https") // spoofed
	r = withLocalAddr(r, "0.0.0.0:6060")

	h := SessionCookieTransportMiddleware("cfm-sid")(setCookieHandler("cfm-sid"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	for _, c := range setCookies(rr) {
		if strings.HasPrefix(c, "cfm-sid=") {
			t.Fatalf("spoofed XFP must not yield a Secure canonical cookie over plaintext: %q", c)
		}
	}
}
