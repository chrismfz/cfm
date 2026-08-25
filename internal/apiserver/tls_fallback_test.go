package apiserver

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cert, err := generateSelfSignedCert(now)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("empty certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		t.Fatalf("cert not valid at generation time: [%v,%v]", leaf.NotBefore, leaf.NotAfter)
	}
	var serverAuth bool
	for _, u := range leaf.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	if !serverAuth {
		t.Fatal("missing ExtKeyUsageServerAuth")
	}
}

func TestWithSelfSignedFallback_PrimaryErrorFallsBack(t *testing.T) {
	// The two error strings that lock a fresh/by-IP client out today.
	for _, msg := range []string{"missing sni", "no cert for host"} {
		primary := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, errors.New(msg) }
		got, err := withSelfSignedFallback(primary)(&tls.ClientHelloInfo{})
		if err != nil || got == nil {
			t.Fatalf("%q: fallback must serve (cert=%v err=%v)", msg, got, err)
		}
	}
}

func TestWithSelfSignedFallback_NilPrimaryFallsBack(t *testing.T) {
	got, err := withSelfSignedFallback(nil)(&tls.ClientHelloInfo{})
	if err != nil || got == nil {
		t.Fatalf("nil primary must serve fallback (cert=%v err=%v)", got, err)
	}
}

func TestWithSelfSignedFallback_RealCertPreferred(t *testing.T) {
	real, err := generateSelfSignedCert(time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("make real: %v", err)
	}
	primary := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return real, nil }
	got, err := withSelfSignedFallback(primary)(&tls.ClientHelloInfo{ServerName: "host.example"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != real {
		t.Fatal("a real cert from the primary must be used unchanged, not the fallback")
	}
}

func TestWithSelfSignedFallback_Caches(t *testing.T) {
	primary := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, errors.New("no cert for host") }
	gc := withSelfSignedFallback(primary)
	a, _ := gc(&tls.ClientHelloInfo{})
	b, _ := gc(&tls.ClientHelloInfo{ServerName: "other"})
	if a == nil || b == nil || a != b {
		t.Fatal("fallback certificate must be generated once and cached")
	}
}

func TestSelfSignedFallback_VerifiesWithTrustedRoot(t *testing.T) {
	// A client that deliberately trusts the fallback cert (adds it to RootCAs) must
	// be able to VERIFY it — this locks in that the cert shape (IsCA + ServerAuth EKU
	// + SAN) is a valid, chain-buildable server cert, not just something Go will serve.
	cert, err := generateSelfSignedCert(time.Now())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()

	// Full verification (no InsecureSkipVerify); ServerName matches the "localhost" SAN.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", ln.Addr().String(),
		&tls.Config{RootCAs: pool, ServerName: "localhost"})
	if err != nil {
		t.Fatalf("a trusting client must verify the fallback cert: %v", err)
	}
	conn.Close()
}

func TestSelfSignedFallback_UsableInTLSHandshake(t *testing.T) {
	// End-to-end: a server whose GetCertificate always errors on the primary must
	// still complete a TLS handshake with an IP-only client (no SNI) via the fallback.
	primary := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, errors.New("missing sni") }
	srvCfg := &tls.Config{GetCertificate: withSelfSignedFallback(primary)}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()

	// No ServerName set -> mimics https://IP:6061 (no SNI). InsecureSkipVerify because
	// the fallback is self-signed and the operator would click through.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", ln.Addr().String(),
		&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed fallback, test only
	if err != nil {
		t.Fatalf("handshake with fallback must succeed for a no-SNI client: %v", err)
	}
	conn.Close()
}
