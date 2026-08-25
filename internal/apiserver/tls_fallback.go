package apiserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"time"

	"cfm/internal/logging"
)

// certFallback lazily generates and caches a self-signed certificate so the direct
// TLS listener (:6061) ALWAYS completes a handshake — even on a fresh system where
// the sslcollector has discovered no real certificate yet, or when a client connects
// by IP with no SNI. Without it, `sslcollector.GetCertificate` returns an error
// ("missing sni" / "no cert for host"), the TLS handshake aborts, and — because a
// healthy :6060 now redirects browser admin to :6061 and refuses plaintext login
// (audit R01/Step 5) — the operator is locked out until a real cert appears. This is
// CFM's own fallback for the direct control plane, independent of the OpenResty/Angie
// edge (a deployment may run neither). It is deliberately self-signed (the browser
// warns and the operator clicks through) and the apiserver pairs it with NO HSTS, so
// a by-IP client (`https://<ip>:6061`, the primary lockout scenario — IP literals are
// exempt from HSTS) can always click through. A by-hostname client can too, UNLESS
// that hostname was pinned with HSTS by some other path on the host. Like any
// self-signed bootstrap (SSH TOFU, an appliance's first-boot cert), the fallback
// window is trust-on-first-use and MITM-able by an active attacker — it is a
// break-glass path to reach the box and install a real certificate, not a steady
// state. A real discovered cert is always preferred and used unchanged.
type certFallback struct {
	mu   sync.Mutex
	cert *tls.Certificate
	done bool // set only once a cert is cached; a failed generation is retried
}

func (f *certFallback) get() (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.done {
		return f.cert, nil
	}
	// Cache only a SUCCESSFUL generation. The only realistic failure is a CSPRNG
	// error, which effectively never happens post-boot; not caching it means a later
	// handshake simply retries rather than being wedged into permanent abort.
	cert, err := generateSelfSignedCert(time.Now())
	if err != nil {
		logging.LogfAPI("[apiserver] self-signed fallback cert generation failed (will retry): %v", err)
		return nil, err
	}
	f.cert, f.done = cert, true
	logging.LogfAPI("[apiserver] serving self-signed fallback certificate on the TLS listener (no discovered cert or no SNI)")
	return f.cert, nil
}

// withSelfSignedFallback wraps a primary GetCertificate so that when the primary has
// nothing to offer (an error, or a nil primary), the listener still serves the cached
// self-signed fallback instead of aborting the handshake. When the primary returns a
// real certificate it is used unchanged — the fallback only ever fills a gap.
func withSelfSignedFallback(primary func(*tls.ClientHelloInfo) (*tls.Certificate, error)) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	fb := &certFallback{}
	return func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if primary != nil {
			if cert, err := primary(chi); err == nil && cert != nil {
				return cert, nil
			}
		}
		return fb.get()
	}
}

func generateSelfSignedCert(now time.Time) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "CFM control plane (self-signed fallback)"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// Self-signed root that also serves as its own leaf: IsCA lets a client that
		// deliberately trusts this cert build and verify the (single-hop) chain. The
		// residual risk of the CA bit is negligible — the key is in-memory only, never
		// persisted, and regenerated every restart, so importing it as a trusted CA is
		// pointless. Browsers ignore all of this and simply click through the warning.
		IsCA:        true,
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}
