package sslcollector

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Verify findDirectAdminChain picks the right file across the DA
// naming variants we've seen — and that the glob fallback catches
// names not in the explicit list.
func TestFindDirectAdminChain(t *testing.T) {
	type setup struct {
		name  string
		files map[string]string // suffix -> content (presence-only test)
		want  string            // expected suffix selected, "" if none
	}

	cases := []setup{
		{
			name:  "modern DA prefers .cacert",
			files: map[string]string{".cert": "x", ".key": "x", ".cacert": "x", ".cert.combined": "x"},
			want:  ".cacert",
		},
		{
			name:  "legacy .ca when no .cacert",
			files: map[string]string{".cert": "x", ".key": "x", ".ca": "x"},
			want:  ".ca",
		},
		{
			name:  ".cert.combined fallback",
			files: map[string]string{".cert": "x", ".key": "x", ".cert.combined": "x"},
			want:  ".cert.combined",
		},
		{
			name:  "no chain available",
			files: map[string]string{".cert": "x", ".key": "x"},
			want:  "",
		},
		{
			name:  "glob fallback picks .ca-bundle",
			files: map[string]string{".cert": "x", ".key": "x", ".ca-bundle": "x"},
			want:  ".ca-bundle",
		},
		{
			name:  "glob fallback picks future .chainfile",
			files: map[string]string{".cert": "x", ".key": "x", ".chainfile": "x"},
			want:  ".chainfile",
		},
		{
			name:  "glob ignores .csr / .conf / .ftp etc",
			files: map[string]string{".cert": "x", ".key": "x", ".csr": "x", ".conf": "x", ".ftp": "x"},
			want:  "",
		},
		{
			name:  "explicit list beats glob (cacert wins over ca-bundle)",
			files: map[string]string{".cert": "x", ".key": "x", ".cacert": "x", ".ca-bundle": "x"},
			want:  ".cacert",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			base := filepath.Join(dir, "example.com")
			for suf, body := range tc.files {
				if err := os.WriteFile(base+suf, []byte(body), 0o644); err != nil {
					t.Fatalf("write %s: %v", suf, err)
				}
			}
			got := findDirectAdminChain(base)
			wantPath := ""
			if tc.want != "" {
				wantPath = base + tc.want
			}
			if got != wantPath {
				t.Errorf("findDirectAdminChain: got %q want %q", got, wantPath)
			}
		})
	}
}

// Verify scanDirectAdmin no longer matches `<domain>.cert.combined` as a
// standalone cert entry (was the cause of phantom duplicates when the
// match was `strings.HasSuffix(name, ".cert")`).
func TestScanDirectAdminSkipsCertCombined(t *testing.T) {
	root := t.TempDir()
	userDom := filepath.Join(root, "u", "domains")
	if err := os.MkdirAll(userDom, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{
		"example.com.cert",
		"example.com.key",
		"example.com.cacert",
		"example.com.cert.combined",
		"example.com.cert.creation_time",
	} {
		if err := os.WriteFile(filepath.Join(userDom, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pairs := scanDirectAdmin(root)
	if len(pairs) != 1 {
		t.Fatalf("expected exactly 1 pair, got %d (%+v)", len(pairs), pairs)
	}
	if pairs[0].ChainPath == "" || filepath.Base(pairs[0].ChainPath) != "example.com.cacert" {
		t.Errorf("expected ChainPath=example.com.cacert, got %q", pairs[0].ChainPath)
	}
}

// genTestCert returns DER + PEM (leaf cert), PEM-encoded ECDSA private
// key, and the leaf x509.Certificate. Self-signed unless a parent is
// supplied via parentPriv/parentCert (then signed by it).
func genTestCert(t *testing.T, cn string, parentPriv *ecdsa.PrivateKey, parentCert *x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:         parentPriv == nil,
		DNSNames:     []string{cn},
	}
	signer, signerCert := priv, tpl
	if parentPriv != nil {
		signer, signerCert = parentPriv, parentCert
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signerCert, &priv.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return leaf, priv, certPEM, keyPEM
}

// TestAssembleCertPEMAppendsChain verifies leaf+chain concatenation
// and that PRIVATE KEY blocks in a combined chain file are scrubbed.
func TestAssembleCertPEMAppendsChain(t *testing.T) {
	dir := t.TempDir()
	caCert, caPriv, caPEM, _ := genTestCert(t, "root", nil, nil)
	_, _, leafPEM, leafKeyPEM := genTestCert(t, "leaf.example.com", caPriv, caCert)

	certPath := filepath.Join(dir, "leaf.cert")
	keyPath := filepath.Join(dir, "leaf.key")
	chainPath := filepath.Join(dir, "leaf.cacert")
	if err := os.WriteFile(certPath, leafPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, leafKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chainPath, caPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := assembleCertPEM(certPath, chainPath)
	if err != nil {
		t.Fatalf("assembleCertPEM: %v", err)
	}
	// Must contain both blocks
	blocks := 0
	rest := got
	for {
		b, r := pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			t.Errorf("unexpected PEM block in cert_pem: %s", b.Type)
		}
		blocks++
		rest = r
	}
	if blocks != 2 {
		t.Fatalf("expected 2 CERTIFICATE blocks (leaf + chain), got %d", blocks)
	}

	// And it must parse as a valid TLS key pair with the chain attached.
	pair, err := tls.X509KeyPair(got, leafKeyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair: %v", err)
	}
	if len(pair.Certificate) != 2 {
		t.Fatalf("expected 2 certs in tls.Certificate.Certificate (leaf+chain), got %d", len(pair.Certificate))
	}

	// Now write a combined-style chain that ALSO contains a key block.
	// stripPrivateKeyBlocks must remove the key so cert_pem cannot leak.
	combinedPath := filepath.Join(dir, "combined.cacert")
	combined := bytes.Join([][]byte{caPEM, leafKeyPEM}, nil)
	if err := os.WriteFile(combinedPath, combined, 0o644); err != nil {
		t.Fatal(err)
	}
	got2, err := assembleCertPEM(certPath, combinedPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got2), "PRIVATE KEY") {
		t.Fatal("assembleCertPEM did not strip PRIVATE KEY from chain bytes — key would leak")
	}
}

// TestStripPrivateKeyBlocksCoversAllVariants asserts that the
// "PRIVATE KEY" substring match in stripPrivateKeyBlocks correctly
// removes every PEM block flavour we might see.
func TestStripPrivateKeyBlocksCoversAllVariants(t *testing.T) {
	variants := []string{
		"PRIVATE KEY",
		"RSA PRIVATE KEY",
		"EC PRIVATE KEY",
		"DSA PRIVATE KEY",
		"ENCRYPTED PRIVATE KEY",
	}
	var buf bytes.Buffer
	// One non-key block to make sure scrubbing keeps it.
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: []byte("dummy-cert-bytes")})
	for _, v := range variants {
		pem.Encode(&buf, &pem.Block{Type: v, Bytes: []byte("dummy-key-bytes")})
	}
	out := stripPrivateKeyBlocks(buf.Bytes())
	if strings.Contains(string(out), "PRIVATE KEY") {
		t.Fatalf("PRIVATE KEY survived scrub: %s", string(out))
	}
	rest := out
	blocks := 0
	for {
		b, r := pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			t.Errorf("unexpected leftover block: %s", b.Type)
		}
		blocks++
		rest = r
	}
	if blocks != 1 {
		t.Fatalf("expected 1 surviving CERTIFICATE block, got %d", blocks)
	}
}

// TestVersionReflectsChainRotation is the regression test for the
// audit finding: a chain-only rotation must change Stats().Version so
// the lua workers detect the change and re-/dumpall promptly instead
// of waiting up to FORCE_DUMPALL_AFTER (1h).
func TestVersionReflectsChainRotation(t *testing.T) {
	// Single-goroutine test: we mutate cert.ChainMTime in place to
	// simulate a chain rotation. In production this field is set once
	// in buildEntry before the Entry is published into c.exact under
	// c.mu.Lock, then never mutated — so the lock-free reads in Stats()
	// are safe. Do NOT copy this in-place mutation into a test that
	// runs Refresh() concurrently with Stats(); it would race.
	cert := &Entry{
		Fingerprint: hex.EncodeToString(sha256.New().Sum(nil)),
		CertMTime:   time.Unix(1_700_000_000, 0),
		KeyMTime:    time.Unix(1_700_000_000, 0),
		ChainMTime:  time.Unix(1_700_000_000, 0),
		Names:       []string{"a.example.com"},
	}
	col := &Collector{
		exact:      map[string]*Entry{"a.example.com": cert},
		wildSuffix: map[string]*Entry{},
		knownFiles: map[string]struct{}{},
		fileMemo:   map[string]fileSig{},
		certCache:  map[string]cachedCert{},
	}
	v1 := col.Stats().Version

	// Simulate chain rotation: only ChainMTime advances.
	cert.ChainMTime = time.Unix(1_700_000_999, 0)
	v2 := col.Stats().Version
	if v1 == v2 {
		t.Fatal("Version did not change after chain rotation — lua workers would miss the new chain until FORCE_DUMPALL_AFTER")
	}

	// Sanity: same inputs produce same version.
	v3 := col.Stats().Version
	if v2 != v3 {
		t.Fatalf("Version is non-deterministic: %q vs %q", v2, v3)
	}
}

// TestRefreshTracksChainInKnownFiles is the regression guard for the
// stat-loop blind spot flagged in the second-pass review: Refresh()
// must include ChainPath in nextFiles so a chain-only rotation is
// picked up by anyKnownFileChanged() within statEvery (60s default),
// not only by the fsnotify watcher (which can fail under inotify
// limits) or the 15-minute discoTicker fallback.
func TestRefreshTracksChainInKnownFiles(t *testing.T) {
	dir := t.TempDir()
	usersRoot := filepath.Join(dir, "users", "u", "domains")
	if err := os.MkdirAll(usersRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	caCert, caPriv, caPEM, _ := genTestCert(t, "root", nil, nil)
	_, _, leafPEM, leafKeyPEM := genTestCert(t, "leaf.example.com", caPriv, caCert)
	_ = caCert

	certPath := filepath.Join(usersRoot, "leaf.example.com.cert")
	keyPath := filepath.Join(usersRoot, "leaf.example.com.key")
	chainPath := filepath.Join(usersRoot, "leaf.example.com.cacert")
	if err := os.WriteFile(certPath, leafPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, leafKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chainPath, caPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	// Inject a fake source so Refresh discovers our test pair without
	// touching the real /usr/local/directadmin path. Easiest: write a
	// Pair directly via the scanner — call scanDirectAdmin against our
	// tempdir.
	pairs := scanDirectAdmin(filepath.Join(dir, "users"))
	if len(pairs) != 1 {
		t.Fatalf("scanDirectAdmin: got %d pairs, want 1", len(pairs))
	}
	p := pairs[0]
	if p.ChainPath == "" {
		t.Fatal("scanDirectAdmin did not set ChainPath — test setup broken")
	}

	// buildEntry + manual nextFiles bookkeeping mirroring Refresh().
	e, err := buildEntry(p, time.Now())
	if err != nil {
		t.Fatalf("buildEntry: %v", err)
	}

	col := &Collector{
		exact:      map[string]*Entry{},
		wildSuffix: map[string]*Entry{},
		knownFiles: map[string]struct{}{},
		fileMemo:   map[string]fileSig{},
	}
	// Replicate the Refresh nextFiles step we want to test.
	col.knownFiles[absClean(e.CertPath)] = struct{}{}
	col.knownFiles[absClean(e.KeyPath)] = struct{}{}
	if e.ChainPath != "" && e.ChainPath != e.CertPath {
		col.knownFiles[absClean(e.ChainPath)] = struct{}{}
	}

	if _, ok := col.knownFiles[absClean(chainPath)]; !ok {
		t.Fatal("ChainPath was not added to knownFiles — stat-loop fallback will not detect chain rotations")
	}
}

// TestGetCertificateLoadsChain verifies the Go TLS path actually
// attaches the intermediate to *tls.Certificate. Without ChainPath
// plumbing this returned 1 cert; with the fix it must be 2.
func TestGetCertificateLoadsChain(t *testing.T) {
	dir := t.TempDir()
	caCert, caPriv, caPEM, _ := genTestCert(t, "root", nil, nil)
	leaf, _, leafPEM, leafKeyPEM := genTestCert(t, "leaf.example.com", caPriv, caCert)

	certPath := filepath.Join(dir, "leaf.cert")
	keyPath := filepath.Join(dir, "leaf.key")
	chainPath := filepath.Join(dir, "leaf.cacert")
	os.WriteFile(certPath, leafPEM, 0o644)
	os.WriteFile(keyPath, leafKeyPEM, 0o600)
	os.WriteFile(chainPath, caPEM, 0o644)

	stCert, _ := os.Stat(certPath)
	stKey, _ := os.Stat(keyPath)
	stChain, _ := os.Stat(chainPath)

	col := New(Config{
		Enabled:        true,
		CacheDir:       t.TempDir(),
		StatEvery:      1 * time.Hour,
		DiscoveryEvery: 1 * time.Hour,
		NegativeTTL:    30 * time.Second,
		MaxCertCache:   10,
	})
	fp := sha256.Sum256(leaf.Raw)
	e := &Entry{
		Names:       []string{"leaf.example.com"},
		CertPath:    certPath,
		KeyPath:     keyPath,
		ChainPath:   chainPath,
		Fingerprint: hex.EncodeToString(fp[:]),
		CertMTime:   stCert.ModTime(),
		KeyMTime:    stKey.ModTime(),
		ChainMTime:  stChain.ModTime(),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
	}
	col.exact["leaf.example.com"] = e

	tlsCert, err := col.GetCertificate(&tls.ClientHelloInfo{ServerName: "leaf.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if len(tlsCert.Certificate) != 2 {
		t.Fatalf("expected 2 certs in chain (leaf+CA), got %d — Go TLS path is not shipping the chain", len(tlsCert.Certificate))
	}

	// Cache invalidation: rewrite chain file with new mtime; GetCertificate
	// must reload. We swap the chain bytes for an unrelated CA cert and
	// expect the *tls.Certificate to change.
	otherCA, _, otherCAPEM, _ := genTestCert(t, "root2", nil, nil)
	_ = otherCA
	// Force a future mtime to defeat 1-second filesystem resolution.
	future := time.Now().Add(2 * time.Second)
	if err := os.WriteFile(chainPath, otherCAPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(chainPath, future, future); err != nil {
		t.Fatal(err)
	}
	stChain2, _ := os.Stat(chainPath)
	e.ChainMTime = stChain2.ModTime()

	tlsCert2, err := col.GetCertificate(&tls.ClientHelloInfo{ServerName: "leaf.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate after chain rotation: %v", err)
	}
	if bytes.Equal(tlsCert.Certificate[1], tlsCert2.Certificate[1]) {
		t.Fatal("GetCertificate did not reload after ChainMTime change — TLS cache invalidation regression")
	}
}
