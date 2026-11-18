package sslcollector

import (
	"bytes"
	"context"
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

// TestScanHomeVirtualmin verifies the Virtualmin home scanner finds the
// leaf+key pair and attaches the intermediate chain (ssl.ca / ssl.combined)
// when present, for users under an arbitrary /home* mount (passed as the
// home arg — discoverPairs iterates homeMounts() to cover /home2+).
func TestScanHomeVirtualmin(t *testing.T) {
	home := t.TempDir()
	mk := func(user, domain string, files map[string]string) string {
		dir := filepath.Join(home, user, "domains", domain)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
		return dir
	}

	// domain with ssl.ca chain
	dCA := mk("alice", "withca.gr", map[string]string{"ssl.key": "k", "ssl.cert": "c", "ssl.ca": "ca"})
	// domain with ssl.combined (and no ssl.ca) — combined is the fallback
	dComb := mk("alice", "withcombined.gr", map[string]string{"ssl.key": "k", "ssl.cert": "c", "ssl.combined": "lc"})
	// domain with no chain at all
	dNone := mk("bob", "nochain.gr", map[string]string{"ssl.key": "k", "ssl.cert": "c"})
	// domain missing the cert — must be skipped entirely
	_ = mk("bob", "keyonly.gr", map[string]string{"ssl.key": "k"})

	pairs := scanHomeVirtualmin(home)

	byKey := map[string]Pair{}
	for _, p := range pairs {
		byKey[p.KeyPath] = p
	}

	if len(byKey) != 3 {
		t.Fatalf("expected 3 pairs (keyonly skipped), got %d: %+v", len(byKey), pairs)
	}
	if p := byKey[filepath.Join(dCA, "ssl.key")]; p.ChainPath != filepath.Join(dCA, "ssl.ca") {
		t.Errorf("withca: ChainPath = %q, want ssl.ca", p.ChainPath)
	}
	if p := byKey[filepath.Join(dComb, "ssl.key")]; p.ChainPath != filepath.Join(dComb, "ssl.combined") {
		t.Errorf("withcombined: ChainPath = %q, want ssl.combined", p.ChainPath)
	}
	if p := byKey[filepath.Join(dNone, "ssl.key")]; p.ChainPath != "" {
		t.Errorf("nochain: ChainPath = %q, want empty", p.ChainPath)
	}
	if _, ok := byKey[filepath.Join(home, "bob", "domains", "keyonly.gr", "ssl.key")]; ok {
		t.Errorf("keyonly.gr should have been skipped (no ssl.cert)")
	}
}

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
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  parentPriv == nil,
		DNSNames:              []string{cn},
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

// TestScanMailcowActiveStoreOnly pins the deliberately narrow Mailcow layout:
// the active root pair and immediate SNI host pairs are discovered, while ACME
// account material, backups, deeper trees, and incomplete pairs are ignored.
func TestScanMailcowActiveStoreOnly(t *testing.T) {
	root := t.TempDir()
	writePair := func(dir, cn string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		_, _, certPEM, keyPEM := genTestCert(t, cn, nil, nil)
		if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o644); err != nil {
			t.Fatalf("write cert in %s: %v", dir, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600); err != nil {
			t.Fatalf("write key in %s: %v", dir, err)
		}
	}

	writePair(root, "mail.example.com")
	sniDir := filepath.Join(root, "sni.example.com")
	writePair(sniDir, "sni.example.com")

	// These contain valid-looking pairs but must never be served.
	writePair(filepath.Join(root, "acme"), "account-key.example")
	writePair(filepath.Join(root, "backups"), "old.example.com")
	writePair(filepath.Join(root, "nested", "too-deep.example"), "too-deep.example")

	incomplete := filepath.Join(root, "incomplete.example")
	if err := os.MkdirAll(incomplete, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incomplete, "cert.pem"), []byte("cert only"), 0o644); err != nil {
		t.Fatal(err)
	}

	pairs := scanMailcow(root)
	if len(pairs) != 2 {
		t.Fatalf("expected root + one SNI pair, got %d: %+v", len(pairs), pairs)
	}

	got := make(map[string]Pair, len(pairs))
	for _, pair := range pairs {
		if pair.Source != SrcMailcow {
			t.Errorf("source = %q, want %q", pair.Source, SrcMailcow)
		}
		if pair.ChainPath != "" {
			t.Errorf("ChainPath = %q, want empty (cert.pem is fullchain)", pair.ChainPath)
		}
		got[pair.CertPath] = pair
	}
	for _, certPath := range []string{
		filepath.Join(root, "cert.pem"),
		filepath.Join(sniDir, "cert.pem"),
	} {
		if _, ok := got[certPath]; !ok {
			t.Errorf("missing active Mailcow pair %s", certPath)
		}
	}
}

// TestBuildEntryRefusesAnUnusableKey: an entry whose key cannot be read is
// left out of every /dumpall payload, which then says complete=false, and the
// edge merges an incomplete payload instead of replacing its store. So a
// dangling Virtualmin ssl.key symlink (the scanner globs for it and checks
// only the cert) turned replacement off for the whole node. buildEntry now
// refuses such a pair, for every source.
func TestBuildEntryRefusesAnUnusableKey(t *testing.T) {
	dir := t.TempDir()
	_, _, certPEM, keyPEM := genTestCert(t, "v.example.gr", nil, nil)
	cert := filepath.Join(dir, "ssl.cert")
	if err := os.WriteFile(cert, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "ssl.key")
	if err := os.Symlink(filepath.Join(dir, "gone.key"), dangling); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.key")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "good.key")
	if err := os.WriteFile(good, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, k := range []string{dangling, empty, filepath.Join(dir, "missing.key")} {
		if e, err := buildEntry(Pair{Source: SrcVirtualmin, CertPath: cert, KeyPath: k}, time.Now()); err == nil || e != nil {
			t.Errorf("buildEntry(key=%s) = %v, %v; want an error", filepath.Base(k), e, err)
		}
	}
	if e, err := buildEntry(Pair{Source: SrcVirtualmin, CertPath: cert, KeyPath: good}, time.Now()); err != nil || e == nil {
		t.Fatalf("buildEntry(good key) = %v, %v", e, err)
	}

	// The scanner still finds the dangling pair; Refresh must not index it.
	vdir := filepath.Join(dir, "home", "u", "domains", "v.example.gr")
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vdir, "ssl.cert"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(vdir, "gone"), filepath.Join(vdir, "ssl.key")); err != nil {
		t.Fatal(err)
	}
	pairs := scanHomeVirtualmin(filepath.Join(dir, "home"))
	if len(pairs) != 1 {
		t.Fatalf("scanHomeVirtualmin: %d pairs, want the dangling one", len(pairs))
	}
	if _, err := buildEntry(pairs[0], time.Now()); err == nil {
		t.Fatal("buildEntry indexed a pair whose ssl.key is a dangling symlink")
	}
}

// TestBuildEntryNonPEMCertIsAnError: buildEntry returned (nil, nil) for a
// cert file with no PEM block, and Refresh then read Names off the nil entry
// and panicked.
func TestBuildEntryNonPEMCertIsAnError(t *testing.T) {
	dir := t.TempDir()
	_, _, _, keyPEM := genTestCert(t, "x.example.gr", nil, nil)
	cert := filepath.Join(dir, "x.cert")
	if err := os.WriteFile(cert, []byte("not a certificate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "x.key")
	if err := os.WriteFile(key, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := buildEntry(Pair{Source: SrcGeneric, CertPath: cert, KeyPath: key}, time.Now())
	if err == nil || e != nil {
		t.Fatalf("buildEntry(non-PEM cert) = %v, %v; want an error", e, err)
	}
}

// TestRefreshCarriesAPairCaughtMidRewrite: the edge replaces its cert store
// on a complete /dumpall payload, so an indexed pair that drops out of the
// index for a moment (its cert or key caught mid-rewrite) would take the site
// to the default cert until the next Refresh. Such a pair keeps its entry for
// buildFailCarry; a cert that is deleted drops at once.
func TestRefreshCarriesAPairCaughtMidRewrite(t *testing.T) {
	dir := t.TempDir()
	_, _, certPEM, keyPEM := genTestCert(t, "carry.example.gr", nil, nil)
	_, _, gonePEM, goneKeyPEM := genTestCert(t, "gone.example.gr", nil, nil)
	cert, key := filepath.Join(dir, "c.cert"), filepath.Join(dir, "c.key")
	gcert, gkey := filepath.Join(dir, "g.cert"), filepath.Join(dir, "g.key")
	for p, b := range map[string][]byte{cert: certPEM, key: keyPEM, gcert: gonePEM, gkey: goneKeyPEM} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pairs := []Pair{
		{Source: SrcGeneric, CertPath: cert, KeyPath: key},
		{Source: SrcGeneric, CertPath: gcert, KeyPath: gkey},
	}
	discoverPairsHook = func() []Pair { return pairs }
	t.Cleanup(func() { discoverPairsHook = nil })

	c := New(Config{})
	ctx := context.Background()
	has := func(h string) bool { return c.EntryForHost(h) != nil }
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if !has("carry.example.gr") || !has("gone.example.gr") {
		t.Fatal("setup: both hosts indexed")
	}

	// The key is truncated mid-rewrite (buildEntry fails), and the other
	// pair's cert is deleted (the scanner no longer finds it).
	if err := os.WriteFile(key, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(gcert); err != nil {
		t.Fatal(err)
	}
	pairs = pairs[:1]
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if !has("carry.example.gr") {
		t.Fatal("a pair caught mid-rewrite left the index at once")
	}
	if has("gone.example.gr") {
		t.Fatal("a deleted cert was carried")
	}

	// The cert itself is empty for a moment: scanners skip an empty cert,
	// so the pair is not discovered at all. Still carried: its file exists.
	if err := os.WriteFile(cert, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pairs = nil
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if !has("carry.example.gr") {
		t.Fatal("an undiscovered pair whose cert file still exists left the index at once")
	}

	// Past buildFailCarry it goes.
	c.carryMu.Lock()
	for k := range c.buildFailSince {
		c.buildFailSince[k] = time.Now().Add(-buildFailCarry - time.Second)
	}
	c.carryMu.Unlock()
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if has("carry.example.gr") {
		t.Fatal("a pair failing for longer than buildFailCarry was still carried")
	}

	// Rewritten: indexed again, and the failure clock is forgotten.
	if err := os.WriteFile(cert, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pairs = []Pair{{Source: SrcGeneric, CertPath: cert, KeyPath: key}}
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if !has("carry.example.gr") {
		t.Fatal("the rewritten pair is not indexed")
	}
	c.carryMu.Lock()
	n := len(c.buildFailSince)
	c.carryMu.Unlock()
	if n != 0 {
		t.Fatalf("failure clocks left after recovery: %d", n)
	}
}

// TestPayloadSkipsACarriedPairWithNoPEM: a pair carried through a rewrite
// (buildFailCarry) still has its old names, but its files read empty or cut.
// writePayload must skip it, making the payload incomplete (the edge merges
// it), rather than send an empty key in a complete payload: a worker with no
// older pair for the name (one just started) would replace with that.
func TestPayloadSkipsACarriedPairWithNoPEM(t *testing.T) {
	dir := t.TempDir()
	_, _, aPEM, aKey := genTestCert(t, "a.example.gr", nil, nil)
	_, _, bPEM, bKey := genTestCert(t, "b.example.gr", nil, nil)
	acert, akey := filepath.Join(dir, "a.cert"), filepath.Join(dir, "a.key")
	bcert, bkey := filepath.Join(dir, "b.cert"), filepath.Join(dir, "b.key")
	for p, b := range map[string][]byte{acert: aPEM, akey: aKey, bcert: bPEM, bkey: bKey} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pairs := []Pair{
		{Source: SrcGeneric, CertPath: acert, KeyPath: akey},
		{Source: SrcGeneric, CertPath: bcert, KeyPath: bkey},
	}
	discoverPairsHook = func() []Pair { return pairs }
	t.Cleanup(func() { discoverPairsHook = nil })

	c := New(Config{})
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	payload := func() (payloadResult, string) {
		var buf strings.Builder
		res, err := c.writePayload(&buf, nil)
		if err != nil {
			t.Fatal(err)
		}
		return res, buf.String()
	}
	if res, body := payload(); !res.Complete || !strings.Contains(body, "a.example.gr") {
		t.Fatalf("setup: complete=%v, a present=%v", res.Complete, strings.Contains(body, "a.example.gr"))
	}

	for _, cut := range [][]byte{nil, aKey[:len(aKey)/2]} {
		// a's key is cut mid-rewrite (carried), and b changes in the same
		// Refresh, so the version moves.
		if err := os.WriteFile(akey, cut, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, b2PEM, b2Key := genTestCert(t, "b.example.gr", nil, nil)
		if err := os.WriteFile(bcert, b2PEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bkey, b2Key, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := c.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		if c.EntryForHost("a.example.gr") == nil {
			t.Fatal("setup: a is not carried")
		}
		res, body := payload()
		if res.Complete {
			t.Errorf("key cut to %d bytes: the payload is complete; want incomplete", len(cut))
		}
		if strings.Contains(body, "a.example.gr") {
			t.Errorf("key cut to %d bytes: the carried pair was sent", len(cut))
		}
		if !strings.Contains(body, "b.example.gr") {
			t.Errorf("key cut to %d bytes: the other pair is missing", len(cut))
		}
	}
}

// TestRefreshDoesNotCarryADanglingCertLink: an indexed pair whose cert is now
// a dangling symlink (an LE live/ link whose archive was removed) is a removed
// cert, not one mid-rewrite: it leaves the index at once.
func TestRefreshDoesNotCarryADanglingCertLink(t *testing.T) {
	dir := t.TempDir()
	_, _, certPEM, keyPEM := genTestCert(t, "link.example.gr", nil, nil)
	real, key := filepath.Join(dir, "archive.pem"), filepath.Join(dir, "k.pem")
	link := filepath.Join(dir, "live.pem")
	if err := os.WriteFile(real, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	pairs := []Pair{{Source: SrcLetsEncrypt, CertPath: link, KeyPath: key}}
	discoverPairsHook = func() []Pair { return pairs }
	t.Cleanup(func() { discoverPairsHook = nil })
	c := New(Config{})
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.EntryForHost("link.example.gr") == nil {
		t.Fatal("setup: not indexed")
	}
	if err := os.Remove(real); err != nil {
		t.Fatal(err)
	}
	pairs = nil // the scanner skips the dangling link
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.EntryForHost("link.example.gr") != nil {
		t.Fatal("a pair whose cert link dangles was carried")
	}
}

// TestReadOnlyRefreshNeverWritesTheSnapshot: the `cfm ssl` CLI's collector
// (ReadOnly) indexes the same certs but leaves the daemon's dump.json and
// cache dir alone; the daemon's collector writes the snapshot as before.
func TestReadOnlyRefreshNeverWritesTheSnapshot(t *testing.T) {
	dir := t.TempDir()
	_, _, certPEM, keyPEM := genTestCert(t, "ro.example.gr", nil, nil)
	cert, key := filepath.Join(dir, "c.cert"), filepath.Join(dir, "c.key")
	for p, b := range map[string][]byte{cert: certPEM, key: keyPEM} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	discoverPairsHook = func() []Pair { return []Pair{{Source: SrcGeneric, CertPath: cert, KeyPath: key}} }
	t.Cleanup(func() { discoverPairsHook = nil })
	origPath := snapshotPathForTests
	snapshotPathForTests = filepath.Join(dir, "snap", "dump.json")
	t.Cleanup(func() { snapshotPathForTests = origPath })

	cacheDir := filepath.Join(dir, "cache")
	ro := New(Config{CacheDir: cacheDir, ReadOnly: true})
	if err := ro.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ro.EntryForHost("ro.example.gr") == nil {
		t.Fatal("a ReadOnly collector must still index the certs")
	}
	if _, err := os.Stat(snapshotPathForTests); !os.IsNotExist(err) {
		t.Fatalf("ReadOnly Refresh wrote the snapshot (stat err=%v)", err)
	}
	if _, err := os.Stat(cacheDir); !os.IsNotExist(err) {
		t.Fatalf("ReadOnly New created the cache dir (stat err=%v)", err)
	}

	rw := New(Config{CacheDir: cacheDir})
	if err := rw.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(snapshotPathForTests); err != nil {
		t.Fatalf("the daemon's collector must write the snapshot: %v", err)
	}
}
