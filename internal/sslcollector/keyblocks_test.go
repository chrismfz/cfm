package sslcollector

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// keyDERs returns the DER bytes of every PRIVATE KEY block, in order.
func keyDERs(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var out [][]byte
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return out
		}
		if strings.Contains(blk.Type, "PRIVATE KEY") {
			out = append(out, blk.Bytes)
		}
	}
}

func bundle(blocks ...[]byte) []byte { return bytes.Join(blocks, nil) }

// rigel, 2026-11-23: key files written as bundles (cPanel combined, DA
// .combined, Virtualmin ssl.combined) went out whole as key_pem: every chain
// twice. Only the key blocks go now, the same key bytes, in the same order.
func TestPrivateKeyBlocksOnly(t *testing.T) {
	key := fakePEM("RSA PRIVATE KEY", 48)
	leaf, inter, root := fakePEM("CERTIFICATE", 40), fakePEM("CERTIFICATE", 41), fakePEM("CERTIFICATE", 42)
	cases := []struct {
		name string
		in   []byte
		keys int
	}{
		{"key then chain (cPanel combined)", bundle(key, leaf, inter, root), 1},
		{"chain then key", bundle(leaf, inter, key), 1},
		{"key only", key, 1},
		{"every key flavour", bundle(fakePEM("PRIVATE KEY", 8), leaf, fakePEM("EC PRIVATE KEY", 9), fakePEM("ENCRYPTED PRIVATE KEY", 10)), 3},
	}
	for _, c := range cases {
		out := privateKeyBlocksOnly(c.in)
		if strings.Contains(string(out), "CERTIFICATE") {
			t.Errorf("%s: a certificate survived: %s", c.name, out)
		}
		want, got := keyDERs(t, c.in), keyDERs(t, out)
		if len(got) != c.keys || len(want) != c.keys {
			t.Fatalf("%s: want %d key blocks, in=%d out=%d", c.name, c.keys, len(want), len(got))
		}
		for i := range want {
			if !bytes.Equal(want[i], got[i]) {
				t.Errorf("%s: key block %d changed", c.name, i)
			}
		}
	}
	// No key block at all: sent as it is (never less parseable than the file).
	noKey := bundle(leaf, []byte("trailing junk\n"))
	if got := privateKeyBlocksOnly(noKey); !bytes.Equal(got, noKey) {
		t.Errorf("a file with no key block was changed: %q", got)
	}
}

// Both ways out of the daemon carry only the key: /dumpall (and the snapshot
// it streams) and /cert.
func TestKeyPEMCarriesOnlyTheKey(t *testing.T) {
	col, path := newSnapshotCollector(t)
	_ = os.Remove(path)
	key := fakePEM("RSA PRIVATE KEY", 48)
	combined := bundle(key, fakePEM("CERTIFICATE", 40), fakePEM("CERTIFICATE", 41))
	if err := os.WriteFile(col.exact["a.example.com"].KeyPath, combined, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &sockServer{col: col, cfg: SockServerConfig{Token: strongToken}, pem: map[string]pemCacheItem{}}

	var payload struct {
		Exact []struct {
			KeyPEM string `json:"key_pem"`
		} `json:"exact"`
	}
	if err := json.Unmarshal([]byte(dumpAllBody(t, s)), &payload); err != nil || len(payload.Exact) == 0 {
		t.Fatalf("decode /dumpall: %v (%d entries)", err, len(payload.Exact))
	}
	for _, e := range payload.Exact {
		if strings.Contains(e.KeyPEM, "CERTIFICATE") {
			t.Errorf("/dumpall key_pem still carries the chain: %s", e.KeyPEM)
		}
		if got := keyDERs(t, []byte(e.KeyPEM)); len(got) != 1 || !bytes.Equal(got[0], keyDERs(t, key)[0]) {
			t.Errorf("/dumpall key_pem lost or changed the key")
		}
	}

	for i := 0; i < 2; i++ { // a miss, then a cache hit
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/cert?host=a.example.com", nil)
		req.Header.Set("X-SSLCollector-Token", strongToken)
		s.handleCert(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("/cert status %d: %s", rr.Code, rr.Body.String())
		}
		var c struct {
			KeyPEM string `json:"key_pem"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(c.KeyPEM, "CERTIFICATE") || len(keyDERs(t, []byte(c.KeyPEM))) != 1 {
			t.Errorf("/cert (call %d) key_pem is not the key alone: %s", i+1, c.KeyPEM)
		}
	}
}
