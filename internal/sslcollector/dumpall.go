package sslcollector

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// assembleCertPEM reads CertPath and, when ChainPath is set and points
// to a different file, appends the chain bytes (with any PRIVATE KEY
// block scrubbed first) so the result is a leaf+chain PEM blob suitable
// for either ngx.ssl.parse_pem_cert (lua workers) or tls.X509KeyPair
// (Go TLS path in Collector.GetCertificate).
//
// A failure to read the chain file is non-fatal: the leaf bytes are
// returned and the caller continues with leaf-only behaviour. Only a
// failure to read CertPath itself is propagated as an error, because
// without the leaf there is nothing to serve.
func assembleCertPEM(certPath, chainPath string) ([]byte, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	if chainPath == "" || chainPath == certPath {
		return certPEM, nil
	}
	chainPEM, cerr := os.ReadFile(chainPath)
	if cerr != nil || len(chainPEM) == 0 {
		return certPEM, nil
	}
	scrubbed := stripPrivateKeyBlocks(chainPEM)
	if len(scrubbed) == 0 {
		return certPEM, nil
	}
	if len(certPEM) > 0 && certPEM[len(certPEM)-1] != '\n' {
		certPEM = append(certPEM, '\n')
	}
	certPEM = append(certPEM, scrubbed...)
	return certPEM, nil
}

// stripPrivateKeyBlocks returns pemData with any PEM block whose Type
// contains "PRIVATE KEY" removed. Used to defensively scrub chain files
// that some panels (eg older DA "<domain>.combined") write as
// key+leaf+chain bundles — we never want a private key inside the
// cert_pem field shipped to workers or persisted to disk snapshots.
func stripPrivateKeyBlocks(pemData []byte) []byte {
	rest := pemData
	var out bytes.Buffer
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if strings.Contains(blk.Type, "PRIVATE KEY") {
			continue
		}
		_ = pem.Encode(&out, blk)
	}
	if out.Len() == 0 {
		return nil
	}
	return out.Bytes()
}

// dumpAllPayload is the JSON envelope returned by /dumpall AND written
// to disk by WriteSnapshot. Keeping a single source of truth for the
// payload shape ensures the on-disk snapshot is byte-for-byte equivalent
// to what the OpenResty/Angie worker would fetch over the socket, so
// load_from_snapshot() and ingest_dumpall(...,"snapshot") behave the
// same as the live path.
type dumpAllPayload struct {
	Version     string    `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Exact       []any     `json:"exact"`
	Wild        []any     `json:"wild"`
}

// BuildDumpAllPayload serializes the collector's current cert index in the
// shape consumed by configs/lua/sslcollector.lua. Returns (jsonBody,
// exactCount, wildCount, error). PEM bytes are read once per unique
// fingerprint to avoid duplicate disk I/O when one (cert,key) covers many
// hostnames.
func (c *Collector) BuildDumpAllPayload() ([]byte, int, int, error) {
	st := c.Stats()

	c.mu.RLock()
	exact := make(map[string]*Entry, len(c.exact))
	for k, v := range c.exact {
		exact[k] = v
	}
	wild := make(map[string]*Entry, len(c.wildSuffix))
	for k, v := range c.wildSuffix {
		wild[k] = v
	}
	c.mu.RUnlock()

	exactKeys := make([]string, 0, len(exact))
	for k := range exact {
		exactKeys = append(exactKeys, k)
	}
	sort.Strings(exactKeys)

	wildKeys := make([]string, 0, len(wild))
	for k := range wild {
		wildKeys = append(wildKeys, k)
	}
	sort.Strings(wildKeys)

	type pemPair struct{ cert, key string }
	pemByFP := map[string]pemPair{}
	getPEM := func(e *Entry) (string, string, bool) {
		if e == nil {
			return "", "", false
		}
		if pp, ok := pemByFP[e.Fingerprint]; ok {
			return pp.cert, pp.key, true
		}
		// assembleCertPEM reads CertPath and, when present, appends the
		// scrubbed ChainPath bytes so DA-style leaf-only certs reach
		// workers with their intermediate chain. LE (fullchain.pem) and
		// cPanel (apache_tls/<dir>/certificates) already embed the chain
		// in CertPath, so this is a no-op for them.
		certPEM, err := assembleCertPEM(e.CertPath, e.ChainPath)
		if err != nil {
			return "", "", false
		}
		keyPEM, err := os.ReadFile(e.KeyPath)
		if err != nil {
			return "", "", false
		}
		cert, key := string(certPEM), string(keyPEM)
		pemByFP[e.Fingerprint] = pemPair{cert: cert, key: key}
		return cert, key, true
	}

	out := dumpAllPayload{
		Version:     st.Version,
		GeneratedAt: st.GeneratedAt,
		Exact:       make([]any, 0, len(exactKeys)),
		Wild:        make([]any, 0, len(wildKeys)),
	}

	for _, host := range exactKeys {
		e := exact[host]
		certPEM, keyPEM, ok := getPEM(e)
		if !ok {
			continue
		}
		out.Exact = append(out.Exact, map[string]any{
			"host":        host,
			"fingerprint": e.Fingerprint,
			"not_after":   e.NotAfter.Format(time.RFC3339),
			"cert_pem":    certPEM,
			"key_pem":     keyPEM,
		})
	}
	for _, suf := range wildKeys {
		e := wild[suf]
		certPEM, keyPEM, ok := getPEM(e)
		if !ok {
			continue
		}
		out.Wild = append(out.Wild, map[string]any{
			"suffix":      suf,
			"fingerprint": e.Fingerprint,
			"not_after":   e.NotAfter.Format(time.RFC3339),
			"cert_pem":    certPEM,
			"key_pem":     keyPEM,
		})
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(out); err != nil {
		return nil, 0, 0, fmt.Errorf("encode dumpall: %w", err)
	}
	return buf.Bytes(), len(out.Exact), len(out.Wild), nil
}
