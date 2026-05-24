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
		certPEM, err := os.ReadFile(e.CertPath)
		if err != nil {
			return "", "", false
		}
		keyPEM, err := os.ReadFile(e.KeyPath)
		if err != nil {
			return "", "", false
		}
		// Append the chain (intermediate certificates) when the source
		// provided one and it isn't the same file we already loaded as
		// the leaf. ngx.ssl.parse_pem_cert accepts a single PEM blob
		// containing leaf + intermediates, so concatenating is enough —
		// no Lua changes required.
		//
		// DA's <domain>.cert is leaf-only; the intermediate lives in
		// <domain>.cacert. Without this append the worker hands the
		// browser a leaf with no path to the trusted root and SSL
		// checkers report "not trusted / install intermediate". LE
		// (fullchain.pem) and cPanel (apache_tls/<dir>/certificates)
		// already embed the chain in CertPath, so this is a no-op for
		// them.
		if e.ChainPath != "" && e.ChainPath != e.CertPath {
			if chainPEM, cerr := os.ReadFile(e.ChainPath); cerr == nil && len(chainPEM) > 0 {
				// Defensive: combined-style files can contain the
				// private key. Strip any PRIVATE KEY blocks before
				// concatenating so key material never leaks into
				// cert_pem.
				if scrubbed := stripPrivateKeyBlocks(chainPEM); len(scrubbed) > 0 {
					if len(certPEM) > 0 && certPEM[len(certPEM)-1] != '\n' {
						certPEM = append(certPEM, '\n')
					}
					certPEM = append(certPEM, scrubbed...)
				}
			}
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
