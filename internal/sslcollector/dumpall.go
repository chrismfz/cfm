package sslcollector

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
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

// dumpAllAfterStatsHook runs between writePayload's version read and its
// copy of the index. Tests only (a Refresh landing in that window).
var dumpAllAfterStatsHook func()

// payloadResult is what writePayload wrote.
type payloadResult struct {
	ExactN, WildN int
	// Complete: every name in the index made it into the payload. An entry
	// whose PEM could not be read is skipped (getPEM); such a payload is
	// still written and served, but never taken as current — the snapshot
	// is rewritten until a whole one is made.
	Complete bool
}

// payloadCountWidth is the room reserved for exact_n / wild_n in the header.
const payloadCountWidth = 10

// writePayload writes the collector's cert index as the /dumpall payload —
// the shape configs/lua/sslcollector.lua ingests, and the on-disk snapshot —
// to w, entry by entry. at is w's underlying file (offset 0 = the first
// byte written): the counts and `complete` sit in the header, ahead of the
// entries, so readSnapshotHeader can take them off the front of a ~110 MB
// file; they are written as padded placeholders and filled in through at
// once the entries are out.
//
// The payload used to be built whole in memory (a map per entry, a buffer
// for the JSON and the encoder's own copy of it): about four times its size
// in heap, so ~450 MB per build on a 7 800-host node, and the daemon reached
// 1.2 GB during an AutoSSL run (earth, 2026-10-11). Now the heap holds the
// index copy, one PEM pair per fingerprint, and a write buffer.
//
// The header is {"version","generated_at","exact_n","wild_n","complete",
// "exact":[...],"wild":[...]}; whitespace pads the placeholders and follows
// each entry, which every JSON reader skips. The entries are written by hand
// (writeJSONString), with no per-entry allocation.
func (c *Collector) writePayload(w io.Writer, at io.WriterAt) (payloadResult, error) {
	var res payloadResult
	st := c.Stats()
	if dumpAllAfterStatsHook != nil {
		dumpAllAfterStatsHook()
	}

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

	// PEM bytes are read once per fingerprint: one (cert,key) commonly
	// covers several names (domain, www., mail., …).
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

	ver, err := json.Marshal(st.Version)
	if err != nil {
		return res, fmt.Errorf("encode dumpall: %w", err)
	}
	gen, err := json.Marshal(st.GeneratedAt)
	if err != nil {
		return res, fmt.Errorf("encode dumpall: %w", err)
	}
	countSlot := fmt.Sprintf("%-*d", payloadCountWidth, 0)
	var head strings.Builder
	head.WriteString(`{"version":`)
	head.Write(ver)
	head.WriteString(`,"generated_at":`)
	head.Write(gen)
	head.WriteString(`,"exact_n":`)
	exactAt := head.Len()
	head.WriteString(countSlot)
	head.WriteString(`,"wild_n":`)
	wildAt := head.Len()
	head.WriteString(countSlot)
	head.WriteString(`,"complete":`)
	completeAt := head.Len()
	head.WriteString(`false`)
	head.WriteString(`,"exact":[`)

	// Errors are sticky in a bufio.Writer: the Flush below reports one.
	bw := bufio.NewWriterSize(w, 256<<10)
	var date []byte
	entry := func(nameKey, name string, e *Entry, certPEM, keyPEM string) {
		// Keys in the order the earlier map encoding had them (sorted).
		bw.WriteString(`{"cert_pem":`)
		writeJSONString(bw, certPEM)
		bw.WriteString(`,"fingerprint":`)
		writeJSONString(bw, e.Fingerprint)
		if nameKey == "host" {
			bw.WriteString(`,"host":`)
			writeJSONString(bw, name)
		}
		bw.WriteString(`,"key_pem":`)
		writeJSONString(bw, keyPEM)
		bw.WriteString(`,"not_after":"`)
		date = e.NotAfter.AppendFormat(date[:0], time.RFC3339)
		bw.Write(date)
		bw.WriteByte('"')
		if nameKey == "suffix" {
			bw.WriteString(`,"suffix":`)
			writeJSONString(bw, name)
		}
		bw.WriteString("}\n")
	}
	bw.WriteString(head.String())
	for _, host := range exactKeys {
		e := exact[host]
		certPEM, keyPEM, ok := getPEM(e)
		if !ok {
			continue
		}
		if res.ExactN > 0 {
			bw.WriteByte(',')
		}
		entry("host", host, e, certPEM, keyPEM)
		res.ExactN++
	}
	bw.WriteString(`],"wild":[`)
	for _, suf := range wildKeys {
		e := wild[suf]
		certPEM, keyPEM, ok := getPEM(e)
		if !ok {
			continue
		}
		if res.WildN > 0 {
			bw.WriteByte(',')
		}
		entry("suffix", suf, e, certPEM, keyPEM)
		res.WildN++
	}
	bw.WriteString("]}\n")
	if err := bw.Flush(); err != nil {
		return res, err
	}

	// The version was read before the maps were copied, and Refresh is not
	// serialised: a swap in between labels this content with a version it
	// does not have. Such a payload is not complete — a snapshot trusted as
	// current at that label would never be rewritten (an unchanged version
	// is skipped).
	res.Complete = res.ExactN == len(exactKeys) && res.WildN == len(wildKeys) &&
		c.Stats().Version == st.Version
	patches := []struct {
		off int
		b   string
	}{
		{exactAt, fmt.Sprintf("%-*d", payloadCountWidth, res.ExactN)},
		{wildAt, fmt.Sprintf("%-*d", payloadCountWidth, res.WildN)},
	}
	if res.Complete {
		patches = append(patches, struct {
			off int
			b   string
		}{completeAt, "true "})
	}
	for _, p := range patches {
		if _, err := at.WriteAt([]byte(p.b), int64(p.off)); err != nil {
			return res, fmt.Errorf("dumpall header: %w", err)
		}
	}
	return res, nil
}

// writeJSONString writes s as a JSON string. encoding/json allocates a
// buffer per value (pooled, but the pool is not reliable: under the race
// detector it drops them), and the payload repeats each certificate's PEM
// for every name it covers. Invalid UTF-8 becomes U+FFFD, as encoding/json
// does; unlike it, <, > and & are not escaped (no HTML is involved).
func writeJSONString(w *bufio.Writer, s string) {
	if !utf8.ValidString(s) {
		// One U+FFFD per invalid byte, as encoding/json writes it.
		var b strings.Builder
		for i := 0; i < len(s); {
			r, n := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && n == 1 {
				b.WriteRune(utf8.RuneError)
			} else {
				b.WriteString(s[i : i+n])
			}
			i += n
		}
		s = b.String()
	}
	const hex = "0123456789abcdef"
	w.WriteByte('"')
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		w.WriteString(s[start:i])
		switch c {
		case '"':
			w.WriteString(`\"`)
		case '\\':
			w.WriteString(`\\`)
		case '\n':
			w.WriteString(`\n`)
		case '\r':
			w.WriteString(`\r`)
		case '\t':
			w.WriteString(`\t`)
		default:
			w.WriteString(`\u00`)
			w.WriteByte(hex[c>>4])
			w.WriteByte(hex[c&0xf])
		}
		start = i + 1
	}
	w.WriteString(s[start:])
	w.WriteByte('"')
}

// dumpAllBuildFile writes the payload to an unlinked temp file and returns
// it positioned at the start, for /dumpall when no current snapshot can be
// written (the regression guard holds the older one, the index is empty, the
// write failed). One build at a time: the workers are staggered, and the
// temp file keeps the payload out of the heap.
func (c *Collector) dumpAllBuildFile() (*os.File, int64, error) {
	c.buildMu.Lock()
	defer c.buildMu.Unlock()
	dir := filepath.Dir(snapshotPath())
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return nil, 0, err
	}
	// On disk next to the snapshot, not in /tmp (a tmpfs is RAM).
	f, err := os.CreateTemp(dir, ".dumpall-*")
	if err != nil {
		return nil, 0, err
	}
	_ = os.Remove(f.Name())
	if _, err := c.writePayload(f, f); err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	size, err := f.Seek(0, io.SeekCurrent)
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, size, nil
}
