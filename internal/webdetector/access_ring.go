package webdetector

import (
	"strings"
	"sync"
)

// AccessEntry is one edge access-log line, kept in a small in-memory ring so an
// operator (or the edge_access_tail MCP tool) can pull the last few requests a
// source IP / vhost made — the raw context around a WAF hit, for false-positive
// triage. It carries only what the access log already exposes (method, URI,
// status, UA, referer, timing) — never request bodies (those can hold secrets).
type AccessEntry struct {
	TS     float64 `json:"ts"`
	IP     string  `json:"ip"`
	Host   string  `json:"host"`
	Method string  `json:"method"`
	URI    string  `json:"uri"`
	Status int     `json:"status"`
	Bytes  int64   `json:"bytes"`
	RTms   int64   `json:"rt_ms"`
	UA     string  `json:"ua,omitempty"`
	Ref    string  `json:"ref,omitempty"`
}

// Bounds. The ring is fixed-size (memory is bounded regardless of traffic) and
// per-field lengths are capped at store time, so one pathological URI/UA can't
// bloat the buffer. Output is separately capped by the handler.
const (
	accessRingCap  = 4096 // entries retained (~a few MB with the caps below)
	accessMaxURI   = 512
	accessMaxUA    = 256
	accessMaxRef   = 256
	accessMaxHost  = 128
	accessDefLimit = 50  // default rows returned
	accessMaxLimit = 500 // hard ceiling on rows returned
)

// accessRing is a fixed-capacity ring of AccessEntry, newest appended last.
type accessRing struct {
	mu  sync.RWMutex
	buf []AccessEntry
	idx int // next write position
	n   int // entries currently held (<= cap)
	cap int
}

func newAccessRing(capacity int) *accessRing {
	if capacity <= 0 {
		capacity = accessRingCap
	}
	return &accessRing{buf: make([]AccessEntry, capacity), cap: capacity}
}

func (r *accessRing) add(e AccessEntry) {
	r.mu.Lock()
	r.buf[r.idx] = e
	r.idx = (r.idx + 1) % r.cap
	if r.n < r.cap {
		r.n++
	}
	r.mu.Unlock()
}

// AccessFilter narrows a query. Zero-value fields match everything.
type AccessFilter struct {
	IP          string
	Host        string
	Method      string
	Status      int    // exact status (0 = any); ignored when StatusClass > 0
	StatusClass int    // 1..5 → match status/100 (0 = any)
	PathSub     string // case-insensitive substring of URI
	Since       float64 // unix seconds; entries older are skipped (0 = any)
	Limit       int
}

func (f AccessFilter) match(e AccessEntry) bool {
	if f.IP != "" && e.IP != f.IP {
		return false
	}
	if f.Host != "" && e.Host != strings.ToLower(f.Host) {
		return false
	}
	if f.Method != "" && e.Method != strings.ToLower(f.Method) {
		return false
	}
	if f.StatusClass > 0 {
		if e.Status/100 != f.StatusClass {
			return false
		}
	} else if f.Status > 0 && e.Status != f.Status {
		return false
	}
	if f.PathSub != "" && !strings.Contains(e.URI, strings.ToLower(f.PathSub)) {
		return false
	}
	if f.Since > 0 && e.TS < f.Since {
		return false
	}
	return true
}

// recent returns matching entries oldest→newest, capped to the filter Limit
// (defaulted/ceilinged to [accessDefLimit, accessMaxLimit]). It walks newest→
// oldest so the cap keeps the MOST RECENT matches, then reverses for return.
func (r *accessRing) recent(f AccessFilter) []AccessEntry {
	limit := f.Limit
	if limit <= 0 {
		limit = accessDefLimit
	}
	if limit > accessMaxLimit {
		limit = accessMaxLimit
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]AccessEntry, 0, limit)
	// newest is at (idx-1); walk backwards n times.
	for i := 0; i < r.n; i++ {
		pos := (r.idx - 1 - i + r.cap*2) % r.cap
		e := r.buf[pos]
		if !f.match(e) {
			continue
		}
		out = append(out, e)
		if len(out) >= limit {
			break
		}
	}
	// reverse to oldest→newest
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// RecentAccess returns recent access entries matching f (oldest→newest). Safe
// on a nil engine/ring (returns nil).
func (e *Engine) RecentAccess(f AccessFilter) []AccessEntry {
	if e == nil || e.accessRing == nil {
		return nil
	}
	return e.accessRing.recent(f)
}

// newAccessEntry builds a bounded AccessEntry from a parsed LogRec: fields are
// truncated to their caps and the URI/referer query strings are redacted of
// obvious secret-bearing parameters.
func newAccessEntry(rec LogRec) AccessEntry {
	return AccessEntry{
		TS:     rec.TS,
		IP:     rec.IP,
		Host:   truncate(rec.Host, accessMaxHost),
		Method: rec.Method,
		URI:    truncate(redactQuery(rec.URI), accessMaxURI),
		Status: rec.Status,
		Bytes:  rec.Bytes,
		RTms:   int64(rec.RT * 1000),
		UA:     truncate(rec.UA, accessMaxUA),
		Ref:    truncate(redactQuery(rec.Ref), accessMaxRef),
	}
}

// secretParamHints are query-string keys whose values we blank out before
// retaining a URI, so a token/password that leaked into a URL is never surfaced
// by the tool. Substring match (lowercased URIs), so "api_key"/"sessionid"/… hit.
var secretParamHints = []string{"token", "secret", "passwd", "password", "pwd", "apikey", "api_key", "auth", "sig", "signature", "sessid", "sessionid", "session"}

// redactQuery replaces the value of any secret-hinted query parameter with
// "[redacted]", leaving path and other params intact. Operates on the already-
// lowercased access URI.
func redactQuery(uri string) string {
	q := strings.IndexByte(uri, '?')
	if q < 0 || q == len(uri)-1 {
		return uri
	}
	path, query := uri[:q+1], uri[q+1:]
	parts := strings.Split(query, "&")
	for i, p := range parts {
		eq := strings.IndexByte(p, '=')
		if eq <= 0 {
			continue
		}
		key := p[:eq]
		for _, hint := range secretParamHints {
			if strings.Contains(key, hint) {
				parts[i] = key + "=[redacted]"
				break
			}
		}
	}
	return path + strings.Join(parts, "&")
}
