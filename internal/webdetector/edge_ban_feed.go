package webdetector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/edgeban"
	"cfm/internal/logging"
)

// edgeBanFeedMax bounds the feed. The store holds the web-related and manual
// bans only (not fleet feeds or cfm.deny), a few thousand at most on a busy
// node; the edge dict (cfm_edgeban, 8m, two slots) holds ~25k.
const edgeBanFeedMax = 20000

// edgeBanFeedCacheMax bounds how long a built feed is reused without a
// version change (IGNORE_IPS can change under it on a config reload).
const edgeBanFeedCacheMax = 30 * time.Second

// edgeBanFeedCache is the last feed built: the edge polls every couple of
// seconds per node, and most polls find nothing changed.
type edgeBanFeedCache struct {
	mu      sync.Mutex
	version uint64
	until   time.Time // the earliest expiry in it, or edgeBanFeedCacheMax
	gen     string
	ips     map[string]int64
	logged  time.Time // last truncation warning
}

// edgeBanFeed is the edge-ban list as the edge pulls it: every address the
// store answers banned, less IGNORE_IPS (the decision path skips those too),
// with each one's expiry in unix seconds (0 = permanent), and its generation:
// a hash of exactly that content. The same content always has the same
// generation, across daemon restarts too, so the edge can tell a current
// copy from a stale one by the generation alone. Rebuilt when the store's
// version changes, an entry in it expires, or after edgeBanFeedCacheMax.
func (b *NginxBridge) edgeBanFeed() (gen string, ips map[string]int64) {
	c := &b.edgeBanCache
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	ver := edgeban.Version()
	if c.gen != "" && c.version == ver && now.Before(c.until) {
		return c.gen, c.ips
	}
	items := edgeban.List()
	ips = make(map[string]int64, len(items))
	until := now.Add(edgeBanFeedCacheMax)
	h := sha256.New()
	truncated := 0
	for _, it := range items {
		if b.bypassFunc != nil && b.bypassFunc(it.IP) {
			continue
		}
		if len(ips) >= edgeBanFeedMax {
			truncated++
			continue
		}
		var exp int64
		if !it.Expires.IsZero() {
			exp = it.Expires.Unix()
			if it.Expires.Before(until) {
				until = it.Expires
			}
		}
		ips[it.IP] = exp
		fmt.Fprintf(h, "%s %d\n", it.IP, exp) // List is sorted: a stable hash
	}
	if truncated > 0 && now.Sub(c.logged) > 10*time.Minute {
		c.logged = now
		logging.Logf("[edgeban] feed holds %d bans, the edge copy takes %d: %d left out (the highest addresses)", len(ips)+truncated, edgeBanFeedMax, truncated)
	}
	c.version, c.until, c.gen, c.ips = ver, until, hex.EncodeToString(h.Sum(nil)[:8]), ips
	return c.gen, c.ips
}

// handleEdgeBan serves GET /nginx/edgeban to cfm_edgeban.lua, which polls it
// every couple of seconds and checks proxied requests against it at the top
// of cfm.lua (before every bypass but the static one, the clearance cookie
// included) and on the static-asset location. ?gen= is the generation the
// caller holds: when it is current the reply is {"gen":G,"unchanged":true},
// else the whole list {"gen":G,"ips":{"203.0.113.5":1760000000,...}};
// {"ready":false} while the store has not reconciled.
func (b *NginxBridge) handleEdgeBan(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var out any
	// A store that has not reconciled yet (a daemon start, nft unreadable)
	// knows nothing either way: the edge keeps the copy it has, which fades
	// within its entry TTL. EDGE_BAN = 0 is an answer: an empty list.
	if s := edgeban.Default(); edgeban.Enabled() && (s == nil || !s.Ready()) {
		writeEdgeBanJSON(w, map[string]any{"ready": false})
		return
	}
	gen, ips := b.edgeBanFeed()
	if strings.TrimSpace(r.URL.Query().Get("gen")) == gen {
		out = map[string]any{"gen": gen, "unchanged": true}
	} else {
		out = map[string]any{"gen": gen, "ips": ips}
	}
	writeEdgeBanJSON(w, out)
}

func writeEdgeBanJSON(w http.ResponseWriter, out any) {
	buf, err := json.Marshal(out)
	if err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(buf)))
	_, _ = w.Write(buf)
}
