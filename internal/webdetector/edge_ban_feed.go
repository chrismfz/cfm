package webdetector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"cfm/internal/edgeban"
)

// edgeBanFeedMax bounds the feed. The store holds the web-related and manual
// bans only (not fleet feeds or cfm.deny), a few thousand at most on a busy
// node; the edge dict (cfm_edgeban, 8m, two slots) holds ~25k.
const edgeBanFeedMax = 20000

// edgeBanFeed is the edge-ban list as the edge pulls it: every address the
// store answers banned, less IGNORE_IPS (the decision path skips those too),
// with each one's expiry in unix seconds (0 = permanent), and its generation:
// a hash of exactly that content. The same content always has the same
// generation, across daemon restarts too, so the edge can tell a current
// copy from a stale one by the generation alone.
func (b *NginxBridge) edgeBanFeed() (gen string, ips map[string]int64) {
	items := edgeban.List()
	ips = make(map[string]int64, len(items))
	h := sha256.New()
	for _, it := range items {
		if len(ips) >= edgeBanFeedMax {
			break
		}
		if b.bypassFunc != nil && b.bypassFunc(it.IP) {
			continue
		}
		var exp int64
		if !it.Expires.IsZero() {
			exp = it.Expires.Unix()
		}
		ips[it.IP] = exp
		fmt.Fprintf(h, "%s %d\n", it.IP, exp) // List is sorted: a stable hash
	}
	return hex.EncodeToString(h.Sum(nil)[:8]), ips
}

// handleEdgeBan serves GET /nginx/edgeban to cfm_edgeban.lua, which polls it
// every couple of seconds and checks proxied requests against it at the top
// of cfm.lua (before every bypass but the static one, the clearance cookie
// included) and on the static-asset location. ?gen= is the generation the
// caller holds: when it is current the reply is {"gen":G,"unchanged":true},
// else the whole list {"gen":G,"ips":{"203.0.113.5":1760000000,...}}.
func (b *NginxBridge) handleEdgeBan(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	gen, ips := b.edgeBanFeed()
	var out any
	if strings.TrimSpace(r.URL.Query().Get("gen")) == gen {
		out = map[string]any{"gen": gen, "unchanged": true}
	} else {
		out = map[string]any{"gen": gen, "ips": ips}
	}
	buf, err := json.Marshal(out)
	if err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(buf)))
	_, _ = w.Write(buf)
}
