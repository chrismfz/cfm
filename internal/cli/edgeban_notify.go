package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"cfm/internal/clihttp"
)

// EdgeBanBaseURL, when set (main wires the daemon's API address), makes a
// successful `cfm block` of a host address tell the running daemon, which
// enforces the ban at the edge too: a client behind a trusted proxy
// (Cloudflare) never meets the nft drop, and this process cannot reach the
// daemon's edge ban store itself. Best effort: a daemon that is down or old
// costs only the edge half of the ban.
var EdgeBanBaseURL string

// notifyEdgeBan POSTs the ban to the daemon (see EdgeBanBaseURL).
func notifyEdgeBan(ip net.IP, ttl *time.Duration) {
	q := url.Values{}
	if ttl != nil && *ttl > 0 {
		q.Set("ttl", ttl.String())
	}
	postEdgeBan(ip, q, "the edge will not block it for a client behind a trusted proxy")
}

// notifyEdgeUnban tells the daemon a `cfm allow` lifted any edge ban.
func notifyEdgeUnban(ip net.IP) {
	postEdgeBan(ip, url.Values{"unban": {"1"}}, "the edge may block it for up to a minute more")
}

func postEdgeBan(ip net.IP, q url.Values, consequence string) {
	base := strings.TrimRight(strings.TrimSpace(EdgeBanBaseURL), "/")
	if base == "" || ip == nil {
		return
	}
	q.Set("ip", ip.String())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/webdet/edge-ban?"+q.Encode(), nil)
	if err != nil {
		return
	}
	resp, err := clihttp.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: daemon not told (%v): %s\n", err, consequence)
		return
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		fmt.Fprintf(os.Stderr, "warning: daemon answered %d: %s\n", resp.StatusCode, consequence)
	}
}
