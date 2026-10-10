package cli

import (
	"context"
	"net"
	"net/http"
	"net/url"
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
	base := strings.TrimRight(strings.TrimSpace(EdgeBanBaseURL), "/")
	if base == "" || ip == nil {
		return
	}
	q := url.Values{"ip": {ip.String()}}
	if ttl != nil && *ttl > 0 {
		q.Set("ttl", ttl.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/webdet/edge-ban?"+q.Encode(), nil)
	if err != nil {
		return
	}
	if resp, err := clihttp.Do(req); err == nil {
		resp.Body.Close()
	}
}
