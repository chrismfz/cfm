// internal/webdetector/nginx_bridge_purge.go
//
// Force-unblock support for the OpenResty/Lua WAF planes.
//
// A blocklist/firewall unblock does NOT touch the WAF enforcement state that
// lives in the OpenResty layer: the Go-side per-IP challenge/block map, and the
// per-IP entries in the `cfm_decisions` shared dict (throttle token buckets,
// decision cache, geo cache, solved-ok touch, waf-push cooldown). A user can
// therefore stay stuck behind a challenge/throttle while every blocklist search
// for their IP comes back empty.
//
// ForceUnblock clears both: ClearIP() drops the Go-side challenge/block state,
// and purgeShared() calls the local nginx /cfm-admin/purge-ip endpoint (served
// by cfm_purge.lua) to delete the per-IP shared-dict keys. It also reports what
// it found, which doubles as the "was this IP actually being enforced, and
// why" signal surfaced in the unblock report / Slack notification.
package webdetector

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cfm/internal/dnat"
	"cfm/internal/unblock"
)

// nginxAdminHTTPPort returns the port the local nginx (angie/openresty) serves
// the /cfm-admin/* endpoints on. This is the web DNAT target, so we resolve it
// through the same canonical helper the rest of the codebase uses
// (CHALLENGE_HTTP_LISTEN takes precedence over the legacy HTTP_PORT, default
// 9080) instead of reading HTTP_PORT directly — otherwise purge would POST to
// the wrong port on deployments that set a custom challenge listener.
func nginxAdminHTTPPort() int {
	if httpPort, _ := dnat.EffectiveTargetPorts(); httpPort > 0 && httpPort < 65536 {
		return httpPort
	}
	return 9080
}

// ForceUnblock clears every per-IP WAF plane for ip and reports what it cleared.
// It satisfies unblock.WAFCleaner. Best-effort and never panics.
func (b *NginxBridge) ForceUnblock(ip string) unblock.WAFResult {
	if b == nil || !b.cfg.Enabled {
		return unblock.WAFResult{}
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return unblock.WAFResult{Err: "empty ip"}
	}

	var res unblock.WAFResult

	// 1) Snapshot the active Go-side verdict BEFORE clearing — this is the
	//    "why" (e.g. challenge because 403waf_flood). GetIPDecision returns
	//    "" when nothing is active or it has expired.
	if action, reason := b.GetIPDecision(ip); action != "" && action != "logonly" {
		res.Cleared = append(res.Cleared, unblock.WAFFinding{Plane: action, Detail: reason})
	}

	// 2) Drop the Go-side challenge/block state and notify the bridge socket.
	//    (The shared-dict ok-touch gate is cleared by purgeShared below. The
	//    in-memory okState bypass is only cleared by ClearIP when OkIPTTL==0;
	//    leaving it is harmless — it suppresses re-challenging, it never
	//    blocks.)
	b.ClearIP(ip)

	// 3) Purge the per-IP shared-dict caches inside nginx.
	purged, err := b.purgeShared(ip)
	res.Cleared = append(res.Cleared, purged...)
	if err != nil {
		res.Err = err.Error()
	}

	res.Found = len(res.Cleared) > 0
	return res
}

// purgeSharedResponse mirrors the JSON returned by cfm_purge.lua.
type purgeSharedResponse struct {
	IP      string         `json:"ip"`
	Deleted map[string]int `json:"deleted"`
	Scanned int            `json:"scanned"`
	Error   string         `json:"error,omitempty"`
}

// purgeShared calls the local nginx /cfm-admin/purge-ip endpoint, which deletes
// the per-IP keys from the cfm_decisions shared dict and returns per-plane
// counts. Authenticated with the same bridge token nginx already trusts.
func (b *NginxBridge) purgeShared(ip string) ([]unblock.WAFFinding, error) {
	endpoint := fmt.Sprintf("http://127.0.0.1:%d/cfm-admin/purge-ip?ip=%s",
		nginxAdminHTTPPort(), url.QueryEscape(ip))

	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("purge build request: %w", err)
	}
	if b.cfg.Token != "" {
		req.Header.Set("X-CFM-Token", b.cfg.Token)
	}

	// Dedicated short-timeout TCP client; b.client dials the unix socket and
	// must not be reused for the nginx admin port.
	hc := &http.Client{Timeout: 3 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("purge unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("purge http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var pr purgeSharedResponse
	if err := json.Unmarshal(body, &pr); err != nil {
		return nil, fmt.Errorf("purge decode: %w", err)
	}
	if pr.Error != "" {
		return nil, fmt.Errorf("purge: %s", pr.Error)
	}

	// Map non-zero per-plane counts to findings. The plane names mirror the
	// shared-dict key namespaces in configs/lua/cfm_purge.lua.
	findings := make([]unblock.WAFFinding, 0, len(pr.Deleted))
	for _, plane := range []string{"throttle", "decision_cache", "geo", "ok_touch", "wafpush", "panel"} {
		if n := pr.Deleted[plane]; n > 0 {
			detail := fmt.Sprintf("%d key", n)
			if n != 1 {
				detail += "s"
			}
			findings = append(findings, unblock.WAFFinding{Plane: plane, Detail: detail})
		}
	}
	return findings, nil
}
