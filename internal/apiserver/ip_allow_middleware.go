package apiserver

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"cfm/internal/allowlist"
	cfgpkg "cfm/internal/config"
	core "cfm/internal/detectors/core"
	"cfm/internal/logging"
)

var ipAllowLookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// IPAllowMiddleware enforces source IP allowlisting for the API server.
//
// Trust model for client IP extraction mirrors request logging helpers:
// if the direct peer is loopback, the first X-Forwarded-For hop is treated
// as the effective client IP.
func IPAllowMiddleware(cfg *cfgpkg.Config, cfgDir string) func(http.Handler) http.Handler {
	apiURL := ""
	if cfg != nil {
		apiURL = cfg.API.URL
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP, ok := effectiveClientIP(r)
			if !ok {
				rejectIP(w, r, "invalid_client_ip", realIPFromRequest(r))
				return
			}

			if allowImmediate(clientIP) {
				next.ServeHTTP(w, r)
				return
			}

			snapshot := loadAllowedSources(r.Context(), cfgDir, apiURL)
			if ipAllowed(clientIP, snapshot.ExactIPs, snapshot.CIDRNets) {
				next.ServeHTTP(w, r)
				return
			}

			rejectIP(w, r, "source_ip_not_allowlisted", clientIP.String())
		})
	}
}

func rejectIP(w http.ResponseWriter, r *http.Request, reason, srcIP string) {
	setAPIAnomalyReason(w, reason)
	logging.LogfAPI("[apiserver] event=api_audit method=%s path=%q src_ip=%s reason=%s status=%d",
		r.Method, r.URL.Path, srcIP, reason, http.StatusForbidden)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(mustJSON(map[string]string{"error": "forbidden: source IP not allowed"}))
}

func effectiveClientIP(r *http.Request) (net.IP, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	direct := net.ParseIP(host)
	if direct == nil {
		return nil, false
	}
	if direct.IsLoopback() {
		if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if parsed := net.ParseIP(first); parsed != nil {
				return parsed, true
			}
		}
	}
	return direct, true
}

func allowImmediate(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	return core.IsSelfIP(ip.String())
}

func ipAllowed(ip net.IP, ipSet map[string]struct{}, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		if _, ok := ipSet[v4.String()]; ok {
			return true
		}
	} else if _, ok := ipSet[ip.String()]; ok {
		return true
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func loadAllowedSources(ctx context.Context, cfgDir, apiURL string) allowlist.Snapshot {
	opts := allowlist.SnapshotOptions{
		ResolverTimeout: 2 * time.Second,
		LookupHost:      ipAllowLookupIP,
	}
	if cfgDir != "" {
		opts.Sources = append(opts.Sources,
			allowlist.SnapshotSource{Path: filepath.Join(cfgDir, "cfm.allow"), ResolveHostnames: true},
			allowlist.SnapshotSource{Path: filepath.Join(cfgDir, "cfm.dyndns"), ResolveHostnames: true},
		)
	}
	if host := apiURLHost(apiURL); host != "" {
		opts.ExtraTokens = append(opts.ExtraTokens, host)
	}
	snapshot, err := allowlist.BuildSnapshot(ctx, opts)
	if err != nil {
		logging.LogfAPI("[apiserver] allowlist snapshot load failed: %v", err)
		return allowlist.Snapshot{ExactIPs: map[string]struct{}{}}
	}
	return snapshot
}

func apiURLHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			return strings.TrimSpace(u.Hostname())
		}
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return strings.TrimSpace(h)
	}
	return raw
}
