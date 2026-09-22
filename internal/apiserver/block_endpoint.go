package apiserver

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"cfm/internal/firewall"
	"cfm/internal/firewall/selfip"
	"cfm/internal/logging"
)

type firewallBlockRequest struct {
	IP     string `json:"ip"`
	TTL    string `json:"ttl"`
	Reason string `json:"reason"`
}

type firewallBlockBatchRequest struct {
	IPs    []string `json:"ips"`
	TTL    string   `json:"ttl"`
	Reason string   `json:"reason"`
}

// blockBatchMaxIPs caps one batch request. The web UI chunks larger
// selections; the cap bounds worst-case work per request.
const blockBatchMaxIPs = 256

// selfIPChecker is the slice of selfip.Resolver the batch guard needs,
// injected so tests can stub the local-IP set.
type selfIPChecker interface {
	Contains(string) bool
	Refresh()
}

// blockBatchSelfIPs answers "is this one of the server's own IPs?" for the
// batch guard. The firewall backends keep their own (unexported) resolvers,
// so the endpoint owns one too rather than plumbing theirs out.
var blockBatchSelfIPs selfIPChecker = selfip.New()

// RegisterBlock adds POST /api/v1/firewall/block and its bulk sibling
// POST /api/v1/firewall/block/batch.
//
// Manual global IP block is admin-only: it blocks an IP across the whole host
// and is meaningless to a per-vhost scoped (cPanel/DA) token, so it must never
// be reachable with one. Guard it like the other global routes (MySQL,
// detectors, system status) rather than relying on the UI to hide it.
func RegisterBlock(m *http.ServeMux, be firewall.Backend) {
	if m == nil {
		return
	}
	m.Handle("/api/v1/firewall/block", adminOnlyHandler(makeBlockHandler(be)))
	m.Handle("/api/v1/firewall/block/batch", adminOnlyHandler(makeBlockBatchHandler(be, blockBatchSelfIPs)))
}

func makeBlockHandler(be firewall.Backend) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
			return
		}
		if be == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "no firewall backend"})
			return
		}

		var req firewallBlockRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid json"})
			return
		}

		ip := net.ParseIP(strings.TrimSpace(req.IP))
		if ip == nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid or missing ip"})
			return
		}

		var ttlPtr *time.Duration
		if strings.TrimSpace(req.TTL) != "" {
			ttl, err := time.ParseDuration(strings.TrimSpace(req.TTL))
			if err != nil || ttl <= 0 {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid ttl"})
				return
			}
			ttlPtr = &ttl
		}

		if err := be.AddBlock(ip, req.Reason, ttlPtr); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":     true,
			"ip":     ip.String(),
			"ttl":    strings.TrimSpace(req.TTL),
			"reason": strings.TrimSpace(req.Reason),
		})
	}
}

// makeBlockBatchHandler blocks a list of IPs in one request (the web UI's
// "Block selected"). Empty TTL = permanent, as on the single endpoint. Unlike
// the client-side loop it replaces, it guards against self-lockout — an IP is
// skipped (never failed-hard, the rest of the batch proceeds) when it is one
// of the server's own IPs or the calling admin's own IP.
//
// The IPs that pass the guards are blocked with ONE AddBlockBatch call: a few
// nft processes for the whole request, not up to three per IP. It only adds or
// extends a block: an IP already blocked permanently, or for longer, keeps
// that block (the single endpoint's AddBlock replaces it); the response's
// added/extended/kept counts say which. The write is a single transaction for
// a request this size, so on failure every one of those IPs is reported failed
// — the UI keeps them selected for retry, and retrying is harmless since the
// call never shortens a block. The error itself is reported once, at the top.
func makeBlockBatchHandler(be firewall.Backend, selfIPs selfIPChecker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
			return
		}
		if be == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "no firewall backend"})
			return
		}

		var req firewallBlockBatchRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid json"})
			return
		}
		if len(req.IPs) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "no ips"})
			return
		}
		if len(req.IPs) > blockBatchMaxIPs {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": false, "error": "too many ips", "max": blockBatchMaxIPs,
			})
			return
		}

		var ttlPtr *time.Duration
		if strings.TrimSpace(req.TTL) != "" {
			ttl, err := time.ParseDuration(strings.TrimSpace(req.TTL))
			if err != nil || ttl <= 0 {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid ttl"})
				return
			}
			ttlPtr = &ttl
		}

		// The calling admin's IP, canonicalised. realIPFromRequest trusts
		// X-Forwarded-For only when RemoteAddr is loopback (the daemon behind
		// the edge proxy); XFF can carry a hop list, keep the first entry.
		caller := ""
		if raw := realIPFromRequest(r); raw != "" {
			first := strings.TrimSpace(strings.SplitN(raw, ",", 2)[0])
			if ip := net.ParseIP(first); ip != nil {
				caller = ip.String()
			}
		}

		// Interfaces change rarely and batches are operator-triggered, so a
		// refresh per request is cheap and keeps the self-IP set current.
		if selfIPs != nil {
			selfIPs.Refresh()
		}

		entry := func(ip net.IP) firewall.BlockEntry {
			if ttlPtr == nil {
				return firewall.BlockEntry{IP: ip, Permanent: true}
			}
			return firewall.BlockEntry{IP: ip, TTL: *ttlPtr}
		}
		var res firewall.BlockBatchResult
		batchErr := ""
		pending := make([]string, 0, len(req.IPs))
		entries := make([]firewall.BlockEntry, 0, len(req.IPs))
		blocked := make([]string, 0, len(req.IPs))
		skipped := make([]map[string]string, 0)
		failed := make([]map[string]string, 0)
		seen := make(map[string]struct{}, len(req.IPs))
		for _, raw := range req.IPs {
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip == nil {
				skipped = append(skipped, map[string]string{"ip": raw, "reason": "invalid"})
				continue
			}
			canon := ip.String()
			if ip.IsUnspecified() {
				skipped = append(skipped, map[string]string{"ip": canon, "reason": "unspecified"})
				continue
			}
			if _, dup := seen[canon]; dup {
				skipped = append(skipped, map[string]string{"ip": canon, "reason": "duplicate"})
				continue
			}
			seen[canon] = struct{}{}
			if selfIPs != nil && selfIPs.Contains(canon) {
				skipped = append(skipped, map[string]string{"ip": canon, "reason": "self_ip"})
				continue
			}
			if caller != "" && canon == caller {
				skipped = append(skipped, map[string]string{"ip": canon, "reason": "caller_ip"})
				continue
			}
			pending = append(pending, canon)
			entries = append(entries, entry(ip))
		}
		if len(entries) > 0 {
			r, err := be.AddBlockBatch(entries)
			res = r
			if err != nil {
				batchErr = err.Error()
				for _, canon := range pending {
					failed = append(failed, map[string]string{"ip": canon, "error": "batch failed"})
				}
			} else {
				blocked = pending
			}
		}

		logging.LogfAPI("[block.batch] requester=%s n=%d blocked=%d (added=%d extended=%d kept=%d) skipped=%d failed=%d ttl=%q reason=%q err=%q",
			caller, len(req.IPs), len(blocked), res.Added, res.Extended, res.Kept, len(skipped), len(failed),
			strings.TrimSpace(req.TTL), strings.TrimSpace(req.Reason), batchErr)
		for _, s := range skipped {
			if s["reason"] == "self_ip" || s["reason"] == "caller_ip" {
				logging.LogfAPI("[block.batch.skip] ip=%s reason=%s requester=%s", s["ip"], s["reason"], caller)
			}
		}

		out := map[string]any{
			"ok":       len(failed) == 0,
			"blocked":  blocked,
			"added":    res.Added,
			"extended": res.Extended,
			"kept":     res.Kept,
			"skipped":  skipped,
			"failed":   failed,
			"ttl":      strings.TrimSpace(req.TTL),
			"reason":   strings.TrimSpace(req.Reason),
		}
		if batchErr != "" {
			out["error"] = batchErr
		}
		_ = json.NewEncoder(w).Encode(out)
	}
}
