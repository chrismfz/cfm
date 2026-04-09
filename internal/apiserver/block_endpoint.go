package apiserver

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"cfm/internal/firewall"
)

type firewallBlockRequest struct {
	IP     string `json:"ip"`
	TTL    string `json:"ttl"`
	Reason string `json:"reason"`
}

// RegisterBlock adds POST /api/v1/firewall/block.
func RegisterBlock(m *http.ServeMux, be firewall.Backend) {
	if m == nil {
		return
	}
	m.HandleFunc("/api/v1/firewall/block", makeBlockHandler(be))
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
