// internal/apiserver/token_store.go
//
// In-memory scoped token store for the cfm apiserver.
//
// Scoped tokens are short-lived credentials issued to panel plugins
// (cPanel, DirectAdmin, etc.) via POST /api/v1/auth/token.
// They carry a vhost allowlist and a role, enforced by the middleware.
//
// Storage is in-memory only — tokens do not survive a daemon restart.
// That is intentional: plugins re-issue tokens on each session start.
// Expired tokens are purged every 10 minutes by a background goroutine
// started by Start() in apiserver.go.

package apiserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

// ── Scoped token ─────────────────────────────────────────────────────────────

// ScopedToken is the in-memory record for an issued scoped token.
type ScopedToken struct {
	Token   string
	// Vhosts is the set of allowed vhosts (lowercase). nil = unrestricted (admin-level).
	Vhosts  map[string]struct{}
	Role    string    // "viewer" | "admin"
	Expiry  time.Time
}

// ── Token store ───────────────────────────────────────────────────────────────

// TokenStore holds all active scoped tokens.
type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*ScopedToken
}

// NewTokenStore creates an empty store.
func NewTokenStore() *TokenStore {
	return &TokenStore{tokens: make(map[string]*ScopedToken)}
}

// Issue creates and stores a new scoped token.
// vhosts is a slice of allowed hostnames; pass nil for unrestricted (admin-level scoped token).
// role should be "viewer" or "admin".
// ttl must be positive.
func (s *TokenStore) Issue(vhosts []string, role string, ttl time.Duration) *ScopedToken {
	// Generate 32 random bytes = 64 hex chars.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		// fallback: use time-based (should never happen)
		logging.Logf("[token_store] rand.Read failed: %v", err)
	}
	tok := hex.EncodeToString(raw)

	var vhostSet map[string]struct{}
	if len(vhosts) > 0 {
		vhostSet = make(map[string]struct{}, len(vhosts))
		for _, v := range vhosts {
			v = strings.ToLower(strings.TrimSpace(v))
			if v != "" {
				vhostSet[v] = struct{}{}
			}
		}
	}

	if role == "" {
		role = "viewer"
	}
	if ttl <= 0 {
		ttl = 2 * time.Hour
	}

	st := &ScopedToken{
		Token:  tok,
		Vhosts: vhostSet,
		Role:   role,
		Expiry: time.Now().Add(ttl),
	}

	s.mu.Lock()
	s.tokens[tok] = st
	s.mu.Unlock()

	logging.Logf("[token_store] issued scoped token role=%s vhosts=%d ttl=%s expires=%s",
		role, len(vhostSet), ttl, st.Expiry.Format(time.RFC3339))

	return st
}

// Lookup returns the ScopedToken for the given token string.
// Returns false if the token is unknown or expired.
func (s *TokenStore) Lookup(tok string) (*ScopedToken, bool) {
	s.mu.RLock()
	st, ok := s.tokens[tok]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(st.Expiry) {
		// Lazy delete — purger will clean it up.
		return nil, false
	}
	return st, true
}

// PurgeExpired removes all expired tokens from the store.
func (s *TokenStore) PurgeExpired() int {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, st := range s.tokens {
		if now.After(st.Expiry) {
			delete(s.tokens, k)
			n++
		}
	}
	return n
}

// StartPurger runs a background goroutine that purges expired tokens every 10 minutes.
func (s *TokenStore) StartPurger(ctx context.Context) {
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n := s.PurgeExpired(); n > 0 {
					logging.Logf("[token_store] purged %d expired scoped token(s)", n)
				}
			}
		}
	}()
}

// ── Issuance HTTP endpoint ────────────────────────────────────────────────────

type tokenIssueRequest struct {
	Vhosts []string `json:"vhosts"`          // list of allowed hostnames
	Role   string   `json:"role"`            // "viewer" | "admin"
	TTL    string   `json:"ttl"`             // e.g. "2h", "30m" — default "2h"
}

type tokenIssueResponse struct {
	Token     string    `json:"token"`
	Role      string    `json:"role"`
	Vhosts    []string  `json:"vhosts"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RegisterTokenEndpoint adds POST /api/v1/auth/token to the mux.
// The endpoint itself is protected by the middleware (admin Bearer required).
func RegisterTokenEndpoint(m *http.ServeMux, store *TokenStore) {
	m.HandleFunc("/api/v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		var req tokenIssueRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}

		// Validate role.
		if req.Role != "viewer" && req.Role != "admin" {
			req.Role = "viewer"
		}

		// Parse TTL.
		ttl := 2 * time.Hour
		if req.TTL != "" {
			if d, err := time.ParseDuration(req.TTL); err == nil && d > 0 && d <= 24*time.Hour {
				ttl = d
			} else {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"invalid ttl — use Go duration format, max 24h"}`, http.StatusBadRequest)
				return
			}
		}

		// Vhosts are required for scoped tokens.
		if len(req.Vhosts) == 0 {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"vhosts is required"}`, http.StatusBadRequest)
			return
		}

		st := store.Issue(req.Vhosts, req.Role, ttl)

		// Build vhosts list for response (normalised).
		vhostList := make([]string, 0, len(st.Vhosts))
		for v := range st.Vhosts {
			vhostList = append(vhostList, v)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenIssueResponse{
			Token:     st.Token,
			Role:      st.Role,
			Vhosts:    vhostList,
			ExpiresAt: st.Expiry,
		})
	})
}
