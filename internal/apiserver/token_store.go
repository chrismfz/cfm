// internal/apiserver/token_store.go
//
// Scoped token store for the cfm apiserver.
//
// Tokens are issued to panel plugins (cPanel, DirectAdmin, etc.) via
// POST /api/v1/auth/token. They carry a vhost allowlist and a role,
// enforced by the middleware via CtxScopeKey{} in vhost_filter.go.
//
// Tokens survive daemon restarts via tokens.json (cfgDir).
// The admin AUTH_TOKEN from cfm.conf is NEVER stored here — it is
// validated directly in the middleware and does not appear in the list.
//
// Expired tokens are purged every 10 minutes by StartPurger().
package apiserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
	webdet "cfm/internal/webdetector"
)

// ── Scoped token ─────────────────────────────────────────────────────────────

// ScopedToken is the in-memory record for an issued scoped token.
type ScopedToken struct {
	ID        string              // stable identifier, e.g. "tok_a1b2c3d4e5f6"
	Token     string              // the secret value sent in Authorization: Bearer
	Label     string              // human-readable name, e.g. "cpanel-user-foo"
	Vhosts    map[string]struct{} // allowed vhosts (lowercase); nil = unrestricted
	Role      string              // "viewer" | "admin"
	CreatedAt time.Time
	Expiry    time.Time
}

// ── Token store ───────────────────────────────────────────────────────────────

// TokenStore holds all active scoped tokens.
type TokenStore struct {
	mu       sync.RWMutex
	tokens   map[string]*ScopedToken // keyed by token value
	byID     map[string]*ScopedToken // keyed by ID
	savePath string                  // "" = no persistence
}

// NewTokenStore creates an empty store.
func NewTokenStore() *TokenStore {
	return &TokenStore{
		tokens: make(map[string]*ScopedToken),
		byID:   make(map[string]*ScopedToken),
	}
}

func newTokenID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "tok_" + hex.EncodeToString(b)
}

// Issue creates and stores a new scoped token.
// vhosts: list of allowed hostnames; nil/empty = unrestricted.
// role:   "viewer" | "admin" (defaults to "viewer").
// label:  human-readable name for display in token list.
// ttl:    must be positive; max 8760h (1 year).
func (s *TokenStore) Issue(vhosts []string, role, label string, ttl time.Duration) *ScopedToken {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
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
		ID:        newTokenID(),
		Token:     tok,
		Label:     label,
		Vhosts:    vhostSet,
		Role:      role,
		CreatedAt: time.Now().UTC(),
		Expiry:    time.Now().Add(ttl),
	}

	s.mu.Lock()
	s.tokens[tok] = st
	s.byID[st.ID] = st
	s.mu.Unlock()

	logging.Logf("[token_store] issued id=%s label=%q role=%s vhosts=%d ttl=%s expires=%s",
		st.ID, label, role, len(vhostSet), ttl, st.Expiry.Format(time.RFC3339))

	_ = s.save()
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
		return nil, false
	}
	return st, true
}

// Revoke removes a token by ID. Returns false if not found.
func (s *TokenStore) Revoke(id string) bool {
	s.mu.Lock()
	st, ok := s.byID[id]
	if ok {
		delete(s.tokens, st.Token)
		delete(s.byID, id)
	}
	s.mu.Unlock()
	if ok {
		logging.Logf("[token_store] revoked id=%s label=%q", id, st.Label)
		_ = s.save()
	}
	return ok
}

// TokenInfo is the safe (no token value) view returned by List.
type TokenInfo struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Vhosts    []string  `json:"vhosts"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Expired   bool      `json:"expired,omitempty"`
}

// List returns a safe view of all tokens, newest first.
// Expired tokens are included (flagged) — purger removes them separately.
func (s *TokenStore) List() []TokenInfo {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]TokenInfo, 0, len(s.byID))
	for _, st := range s.byID {
		vhosts := make([]string, 0, len(st.Vhosts))
		for v := range st.Vhosts {
			vhosts = append(vhosts, v)
		}
		sort.Strings(vhosts)
		out = append(out, TokenInfo{
			ID:        st.ID,
			Label:     st.Label,
			Vhosts:    vhosts,
			Role:      st.Role,
			CreatedAt: st.CreatedAt,
			ExpiresAt: st.Expiry,
			Expired:   now.After(st.Expiry),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

// PurgeExpired removes all expired tokens from the store.
func (s *TokenStore) PurgeExpired() int {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, st := range s.tokens {
		if now.After(st.Expiry) {
			delete(s.byID, st.ID)
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
					logging.Logf("[token_store] purged %d expired token(s)", n)
					_ = s.save()
				}
			}
		}
	}()
}

// ── Persistence ───────────────────────────────────────────────────────────────

type persistedToken struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	Label     string    `json:"label"`
	Vhosts    []string  `json:"vhosts"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	Expiry    time.Time `json:"expiry"`
}

// save writes all non-expired tokens to disk atomically.
// Called without holding the lock — acquires read lock internally.
func (s *TokenStore) save() error {
	s.mu.RLock()
	path := s.savePath
	if path == "" {
		s.mu.RUnlock()
		return nil
	}
	now := time.Now()
	var rows []persistedToken
	for _, st := range s.byID {
		if now.After(st.Expiry) {
			continue
		}
		vhosts := make([]string, 0, len(st.Vhosts))
		for v := range st.Vhosts {
			vhosts = append(vhosts, v)
		}
		sort.Strings(vhosts)
		rows = append(rows, persistedToken{
			ID:        st.ID,
			Token:     st.Token,
			Label:     st.Label,
			Vhosts:    vhosts,
			Role:      st.Role,
			CreatedAt: st.CreatedAt,
			Expiry:    st.Expiry,
		})
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load reads persisted tokens from path, skipping expired ones.
// Sets the save path so subsequent Issue/Revoke calls persist automatically.
// Call once at startup before StartPurger.
func (s *TokenStore) Load(path string) error {
	s.mu.Lock()
	s.savePath = path
	s.mu.Unlock()

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil // first run — no tokens yet
	}
	if err != nil {
		return err
	}
	var rows []persistedToken
	if err := json.Unmarshal(data, &rows); err != nil {
		logging.Logf("[token_store] load %s: parse error: %v — starting fresh", path, err)
		return err
	}
	now := time.Now()
	n := 0
	s.mu.Lock()
	for _, row := range rows {
		if now.After(row.Expiry) {
			continue
		}
		vhostSet := make(map[string]struct{}, len(row.Vhosts))
		for _, v := range row.Vhosts {
			vhostSet[v] = struct{}{}
		}
		st := &ScopedToken{
			ID:        row.ID,
			Token:     row.Token,
			Label:     row.Label,
			Vhosts:    vhostSet,
			Role:      row.Role,
			CreatedAt: row.CreatedAt,
			Expiry:    row.Expiry,
		}
		s.tokens[row.Token] = st
		s.byID[row.ID] = st
		n++
	}
	s.mu.Unlock()
	logging.Logf("[token_store] loaded %d active token(s) from %s", n, path)
	return nil
}

// ── Issue endpoint (POST /api/v1/auth/token) ──────────────────────────────────

type tokenIssueRequest struct {
	Vhosts []string `json:"vhosts"`
	Role   string   `json:"role"`
	TTL    string   `json:"ttl"`   // Go duration string, e.g. "2h", "8760h"
	Label  string   `json:"label"` // human-readable name
}

type tokenIssueResponse struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	Label     string    `json:"label"`
	Role      string    `json:"role"`
	Vhosts    []string  `json:"vhosts"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RegisterTokenEndpoint adds POST /api/v1/auth/token to the mux.
// Protected by the middleware (admin Bearer or session required).
func RegisterTokenEndpoint(m *http.ServeMux, store *TokenStore) {
	m.HandleFunc("/api/v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if !webdet.IsAdminRequest(r) {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"admin access required"}`, http.StatusForbidden)
			return
		}
		var req tokenIssueRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}
		if req.Role != "viewer" && req.Role != "admin" {
			req.Role = "viewer"
		}
		ttl := 2 * time.Hour
		if req.TTL != "" {
			if d, err := time.ParseDuration(req.TTL); err == nil && d > 0 && d <= 8760*time.Hour {
				ttl = d
			} else {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"invalid ttl — use Go duration format, max 8760h"}`, http.StatusBadRequest)
				return
			}
		}
		if len(req.Vhosts) == 0 {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"vhosts is required"}`, http.StatusBadRequest)
			return
		}
		st := store.Issue(req.Vhosts, req.Role, req.Label, ttl)
		vhostList := make([]string, 0, len(st.Vhosts))
		for v := range st.Vhosts {
			vhostList = append(vhostList, v)
		}
		sort.Strings(vhostList)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenIssueResponse{
			ID:        st.ID,
			Token:     st.Token,
			Label:     st.Label,
			Role:      st.Role,
			Vhosts:    vhostList,
			ExpiresAt: st.Expiry,
		})
	})
}
