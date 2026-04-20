package apiserver

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	cfgpkg "cfm/internal/config"
	"cfm/internal/logging"
	webdet "cfm/internal/webdetector"
)

const (
	embedBootstrapCookieName = "cfm-embed-scope"
	embedBootstrapTTL        = 600 * time.Second
	embedExchangeCodeTTL     = 45 * time.Second
	embedCodeRLWindow        = 8 * time.Second
	embedCodeRLBurst         = 4
	embedBootstrapRLWindow   = 8 * time.Second
	embedBootstrapRLBurst    = 3
	embedCookieHKDFInfo      = "cfm-apiserver-embed-bootstrap-cookie-v1"
	embedCookieHKDFSalt      = "cfm-apiserver-embed-bootstrap-cookie-salt-v1"
	// embedBootstrapRenewThreshold is the remaining-lifetime cutoff below
	// which a cookie-authenticated request triggers a rolling renewal. Picked
	// so that active sessions refresh well before the cookie expires while
	// avoiding a Set-Cookie on every single poll.
	embedBootstrapRenewThreshold = embedBootstrapTTL / 2
)

var (
	embedLegacyCookieCutoff       = time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	embedCookieSigningKeyProvider = deriveEmbedCookieSigningKey
	embedBootstrapNow             = time.Now
)

type embedRateState struct {
	windowStart time.Time
	count       int
	lastSeen    time.Time
}

type embedRateLimiter struct {
	mu sync.Mutex
	m  map[string]embedRateState
}

func (l *embedRateLimiter) allow(key string, now time.Time, window time.Duration, burst int) bool {
	if strings.TrimSpace(key) == "" {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = make(map[string]embedRateState)
	}
	st := l.m[key]
	st.lastSeen = now
	if st.windowStart.IsZero() || now.Sub(st.windowStart) >= window {
		st.windowStart = now
		st.count = 0
	}
	st.count++
	l.m[key] = st
	// Opportunistic prune to keep memory bounded.
	if len(l.m) > 4096 {
		for k, v := range l.m {
			if now.Sub(v.lastSeen) > 3*window {
				delete(l.m, k)
			}
		}
	}
	return st.count <= burst
}

func (l *embedRateLimiter) reset() {
	l.mu.Lock()
	l.m = nil
	l.mu.Unlock()
}

var embedBootstrapRateLimiter embedRateLimiter

type embedExchangeRecord struct {
	token    string
	nextPath string
	expires  time.Time
}

type embedExchangeStore struct {
	codes sync.Map // code -> embedExchangeRecord
}

func (s *embedExchangeStore) Mint(token, nextPath string, ttl time.Duration) (string, error) {
	if strings.TrimSpace(token) == "" {
		return "", errors.New("token is required")
	}
	if strings.TrimSpace(nextPath) == "" {
		return "", errors.New("next is required")
	}
	if ttl == 0 {
		ttl = embedExchangeCodeTTL
	}
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	code := hex.EncodeToString(buf)
	s.codes.Store(code, embedExchangeRecord{
		token:    token,
		nextPath: nextPath,
		expires:  time.Now().Add(ttl),
	})
	return code, nil
}

func (s *embedExchangeStore) Consume(code, nextPath string) (string, bool) {
	if strings.TrimSpace(code) == "" {
		return "", false
	}
	v, ok := s.codes.LoadAndDelete(code)
	if !ok {
		return "", false
	}
	rec, ok := v.(embedExchangeRecord)
	if !ok {
		return "", false
	}
	if time.Now().After(rec.expires) {
		return "", false
	}
	if nextPath != rec.nextPath {
		return "", false
	}
	return rec.token, true
}

func (s *embedExchangeStore) PurgeExpired(now time.Time) int {
	purged := 0
	s.codes.Range(func(k, v any) bool {
		rec, ok := v.(embedExchangeRecord)
		if !ok || now.After(rec.expires) {
			s.codes.Delete(k)
			purged++
		}
		return true
	})
	return purged
}

var defaultEmbedExchangeStore embedExchangeStore

func RegisterEmbedBootstrapEndpoint(m *http.ServeMux, store *TokenStore) {
	m.HandleFunc("/api/v1/embed/code", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			apiJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tok, _ := extractToken(r)
		st, ok := store.Lookup(tok)
		if !ok {
			apiJSONError(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}
		now := embedBootstrapNow()
		srcIP := realIPFromRequest(r)
		if !allowEmbedRate("embed_code", srcIP, st.ID, now, embedCodeRLWindow, embedCodeRLBurst) {
			logEmbedRateLimitEvent(r, "embed_code", srcIP, st.ID, embedCodeRLWindow, embedCodeRLBurst)
			w.Header().Set("Retry-After", strconv.Itoa(int(embedCodeRLWindow.Seconds())))
			apiJSONError(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		nextPath, err := normalizeEmbedNext(r.URL.Query().Get("next"))
		if err != nil {
			apiJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		code, err := defaultEmbedExchangeStore.Mint(st.Token, nextPath, embedExchangeCodeTTL)
		if err != nil {
			apiJSONError(w, "failed to mint embed code", http.StatusInternalServerError)
			return
		}
		_ = defaultEmbedExchangeStore.PurgeExpired(time.Now())
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"code":%q,"expires_in":%d}`, code, int(embedExchangeCodeTTL.Seconds()))
	})

	m.HandleFunc("/api/v1/embed/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			apiJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		code := strings.TrimSpace(r.URL.Query().Get("code"))
		nextPath, err := normalizeEmbedNext(r.URL.Query().Get("next"))
		if err != nil {
			apiJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		token, ok := defaultEmbedExchangeStore.Consume(code, nextPath)
		if !ok {
			apiJSONError(w, "invalid, expired, or already used code", http.StatusUnauthorized)
			return
		}
		st, ok := store.Lookup(token)
		if !ok {
			apiJSONError(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}
		now := embedBootstrapNow()
		srcIP := realIPFromRequest(r)
		if !allowEmbedRate("embed_bootstrap", srcIP, st.ID, now, embedBootstrapRLWindow, embedBootstrapRLBurst) {
			logEmbedRateLimitEvent(r, "embed_bootstrap", srcIP, st.ID, embedBootstrapRLWindow, embedBootstrapRLBurst)
			w.Header().Set("Retry-After", strconv.Itoa(int(embedBootstrapRLWindow.Seconds())))
			apiJSONError(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		value, err := encodeEmbedCookie(r, st.ID, now.Add(embedBootstrapTTL))
		if err != nil {
			logging.LogfAPI("[apiserver] embed bootstrap signing key unavailable: %v", err)
			apiJSONError(w, "failed to create embed bootstrap cookie", http.StatusInternalServerError)
			return
		}
		writeEmbedBootstrapCookie(w, value)

		redirectTarget := appendExpectedParentOrigin(nextPath, r.URL.Query().Get("cfmExpectedOrigin"))
		logging.LogfAPI("[apiserver] embed bootstrap ok token_id=%s label=%q role=%s next=%s", st.ID, st.Label, st.Role, nextPath)
		http.Redirect(w, r, redirectTarget, http.StatusSeeOther)
	})
}

// appendExpectedParentOrigin preserves the parent-origin hint across the
// bootstrap redirect so the iframe's auth-context.js can build a postMessage
// allowlist containing the parent frame's origin. The value is validated and
// normalized to an http(s) origin; anything else is dropped silently.
func appendExpectedParentOrigin(nextPath, rawExpectedOrigin string) string {
	origin := sanitizeExpectedParentOrigin(rawExpectedOrigin)
	if origin == "" {
		return nextPath
	}
	u, err := url.Parse(nextPath)
	if err != nil {
		return nextPath
	}
	q := u.Query()
	q.Set("cfmExpectedOrigin", origin)
	u.RawQuery = q.Encode()
	return u.RequestURI()
}

func sanitizeExpectedParentOrigin(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return ""
	}
	origin := strings.ToLower(u.Scheme) + "://" + u.Host
	return origin
}

func allowEmbedRate(action, srcIP, tokenID string, now time.Time, window time.Duration, burst int) bool {
	ipKey := fmt.Sprintf("%s:ip:%s", action, strings.TrimSpace(srcIP))
	tokenKey := fmt.Sprintf("%s:token:%s", action, strings.TrimSpace(tokenID))
	return embedBootstrapRateLimiter.allow(ipKey, now, window, burst) &&
		embedBootstrapRateLimiter.allow(tokenKey, now, window, burst)
}

func logEmbedRateLimitEvent(r *http.Request, action, srcIP, tokenID string, window time.Duration, burst int) {
	method := ""
	path := ""
	ua := ""
	if r != nil {
		method = r.Method
		if r.URL != nil {
			path = r.URL.Path
		}
		ua = strings.TrimSpace(r.UserAgent())
	}
	logging.LogfAPI("[apiserver] event=api_anomaly src_ip=%s signal=embed_bootstrap_rate_limited count=1 scope=api method=%s path=%q status=%d ua=%q detail=%q",
		srcIP, method, path, http.StatusTooManyRequests, ua, fmt.Sprintf("action=%s token_id=%s window=%s burst=%d", action, tokenID, window, burst))
	publishAPIAnomalyEvent(APIAnomalyEvent{
		When:      embedBootstrapNow(),
		Source:    "apiserver",
		Reason:    "api_anomaly",
		Signal:    "embed_bootstrap_rate_limited",
		Scope:     "api",
		Count:     1,
		SrcIP:     srcIP,
		Method:    method,
		Path:      path,
		Status:    http.StatusTooManyRequests,
		UserAgent: ua,
	})
}

func embedScopedContextFromCookie(w http.ResponseWriter, r *http.Request, store *TokenStore) (context.Context, bool) {
	if r == nil || store == nil {
		return nil, false
	}
	if !strings.HasPrefix(r.URL.Path, "/cfm-admin/") && r.URL.Path != "/cfm-admin" {
		return nil, false
	}
	c, err := r.Cookie(embedBootstrapCookieName)
	if err != nil || strings.TrimSpace(c.Value) == "" {
		return nil, false
	}
	ok, cookieRef, legacy, expiry := decodeEmbedCookie(r, c.Value)
	if !ok {
		return nil, false
	}
	var (
		st     *ScopedToken
		exists bool
	)
	if legacy {
		st, exists = store.Lookup(cookieRef)
	} else {
		st, exists = store.LookupByID(cookieRef)
	}
	if !exists {
		return nil, false
	}
	// Rolling renewal: when the cookie has less than embedBootstrapRenewThreshold
	// of remaining lifetime, re-issue it so active users don't get 303'd to /login
	// mid-session. Signed v1 cookies only; legacy unsigned cookies are left alone
	// and will phase out at embedLegacyCookieCutoff.
	if w != nil && !legacy {
		renewEmbedBootstrapCookie(w, r, st.ID, expiry, embedBootstrapNow())
	}
	ctx := context.WithValue(r.Context(), webdet.CtxScopeKey{}, st.Vhosts)
	ctx = context.WithValue(ctx, webdet.CtxDBScopeKey{}, webdet.ScopedDBScope{
		Users:     st.DBUsers,
		Databases: st.Databases,
	})
	ctx = context.WithValue(ctx, webdet.CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, webdet.CtxRoleScoped)
	ctx = context.WithValue(ctx, embedCookieTokenIDKey{}, st.ID)
	return ctx, true
}

// renewEmbedBootstrapCookie re-issues the cookie when its remaining lifetime is
// below embedBootstrapRenewThreshold. Failures are logged and ignored — the
// caller still gets a valid context on the current request.
func renewEmbedBootstrapCookie(w http.ResponseWriter, r *http.Request, tokenID string, currentExpiry, now time.Time) {
	if currentExpiry.IsZero() || now.IsZero() {
		return
	}
	if currentExpiry.Sub(now) > embedBootstrapRenewThreshold {
		return
	}
	value, err := encodeEmbedCookie(r, tokenID, now.Add(embedBootstrapTTL))
	if err != nil {
		logging.LogfAPI("[apiserver] embed bootstrap cookie renewal failed: %v", err)
		return
	}
	writeEmbedBootstrapCookie(w, value)
}

// writeEmbedBootstrapCookie is the single source of truth for the cookie's
// browser-facing attributes so bootstrap issuance and rolling renewal can't
// drift.
func writeEmbedBootstrapCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     embedBootstrapCookieName,
		Value:    value,
		Path:     "/cfm-admin/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		MaxAge:   int(embedBootstrapTTL.Seconds()),
	})
}

// embedCookieTokenIDKey is the context key used by the bootstrap-cookie auth
// path to expose the underlying scoped token ID to handlers that need to look
// up token metadata without a bearer header (notably /api/v1/tokens/me).
type embedCookieTokenIDKey struct{}

func scopedTokenIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(embedCookieTokenIDKey{}).(string)
	return id
}

func normalizeEmbedNext(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("next is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("invalid next path")
	}
	if u.IsAbs() || u.Host != "" {
		return "", errors.New("next must be same-origin relative path")
	}
	if !strings.HasPrefix(u.Path, "/cfm-admin/") && u.Path != "/cfm-admin" {
		return "", errors.New("next must stay under /cfm-admin/")
	}
	return u.RequestURI(), nil
}

func encodeEmbedCookie(r *http.Request, tokenRef string, expiry time.Time) (string, error) {
	if strings.TrimSpace(tokenRef) == "" {
		return "", errors.New("token reference is required")
	}
	unsigned := buildEmbedCookiePayload(r, tokenRef, expiry)
	key, err := embedCookieSigningKeyProvider()
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(unsigned))
	sig := mac.Sum(nil)
	return "v1." +
		base64.RawURLEncoding.EncodeToString([]byte(unsigned)) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

func decodeEmbedCookie(r *http.Request, v string) (bool, string, bool, time.Time) {
	v = strings.TrimSpace(v)
	if v == "" {
		return false, "", false, time.Time{}
	}
	if strings.HasPrefix(v, "v1.") {
		return decodeSignedEmbedCookie(r, v)
	}
	if time.Now().After(embedLegacyCookieCutoff) {
		return false, "", false, time.Time{}
	}
	buf, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return false, "", false, time.Time{}
	}
	parts := strings.SplitN(string(buf), ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
		return false, "", false, time.Time{}
	}
	expUnix, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil {
		return false, "", false, time.Time{}
	}
	expiry := time.Unix(expUnix, 0)
	if time.Now().After(expiry) {
		return false, "", false, time.Time{}
	}
	logging.LogfAPI("[apiserver] accepted legacy unsigned embed cookie; migration deadline=%s", embedLegacyCookieCutoff.Format(time.RFC3339))
	return true, parts[1], true, expiry
}

func decodeSignedEmbedCookie(r *http.Request, v string) (bool, string, bool, time.Time) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return false, "", false, time.Time{}
	}
	unsignedRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(unsignedRaw) == 0 {
		return false, "", false, time.Time{}
	}
	sigRaw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sigRaw) == 0 {
		return false, "", false, time.Time{}
	}
	key, err := embedCookieSigningKeyProvider()
	if err != nil {
		return false, "", false, time.Time{}
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(unsignedRaw)
	if !hmac.Equal(mac.Sum(nil), sigRaw) {
		return false, "", false, time.Time{}
	}
	claims, err := url.ParseQuery(string(unsignedRaw))
	if err != nil {
		return false, "", false, time.Time{}
	}
	tokenRef := strings.TrimSpace(claims.Get("ref"))
	if tokenRef == "" {
		return false, "", false, time.Time{}
	}
	expUnix, err := strconv.ParseInt(strings.TrimSpace(claims.Get("exp")), 10, 64)
	if err != nil {
		return false, "", false, time.Time{}
	}
	expiry := time.Unix(expUnix, 0)
	if time.Now().After(expiry) {
		return false, "", false, time.Time{}
	}
	if pfx := strings.TrimSpace(claims.Get("pfx")); pfx != "" && r != nil && !strings.HasPrefix(r.URL.Path, pfx) {
		return false, "", false, time.Time{}
	}
	if hostClaim := strings.TrimSpace(claims.Get("hst")); hostClaim != "" && r != nil {
		if canonicalRequestHost(r.Host) != strings.ToLower(hostClaim) {
			return false, "", false, time.Time{}
		}
	}
	if uaHash := strings.TrimSpace(claims.Get("uah")); uaHash != "" && r != nil {
		if uaHash != hashUserAgent(r.UserAgent()) {
			return false, "", false, time.Time{}
		}
	}
	return true, tokenRef, false, expiry
}

func buildEmbedCookiePayload(r *http.Request, tokenRef string, expiry time.Time) string {
	claims := []string{
		"ref=" + url.QueryEscape(strings.TrimSpace(tokenRef)),
		"exp=" + strconv.FormatInt(expiry.Unix(), 10),
		"pfx=" + url.QueryEscape("/cfm-admin/"),
	}
	if r != nil {
		if host := canonicalRequestHost(r.Host); host != "" {
			claims = append(claims, "hst="+url.QueryEscape(host))
		}
		if ua := hashUserAgent(r.UserAgent()); ua != "" {
			claims = append(claims, "uah="+url.QueryEscape(ua))
		}
	}
	return strings.Join(claims, "&")
}

func hashUserAgent(userAgent string) string {
	userAgent = strings.TrimSpace(userAgent)
	if userAgent == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(userAgent))
	return hex.EncodeToString(sum[:16])
}

func canonicalRequestHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	if h, _, found := strings.Cut(host, ":"); found && h != "" {
		return h
	}
	return host
}

func deriveEmbedCookieSigningKey() ([]byte, error) {
	authToken, err := loadAuthTokenFromRuntimeConfig()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(authToken) == "" {
		return nil, errors.New("auth token missing")
	}
	key, err := hkdf.Key(sha256.New, []byte(authToken), []byte(embedCookieHKDFSalt), embedCookieHKDFInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("derive embed cookie key: %w", err)
	}
	return key, nil
}

func loadAuthTokenFromRuntimeConfig() (string, error) {
	cfgPath, err := resolveRuntimeCFMConfPath()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return "", err
	}
	cfg, err := cfgpkg.ParseCFMConf(bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(cfg.API.AuthToken), nil
}

func resolveRuntimeCFMConfPath() (string, error) {
	if envDir := strings.TrimSpace(os.Getenv("CFM_CONFIG_DIR")); envDir != "" {
		path := filepath.Join(envDir, "cfm.conf")
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	if b, err := os.ReadFile("/run/cfm/config.path"); err == nil {
		if dir := strings.TrimSpace(string(b)); dir != "" {
			path := filepath.Join(dir, "cfm.conf")
			if _, err := os.Stat(path); err == nil {
				return path, nil
			}
		}
	}
	const fallbackPath = "/etc/cfm/cfm.conf"
	if _, err := os.Stat(fallbackPath); err == nil {
		return fallbackPath, nil
	}
	return "", errors.New("auth token config not found")
}
