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
	embedBootstrapTTL        = 90 * time.Second
	embedExchangeCodeTTL     = 45 * time.Second
	embedCookieHKDFInfo      = "cfm-apiserver-embed-bootstrap-cookie-v1"
	embedCookieHKDFSalt      = "cfm-apiserver-embed-bootstrap-cookie-salt-v1"
)

var (
	embedLegacyCookieCutoff       = time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	embedCookieSigningKeyProvider = deriveEmbedCookieSigningKey
)

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

		value, err := encodeEmbedCookie(r, st.ID, time.Now().Add(embedBootstrapTTL))
		if err != nil {
			logging.Logf("[apiserver] embed bootstrap signing key unavailable: %v", err)
			apiJSONError(w, "failed to create embed bootstrap cookie", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     embedBootstrapCookieName,
			Value:    value,
			Path:     "/cfm-admin/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
			MaxAge:   int(embedBootstrapTTL.Seconds()),
		})

		logging.Logf("[apiserver] embed bootstrap ok token_id=%s label=%q role=%s next=%s", st.ID, st.Label, st.Role, nextPath)
		http.Redirect(w, r, nextPath, http.StatusSeeOther)
	})
}

func embedScopedContextFromCookie(r *http.Request, store *TokenStore) (context.Context, bool) {
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
	ok, cookieRef, legacy := decodeEmbedCookie(r, c.Value)
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
	ctx := context.WithValue(r.Context(), webdet.CtxScopeKey{}, st.Vhosts)
	ctx = context.WithValue(ctx, webdet.CtxDBScopeKey{}, webdet.ScopedDBScope{
		Users:     st.DBUsers,
		Databases: st.Databases,
	})
	ctx = context.WithValue(ctx, webdet.CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, webdet.CtxRoleScoped)
	return ctx, true
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

func decodeEmbedCookie(r *http.Request, v string) (bool, string, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return false, "", false
	}
	if strings.HasPrefix(v, "v1.") {
		return decodeSignedEmbedCookie(r, v)
	}
	if time.Now().After(embedLegacyCookieCutoff) {
		return false, "", false
	}
	buf, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return false, "", false
	}
	parts := strings.SplitN(string(buf), ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
		return false, "", false
	}
	expUnix, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil {
		return false, "", false
	}
	if time.Now().After(time.Unix(expUnix, 0)) {
		return false, "", false
	}
	logging.Logf("[apiserver] accepted legacy unsigned embed cookie; migration deadline=%s", embedLegacyCookieCutoff.Format(time.RFC3339))
	return true, parts[1], true
}

func decodeSignedEmbedCookie(r *http.Request, v string) (bool, string, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return false, "", false
	}
	unsignedRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(unsignedRaw) == 0 {
		return false, "", false
	}
	sigRaw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sigRaw) == 0 {
		return false, "", false
	}
	key, err := embedCookieSigningKeyProvider()
	if err != nil {
		return false, "", false
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(unsignedRaw)
	if !hmac.Equal(mac.Sum(nil), sigRaw) {
		return false, "", false
	}
	claims, err := url.ParseQuery(string(unsignedRaw))
	if err != nil {
		return false, "", false
	}
	tokenRef := strings.TrimSpace(claims.Get("ref"))
	if tokenRef == "" {
		return false, "", false
	}
	expUnix, err := strconv.ParseInt(strings.TrimSpace(claims.Get("exp")), 10, 64)
	if err != nil || time.Now().After(time.Unix(expUnix, 0)) {
		return false, "", false
	}
	if pfx := strings.TrimSpace(claims.Get("pfx")); pfx != "" && r != nil && !strings.HasPrefix(r.URL.Path, pfx) {
		return false, "", false
	}
	if hostClaim := strings.TrimSpace(claims.Get("hst")); hostClaim != "" && r != nil {
		if canonicalRequestHost(r.Host) != strings.ToLower(hostClaim) {
			return false, "", false
		}
	}
	if uaHash := strings.TrimSpace(claims.Get("uah")); uaHash != "" && r != nil {
		if uaHash != hashUserAgent(r.UserAgent()) {
			return false, "", false
		}
	}
	return true, tokenRef, false
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
