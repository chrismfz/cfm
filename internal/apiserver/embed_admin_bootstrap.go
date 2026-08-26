package apiserver

// Admin single-sign-on bootstrap for the CFM admin UI.
//
// This parallels the scoped embed flow in embed_bootstrap.go, but mints a full
// ADMIN browser session instead of a per-vhost scoped one. Purpose: let a
// trusted, already-admin-authenticated caller (the cfm-web fleet controller, or
// the root WHM plugin) hand an operator a one-click login into a node's
// /cfm-admin/ without re-entering that node's password + MFA.
//
// Security model — mirrors the scoped flow, and grants NOTHING the caller did
// not already hold:
//   - /api/v1/embed/admin-code is NOT a public path: the auth middleware
//     requires a valid credential to reach it, and the handler additionally
//     rejects any non-admin role — so a scoped token or scoped embed cookie can
//     never mint an admin session. The admin bearer token already grants full
//     admin API access, so turning it into a browser session is not an
//     escalation.
//   - The minted exchange code is 160-bit random, single-use (LoadAndDelete),
//     and expires in embedExchangeCodeTTL (45s).
//   - /api/v1/embed/admin-bootstrap consumes the code and sets a short-lived,
//     HMAC-signed, host+UA-bound admin cookie scoped to /cfm-admin/. The cookie
//     is signed with a RANDOM, per-node key (see embed_admin_cookie_key.go) — NOT
//     derived from AUTH_TOKEN — so a cfm-web DB leak (which exposes AUTH_TOKEN)
//     cannot forge it. It is also domain-separated from the scoped embed cookie
//     (distinct name AND a distinct signing key), so neither can be replayed as
//     the other.
//   - Unlike the scoped embed cookie (SameSite=None, because it lives in a
//     cross-site cPanel iframe), the admin session is a top-level navigation and
//     same-origin thereafter, so it uses SameSite=Lax to shrink CSRF surface for
//     the higher-privilege cookie.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
	webdet "cfm/internal/webdetector"
)

const (
	embedAdminCookieName              = "cfm-embed-admin"
	embedAdminBootstrapTTL            = 600 * time.Second
	embedAdminBootstrapRenewThreshold = embedAdminBootstrapTTL / 2
)

var embedAdminCookieSigningKeyProvider = loadOrCreateEmbedAdminCookieSigningKey

type embedAdminExchangeRecord struct {
	nextPath string
	expires  time.Time
}

// embedAdminExchangeStore is a dedicated one-time-code store for the admin
// flow. Kept separate from the scoped exchange store so an admin code and a
// scoped code can never be confused, and so the admin record carries no token
// material (the role IS admin — there is no per-vhost token to mint).
type embedAdminExchangeStore struct {
	codes sync.Map // code -> embedAdminExchangeRecord
}

func (s *embedAdminExchangeStore) Mint(nextPath string, ttl time.Duration) (string, error) {
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
	s.codes.Store(code, embedAdminExchangeRecord{
		nextPath: nextPath,
		expires:  embedBootstrapNow().Add(ttl),
	})
	return code, nil
}

func (s *embedAdminExchangeStore) Consume(code, nextPath string) bool {
	if strings.TrimSpace(code) == "" {
		return false
	}
	v, ok := s.codes.LoadAndDelete(code)
	if !ok {
		return false
	}
	rec, ok := v.(embedAdminExchangeRecord)
	if !ok {
		return false
	}
	if embedBootstrapNow().After(rec.expires) {
		return false
	}
	return nextPath == rec.nextPath
}

func (s *embedAdminExchangeStore) PurgeExpired(now time.Time) int {
	purged := 0
	s.codes.Range(func(k, v any) bool {
		rec, ok := v.(embedAdminExchangeRecord)
		if !ok || now.After(rec.expires) {
			s.codes.Delete(k)
			purged++
		}
		return true
	})
	return purged
}

var defaultEmbedAdminExchangeStore embedAdminExchangeStore

// RegisterEmbedAdminBootstrapEndpoint wires the admin SSO code + bootstrap
// endpoints onto the mux. The code endpoint is protected by the auth middleware
// (admin credential required); the bootstrap endpoint is a public path that
// only succeeds against a valid one-time code.
func RegisterEmbedAdminBootstrapEndpoint(m *http.ServeMux) {
	m.HandleFunc("/api/v1/embed/admin-code", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			apiJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// The auth middleware has already required a valid credential to reach a
		// non-public path; additionally require the ADMIN role so a scoped token
		// (or scoped embed cookie) can never mint an admin session.
		if role, _ := r.Context().Value(webdet.CtxRoleKey{}).(string); role != webdet.CtxRoleAdmin {
			apiJSONError(w, "admin role required", http.StatusForbidden)
			return
		}
		now := embedBootstrapNow()
		srcIP := realIPFromRequest(r)
		if !allowEmbedRate("embed_admin_code", srcIP, "admin", now, embedCodeRLWindow, embedCodeRLBurst) {
			logEmbedRateLimitEvent(r, "embed_admin_code", srcIP, "admin", embedCodeRLWindow, embedCodeRLBurst)
			w.Header().Set("Retry-After", strconv.Itoa(int(embedCodeRLWindow.Seconds())))
			apiJSONError(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		nextPath, err := normalizeEmbedNext(r.URL.Query().Get("next"))
		if err != nil {
			apiJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		nextPath = ensureAdminNextTrailingSlash(nextPath)
		code, err := defaultEmbedAdminExchangeStore.Mint(nextPath, embedExchangeCodeTTL)
		if err != nil {
			apiJSONError(w, "failed to mint admin embed code", http.StatusInternalServerError)
			return
		}
		_ = defaultEmbedAdminExchangeStore.PurgeExpired(now)
		logging.LogfAPI("[apiserver] embed admin-code minted src_ip=%s next=%s", srcIP, nextPath)
		// The body carries a live one-time admin capability — never cache it.
		setAuthIdentityNoCacheHeaders(w)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"code":%q,"expires_in":%d}`, code, int(embedExchangeCodeTTL.Seconds()))
	})

	m.HandleFunc("/api/v1/embed/admin-bootstrap", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			apiJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		nextPath, err := normalizeEmbedNext(r.URL.Query().Get("next"))
		if err != nil {
			apiJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		nextPath = ensureAdminNextTrailingSlash(nextPath)
		now := embedBootstrapNow()
		srcIP := realIPFromRequest(r)
		// Rate-limit BEFORE consuming so a burst can never burn a valid code and
		// so cookie crypto is not run under a flood. Keyed on the constant admin
		// subject + source IP.
		if !allowEmbedRate("embed_admin_bootstrap", srcIP, "admin", now, embedBootstrapRLWindow, embedBootstrapRLBurst) {
			logEmbedRateLimitEvent(r, "embed_admin_bootstrap", srcIP, "admin", embedBootstrapRLWindow, embedBootstrapRLBurst)
			w.Header().Set("Retry-After", strconv.Itoa(int(embedBootstrapRLWindow.Seconds())))
			apiJSONError(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		code := strings.TrimSpace(r.URL.Query().Get("code"))
		if !defaultEmbedAdminExchangeStore.Consume(code, nextPath) {
			apiJSONError(w, "invalid, expired, or already used code", http.StatusUnauthorized)
			return
		}
		value, err := encodeEmbedAdminCookie(r, now.Add(embedAdminBootstrapTTL))
		if err != nil {
			logging.LogfAPI("[apiserver] embed admin bootstrap signing key unavailable: %v", err)
			apiJSONError(w, "failed to create admin embed cookie", http.StatusInternalServerError)
			return
		}
		// Identity-establishing response carrying a Set-Cookie — never cache it.
		setAuthIdentityNoCacheHeaders(w)
		writeEmbedAdminBootstrapCookie(w, value)
		logging.LogfAPI("[apiserver] embed admin bootstrap ok src_ip=%s next=%s", srcIP, nextPath)
		http.Redirect(w, r, nextPath, http.StatusSeeOther)
	})
}

// ensureAdminNextTrailingSlash canonicalizes the bare "/cfm-admin" base to
// "/cfm-admin/". Without it, the SSO cookie (Path=/cfm-admin/) would not be sent
// to a redirect target of exactly "/cfm-admin" (RFC 6265 path-match), silently
// breaking the one-click login. Applied identically at mint and redeem so the
// stored and consumed next paths still match.
func ensureAdminNextTrailingSlash(next string) string {
	if next == "/cfm-admin" {
		return "/cfm-admin/"
	}
	return next
}

// clearEmbedBootstrapCookies expires the admin SSO and scoped embed cookies.
// They are independent of the goauth session, so an explicit Logout must delete
// them too — otherwise a full-admin SSO session (rolling-renewed) would survive
// logout until its TTL lapsed. Deletion matches on Name+Path; the browser
// ignores the other attributes for expiry.
func clearEmbedBootstrapCookies(w http.ResponseWriter) {
	for _, name := range []string{embedAdminCookieName, embedBootstrapCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/cfm-admin/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
		})
	}
}

// embedAdminContextFromCookie authenticates a request carrying a valid admin
// bootstrap cookie and returns an admin-role context. Honored only for requests
// whose effective base is /cfm-admin (same guard as the scoped cookie path).
func embedAdminContextFromCookie(w http.ResponseWriter, r *http.Request) (context.Context, bool) {
	if r == nil {
		return nil, false
	}
	if cfmBase(r) != "/cfm-admin" {
		return nil, false
	}
	c, err := r.Cookie(embedAdminCookieName)
	if err != nil || strings.TrimSpace(c.Value) == "" {
		return nil, false
	}
	ok, expiry := decodeEmbedAdminCookie(r, c.Value)
	if !ok {
		return nil, false
	}
	// Rolling renewal so an actively-used admin session refreshes before expiry
	// instead of being 303'd to /login mid-session.
	if w != nil {
		renewEmbedAdminBootstrapCookie(w, r, expiry, embedBootstrapNow())
	}
	ctx := context.WithValue(r.Context(), webdet.CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, webdet.CtxRoleAdmin)
	ctx = withAuthnSubject(ctx, "admin") // shares the single admin rate-limit bucket
	return ctx, true
}

func renewEmbedAdminBootstrapCookie(w http.ResponseWriter, r *http.Request, currentExpiry, now time.Time) {
	if currentExpiry.IsZero() || now.IsZero() {
		return
	}
	if currentExpiry.Sub(now) > embedAdminBootstrapRenewThreshold {
		return
	}
	value, err := encodeEmbedAdminCookie(r, now.Add(embedAdminBootstrapTTL))
	if err != nil {
		logging.LogfAPI("[apiserver] embed admin cookie renewal failed: %v", err)
		return
	}
	writeEmbedAdminBootstrapCookie(w, value)
}

// writeEmbedAdminBootstrapCookie is the single source of truth for the admin
// cookie's browser-facing attributes so issuance and rolling renewal can't
// drift.
func writeEmbedAdminBootstrapCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     embedAdminCookieName,
		Value:    value,
		Path:     "/cfm-admin/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(embedAdminBootstrapTTL.Seconds()),
	})
}

func encodeEmbedAdminCookie(r *http.Request, expiry time.Time) (string, error) {
	unsigned := buildEmbedAdminCookiePayload(r, expiry)
	key, err := embedAdminCookieSigningKeyProvider()
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

func buildEmbedAdminCookiePayload(r *http.Request, expiry time.Time) string {
	claims := []string{
		"typ=admin",
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

// decodeEmbedAdminCookie validates the signature, type, expiry and the
// host/UA/prefix bindings. Signed v1 cookies only — the admin cookie never had
// a legacy unsigned form.
func decodeEmbedAdminCookie(r *http.Request, v string) (bool, time.Time) {
	v = strings.TrimSpace(v)
	parts := strings.Split(v, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return false, time.Time{}
	}
	unsignedRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(unsignedRaw) == 0 {
		return false, time.Time{}
	}
	sigRaw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sigRaw) == 0 {
		return false, time.Time{}
	}
	key, err := embedAdminCookieSigningKeyProvider()
	if err != nil {
		return false, time.Time{}
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(unsignedRaw)
	if !hmac.Equal(mac.Sum(nil), sigRaw) {
		return false, time.Time{}
	}
	claims, err := url.ParseQuery(string(unsignedRaw))
	if err != nil {
		return false, time.Time{}
	}
	if strings.TrimSpace(claims.Get("typ")) != "admin" {
		return false, time.Time{}
	}
	expUnix, err := strconv.ParseInt(strings.TrimSpace(claims.Get("exp")), 10, 64)
	if err != nil {
		return false, time.Time{}
	}
	expiry := time.Unix(expUnix, 0)
	if embedBootstrapNow().After(expiry) {
		return false, time.Time{}
	}
	if pfx := strings.TrimSpace(claims.Get("pfx")); pfx != "" && r != nil && !requestWithinEmbedPrefix(r, pfx) {
		return false, time.Time{}
	}
	if hostClaim := strings.TrimSpace(claims.Get("hst")); hostClaim != "" && r != nil {
		if canonicalRequestHost(r.Host) != strings.ToLower(hostClaim) {
			return false, time.Time{}
		}
	}
	if uaHash := strings.TrimSpace(claims.Get("uah")); uaHash != "" && r != nil {
		if uaHash != hashUserAgent(r.UserAgent()) {
			return false, time.Time{}
		}
	}
	return true, expiry
}
