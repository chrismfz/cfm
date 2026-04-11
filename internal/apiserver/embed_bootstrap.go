package apiserver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cfm/internal/logging"
	webdet "cfm/internal/webdetector"
)

const (
	embedBootstrapCookieName = "cfm-embed-scope"
	embedBootstrapTTL        = 90 * time.Second
)

func RegisterEmbedBootstrapEndpoint(m *http.ServeMux, store *TokenStore) {
	m.HandleFunc("/api/v1/embed/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			apiJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		tok := strings.TrimSpace(r.URL.Query().Get("token"))
		nextPath, err := normalizeEmbedNext(r.URL.Query().Get("next"))
		if err != nil {
			apiJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		st, ok := store.Lookup(tok)
		if !ok {
			apiJSONError(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		value := encodeEmbedCookie(st.Token, time.Now().Add(embedBootstrapTTL))
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
	ok, tok := decodeEmbedCookie(c.Value)
	if !ok {
		return nil, false
	}
	st, exists := store.Lookup(tok)
	if !exists {
		return nil, false
	}
	ctx := context.WithValue(r.Context(), webdet.CtxScopeKey{}, st.Vhosts)
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

func encodeEmbedCookie(token string, expiry time.Time) string {
	payload := fmt.Sprintf("%d:%s", expiry.Unix(), token)
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func decodeEmbedCookie(v string) (bool, string) {
	buf, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return false, ""
	}
	parts := strings.SplitN(string(buf), ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
		return false, ""
	}
	expUnix, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil {
		return false, ""
	}
	if time.Now().After(time.Unix(expUnix, 0)) {
		return false, ""
	}
	return true, parts[1]
}
