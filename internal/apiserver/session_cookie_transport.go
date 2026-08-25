package apiserver

import (
	"net/http"
	"strings"
)

// Audit Step 6: make the session cookie's transport request-aware WITHOUT mutating
// goauth's manager-global cookie config (which would race across concurrent requests).
//
// goauth always emits a Secure `<canonical>` (default cfm-sid) cookie. Every real
// path is effective-https (the edge hop, or direct :6061 TLS), and after Step 5 a
// healthy :6060 redirects browser admin to :6061 before any session is written — so
// the ONLY place a session cookie is written over genuine plaintext is the TLS-down
// degraded :6060 window. There, this middleware translates on the wire to a DISTINCT
// non-Secure `<canonical>-http-fallback` cookie (and renames it back on the way in),
// so one goauth session store is shared with no global mutation and no race. A browser
// holding `<canonical>; Secure` never sends it over http, so that Secure cookie is
// never downgraded or overwritten by the fallback.

const sessionCookieFallbackSuffix = "-http-fallback"

func sessionCookieFallbackName(canonical string) string {
	// A non-Secure cookie cannot carry a __Host-/__Secure- prefix (browsers require
	// Secure for those), so strip it from the fallback name to keep it valid.
	base := canonical
	for _, p := range []string{"__Host-", "__Secure-"} {
		if strings.HasPrefix(base, p) {
			base = strings.TrimPrefix(base, p)
			break
		}
	}
	return base + sessionCookieFallbackSuffix
}

// SessionCookieTransportMiddleware must wrap goauth's LoadAndSave from OUTSIDE (it
// rewrites the request cookie before goauth reads it and the Set-Cookie after goauth
// writes it).
func SessionCookieTransportMiddleware(canonicalName string) func(http.Handler) http.Handler {
	if strings.TrimSpace(canonicalName) == "" {
		canonicalName = "cfm-sid"
	}
	fallback := sessionCookieFallbackName(canonicalName)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only the degraded plaintext window rewrites. The effective scheme is
			// spoof-safe: a direct :6060 client cannot forge X-Forwarded-Proto (trusted
			// only from a loopback edge peer), so it stays http here (Step 1).
			peer := requestPeer(r)
			if peer.Entry != "6060" || peer.Scheme != "http" {
				next.ServeHTTP(w, r) // native Secure cookie stands
				return
			}
			renameRequestCookie(r, fallback, canonicalName)
			rw := &sessionCookieRewriteWriter{ResponseWriter: w, canonical: canonicalName, fallback: fallback}
			next.ServeHTTP(rw, r)
			// Also cover the SCS path where a handler mutates the session but never
			// writes a response: SCS then commits the Set-Cookie directly to the header
			// after the handler returns, bypassing our WriteHeader/Write hooks. rewrite()
			// is idempotent (the `done` guard), so this is a no-op when a response was
			// already written.
			rw.rewrite()
		})
	}
}

// renameRequestCookie rewrites the request's Cookie header so downstream (goauth) sees
// the fallback cookie `from` under its canonical name `to`. Any INBOUND canonical `to`
// cookie is DROPPED: over plaintext the real (Secure) canonical cookie is never sent by
// a browser, so a `to` seen here can only be an injected/forged value — dropping it
// keeps an on-path attacker from shadowing the fallback session. No-op when neither is
// present.
func renameRequestCookie(r *http.Request, from, to string) {
	cookies := r.Cookies()
	var hasFrom, hasCanonical bool
	for _, c := range cookies {
		switch c.Name {
		case from:
			hasFrom = true
		case to:
			hasCanonical = true
		}
	}
	if !hasFrom && !hasCanonical {
		return
	}
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		switch c.Name {
		case to:
			continue // drop an inbound canonical cookie (see doc comment)
		case from:
			parts = append(parts, to+"="+c.Value)
		default:
			parts = append(parts, c.Name+"="+c.Value)
		}
	}
	if len(parts) == 0 {
		r.Header.Del("Cookie")
		return
	}
	r.Header.Set("Cookie", strings.Join(parts, "; "))
}

// sessionCookieRewriteWriter rewrites an outbound Set-Cookie for the canonical session
// cookie to the non-Secure fallback name, at header-flush time. Every other header and
// cookie passes through untouched.
type sessionCookieRewriteWriter struct {
	http.ResponseWriter
	canonical string
	fallback  string
	done      bool
}

func (w *sessionCookieRewriteWriter) rewrite() {
	if w.done {
		return
	}
	w.done = true
	sc := w.Header()["Set-Cookie"]
	for i, v := range sc {
		if strings.HasPrefix(v, w.canonical+"=") {
			sc[i] = stripCookieSecureAttr(w.fallback + "=" + strings.TrimPrefix(v, w.canonical+"="))
		}
	}
}

func (w *sessionCookieRewriteWriter) WriteHeader(code int) {
	w.rewrite()
	w.ResponseWriter.WriteHeader(code)
}

func (w *sessionCookieRewriteWriter) Write(b []byte) (int, error) {
	w.rewrite()
	return w.ResponseWriter.Write(b)
}

// Flush keeps the ResponseWriter's flushing behaviour (harmless for session responses,
// but avoids silently disabling it for anything that streams on this path).
func (w *sessionCookieRewriteWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer (e.g. for
// SetWriteDeadline / Hijack), since this wrapper doesn't itself implement those.
func (w *sessionCookieRewriteWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// stripCookieSecureAttr removes the `Secure` attribute from a Set-Cookie value,
// leaving `name=value` and every other attribute intact.
func stripCookieSecureAttr(setCookie string) string {
	parts := strings.Split(setCookie, "; ")
	out := parts[:0]
	for _, p := range parts {
		if strings.EqualFold(strings.TrimSpace(p), "Secure") {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, "; ")
}
