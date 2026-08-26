package apiserver

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

var globalAPIAbuseSignalClassifier = newAPIAbuseSignalClassifier()

type anomalyReasonRecorder struct {
	*statusRecorder
	state *requestAnomalyState
}

func (r *anomalyReasonRecorder) SetAPIAnomalyReason(reason string) {
	r.state.setReason(reason)
}

type requestAnomalyStateKey struct{}

type requestAnomalyState struct {
	mu     sync.Mutex
	reason string
	direct bool
}

func (s *requestAnomalyState) setReason(reason string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.reason = reason
	s.mu.Unlock()
}

func (s *requestAnomalyState) markDirect() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.direct = true
	s.mu.Unlock()
}

func (s *requestAnomalyState) snapshot() (string, bool) {
	if s == nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reason, s.direct
}

func anomalyStateFromRequest(r *http.Request) *requestAnomalyState {
	if r == nil {
		return nil
	}
	state, _ := r.Context().Value(requestAnomalyStateKey{}).(*requestAnomalyState)
	return state
}

func APISecurityAnomalyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := &requestAnomalyState{}
		r = r.WithContext(context.WithValue(r.Context(), requestAnomalyStateKey{}, state))
		rec := &anomalyReasonRecorder{
			statusRecorder: &statusRecorder{ResponseWriter: w, status: http.StatusOK},
			state:          state,
		}
		next.ServeHTTP(rec, r)

		reason, direct := state.snapshot()
		if reason == "" {
			switch rec.status {
			case http.StatusNotFound:
				reason = "route_not_found"
			case http.StatusMethodNotAllowed:
				reason = "method_not_allowed"
			}
		}

		srcIP := realIPFromRequest(r)
		ua := strings.TrimSpace(r.UserAgent())
		for _, ev := range globalAPIAbuseSignalClassifier.Evaluate(r, rec.status, classifierReason(reason, direct)) {
			logging.LogfAPI("[apiserver] event=%s src_ip=%s signal=%s count=%d scope=%s method=%s path=%q status=%d ua=%q",
				ev.Name, srcIP, ev.Signal, ev.Count, ev.Scope, r.Method, r.URL.Path, rec.status, ua)
			publishAPIAnomalyEvent(APIAnomalyEvent{
				When:      time.Now(),
				Source:    "apiserver",
				Reason:    ev.Name,
				Signal:    ev.Signal,
				Scope:     ev.Scope,
				Count:     ev.Count,
				SrcIP:     srcIP,
				Method:    r.Method,
				Path:      r.URL.Path,
				Status:    rec.status,
				UserAgent: ua,
			})
		}
	})
}

func classifierReason(reason string, direct bool) string {
	if direct {
		return "direct_auth_event"
	}
	switch reason {
	case "token_invalid", "token_malformed", "admin_token_source_ip", "login_failed", "mfa_failed", "csrf_reject":
		// These paths publish one structured event per attempt/decision directly.
		// Suppress the generic 401/403 burst event to avoid double counting.
		return "direct_auth_event"
	default:
		return reason
	}
}
