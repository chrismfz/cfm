package apiserver

import (
	"net/http"
	"strings"
	"time"

	"cfm/internal/logging"
)

var globalAPIAbuseSignalClassifier = newAPIAbuseSignalClassifier()

type anomalyReasonRecorder struct {
	*statusRecorder
	reason string
}

func (r *anomalyReasonRecorder) SetAPIAnomalyReason(reason string) {
	r.reason = reason
}

func APISecurityAnomalyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &anomalyReasonRecorder{
			statusRecorder: &statusRecorder{ResponseWriter: w, status: http.StatusOK},
		}
		next.ServeHTTP(rec, r)

		reason := rec.reason
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
		for _, ev := range globalAPIAbuseSignalClassifier.Evaluate(r, rec.status, reason) {
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
