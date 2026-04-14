package apiserver

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

const (
	apiAnomalyWindow            = 30 * time.Second
	authDeniedBurstThreshold    = 5
	routeNotFoundBurstThreshold = 12
)

type anomalyCounter struct {
	start    time.Time
	count    int
	lastEmit int
}

type apiAnomalyTracker struct {
	mu    sync.Mutex
	items map[string]anomalyCounter
}

var globalAPIAnomalyTracker = &apiAnomalyTracker{items: make(map[string]anomalyCounter)}

type anomalyReasonRecorder struct {
	*statusRecorder
	reason string
}

func (r *anomalyReasonRecorder) SetAPIAnomalyReason(reason string) {
	r.reason = reason
}

func (t *apiAnomalyTracker) increment(key string, now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	item := t.items[key]
	if item.start.IsZero() || now.Sub(item.start) > apiAnomalyWindow {
		item = anomalyCounter{start: now}
	}
	item.count++
	t.items[key] = item
	return item.count
}

func (t *apiAnomalyTracker) shouldEmitThreshold(key string, threshold int, now time.Time) (bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	item := t.items[key]
	if item.start.IsZero() || now.Sub(item.start) > apiAnomalyWindow {
		item = anomalyCounter{start: now}
	}
	item.count++
	emit := item.count >= threshold && (item.lastEmit == 0 || item.count-item.lastEmit >= threshold)
	if emit {
		item.lastEmit = item.count
	}
	t.items[key] = item
	return emit, item.count
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
		if reason == "" {
			return
		}

		now := time.Now()
		srcIP := realIPFromRequest(r)
		ua := strings.TrimSpace(r.UserAgent())
		sourceKey := fmt.Sprintf("%s|%s", srcIP, ua)
		path := r.URL.Path

		switch reason {
		case "route_not_found":
			emit, count := globalAPIAnomalyTracker.shouldEmitThreshold("nf|"+sourceKey, routeNotFoundBurstThreshold, now)
			if !emit {
				return
			}
			logging.LogfAPI("[apiserver] event=api_anomaly src_ip=%s reason=%s count=%d method=%s path=%q status=%d ua=%q",
				srcIP, reason, count, r.Method, path, rec.status, ua)
		case "auth_missing", "token_invalid", "method_not_allowed":
			count := globalAPIAnomalyTracker.increment(reason+"|"+sourceKey, now)
			logging.LogfAPI("[apiserver] event=api_anomaly src_ip=%s reason=%s count=%d method=%s path=%q status=%d ua=%q",
				srcIP, reason, count, r.Method, path, rec.status, ua)
		default:
			count := globalAPIAnomalyTracker.increment(reason+"|"+sourceKey, now)
			logging.LogfAPI("[apiserver] event=api_anomaly src_ip=%s reason=%s count=%d method=%s path=%q status=%d ua=%q",
				srcIP, reason, count, r.Method, path, rec.status, ua)
		}

		if rec.status == http.StatusUnauthorized || rec.status == http.StatusForbidden {
			emit, count := globalAPIAnomalyTracker.shouldEmitThreshold("deny|"+sourceKey, authDeniedBurstThreshold, now)
			if emit {
				logging.LogfAPI("[apiserver] event=api_anomaly src_ip=%s reason=auth_denied_burst count=%d method=%s path=%q status=%d ua=%q",
					srcIP, count, r.Method, path, rec.status, ua)
			}
		}
	})
}
