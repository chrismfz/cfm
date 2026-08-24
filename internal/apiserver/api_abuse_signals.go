package apiserver

import (
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

type apiAbuseEvent struct {
	Name   string
	Signal string
	Count  int
	Scope  string
}

type ttlCounter struct {
	count     int
	expiresAt time.Time
}

type apiAbuseSignalClassifier struct {
	mu       sync.Mutex
	now      func() time.Time
	counters map[string]ttlCounter
}

func newAPIAbuseSignalClassifier() *apiAbuseSignalClassifier {
	return &apiAbuseSignalClassifier{
		now:      time.Now,
		counters: make(map[string]ttlCounter),
	}
}

func (c *apiAbuseSignalClassifier) Evaluate(r *http.Request, status int, reason string) []apiAbuseEvent {
	if r == nil {
		return nil
	}
	ip := realIPFromRequest(r)
	ua := strings.TrimSpace(r.UserAgent())
	ipUA := ip + "|" + ua
	path := strings.ToLower(r.URL.Path)

	var events []apiAbuseEvent
	if (status == http.StatusNotFound || reason == "route_not_found") && c.crossed("unknown|"+ipUA, 20*time.Second, 8) {
		events = append(events, apiAbuseEvent{Name: "api_probe", Signal: "unknown_endpoint_burst", Count: c.count("unknown|" + ipUA), Scope: "ip+ua"})
	}
	if (status == http.StatusMethodNotAllowed || reason == "method_not_allowed") && c.crossed("method|"+ip, 25*time.Second, 4) {
		events = append(events, apiAbuseEvent{Name: "api_probe", Signal: "method_mismatch_burst", Count: c.count("method|" + ip), Scope: "ip"})
	}
	if isSensitiveProbePath(path) && c.crossed("sensitive|"+ip, 30*time.Second, 3) {
		events = append(events, apiAbuseEvent{Name: "api_probe", Signal: "sensitive_path_probe", Count: c.count("sensitive|" + ip), Scope: "ip"})
	}
	if looksLikeFuzzPath(path) && c.crossed("fuzz|"+ipUA, 30*time.Second, 3) {
		events = append(events, apiAbuseEvent{Name: "api_fuzz", Signal: "path_entropy_or_fuzz", Count: c.count("fuzz|" + ipUA), Scope: "ip+ua"})
	}
	if reason != "direct_auth_event" && (status == http.StatusUnauthorized || status == http.StatusForbidden) && c.crossed("unauth|"+ipUA, 30*time.Second, 5) {
		events = append(events, apiAbuseEvent{Name: "api_unauthorized_burst", Signal: "unauthorized_burst", Count: c.count("unauth|" + ipUA), Scope: "ip+ua"})
	}

	return events
}

func (c *apiAbuseSignalClassifier) crossed(key string, ttl time.Duration, threshold int) bool {
	if threshold <= 0 {
		return false
	}
	count := c.increment(key, ttl)
	if count < threshold {
		return false
	}
	return count%threshold == 0
}

func (c *apiAbuseSignalClassifier) increment(key string, ttl time.Duration) int {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	item := c.counters[key]
	if item.expiresAt.Before(now) {
		item = ttlCounter{}
	}
	item.count++
	item.expiresAt = now.Add(ttl)
	c.counters[key] = item
	return item.count
}

func (c *apiAbuseSignalClassifier) count(key string) int {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	item := c.counters[key]
	if item.expiresAt.Before(now) {
		delete(c.counters, key)
		return 0
	}
	return item.count
}

func (c *apiAbuseSignalClassifier) pruneLocked(now time.Time) {
	for k, v := range c.counters {
		if v.expiresAt.Before(now) {
			delete(c.counters, k)
		}
	}
}

func isSensitiveProbePath(path string) bool {
	for _, marker := range []string{
		"/.env", "/.git", "/.aws", "/.svn", "/actuator", "/admin", "/wp-admin", "/phpmyadmin", "/server-status", "/boaform", "/jmx-console",
	} {
		if path == marker || strings.HasPrefix(path, marker+"/") {
			return true
		}
	}
	return false
}

func looksLikeFuzzPath(path string) bool {
	if strings.Contains(path, "../") || strings.Contains(path, "%2e%2e") || strings.Contains(path, "%00") {
		return true
	}
	for _, sig := range []string{"<script", "union+select", "or+1=1", "${jndi", "%3cscript", "' or '1'='1"} {
		if strings.Contains(path, sig) {
			return true
		}
	}
	parts := strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '-' || r == '_' || r == '.' })
	for _, p := range parts {
		if len(p) >= 16 && shannonEntropy(p) >= 3.6 {
			return true
		}
	}
	return false
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	var entropy float64
	length := float64(len(s))
	for _, n := range freq {
		p := n / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}
