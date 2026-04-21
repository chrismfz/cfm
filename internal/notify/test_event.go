package notify

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

type TestDeliveryResult struct {
	Channel       string    `json:"channel"`
	AttemptedAt   time.Time `json:"attempted_at"`
	Status        string    `json:"status"`
	Success       bool      `json:"success"`
	Error         string    `json:"error,omitempty"`
	Latency       string    `json:"latency"`
	CorrelationID string    `json:"correlation_id"`
}

func BuildSyntheticTestEvent(detector string, sample map[string]any) Event {
	ev := Event{
		Kind:     "NOTIFIER/TEST",
		Section:  "notifier_test",
		Severity: "info",
		When:     time.Now(),
		Reason:   "Synthetic notifier channel test from CFM admin UI.",
	}
	detector = strings.TrimSpace(detector)
	if detector != "" {
		ev.Extra = map[string]string{"detector": detector}
		ev.Samples = append(ev.Samples, fmt.Sprintf("detector=%s", detector))
	}
	if len(sample) > 0 {
		if ev.Extra == nil {
			ev.Extra = map[string]string{}
		}
		for k, v := range sample {
			key := strings.TrimSpace(k)
			if key == "" {
				continue
			}
			val := strings.TrimSpace(fmt.Sprint(v))
			ev.Extra[key] = val
			ev.Samples = append(ev.Samples, fmt.Sprintf("%s=%s", key, val))
		}
	}
	return ev
}

func BuildSyntheticTestEventFromPayload(payload map[string]any) Event {
	ev := Event{
		Kind:     "NOTIFIER/TEST",
		Section:  "notifier_test",
		Severity: "info",
		When:     time.Now(),
		Reason:   "Synthetic notifier channel test from CFM admin UI.",
	}
	if len(payload) == 0 {
		return ev
	}
	if ev.Extra == nil {
		ev.Extra = map[string]string{}
	}

	for k, v := range payload {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		switch strings.ToLower(key) {
		case "host":
			ev.Host = strings.TrimSpace(fmt.Sprint(v))
		case "srcip", "src_ip":
			ev.SrcIP = strings.TrimSpace(fmt.Sprint(v))
		case "reason":
			ev.Reason = strings.TrimSpace(fmt.Sprint(v))
		case "severity":
			ev.Severity = strings.TrimSpace(fmt.Sprint(v))
		case "kind":
			// Keep Kind fixed for test-history filtering support.
			continue
		default:
			ev.Extra[key] = strings.TrimSpace(fmt.Sprint(v))
		}
	}
	subject := strings.TrimSpace(fmt.Sprint(payload["subject"]))
	if subject != "" {
		ev.Extra["subject"] = subject
	}
	body := strings.TrimSpace(fmt.Sprint(payload["body"]))
	if body != "" {
		ev.Extra["body"] = body
	}
	return ev
}

func SendSyntheticTest(ev Event, channels []string) ([]TestDeliveryResult, error) {
	cfgMu.RLock()
	c := cfg
	cfgMu.RUnlock()
	if c == nil {
		return nil, fmt.Errorf("notifier is not initialized; reload notifier config first")
	}

	if ev.Host == "" {
		ev.Host = hostname
	}
	if ev.When.IsZero() {
		ev.When = time.Now()
	}
	if strings.TrimSpace(ev.Kind) == "" {
		ev.Kind = "NOTIFIER/TEST"
	}
	if strings.TrimSpace(ev.Section) == "" {
		ev.Section = "notifier_test"
	}
	if strings.TrimSpace(ev.Severity) == "" {
		ev.Severity = "info"
	}

	subj, _ := renderSubject(c.SubjectTmpl, ev)
	body, _ := render(c.BodyTmpl, ev)
	if custom := strings.TrimSpace(ev.Extra["subject"]); custom != "" {
		subj = custom
	}
	if custom := strings.TrimSpace(ev.Extra["body"]); custom != "" {
		body = custom
	}
	return sendToNamedChannels(c, ev, subj, body, channels), nil
}

func sendToNamedChannels(c *config, ev Event, subj, body string, channels []string) []TestDeliveryResult {
	correlationID := testCorrelationID()
	wanted := map[string]struct{}{}
	for _, channel := range channels {
		name := strings.ToLower(strings.TrimSpace(channel))
		if name != "" {
			wanted[name] = struct{}{}
		}
	}

	results := make([]TestDeliveryResult, 0, len(channels))
	for _, requested := range channels {
		name := strings.TrimSpace(requested)
		if name == "" {
			continue
		}

		var match Channel
		for _, ch := range c.Channels {
			if strings.EqualFold(strings.TrimSpace(ch.Name()), name) {
				match = ch
				break
			}
		}

		start := time.Now()
		res := TestDeliveryResult{Channel: name, AttemptedAt: start.UTC(), Status: "failure", Success: false, CorrelationID: correlationID}
		if match == nil {
			res.Error = "channel not found or disabled"
			res.Latency = time.Since(start).String()
			appendSyntheticTestHistory(c.JSONLPath, ev, res)
			results = append(results, res)
			continue
		}
		if _, ok := wanted[strings.ToLower(name)]; !ok {
			continue
		}
		if err := match.Send(ev, subj, body); err != nil {
			res.Error = err.Error()
			res.Latency = time.Since(start).String()
			appendSyntheticTestHistory(c.JSONLPath, ev, res)
			results = append(results, res)
			continue
		}
		res.Status = "success"
		res.Success = true
		res.Latency = time.Since(start).String()
		appendSyntheticTestHistory(c.JSONLPath, ev, res)
		results = append(results, res)
	}
	return results
}

func appendSyntheticTestHistory(path string, ev Event, res TestDeliveryResult) {
	_ = appendJSONL(path, map[string]any{
		"time":           res.AttemptedAt.UTC().Format(time.RFC3339Nano),
		"host":           ev.Host,
		"kind":           "NOTIFIER/TEST",
		"srcip":          ev.SrcIP,
		"reason":         ev.Reason,
		"section":        ev.Section,
		"channel":        res.Channel,
		"status":         res.Status,
		"err":            res.Error,
		"latency":        res.Latency,
		"correlation_id": res.CorrelationID,
	})
}

func testCorrelationID() string {
	return fmt.Sprintf("test-%x-%x", time.Now().UTC().UnixNano(), rand.Uint64())
}
