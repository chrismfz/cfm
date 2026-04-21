package notify

import (
	"fmt"
	"strings"
	"time"
)

type TestDeliveryResult struct {
	Channel          string    `json:"channel"`
	AttemptedAt      time.Time `json:"attempted_at"`
	Status           string    `json:"status"`
	Success          bool      `json:"success"`
	Error            string    `json:"error,omitempty"`
	DeliveryDuration string    `json:"delivery_duration"`
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
	return sendToNamedChannels(c, ev, subj, body, channels), nil
}

func sendToNamedChannels(c *config, ev Event, subj, body string, channels []string) []TestDeliveryResult {
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
		res := TestDeliveryResult{
			Channel:     name,
			AttemptedAt: start.UTC(),
			Status:      "failure",
			Success:     false,
		}
		if match == nil {
			res.Error = "channel not found or disabled"
			res.DeliveryDuration = time.Since(start).String()
			results = append(results, res)
			continue
		}
		if _, ok := wanted[strings.ToLower(name)]; !ok {
			continue
		}
		if err := match.Send(ev, subj, body); err != nil {
			res.Error = err.Error()
			res.DeliveryDuration = time.Since(start).String()
			results = append(results, res)
			continue
		}
		res.Status = "success"
		res.Success = true
		res.DeliveryDuration = time.Since(start).String()
		results = append(results, res)
	}
	return results
}
