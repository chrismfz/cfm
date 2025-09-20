package detectors

import (
    "net"
    "regexp"
    "sync"
    "time"

    core "cfm/internal/detectors/core"
    "cfm/internal/firewall"
//    "cfm/internal/logging"
)

type sectionSink struct {
    section string
    pol     blockPolicy
    inner   core.Sink

    fw   firewall.Backend
    mu   sync.Mutex
    last map[string]time.Time // ip -> last block time (per section)
}


func newSectionSink(section string, pol blockPolicy, inner core.Sink, fw firewall.Backend) core.Sink {
    return &sectionSink{
        section: section,
        pol:     pol,
        inner:   inner,
        fw:      fw,
        last:    make(map[string]time.Time),
    }
}


var reIP = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)


func (s *sectionSink) Publish(a core.Alert) {
	// Default outcome
	out := a
	if out.Extra == nil {
		out.Extra = map[string]string{}
	}
	out.Extra["blocked"] = "no"

	// No policy or no backend → just print with "No"
	if s.pol.Mode == "no" || s.fw == nil {
		if s.inner != nil { s.inner.Publish(out) }
		return
	}

	ipStr := s.pickIP(a)
	if ipStr == "" {
		// No actionable IP → still print with "No"
		if s.inner != nil { s.inner.Publish(out) }
		return
	}

	// Cooldown
	if s.pol.Cooldown > 0 {
		s.mu.Lock()
		if last, ok := s.last[ipStr]; ok && time.Since(last) < s.pol.Cooldown {
			s.mu.Unlock()
			// Suppressed by cooldown → still print with "No"
			if s.inner != nil { s.inner.Publish(out) }
			return
		}
		s.last[ipStr] = time.Now()
		s.mu.Unlock()
	}

	// Comment for firewall
	comment := string(a.Kind)
	if s.section != "" {
		comment += " | " + s.section
	}
	if a.Key != "" && a.Key != ipStr {
		comment += " | " + a.Key
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		if s.inner != nil { s.inner.Publish(out) }
		return
	}

	switch s.pol.Mode {
	case "dryrun":
		out.Extra["blocked"]    = "dryrun"
		out.Extra["block_mode"] = "dryrun"

	case "permanent":
		if err := s.fw.AddBlock(ip, comment, nil); err == nil {
			out.Extra["blocked"]    = "yes"
			out.Extra["block_mode"] = "permanent"
		}

	case "ttl":
		ttl := s.pol.TTL
		if ttl <= 0 { ttl = time.Hour }
		if err := s.fw.AddBlock(ip, comment, &ttl); err == nil {
			out.Extra["blocked"]    = "yes"
			out.Extra["block_mode"] = "ttl"
			out.Extra["ttl"]        = ttl.String()
		}
	}

	// Now publish ONCE with the final outcome
	if s.inner != nil {
		s.inner.Publish(out)
	}
}



func (s *sectionSink) pickIP(a core.Alert) string {
    // 1) If the alert key itself is an IP (e.g., SSH per-IP alerts), use it.
    if ip := net.ParseIP(a.Key); ip != nil {
        return ip.String()
    }
    // 2) Try to parse the first IP from the samples (works for exim detectors)
    for _, ln := range a.Samples {
        if m := reIP.FindStringSubmatch(ln); m != nil && m[1] != "" {
            return m[1]
        }
    }
    // 3) If detectors stash an ip in Extra["ip"], use it.
    if a.Extra != nil {
        if ip := net.ParseIP(a.Extra["ip"]); ip != nil {
            return ip.String()
        }
    }
    return ""
}
