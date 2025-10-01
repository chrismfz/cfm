package detectors

import (
    "net"
    "regexp"
    "sync"
    "time"

    core "cfm/internal/detectors/core"
    "cfm/internal/firewall"
//    "cfm/internal/logging"

//for notifications//
    "strings"
//    "fmt"
    "cfm/internal/notify"

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


    // --- ignore loopback addresses (127.0.0.0/8, ::1) ---
    if ip := net.ParseIP(ipStr); ip != nil && (ip.IsLoopback()) {
        out.Extra["blocked"] = "no"
        out.Extra["reason"]  = "ignored_loopback"
        if s.inner != nil { s.inner.Publish(out) }
        return
    }


    // Cooldown check (do NOT stamp yet; stamp only after a real block)
    if s.pol.Cooldown > 0 {
        s.mu.Lock()
        if last, ok := s.last[ipStr]; ok && time.Since(last) < s.pol.Cooldown {
            s.mu.Unlock()
            if s.inner != nil { s.inner.Publish(out) }
            return
        }
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

    var blockOK bool
	switch s.pol.Mode {
	case "dryrun":
		out.Extra["blocked"]    = "dryrun"
		out.Extra["block_mode"] = "dryrun"

	case "permanent":
		if err := s.fw.AddBlock(ip, comment, nil); err == nil {
			out.Extra["blocked"]    = "yes"
			out.Extra["block_mode"] = "permanent"
			blockOK = true
		}

	case "ttl":
		ttl := s.pol.TTL
		if ttl <= 0 { ttl = time.Hour }
		if err := s.fw.AddBlock(ip, comment, &ttl); err == nil {
			out.Extra["blocked"]    = "yes"
			out.Extra["block_mode"] = "ttl"
			out.Extra["ttl"]        = ttl.String()
			blockOK = true
		}
	}



    // If we truly blocked and a cooldown is set, stamp it now (after success)
    if blockOK && s.pol.Cooldown > 0 {
        s.mu.Lock()
        s.last[ipStr] = time.Now()
        s.mu.Unlock()
    }


// --- emit notify once if a real block happened ---
if out.Extra["blocked"] == "yes" {
    // compute TTL seconds only for ttl blocks
    ttlSec := 0
    if out.Extra["block_mode"] == "ttl" {
        if d, err := time.ParseDuration(out.Extra["ttl"]); err == nil {
            ttlSec = int(d / time.Second)
        }
    }

    // cap samples to first 10 lines
    smp := out.Samples
    if len(smp) > 10 {
        smp = smp[:10]
    }

    ev := notify.Event{
        Kind:     string(a.Kind),       //  e.g. "SSH/AUTHFAIL", "MYSQL/ROOT_DENIED", "MODSEC/403"
        SrcIP:    ipStr,            // from pickIP(a)
        Reason:   string(a.Kind),   // e.g. "SSH/AUTHFAIL" (your detector kind)
        TTL:      time.Duration(ttlSec) * time.Second,
        Count:    a.Count,                // (optional) put any counters in Extra if you want
        Section:  s.section,        // detectors.conf section name
        When:     time.Now(),
        Severity: "warning",
        Samples:  smp,
        Extra: map[string]string{
            "block_mode": out.Extra["block_mode"], // "ttl" | "permanent"
            "ttl_text":   out.Extra["ttl"],        // e.g. "4h0m0s" if ttl
            "key":        a.Key,                   // detector-specific key (may be same as IP)
        },
    }




    notify.Enqueue(ev) // non-blocking; templates will include host + ASN, Country if set


    // Also report to API via firewall backend policy (respects DETECTORS_SEND_TO_API & fallbacks)
    _ = s.fw.ReportBlock(ipStr, comment, "detector", out.Extra["block_mode"], ttlSec)

}
// --- end notify ---

// --- [NEW] emit notify for NON-blocked events as well ---
if out.Extra["blocked"] != "yes" {
    // Optional: pick an IP if υπάρχει (health συνήθως δεν έχει)
    ipStr := s.pickIP(a)

    // cap samples to first 10 lines
    smp := out.Samples
    if len(smp) > 10 { smp = smp[:10] }

    ev := notify.Event{
        Kind:     string(a.Kind),      // π.χ. "HEALTH/SYN_RECV_SPIKE"
        Section:  s.section,           // κρίσιμο για το [detector "health"] routing
        SrcIP:    ipStr,               // μπορεί να είναι ""
        Reason:   firstNonEmpty(a.Extra["reason"], string(a.Kind)),
        Count:    a.Count,
        When:     a.When,              // ή time.Now()
        Severity: "warn",              // ή "info" ανάλογα το health sub-event
        Samples:  smp,
        Extra:    map[string]string{
            "key": a.Key,
        },
    }
    notify.Enqueue(ev)
}
// --- end NEW ---





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

func firstNonEmpty(ss ...string) string {
    for _, s := range ss {
        if strings.TrimSpace(s) != "" { return s }
    }
    return ""
}
