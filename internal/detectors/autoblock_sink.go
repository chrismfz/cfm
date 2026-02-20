package detectors

import (
    "net"
    "regexp"
    "sync"
    "time"
    "fmt"
    "context"

    core "cfm/internal/detectors/core"
    "cfm/internal/firewall"
    "cfm/internal/enrich"
    "cfm/internal/logging"
    "cfm/internal/notify"

    "strings"

)

type sectionSink struct {
    section string
    pol     blockPolicy
    inner   core.Sink

    fw    firewall.Backend
    mu    sync.Mutex
    last  map[string]time.Time // ip -> last block time (per section)
    enr   *enrich.Enricher
    ignore *IPIgnore // global ignore from [global]
    chalMu    sync.Mutex
    chalState map[string]challengeState
    chalCooldown time.Duration

    chalExclude *ChallengeExclude

}

type challengeState struct {
    Count    int
    LastSeen time.Time

    // Suppressed re-triggers within cooldown (for summary only)
    Suppressed int
    SuppFirstURI string
    SuppLastURI  string

}




func newSectionSink(section string, pol blockPolicy, inner core.Sink, fw firewall.Backend, enr *enrich.Enricher, ig *IPIgnore, chalCooldown time.Duration, chalExclude *ChallengeExclude) core.Sink {
    return &sectionSink{
        section: section,
        pol:     pol,
        inner:   inner,
        fw:      fw,
        last:    make(map[string]time.Time),
        enr:     enr,
        ignore:  ig,
        chalState: make(map[string]challengeState),
        chalCooldown: chalCooldown,
        chalExclude: chalExclude,
    }
}


const (
    defaultChallengeTTL        = 30 * time.Minute
    defaultChallengeFailWindow = 30 * time.Minute
    defaultChallengeFailN      = 5
    defaultChallengeEscalate   = false
)


var reIP = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)

func (s *sectionSink) Publish(a core.Alert) {
    // Default outcome
    out := a
    if out.Extra == nil {
        out.Extra = map[string]string{}
    }
    out.Extra["blocked"] = "no"

    // --- pick & decorate IP EARLY so every path (even early returns) gets enrichment ---
    ipStr := s.pickIP(a)
    if ipStr != "" {
        out.Extra["src_ip"] = ipStr
        // set the key that the logger prints after the comma in the "Type: ..." line
        out.Key = s.decorateIP(ipStr)
    }

    // DEBUG: log what the sink finally decided to use before any early returns
    if logging.DebugEnabled() {
        logging.LogfDETECTOR("[autoblock][debug] section=%s mode=%s picked_ip=%q kind=%s key=%q",
            s.section, s.pol.Mode, ipStr, a.Kind, out.Key)
    }
    // DEBUG END

    // --- Global ignore για IPs / subnets από [global] IGNORE_IPS / IGNORE_NETS ---
    // Αν το επιλεγμένο IP είναι σε ignore list, δεν προχωράμε σε block/cooldown/notify.
    if s.ignore != nil && ipStr != "" && s.ignore.ShouldIgnore(ipStr) {
        out.Extra["blocked"] = "no"
        out.Extra["reason"]  = "ignored_global_ip"

        if logging.DebugEnabled() {
            logging.LogfDETECTOR("[autoblock] ignoring alert for %s (section=%s kind=%s) due to global ignore list",
                ipStr, s.section, a.Kind)
        }

        // Αν LOG_IGNORED=yes (global), τότε μόνο το γράφουμε στο inner sink (logfile).
        if s.inner != nil && s.ignore.LogIgnoredReports() {
            s.inner.Publish(out)
        }

        // Σε κάθε περίπτωση κόβουμε εδώ: δεν προχωράμε σε block / cooldown / notify.
        return
    }

    // No policy or no backend → just print with "No"
    // BUT: in OpenResty mode we may still enforce WEB/CHALLENGE via nginxBridge even if fw is nil.
    if s.pol.Mode == "no" || (s.fw == nil && nginxBridge == nil) {
        smp := out.Samples
        if len(smp) > 10 { smp = smp[:10] }
        notify.Enqueue(notify.Event{
            Kind:     string(a.Kind),
            Section:  s.section,
            SrcIP:    ipStr, // may be ""
            Reason:   firstNonEmpty(a.Extra["reason"], string(a.Kind)),
            Count:    a.Count,
            When:     a.When,
            Severity: "warn",
            Samples:  smp,
            Extra:    map[string]string{"key": a.Key},
        })
        if s.inner != nil { s.inner.Publish(out) }
        return
    }

    if ipStr == "" {
        smp := out.Samples
        if len(smp) > 10 { smp = smp[:10] }
        notify.Enqueue(notify.Event{
            Kind:     string(a.Kind),
            Section:  s.section,
            SrcIP:    "", // unknown
            Reason:   firstNonEmpty(a.Extra["reason"], string(a.Kind)),
            Count:    a.Count,
            When:     a.When,
            Severity: "warn",
            Samples:  smp,
            Extra:    map[string]string{"key": a.Key},
        })
        if s.inner != nil { s.inner.Publish(out) }
        return
    }

    // --- ignore loopback addresses (127.0.0.0/8, ::1) ---
    // Parse once (used by self/loopback and firewall add)
    ip := net.ParseIP(ipStr)
    if ip == nil {
        if s.inner != nil { s.inner.Publish(out) }
        return
    }

    // --- ignore SELF IPs (all local interface addresses) ---
if core.IsSelfIP(ipStr) {
        out.Extra["blocked"] = "no"
        out.Extra["reason"]  = "ignored_self_ip"

        if logging.DebugEnabled() {
            logging.LogfDETECTOR("[autoblock] ignoring SELF ip=%s (section=%s kind=%s)", ipStr, s.section, a.Kind)
        }

        // Keep the log record so you can debug why it happened
        if s.inner != nil { s.inner.Publish(out) }
        return
    }

    // --- ignore loopback addresses (127.0.0.0/8, ::1) ---
    if ip.IsLoopback() {
        out.Extra["blocked"] = "no"
        out.Extra["reason"]  = "ignored_loopback"
        if s.inner != nil { s.inner.Publish(out) }
        return
    }



    // --- CHALLENGE branch ---
    // Triggered when detector emits Extra["action"]="challenge"
    if out.Extra != nil && out.Extra["action"] == "challenge" {

        // --- Challenge exclude / whitelist (ASN+UA+PTR combos etc.) ---
        if s.chalExclude != nil {
            host := strings.TrimSpace(out.Extra["host"])
            rule := strings.TrimSpace(out.Extra["rule"])
            ua := strings.TrimSpace(out.Extra["ua"])
            if ua == "" {
                ua = extractUserAgent(out.Samples)
            }
            asn := ""
            ptr := ""
            if s.enr != nil {
                r := s.enr.Lookup(ipStr)
                if r.ASN > 0 {
                    asn = fmt.Sprintf("AS%d", r.ASN)
                }
                if r.PTR != "" {
                    ptr = r.PTR
                }
            }
            if ptr == "" {
                // fallback (bounded timeout)
                ptr = lookupPTR(ipStr)
            }

            if act, why, ok := s.chalExclude.Match(ipStr, host, ua, asn, ptr, rule); ok {
                // Action may suppress all challenges or only vhost-wide ones.
                if act == "skip" || act == "skip_vhost_only" {
                    out.Extra["blocked"]  = "challenge"
                    out.Extra["enforced"] = "challenge_suppressed"
                    out.Extra["reason"]   = "excluded"
                    out.Extra["exclude"]  = why

                    if out.Extra["challenge_log"] != "0" && out.Extra["challenge_log_suppressed"] == "1" {
                        logging.LogfCHALLENGES(
                            "[challenge] ip=%s rule=%s host=%s uri=%s ttl=%s enforced=%s reason=%s exclude=%s%s",
                            ipStr,
                            firstNonEmpty(out.Extra["rule"], "WEB/CHALLENGE"),
                            out.Extra["host"],
                            out.Extra["uri"],
                            firstNonEmpty(out.Extra["ttl"], defaultChallengeTTL.String()),
                            out.Extra["enforced"],
                            out.Extra["reason"],
                            out.Extra["exclude"],
                            s.challengeEnrichSuffix(ipStr),
                        )
                    }

                    // Optional notify (audit) — gated by challenge_notify flag.
                    if out.Extra["challenge_notify"] != "0" {
                        smp := out.Samples
                        if len(smp) > 10 { smp = smp[:10] }
                        notify.Enqueue(notify.Event{
                            Kind:     "WEB/CHALLENGE_EXCLUDED",
                            Section:  s.section,
                            SrcIP:    ipStr,
                            Reason:   why,
                            Count:    out.Count,
                            When:     time.Now(),
                            Severity: "info",
                            Samples:  smp,
                            Extra: map[string]string{
                                "rule": rule,
                                "host": host,
                                "ua":   ua,
                                "asn":  asn,
                                "ptr":  ptr,
                                "key":  a.Key,
                            },
                        })
                    }

                    if s.inner != nil { s.inner.Publish(out) }
                    return
                }
            }
        }


        // TTL (alert override -> default)
        ttl := defaultChallengeTTL
        if t := out.Extra["ttl"]; t != "" {
            if d, err := time.ParseDuration(t); err == nil && d > 0 {
                ttl = d
            }
        }

enrSuffix := s.challengeEnrichSuffix(ipStr)

        // Global challenge cooldown per IP (prevents loops/spam)
        if s.chalCooldown > 0 {
            now := out.When
            if now.IsZero() { now = time.Now() }

            suppressed := func() bool {
                s.chalMu.Lock()
                defer s.chalMu.Unlock()

                st := s.chalState[ipStr]
                if !st.LastSeen.IsZero() && now.Sub(st.LastSeen) < s.chalCooldown {
                    // Suppress re-challenge within cooldown window
                    out.Extra["blocked"]  = "challenge"
                    out.Extra["enforced"] = "challenge_suppressed"
                    out.Extra["ttl"]      = ttl.String()
                    out.Extra["cooldown"] = s.chalCooldown.String()

                    // Track suppressed count for optional summary
                    st.Suppressed++
                    if st.SuppFirstURI == "" {
                        st.SuppFirstURI = out.Extra["uri"]
                    }
                    st.SuppLastURI = out.Extra["uri"]
                    s.chalState[ipStr] = st

                    return true
                }
                return false
            }()

            if suppressed {
                if out.Extra["challenge_log"] != "0" && out.Extra["challenge_log_suppressed"] == "1" {
                    logging.LogfCHALLENGES(
                        "[challenge] ip=%s rule=%s host=%s uri=%s ttl=%s enforced=%s cooldown=%s%s",
                        ipStr,
                        firstNonEmpty(out.Extra["rule"], "WEB/CHALLENGE"),
                        out.Extra["host"],
                        out.Extra["uri"],
                        ttl.String(),
                        out.Extra["enforced"],
                        out.Extra["cooldown"],
                        enrSuffix,
                    )
                }
                if s.inner != nil { s.inner.Publish(out) }
                return
            }
        }


// If we suppressed repeated triggers during cooldown, emit one summary now (optional).
if s.chalCooldown > 0 {
    s.chalMu.Lock()
    st := s.chalState[ipStr]
    // Only log summary if enabled explicitly; otherwise just reset counters silently.
    if st.Suppressed > 0 {
        if out.Extra["challenge_log"] != "0" && out.Extra["challenge_log_suppressed"] == "1" {
            logging.LogfCHALLENGES(
                "[challenge] ip=%s rule=%s host=%s suppressed_count=%d first_uri=%s last_uri=%s window=%s%s",
                ipStr,
                firstNonEmpty(out.Extra["rule"], "WEB/CHALLENGE"),
                out.Extra["host"],
                st.Suppressed,
                st.SuppFirstURI,
                st.SuppLastURI,
                s.chalCooldown.String(),
                enrSuffix,
            )
        }
        st.Suppressed = 0
        st.SuppFirstURI = ""
        st.SuppLastURI = ""
        s.chalState[ipStr] = st
    }
    s.chalMu.Unlock()
}

// Enforce challenge (no block here)
enforced := "challenge_failed"
if s.pol.Mode == "dryrun" {
    enforced = "challenge_dryrun"
} else {
    // OpenResty mode: enforce via nginx bridge, not nft backend.
    if nginxBridge != nil {
        nginxBridge.ChallengeIP(ipStr, ttl)
        enforced = "challenge"
        out.Extra["enforced_via"] = "nginx_bridge"
    } else {
        if s.fw != nil {
            if err := s.fw.AddChallenge(ip, &ttl); err == nil {
                enforced = "challenge"
            } else {
                out.Extra["challenge_err"] = err.Error()
            }
        } else {
            // Should not happen due to earlier guard, but keep safe behavior.
            out.Extra["challenge_err"] = "no_firewall_backend"
        }
    }

}

// stamp cooldown only if challenge enforcement succeeded
if enforced == "challenge" && s.chalCooldown > 0 {
    now := out.When
    if now.IsZero() { now = time.Now() }

    s.chalMu.Lock()
    defer s.chalMu.Unlock()
    st := s.chalState[ipStr]
    st.LastSeen = now
    s.chalState[ipStr] = st
}



        // Mark outcome for outcome_sink + detector log
        out.Extra["blocked"]    = "challenge"
        out.Extra["block_mode"] = "ttl"
        out.Extra["ttl"]        = ttl.String()
        out.Extra["enforced"]   = enforced

        // --- Escalation: challenged N times within window => block ---
        // (simple heuristic: repeated challenge alerts means they keep hitting challenge rules)
        if defaultChallengeEscalate && enforced == "challenge" {
            now := out.When
            if now.IsZero() { now = time.Now() }

            s.chalMu.Lock()
            st := s.chalState[ipStr]

            if !st.LastSeen.IsZero() && now.Sub(st.LastSeen) > defaultChallengeFailWindow {
                st.Count = 0
            }
            st.Count++
            st.LastSeen = now
            s.chalState[ipStr] = st
            s.chalMu.Unlock()

            out.Extra["challenge_fails"] = fmt.Sprintf("%d", st.Count)

            if st.Count >= defaultChallengeFailN {
                // Escalate to normal block (TTL block)
                bttl := s.pol.TTL
                if bttl <= 0 { bttl = time.Hour }

                comment := "CHALLENGE_FAIL"
                if r := firstNonEmpty(out.Extra["rule"], out.Extra["reason"], string(out.Kind)); r != "" {
                    comment = "CHALLENGE_FAIL | " + r
                }

                if s.pol.Mode != "dryrun" {
                    if err := s.fw.AddBlock(ip, comment, &bttl); err == nil {
                        out.Extra["escalated"] = "block"
                        out.Extra["block_ttl"] = bttl.String()
                    } else {
                        out.Extra["escalated"] = "block_failed"
                        out.Extra["block_err"] = err.Error()
                    }
                } else {
                    out.Extra["escalated"] = "block_dryrun"
                    out.Extra["block_ttl"] = bttl.String()
                }
            }
        }

        // --- Challenges log file (separate) ---
        if out.Extra["challenge_log"] != "0" {
            logging.LogfCHALLENGES(
                "[challenge] ip=%s rule=%s host=%s uri=%s method=%s status=%s ttl=%s enforced=%s fails=%s escalated=%s%s",
                ipStr,
                firstNonEmpty(out.Extra["rule"], "WEB/CHALLENGE"),
                out.Extra["host"],
                out.Extra["uri"],
                out.Extra["method"],
                out.Extra["status"],
                ttl.String(),
                out.Extra["enforced"],
                out.Extra["challenge_fails"],
                out.Extra["escalated"],
                enrSuffix,
            )
        }

        // --- Notify (same notify system) ---
        if out.Extra["challenge_notify"] != "0" {
            smp := out.Samples
            if len(smp) > 10 { smp = smp[:10] }
            notify.Enqueue(notify.Event{
                Kind:     "WEB/CHALLENGE",
                Section:  s.section,
                SrcIP:    ipStr,
                Reason:   firstNonEmpty(out.Extra["rule"], out.Extra["reason"], "WEB/CHALLENGE"),
                TTL:      ttl,
                Count:    out.Count,
                When:     time.Now(),
                Severity: "info",
                Samples:  smp,
                Extra: map[string]string{
                    "rule":      out.Extra["rule"],
                    "host":      out.Extra["host"],
                    "uri":       out.Extra["uri"],
                    "method":    out.Extra["method"],
                    "status":    out.Extra["status"],
                    "enforced":  out.Extra["enforced"],
                    "fails":     out.Extra["challenge_fails"],
                    "escalated": out.Extra["escalated"],
                    "ttl_text":  out.Extra["ttl"],
                    "key":       a.Key,
                },
            })
        }

        // Publish final outcome once (like blocks) and exit.
        if s.inner != nil { s.inner.Publish(out) }
        return
    }
    // --- end CHALLENGE branch ---



    // Cooldown check (do NOT stamp yet; stamp only after a real block)
    if s.pol.Cooldown > 0 {

        skip := func() bool {
            s.mu.Lock()
            defer s.mu.Unlock()
            if last, ok := s.last[ipStr]; ok && time.Since(last) < s.pol.Cooldown {
                return true
            }
            return false
        }()
        if skip {
            if s.inner != nil { s.inner.Publish(out) }
            return
        }
    }

    // Comment for firewall
    comment := string(a.Kind)
    if s.section != "" {
        comment += " | " + s.section
    }
    if a.Key != "" && a.Key != ipStr {
        comment += " | " + a.Key
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
        defer s.mu.Unlock()
        s.last[ipStr] = time.Now()
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
            Kind:     string(a.Kind),      // e.g. "SSH/AUTHFAIL", "MYSQL/ROOT_DENIED", "MODSEC/403"
            SrcIP:    ipStr,              // from pickIP(a)
            Reason:   string(a.Kind),     // e.g. "SSH/AUTHFAIL"
            TTL:      time.Duration(ttlSec) * time.Second,
            Count:    a.Count,
            Section:  s.section,          // detectors.conf section name
            When:     time.Now(),
            Severity: "warning",
            Samples:  smp,
            Extra: map[string]string{
                "block_mode": out.Extra["block_mode"], // "ttl" | "permanent"
                "ttl_text":   out.Extra["ttl"],        // e.g. "4h0m0s"
                "key":        a.Key,                   // detector-specific key
            },
        }

        notify.Enqueue(ev)

        // Also report to API via firewall backend policy
        if err := s.fw.ReportBlock(ipStr, comment, "detector", out.Extra["block_mode"], ttlSec); err != nil {
            logging.Logf("[detectors] ReportBlock(detector) failed for %s: %v (mode=%s ttl=%ds)",
                ipStr, err, out.Extra["block_mode"], ttlSec)
        }
    }
    // --- end notify ---

    // --- emit notify for NON-blocked events as well ---
    if out.Extra["blocked"] != "yes" {
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
            Extra: map[string]string{
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
    // 0) Prefer detector-provided IP (authoritative).
    if a.Extra != nil {
        if ip := net.ParseIP(strings.TrimSpace(a.Extra["ip"])); ip != nil {
            return ip.String()
        }
    }
    // 1) If alert key itself is an IP, or "ip X..." (from decorateIP), use it.
    if ip := net.ParseIP(a.Key); ip != nil {
        return ip.String()
    }
    if strings.HasPrefix(a.Key, "ip ") {
        // e.g. "ip 91.138.225.80 (AS...)" or "ip 91.138.225.80 [ASN ...]"
        f := strings.Fields(a.Key)
        if len(f) >= 2 {
            // strip trailing punctuation just in case
            cand := strings.TrimRight(f[1], "],)")
            if ip := net.ParseIP(cand); ip != nil {
                return ip.String()
            }
        }
    }
    // 2) Fallback: scan samples like the detector does (right-most bracket, prefer public).
    for _, ln := range a.Samples {
        if ip := rightMostBracketIP(ln); ip != "" {
            return ip
        }
        // last resort: first IPv4 in line
        if m := reIP.FindStringSubmatch(ln); m != nil && m[1] != "" {
            return m[1]
        }
        // ultimate fallback: token scan (IPv4/IPv6)
        if ip := firstParsedIP(ln); ip != "" {
            return ip
        }
    }
    return ""
}

// tokenize and return the first token that parses as an IP (v4 or v6)
func firstParsedIP(s string) string {
    // split on anything that's not a hex digit, dot, or colon
    f := func(r rune) bool {
        if r == '.' || r == ':' { return false }
        if (r >= '0' && r <= '9') || (r|32 >= 'a' && r|32 <= 'f') { return false }
        return true
    }
    for _, tok := range strings.FieldsFunc(s, f) {
        if ip := net.ParseIP(tok); ip != nil {
            return ip.String()
        }
    }
    return ""
}

// rightMostBracketIP replicates the detector’s selection:
// choose the right-most [ ... ] token; prefer global/public; supports IPv4 & IPv6 and IPv6-mapped v4.
func rightMostBracketIP(line string) string {
    type span struct{ lo, hi int }
    spans := make([]span, 0, 4)
    for i := 0; i < len(line); i++ {
        if line[i] != '[' { continue }
        j := strings.IndexByte(line[i:], ']')
        if j <= 1 { continue }
        lo, hi := i+1, i+j
        if lo < hi && hi <= len(line) {
            spans = append(spans, span{lo: lo, hi: hi})
        }
        i += j
    }
    if len(spans) == 0 { return "" }

    parseCanonical := func(s string) (net.IP, string) {
        s = strings.TrimSpace(s)
        if strings.Count(s, ":") >= 2 {
            if k := strings.LastIndexByte(s, ':'); k >= 0 && k+1 < len(s) {
                if v4 := net.ParseIP(s[k+1:]); v4 != nil {
                    if q := v4.To4(); q != nil { return q, q.String() }
                }
            }
        }
        ip := net.ParseIP(s)
        if ip == nil { return nil, "" }
        if v4 := ip.To4(); v4 != nil { return v4, v4.String() }
        return ip, ip.String()
    }
    isGlobal := func(ip net.IP) bool {
        if ip == nil { return false }
        if v4 := ip.To4(); v4 != nil {
            if v4[0] == 10 { return false }
            if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 { return false }
            if v4[0] == 192 && v4[1] == 168 { return false }
            if v4[0] == 169 && v4[1] == 254 { return false }
            if v4[0] == 127 { return false }
            return true
        }
        if ip.IsLoopback() { return false }
        if ip[0]&0xfe == 0xfc { return false }                        // fc00::/7
        if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 { return false }     // fe80::/10
        return true
    }
    // Pass 1: prefer right-most global
    for i := len(spans) - 1; i >= 0; i-- {
        ip, canon := parseCanonical(line[spans[i].lo:spans[i].hi])
        if canon != "" && isGlobal(ip) { return canon }
    }
    // Pass 2: right-most valid
    for i := len(spans) - 1; i >= 0; i-- {
        _, canon := parseCanonical(line[spans[i].lo:spans[i].hi])
        if canon != "" { return canon }
    }
    return ""
}

func firstNonEmpty(ss ...string) string {
    for _, s := range ss {
        if strings.TrimSpace(s) != "" { return s }
    }
    return ""
}

func lookupPTR(ip string) string {
    ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
    defer cancel()
    names, _ := net.DefaultResolver.LookupAddr(ctx, ip)
    if len(names) > 0 { return strings.TrimSuffix(names[0], ".") }
    return ""
}

func (s *sectionSink) decorateIP(ip string) string {
    label := ip

    // Prefer the injected enricher if available
    if s.enr != nil {
        r := s.enr.Lookup(ip)
        parts := []string{}
        if r.ASN > 0 {
            if r.ASNName != "" {
                parts = append(parts, fmt.Sprintf("%d %s", r.ASN, r.ASNName))
            } else {
                parts = append(parts, fmt.Sprintf("%d", r.ASN))
            }
        }
        if r.Country != "" {
            parts = append(parts, r.Country)
        }
        if len(parts) > 0 {
            label += " [" + strings.Join(parts, " ") + "]"
        }
        // PTR from enricher if present; else fall back below
        if r.PTR != "" {
            if strings.Contains(label, "[") {
                label = strings.TrimSuffix(label, "]") + "; PTR " + r.PTR + "]"
            } else {
                label += " [[PTR " + r.PTR + "]]"
            }
            return label
        }
    }

    // PTR fallback (no enricher or PTR not found)
    if ptr := lookupPTR(ip); ptr != "" {
        if strings.Contains(label, "[") {
            label = strings.TrimSuffix(label, "]") + "; PTR " + ptr + "]"
        } else {
            label += " [[PTR " + ptr + "]]"
        }
    }
    return label
}





// challengeEnrichSuffix returns: ` - (AS16509 Amazon.com, Inc., Singapore)`
// or "" if enrichment is unavailable.
func (s *sectionSink) challengeEnrichSuffix(ip string) string {
    ip = strings.TrimSpace(ip)
    if ip == "" || s.enr == nil {
        return ""
    }
    r := s.enr.Lookup(ip)
    parts := []string{}

    // AS first
    if r.ASN > 0 {
        if r.ASNName != "" {
            parts = append(parts, fmt.Sprintf("AS%d %s", r.ASN, r.ASNName))
        } else {
            parts = append(parts, fmt.Sprintf("AS%d", r.ASN))
        }
    }
    // Country next (you can swap ordering if you want)
    if r.Country != "" {
        parts = append(parts, r.Country)
    }

    if len(parts) == 0 {
        return ""
    }
    return " - (" + strings.Join(parts, ", ") + ")"
}



// extractUserAgent tries to pull a User-Agent from common combined log samples.
// Best-effort only.
func extractUserAgent(samples []string) string {
    // Best-effort:
    // 1) TSV samples (webdetector): UA is usually the last TAB-separated column
    // 2) Apache/Nginx combined logs: last quoted segment is UA: "ref" "ua"
    for i := len(samples) - 1; i >= 0; i-- {
        ln := strings.TrimSpace(samples[i])
        if ln == "" {
            continue
        }

        // --- (1) TSV mode ---
        if strings.Contains(ln, "\t") {
            cols := strings.Split(ln, "\t")
            if len(cols) > 0 {
                ua := strings.TrimSpace(cols[len(cols)-1])
                if ua != "" && ua != "-" {
                    return ua
                }
            }
        }


        // --- (2) Quoted combined log mode ---
        segs := make([]string, 0, 4)
        in := false
        start := 0
        for j := 0; j < len(ln); j++ {
            if ln[j] == '"' {
                if !in {
                    in = true
                    start = j + 1
                } else {
                    if start <= j {
                        segs = append(segs, ln[start:j])
                    }
                    in = false
                }
            }
        }
        if len(segs) >= 1 {
            ua := strings.TrimSpace(segs[len(segs)-1])
            if ua != "" && ua != "-" {
                return ua
            }
        }
    }
    return ""
}
