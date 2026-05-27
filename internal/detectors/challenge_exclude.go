
package detectors

import (
    "bufio"
    "context"
    "net"
    "os"
    "strings"
    "time"
)

// ChallengeExclude: suppress challenges for known-good/verified crawlers or trusted partners.
//
// File format (one rule per line):
//   ua=*googlebot*; ptr=*.googlebot.com; verify_fcrdns=1; action=skip
//   asn=32934; ua=meta*; action=skip
//   asn=AS8874; action=skip_vhost_only
//
// Supported keys: ua, asn, ptr, host, verify_fcrdns, action, mode
//   - action: skip | skip_vhost_only
//   - mode:   all | any   (default all)
//   - verify_fcrdns=1: require forward-confirmed reverse DNS for ptr match
//
// Matching is case-insensitive. Values are glob patterns using '*' and '?'.
type ChallengeExclude struct {
    rules []challengeExcludeRule
}

type challengeExcludeRule struct {
    raw    string
    ua     string
    asn    string
    ptr    string
    host   string
    modeAny bool
    verifyFcrdns bool
    action string // skip | skip_vhost_only
}

func LoadChallengeExclude(path string) (*ChallengeExclude, error) {
    path = strings.TrimSpace(path)
    if path == "" {
        return nil, nil
    }
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    ce := &ChallengeExclude{}
    sc := bufio.NewScanner(f)
    for sc.Scan() {
        ln := strings.TrimSpace(sc.Text())
        if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, ";") {
            continue
        }
        r := parseChallengeExcludeRule(ln)
        if r.action == "" {
            r.action = "skip"
        }
        if r.ua == "" && r.asn == "" && r.ptr == "" && r.host == "" {
            continue
        }
        ce.rules = append(ce.rules, r)
    }
    if err := sc.Err(); err != nil {
        return nil, err
    }
    if len(ce.rules) == 0 {
        return nil, nil
    }
    return ce, nil
}

func parseChallengeExcludeRule(line string) challengeExcludeRule {
    r := challengeExcludeRule{raw: line}
    parts := strings.Split(line, ";")
    for _, p := range parts {
        p = strings.TrimSpace(p)
        if p == "" { continue }
        kv := strings.SplitN(p, "=", 2)
        if len(kv) != 2 { continue }

        k := strings.ToLower(strings.TrimSpace(kv[0]))
        v := strings.ToLower(strings.TrimSpace(kv[1]))
       switch k {
        case "ua", "useragent", "agent":
           r.ua = v
        case "asn":
            v = strings.TrimSpace(v)
            if v != "" && !strings.HasPrefix(v, "as") {
                if allDigits(v) {
                    v = "as" + v
                }
            }
            r.asn = v
        case "ptr", "rdns":
            r.ptr = v
        case "host", "vhost":
            r.host = v
        case "mode":
            if v == "any" { r.modeAny = true }
        case "verify_fcrdns", "fcrdns":
            if v == "1" || v == "true" || v == "yes" {
                r.verifyFcrdns = true
            }
        case "action":
            if v == "skip" || v == "skip_vhost_only" {
                r.action = v
            }
        }
    }
    return r
}

func allDigits(s string) bool {
    if s == "" { return false }
    for i := 0; i < len(s); i++ {
        if s[i] < '0' || s[i] > '9' { return false }
    }
    return true
}

// Match returns (action, reason, true) when a rule matches.
// ruleName is used to implement skip_vhost_only semantics.
func (ce *ChallengeExclude) Match(ip, host, ua, asn, ptr, ruleName string) (string, string, bool) {
    if ce == nil || len(ce.rules) == 0 {
        return "", "", false
    }

    hostL := strings.ToLower(strings.TrimSpace(host))
    uaL := strings.ToLower(strings.TrimSpace(ua))
    asnL := strings.ToLower(strings.TrimSpace(asn))
    ptrL := strings.ToLower(strings.TrimSpace(ptr))
    rn := strings.ToUpper(strings.TrimSpace(ruleName))

    isVHostWide := rn == "CHALLENGE_VHOST" || rn == "CHALLENGE_SUSPICIOUS_VHOST_SCORE"

    for _, r := range ce.rules {
        if r.action == "skip_vhost_only" && !isVHostWide {
            continue
        }

        checks := 0
        matches := 0

        if r.host != "" {
            checks++
            if globMatch(r.host, hostL) { matches++ }
        }
        if r.ua != "" {
            checks++
            if globMatch(r.ua, uaL) { matches++ }
        }
        if r.asn != "" {
            checks++
            if globMatch(r.asn, asnL) { matches++ }
        }
        if r.ptr != "" {
            checks++
            if globMatch(r.ptr, ptrL) {
                if r.verifyFcrdns {
                    if forwardConfirmPTR(ip, ptrL) { matches++ }
                } else {
                    matches++
                }
            }
        }
        if checks == 0 { continue }

        ok := false
        if r.modeAny {
            ok = matches >= 1
        } else {
            ok = matches == checks
        }
        if ok {
            why := r.raw
           if len(why) > 160 {
                why = why[:160] + "…"
            }
            return r.action, why, true
        }
    }
    return "", "", false
}

// globMatch is a small, case-insensitive glob matcher for '*' and '?'.
// '*' matches any sequence (including empty) of ANY characters — '/' is not
// a separator here, since values are UA strings / hostnames, not paths.
// '?' matches exactly one character. If the pattern contains no wildcards,
// falls back to substring containment for convenience.
func globMatch(pattern, value string) bool {
    pattern = strings.TrimSpace(strings.ToLower(pattern))
    value = strings.TrimSpace(strings.ToLower(value))
    if pattern == "" { return false }
    if !strings.ContainsAny(pattern, "*?") {
        return strings.Contains(value, pattern)
    }
    return wildcardMatch(pattern, value)
}

// wildcardMatch is the classic iterative '*'/'?' matcher with backtracking.
// O(len(pattern) * len(value)) worst case; both inputs are short here.
func wildcardMatch(pattern, value string) bool {
    pi, vi := 0, 0
    star, mark := -1, 0
    for vi < len(value) {
        if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == value[vi]) {
            pi++
            vi++
            continue
        }
        if pi < len(pattern) && pattern[pi] == '*' {
            star = pi
            mark = vi
            pi++
            continue
        }
        if star != -1 {
            pi = star + 1
            mark++
            vi = mark
            continue
        }
        return false
    }
    for pi < len(pattern) && pattern[pi] == '*' {
        pi++
    }
    return pi == len(pattern)
}

// forwardConfirmPTR verifies FCrDNS: resolve PTR hostname and ensure it maps back to ip.
func forwardConfirmPTR(ip, ptrName string) bool {
    ip = strings.TrimSpace(ip)
    ptrName = strings.TrimSuffix(strings.TrimSpace(ptrName), ".")
    if ip == "" || ptrName == "" { return false }

    ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
    defer cancel()

    ips, err := net.DefaultResolver.LookupHost(ctx, ptrName)
    if err != nil { return false }
    for _, got := range ips {
        if strings.TrimSpace(got) == ip {
            return true
        }
    }
    return false
}
