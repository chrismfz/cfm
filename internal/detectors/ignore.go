package detectors

import (
    "net"
    "strings"
)

type IPIgnore struct {
    exact map[string]struct{}
    nets  []*net.IPNet
    logIgnored bool

}

func newIPIgnoreFromGlobal(global KV) *IPIgnore {
    rawIPs  := kvStrClean(global, "IGNORE_IPS", "")
    rawNets := kvStrClean(global, "IGNORE_NETS", "")

    // Default: δεν κάνουμε log τα ignored στο sink (LOG_IGNORED absent → false)
    logIgnored := kvBool(global, "LOG_IGNORED", false)


    exact := make(map[string]struct{})
    var nets []*net.IPNet

    // helper: split σε comma/space
    split := func(s string) []string {
        if s == "" {
            return nil
        }
        return strings.FieldsFunc(s, func(r rune) bool {
            return r == ',' || r == ' ' || r == '\t' || r == ';'
        })
    }

    for _, tok := range split(rawIPs) {
        tok = strings.TrimSpace(tok)
        if tok == "" {
            continue
        }
        exact[tok] = struct{}{}
    }

    for _, tok := range split(rawNets) {
        tok = strings.TrimSpace(tok)
        if tok == "" {
            continue
        }
        if _, netw, err := net.ParseCIDR(tok); err == nil {
            nets = append(nets, netw)
        }
    }

    if len(exact) == 0 && len(nets) == 0 {
        return nil
    }
    return &IPIgnore{
        exact:      exact,
        nets:       nets,
        logIgnored: logIgnored,
    }

}

func (ig *IPIgnore) ShouldIgnore(ipStr string) bool {
    if ig == nil {
        return false
    }
    ipStr = strings.TrimSpace(ipStr)
    if ipStr == "" {
        return false
    }

    if _, ok := ig.exact[ipStr]; ok {
        return true
    }

    ip := net.ParseIP(ipStr)
    if ip == nil {
        return false
    }
    for _, n := range ig.nets {
        if n.Contains(ip) {
            return true
        }
    }
    return false
}


// LogIgnoredReports επιστρέφει αν πρέπει να περνάνε τα ignored events στα sinks.
// Ελέγχεται από το LOG_IGNORED στο [global].
func (ig *IPIgnore) LogIgnoredReports() bool {
    if ig == nil { return false }
    return ig.logIgnored
}
