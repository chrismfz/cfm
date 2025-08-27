// cmd/cfm/dyndns.go
package main

import (
    "context"
    "strings"
    "time"
    "net"

    "github.com/miekg/dns"
)

type dynRecord struct {
    Host         string
    LastV4, LastV6 []string
    NextRefresh  time.Time
    Interval     time.Duration // optional override; 0 = use DNS TTL
}

// resolveWithTTL returns A and AAAA plus the minimum TTL seen (fallback defaultTTL if none).
func resolveWithTTL(ctx context.Context, host string, defaultTTL time.Duration) (v4, v6 []string, ttl time.Duration, err error) {
    ttl = defaultTTL
    c := new(dns.Client)
    // pick system resolv.conf nameserver
    cfg, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
    if cfg == nil || len(cfg.Servers) == 0 {
        cfg = &dns.ClientConfig{Servers: []string{"1.1.1.1"}, Port: "53", Timeout: 2}
    }
    q := func(qtype uint16) ([]string, uint32, error) {
        m := new(dns.Msg)
        m.SetQuestion(dns.Fqdn(host), qtype)
        server := net.JoinHostPort(cfg.Servers[0], cfg.Port)
        r, _, e := c.ExchangeContext(ctx, m, server)
        if e != nil || r == nil || r.Rcode != dns.RcodeSuccess {
            return nil, 0, e
        }
        var out []string
        minTTL := uint32(0)
        for _, a := range r.Answer {
            switch rr := a.(type) {
            case *dns.A:
                if qtype == dns.TypeA {
                    out = append(out, rr.A.String())
                    if minTTL == 0 || rr.Hdr.Ttl < minTTL { minTTL = rr.Hdr.Ttl }
                }
            case *dns.AAAA:
                if qtype == dns.TypeAAAA {
                    out = append(out, rr.AAAA.String())
                    if minTTL == 0 || rr.Hdr.Ttl < minTTL { minTTL = rr.Hdr.Ttl }
                }
            }
        }
        return out, minTTL, nil
    }
    // query both
    v4s, ttl4, err4 := q(dns.TypeA)
    v6s, ttl6, err6 := q(dns.TypeAAAA)
    if err4 != nil && err6 != nil {
        if err4 != nil { err = err4 } else { err = err6 }
        return
    }
    v4, v6 = v4s, v6s
    minTTL := ttl4
    if minTTL == 0 || (ttl6 != 0 && ttl6 < minTTL) { minTTL = ttl6 }
    if minTTL > 0 { ttl = time.Duration(minTTL) * time.Second }
    // clamp
    if ttl < 30*time.Second { ttl = 30 * time.Second }
    if ttl > 1*time.Hour { ttl = 1 * time.Hour }
    return
}

// equal string slices (set)
func eqStrSet(a, b []string) bool {
    if len(a) != len(b) { return false }
    m := make(map[string]struct{}, len(a))
    for _, s := range a { m[s] = struct{}{} }
    for _, s := range b { if _, ok := m[s]; !ok { return false } }
    return true
}

// parse simple cfm.dyndns format: one hostname per line, with optional "interval=5m"
func parseDynDNS(b []byte) []struct{ Host string; Interval time.Duration } {
    var out []struct{ Host string; Interval time.Duration }
    for _, line := range strings.Split(string(b), "\n") {
        line = strings.TrimSpace(line)
        if line == "" || strings.HasPrefix(line, "#") { continue }
        host := strings.Fields(line)[0]
        var iv time.Duration
        for _, f := range strings.Fields(line)[1:] {
            if strings.HasPrefix(f, "interval=") {
                if d, err := time.ParseDuration(strings.TrimPrefix(f, "interval=")); err == nil { iv = d }
            }
        }
        out = append(out, struct{ Host string; Interval time.Duration }{host, iv})
    }
    return out
}
