package allowlist

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	defaultResolverTimeout = 2 * time.Second
	hostLabelPattern       = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
)

type Kind string

const (
	KindIP       Kind = "ip"
	KindCIDR     Kind = "cidr"
	KindHostname Kind = "hostname"
)

type Entry struct {
	Kind     Kind
	Token    string
	IP       net.IP
	CIDR     string
	TTL      *time.Duration
	Until    *time.Time
	FilePath string
	Line     int
}

type Meta struct {
	FilePath   string
	Line       int
	Token      string
	Kind       Kind
	ResolvedIP []string
	Note       string
}

type ReadOptions struct {
	ResolveHostnames bool
	ResolverTimeout  time.Duration
	LookupHost       func(ctx context.Context, host string) ([]net.IP, error)
}

type SnapshotSource struct {
	Path             string
	ResolveHostnames bool
}

type SnapshotOptions struct {
	Sources         []SnapshotSource
	ExtraTokens     []string
	ResolverTimeout time.Duration
	LookupHost      func(ctx context.Context, host string) ([]net.IP, error)
}

type Snapshot struct {
	ExactIPs map[string]struct{}
	CIDRNets []*net.IPNet
	Metadata []Meta
}

func ReadEntriesFromFile(ctx context.Context, path string, opts ReadOptions) ([]Entry, []Meta, error) {
	path = filepath.Clean(path)
	b, err := os.ReadFile(path) // #nosec G304 - caller provides config path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	return parseEntries(ctx, string(b), path, opts)
}

func BuildSnapshot(ctx context.Context, opts SnapshotOptions) (Snapshot, error) {
	s := Snapshot{ExactIPs: map[string]struct{}{}}
	lookup := opts.LookupHost
	if lookup == nil {
		lookup = defaultLookupHost
	}
	ropts := ReadOptions{ResolverTimeout: opts.ResolverTimeout, LookupHost: lookup}

	for _, src := range opts.Sources {
		ropts.ResolveHostnames = src.ResolveHostnames
		entries, meta, err := ReadEntriesFromFile(ctx, src.Path, ropts)
		if err != nil {
			return Snapshot{}, err
		}
		s.Metadata = append(s.Metadata, meta...)
		addEntriesToSnapshot(&s, entries)
	}

	for _, tok := range opts.ExtraTokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		entries, meta, err := parseEntries(ctx, tok, "<inline>", ReadOptions{
			ResolveHostnames: true,
			ResolverTimeout:  opts.ResolverTimeout,
			LookupHost:       lookup,
		})
		if err != nil {
			return Snapshot{}, err
		}
		s.Metadata = append(s.Metadata, meta...)
		addEntriesToSnapshot(&s, entries)
	}

	sort.Slice(s.CIDRNets, func(i, j int) bool {
		return s.CIDRNets[i].String() < s.CIDRNets[j].String()
	})

	return s, nil
}

func parseEntries(ctx context.Context, content, filePath string, opts ReadOptions) ([]Entry, []Meta, error) {
	lookup := opts.LookupHost
	if lookup == nil {
		lookup = defaultLookupHost
	}
	resolveTimeout := opts.ResolverTimeout
	if resolveTimeout <= 0 {
		resolveTimeout = defaultResolverTimeout
	}

	var out []Entry
	var meta []Meta
	sc := bufio.NewScanner(strings.NewReader(content))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		head := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		fields := strings.Fields(head)
		if len(fields) == 0 {
			continue
		}

		token := strings.TrimSpace(fields[0])
		ttl, until := parseTTLUntil(fields[1:])

		if strings.ContainsRune(token, '/') {
			if _, nw, err := net.ParseCIDR(token); err == nil {
				nw.IP = nw.IP.Mask(nw.Mask)
				out = append(out, Entry{Kind: KindCIDR, Token: token, CIDR: nw.String(), TTL: ttl, Until: until, FilePath: filePath, Line: lineNo})
				meta = append(meta, Meta{FilePath: filePath, Line: lineNo, Token: token, Kind: KindCIDR})
			}
			continue
		}

		if ip := net.ParseIP(token); ip != nil {
			out = append(out, Entry{Kind: KindIP, Token: token, IP: ip, TTL: ttl, Until: until, FilePath: filePath, Line: lineNo})
			meta = append(meta, Meta{FilePath: filePath, Line: lineNo, Token: token, Kind: KindIP, ResolvedIP: []string{canonicalIP(ip)}})
			continue
		}

		if !opts.ResolveHostnames {
			continue
		}
		host, ok := normalizeAndValidateHostname(token)
		if !ok {
			meta = append(meta, Meta{FilePath: filePath, Line: lineNo, Token: token, Kind: KindHostname, Note: "ignored: invalid hostname"})
			continue
		}
		lctx, cancel := context.WithTimeout(ctx, resolveTimeout)
		ips, err := lookup(lctx, host)
		cancel()
		if err != nil {
			meta = append(meta, Meta{FilePath: filePath, Line: lineNo, Token: host, Kind: KindHostname, Note: fmt.Sprintf("lookup failed: %v", err)})
			continue
		}
		var resolved []string
		for _, ip := range ips {
			if ip == nil {
				continue
			}
			out = append(out, Entry{Kind: KindHostname, Token: host, IP: ip, TTL: ttl, Until: until, FilePath: filePath, Line: lineNo})
			resolved = append(resolved, canonicalIP(ip))
		}
		meta = append(meta, Meta{FilePath: filePath, Line: lineNo, Token: host, Kind: KindHostname, ResolvedIP: dedupStrings(resolved)})
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	return out, meta, nil
}

func addEntriesToSnapshot(s *Snapshot, entries []Entry) {
	for _, e := range entries {
		switch e.Kind {
		case KindCIDR:
			_, nw, err := net.ParseCIDR(e.CIDR)
			if err != nil {
				continue
			}
			s.CIDRNets = append(s.CIDRNets, nw)
		default:
			if e.IP == nil {
				continue
			}
			s.ExactIPs[canonicalIP(e.IP)] = struct{}{}
		}
	}
}

func parseTTLUntil(fields []string) (*time.Duration, *time.Time) {
	var ttl *time.Duration
	var until *time.Time
	for _, f := range fields {
		if strings.HasPrefix(f, "ttl=") {
			if d, err := time.ParseDuration(strings.TrimPrefix(f, "ttl=")); err == nil && d > 0 {
				ttl = &d
			}
			continue
		}
		if strings.HasPrefix(f, "until=") {
			if t, err := time.Parse(time.RFC3339, strings.TrimPrefix(f, "until=")); err == nil {
				until = &t
			}
		}
	}
	return ttl, until
}

func DurationFromEntryNow(e Entry, now time.Time) *time.Duration {
	if e.Until != nil {
		rem := e.Until.Sub(now)
		if rem > 0 {
			return &rem
		}
		return nil
	}
	return e.TTL
}

func normalizeAndValidateHostname(host string) (string, bool) {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /:@") {
		return "", false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return "", false
		}
		if !hostLabelPattern.MatchString(label) {
			return "", false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", false
		}
	}
	return strings.ToLower(host), true
}

func defaultLookupHost(ctx context.Context, host string) ([]net.IP, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("lookup timeout for %q", host)
		}
		return nil, err
	}
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.IP)
	}
	return out, nil
}

func canonicalIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func dedupStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
