package feedutil

import (
	"net"
	"strconv"
	"strings"
)

// SanitizeFeedName normalizes a user-provided feed name into a stable key.
func SanitizeFeedName(s string) string {
	s = strings.ToLower(s)
	b := make([]rune, 0, len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b = append(b, r)
		} else {
			b = append(b, '_')
		}
	}
	out := strings.Trim(collapseUnderscores(string(b)), "_")
	if out == "" {
		out = "feed"
	}
	if out[0] >= '0' && out[0] <= '9' {
		out = "f_" + out
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

func collapseUnderscores(s string) string {
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	return s
}

// SplitHostsNets separates a mixed IP/CIDR slice into host IPs and network
// prefixes, validating address-family consistency.
func SplitHostsNets(elems []string, isV6 bool) (hosts, nets []string) {
	seenH := make(map[string]struct{})
	seenN := make(map[string]struct{})
	maxBits := 32
	if isV6 {
		maxBits = 128
	}
	for _, s := range elems {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				continue
			}
			ones, bits := n.Mask.Size()
			if bits != maxBits {
				continue
			}
			if ones == maxBits {
				ip := n.IP.String()
				if _, ok := seenH[ip]; !ok {
					seenH[ip] = struct{}{}
					hosts = append(hosts, ip)
				}
			} else {
				canon := n.IP.Mask(n.Mask).String() + "/" + strconv.Itoa(ones)
				if _, ok := seenN[canon]; !ok {
					seenN[canon] = struct{}{}
					nets = append(nets, canon)
				}
			}
		} else {
			ip := net.ParseIP(s)
			if ip == nil {
				continue
			}
			if !isV6 && ip.To4() == nil {
				continue
			}
			if isV6 && (ip.To16() == nil || ip.To4() != nil) {
				continue
			}
			ipS := ip.String()
			if _, ok := seenH[ipS]; !ok {
				seenH[ipS] = struct{}{}
				hosts = append(hosts, ipS)
			}
		}
	}
	return
}

func DedupKeepOrder(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, x := range in {
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}
