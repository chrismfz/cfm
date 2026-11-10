package panelmap

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// UserDataDir is cPanel's per-account userdata tree
// (/var/cpanel/userdata/<user>/<domain>). A package var so tests can point it
// at a fixture.
var UserDataDir = "/var/cpanel/userdata"

// WithWebAliases returns the account's domains plus the host names its sites
// also answer on: "www.<domain>" for every domain, and the domain's own
// ServerAlias list from cPanel's userdata (www., mail., parked aliases).
//
// Why: /etc/userdatadomains lists a site as "trimel.gr", but nearly all of its
// traffic is logged under the Host it was asked for, "www.trimel.gr" (41 894 of
// 41 907 requests on qualityweb, 2026-11-09). A scoped cPanel token built from
// the bare list matched almost none of the account's own traffic.
//
// Fail-closed: an alias is kept only when it IS one of the account's domains or
// a subdomain of one ("www.trimel.gr" under "trimel.gr"). cPanel only lets the
// owner of a domain create names under it, so this can never widen a token to
// another account's site, even from a hand-edited userdata file. Wildcards
// ("*.example.com") are dropped: scope matching is exact, so they would match
// nothing anyway.
func WithWebAliases(user string, domains []string) []string {
	owned := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		if d = normalizeHost(d); d != "" {
			owned[d] = struct{}{}
		}
	}
	out := make(map[string]struct{}, len(owned)*2)
	for d := range owned {
		out[d] = struct{}{}
		if !strings.HasPrefix(d, "www.") {
			out["www."+d] = struct{}{}
		}
		for _, a := range serverAliases(user, d) {
			if underOwned(a, owned) {
				out[a] = struct{}{}
			}
		}
	}
	list := make([]string, 0, len(out))
	for h := range out {
		list = append(list, h)
	}
	sort.Strings(list)
	return list
}

func normalizeHost(h string) string {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	if h == "" || strings.ContainsAny(h, "/\\* \t") || strings.Contains(h, "..") || !strings.Contains(h, ".") {
		return ""
	}
	return h
}

// underOwned reports whether h is an owned domain or a subdomain of one.
func underOwned(h string, owned map[string]struct{}) bool {
	for {
		if _, ok := owned[h]; ok {
			return true
		}
		dot := strings.IndexByte(h, '.')
		if dot < 0 || dot+1 >= len(h) {
			return false
		}
		h = h[dot+1:]
	}
}

// serverAliases reads the "serveralias:" line of
// /var/cpanel/userdata/<user>/<domain> (cPanel writes it as one
// space-separated YAML scalar). A missing or unreadable file yields nothing.
func serverAliases(user, domain string) []string {
	if user == "" || strings.ContainsAny(user, "/\\.") || domain == "" {
		return nil
	}
	f, err := os.Open(filepath.Join(UserDataDir, user, domain))
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		v, ok := strings.CutPrefix(line, "serveralias:")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `'"`)
		var out []string
		for _, f := range strings.Fields(v) {
			if h := normalizeHost(f); h != "" {
				out = append(out, h)
			}
		}
		return out
	}
	return nil
}
