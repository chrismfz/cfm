// internal/locate/files.go
//
// File-based probes: cfm.deny and the csf list files. Reading the files
// directly (instead of shelling out to `csf -g`) keeps the probe
// deterministic, read-only, subnet-aware and independent of csf's
// output format.
package locate

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cfm/internal/ipquery"
)

// ---------------------------------------------------------------- cfm.deny

// searchCFMDeny scans <cfgDir>/cfm.deny. Same path constraints as
// unblock.removeFromFile, minus the write.
func searchCFMDeny(cfgDir string, qs []*query) ([][]Location, error) {
	base := filepath.Clean(cfgDir)
	path := filepath.Clean(filepath.Join(base, "cfm.deny"))
	if path != base && !strings.HasPrefix(path, base+string(os.PathSeparator)) {
		return nil, fmt.Errorf("path escapes config dir")
	}
	// #nosec G304 -- path is cfgDir + fixed filename, verified above.
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no file = simply no entries
		}
		return nil, err
	}
	defer f.Close()
	idx := ipquery.NewIndex[Location]()
	scanListFile(f, "cfm.deny", "cfm.deny", ActionBlock, idx)
	return matchAll(idx, qs), nil
}

// listScanner returns a line scanner with a 1MB token limit: the default
// 64KB cap would make Scan() abort on one pathological line and silently
// skip every entry after it.
func listScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return sc
}

// scanListFile adds the entries of a file in the common "<ip-or-cidr>
// [# comment]" format used by cfm.deny, csf.deny and csf.allow.
func scanListFile(r io.Reader, source, list, action string, idx *ipquery.Index[Location]) {
	sc := listScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry := line
		reason := ""
		if i := strings.Index(line, "#"); i >= 0 {
			entry = strings.TrimSpace(line[:i])
			reason = strings.TrimSpace(line[i+1:])
		}
		if i := strings.IndexAny(entry, " \t"); i >= 0 {
			entry = entry[:i]
		}
		// csf.allow supports advanced "tcp|in|d=22|s=1.2.3.4" syntax;
		// pull the s=/d= address out so those rules still match.
		if strings.Contains(entry, "|") {
			entry = extractCSFAdvanced(entry)
		}
		if entry != "" {
			idx.Add(entry, Location{
				Source: source, List: list, Action: action,
				Match: entry, Reason: reason,
			})
		}
	}
}

// extractCSFAdvanced pulls the first s=/d= IP (or CIDR) out of a csf
// advanced-syntax rule like "tcp|in|d=22|s=1.2.3.4".
func extractCSFAdvanced(rule string) string {
	for _, f := range strings.Split(rule, "|") {
		f = strings.TrimSpace(f)
		for _, pfx := range []string{"s=", "d="} {
			if v, ok := strings.CutPrefix(f, pfx); ok {
				if looksLikeAddr(v) {
					return v
				}
			}
		}
	}
	return ""
}

func looksLikeAddr(s string) bool {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

// ------------------------------------------------------------------- csf

// searchCSF probes csf's static and temp list files. Returns
// (locations, "") on success or (nil, why) when csf isn't present.
func searchCSF(opts Options, qs []*query) ([][]Location, string) {
	etc := opts.CSFDir
	if etc == "" {
		etc = "/etc/csf"
	}
	data := opts.CSFDataDir
	if data == "" {
		data = "/var/lib/csf"
	}
	if _, err := os.Stat(etc); err != nil {
		return nil, "not installed"
	}

	idx := ipquery.NewIndex[Location]()
	static := []struct {
		file   string
		action string
	}{
		{"csf.deny", ActionBlock},
		{"csf.allow", ActionAllow},
	}
	for _, s := range static {
		// #nosec G304 -- fixed filenames under the csf config dir.
		f, err := os.Open(filepath.Join(etc, s.file))
		if err != nil {
			continue
		}
		scanListFile(f, "csf", s.file, s.action, idx)
		f.Close()
	}

	temp := []struct {
		file   string
		action string
	}{
		{"csf.tempban", ActionBlock},
		{"csf.tempallow", ActionAllow},
	}
	for _, t := range temp {
		// #nosec G304 -- fixed filenames under the csf data dir.
		f, err := os.Open(filepath.Join(data, t.file))
		if err != nil {
			continue
		}
		scanCSFTempFile(f, t.file, t.action, idx)
		f.Close()
	}
	return matchAll(idx, qs), ""
}

// scanCSFTempFile adds the entries of a csf temp list file. The format is
// pipe-separated (timestamp|ip|port|inout|ttl|comment in current csf);
// to stay robust across versions we locate the IP field by parsing and
// take the last field as the comment.
func scanCSFTempFile(r io.Reader, list, action string, idx *ipquery.Index[Location]) {
	sc := listScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "|")
		entry := ""
		for _, f := range fields {
			f = strings.TrimSpace(f)
			if looksLikeAddr(f) {
				entry = f
				break
			}
		}
		if entry == "" {
			continue
		}
		reason := strings.TrimSpace(fields[len(fields)-1])
		if reason == entry {
			reason = ""
		}
		// First field is the ban epoch in current csf; surface it when
		// it parses, since "banned since" is useful context.
		if ts, err := strconv.ParseInt(strings.TrimSpace(fields[0]), 10, 64); err == nil && ts > 1000000000 {
			when := time.Unix(ts, 0).UTC().Format("2006-01-02 15:04 UTC")
			if reason != "" {
				reason += " (since " + when + ")"
			} else {
				reason = "since " + when
			}
		}
		idx.Add(entry, Location{
			Source: "csf", List: list, Action: action,
			Match: entry, Reason: reason,
		})
	}
}
