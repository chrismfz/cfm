// internal/locate/files.go
//
// File-based probe: cfm.deny, read directly (deterministic, read-only,
// subnet-aware).
package locate

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"cfm/internal/ipquery"
)

// ---------------------------------------------------------------- cfm.deny

// searchCFMDeny scans <cfgDir>/cfm.deny. Same path constraints as the
// unblock's cfm.deny cleanup (unblock.removeFromFileMany), minus the write.
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
// [# comment]" format of cfm.deny.
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
		if entry != "" {
			idx.Add(entry, Location{
				Source: source, List: list, Action: action,
				Match: entry, Reason: reason,
			})
		}
	}
}
