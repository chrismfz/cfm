package authstore

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

var sqliteSidecars = []string{"", "-wal", "-shm"}

// HardenSQLiteFiles enforces 0600 on sqlite DB files and known sidecars.
// Missing files are ignored.
func HardenSQLiteFiles(paths ...string) error {
	var errs []error
	seen := map[string]struct{}{}
	for _, raw := range paths {
		path := strings.TrimSpace(raw)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		for _, suffix := range sqliteSidecars {
			candidate := path + suffix
			st, err := os.Stat(candidate)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				errs = append(errs, fmt.Errorf("stat %s: %w", candidate, err))
				continue
			}
			if !st.Mode().IsRegular() {
				continue
			}
			if err := os.Chmod(candidate, 0o600); err != nil {
				errs = append(errs, fmt.Errorf("chmod 600 %s: %w", candidate, err))
			}
		}
	}
	return errors.Join(errs...)
}
