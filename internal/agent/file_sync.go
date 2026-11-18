package agent

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"cfm/internal/logging"
)

func sha1File(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp := filepath.Join(dir, "."+base+".tmp")
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (r *Runner) syncConfigs(ctx context.Context) {
	cfg := r.cur()
	if cfg.BaseURL == "" || cfg.Token == "" {
		return
	}
	api := &APIClient{BaseURL: cfg.BaseURL, Token: cfg.Token, HTTP: r.client}

	tracked, err := api.ListTrackedFiles()
	if err != nil {
		logging.LogfAPI("[files] list failed: %v", err)
		return
	}
	if len(tracked) == 0 {
		//logging.LogfAPI("[files] no tracked files (nothing to do)")
		return
	}

	// figure out diffs
	var need []string
	for path, remoteHash := range tracked {
		if local := sha1File(path); !strings.EqualFold(local, remoteHash) {
			need = append(need, path)
		}
	}
	if len(need) == 0 {
		return
	}

	updates, err := api.GetUpdates(need)
	if err != nil {
		logging.LogfAPI("[files] updates failed: %v", err)
		return
	}

	r.files.applyUpdates(ctx, updates, syncAllowedPrefixes)
}
