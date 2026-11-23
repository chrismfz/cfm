package agent

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

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

// fileOwner is the uid/gid a rewritten file keeps.
type fileOwner struct{ uid, gid int }

// ownerOf is fi's owner, or nil when the platform doesn't say.
func ownerOf(fi os.FileInfo) *fileOwner {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return &fileOwner{uid: int(st.Uid), gid: int(st.Gid)}
	}
	return nil
}

// atomicWrite replaces path with data: a unique temp file in the same dir,
// given perm (exactly — not masked by the umask) and, when owner is set, that
// owner, then renamed over path. A reader sees the old file or the new one,
// never a half-written one or one with the wrong mode.
func atomicWrite(path string, data []byte, perm os.FileMode, owner *fileOwner) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	if owner != nil {
		if err := os.Chown(tmp, owner.uid, owner.gid); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// startConfigSync runs syncConfigs on its own goroutine, so a SpamAssassin lint
// and spamd restart (seconds, minutes on a loaded box) never hold up the work
// loop's unblocks and fingerprint-policy pulls. A tick that finds the previous
// sync still running skips this one. Stop cancels it (the lint and the
// post-update command run under its context).
func (r *Runner) startConfigSync() {
	if !r.fileSyncRunning.CompareAndSwap(false, true) {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-r.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	go func() {
		defer r.fileSyncRunning.Store(false)
		defer cancel()
		r.syncConfigs(ctx)
	}()
}

func (r *Runner) syncConfigs(ctx context.Context) {
	cfg := r.cur()
	if cfg.BaseURL == "" || cfg.Token == "" {
		return
	}
	api := &APIClient{BaseURL: cfg.BaseURL, Token: cfg.Token, HTTP: r.client}

	// A restart that failed on an earlier sync: the files already match, so
	// nothing below would trigger it again.
	r.files.retryPendingActions()

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
		if local := sha1File(path); strings.EqualFold(local, remoteHash) {
			continue
		}
		if r.files.isParked(path, remoteHash) {
			continue // failed the SpamAssassin lint; not worth downloading again
		}
		if isSpamassassinFile(filepath.Clean(path)) && r.files.lintWaiting() {
			continue // would only be deferred again until the lint backoff ends
		}
		need = append(need, path)
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
