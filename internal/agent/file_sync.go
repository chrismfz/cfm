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
	"time"

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

// staleTempAge is how old a leftover temp file of ours must be before
// atomicWrite deletes it: older than any write in progress.
const staleTempAge = time.Minute

// atomicWrite replaces path with data: a unique temp file in the same dir,
// given perm (exactly — not masked by the umask) and, when owner is set, that
// owner, then renamed over path. A reader sees the old file or the new one,
// never a half-written one or one with the wrong mode. A failed chown is
// logged, not fatal: the content still lands, owned by the agent, as it
// always did (an NFS root_squash mount or a non-root agent can't chown).
// Temp files a crashed earlier write left behind are removed first.
func atomicWrite(path string, data []byte, perm os.FileMode, owner *fileOwner) error {
	dir, pattern := filepath.Dir(path), "."+filepath.Base(path)+".tmp*"
	removeStaleTemps(dir, pattern)
	f, err := os.CreateTemp(dir, pattern)
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
			logging.LogfAPI("[files] chown %s to %d:%d: %v (writing it as the agent's)", path, owner.uid, owner.gid, err)
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// removeStaleTemps deletes temp files matching pattern in dir that are older
// than staleTempAge: what a write killed between CreateTemp and Rename leaves.
func removeStaleTemps(dir, pattern string) {
	matches, _ := filepath.Glob(filepath.Join(dir, pattern))
	for _, m := range matches {
		if fi, err := os.Lstat(m); err == nil && fi.Mode().IsRegular() && time.Since(fi.ModTime()) > staleTempAge {
			os.Remove(m)
		}
	}
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
