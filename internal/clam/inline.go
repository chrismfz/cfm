package clam

import (
	"os"
	"path/filepath"
	"time"
)

// Inline (blocking) upload scanning — CLAM_SCAN_MODE=inline. The edge calls
// the bridge's synchronous endpoint, which calls ScanUploadSync and relays
// the verdict; the edge obeys ONLY the Block flag. ALL policy lives here:
// breaker, scope, sig-ignore, dry-run. The critical safety property is FAIL
// OPEN — any failure (clamd down/hung, stream rejected, read error) must
// resolve to Block=false, with the file handed to the async queue best-effort
// so coverage is not silently lost.

// SyncVerdict is the bridge's answer to an inline scan request.
type SyncVerdict struct {
	// Verdict: clean | infected | skipped_breaker | skipped_scope |
	// skipped_ignored | error. Informational; the edge keys on Block alone.
	Verdict   string
	Signature string
	// Block is true ONLY for: infected AND not sig-ignored AND not dry-run.
	Block bool
	// WouldBlock reports what Block would have been without dry-run, so a
	// burn-in can measure FP rate from logs/history before arming.
	WouldBlock bool
}

// ScanUploadSync scans job.Path synchronously for the inline edge path.
// The caller (bridge handler) owns temp-file cleanup; this function never
// deletes job.Path. Bounded by Config.InlineTimeout (default 3s).
func (m *Manager) ScanUploadSync(job Job) SyncVerdict {
	if m == nil || !m.started {
		return SyncVerdict{Verdict: "error"}
	}
	if _, err := os.Stat(job.Path); err != nil {
		logf("[clam_inline] result=error ip=%s host=%s uri=%s err=%q",
			job.IP, job.Host, job.URI, err)
		return SyncVerdict{Verdict: "error"}
	}

	// clamd known-down: never make uploads wait on a dead daemon.
	if m.health.isOpen() {
		m.health.skippedBreaker.Add(1)
		logf("[clam_inline] result=skipped_clamd_down ip=%s host=%s uri=%s",
			job.IP, job.Host, job.URI)
		return SyncVerdict{Verdict: "skipped_breaker"}
	}

	// Scope gate — same rule as async: only archives are worth blocking on.
	if m.cfg.ScanScope == ScanScopeArchives {
		if isArch, aerr := isArchiveFile(job.Path); aerr == nil && !isArch {
			m.health.skippedScope.Add(1)
			return SyncVerdict{Verdict: "skipped_scope"}
		}
	}

	d := m.cfg.InlineTimeout
	if d <= 0 {
		d = 3 * time.Second
	}
	r, err := m.client.ScanFileStream(job.Path, d)
	if err != nil {
		m.recordScan(false, err.Error())
		logf("[clam_inline] result=error ip=%s host=%s uri=%s err=%q (fail-open, falling back to async)",
			job.IP, job.Host, job.URI, err)
		m.enqueueAsyncFallback(job)
		return SyncVerdict{Verdict: "error"}
	}
	m.recordScan(true, "")

	if !r.Infected {
		m.safeNotifyUpload(job, r)
		logf("[clam_inline] result=clean ip=%s host=%s uri=%s file=%s",
			job.IP, job.Host, job.URI, jobFileName(job))
		return SyncVerdict{Verdict: "clean"}
	}

	mode := "inline"
	if m.cfg.InlineDryRun {
		mode = "inline_dryrun"
	}

	if ignored, by := m.sigIgnored(job.Host, r.Signature); ignored {
		m.health.sigIgnored.Add(1)
		logf("[clam_inline] result=infected_ignored ip=%s host=%s uri=%s sig=%q by=%s",
			job.IP, job.Host, job.URI, r.Signature, by)
		publishScanEvent(ScanEvent{
			EventType: "clam_infected", Host: job.Host, IP: job.IP, URI: job.URI,
			FileName: jobFileName(job), Signature: r.Signature,
			SigIgnored: true, IgnoredBy: by, Mode: mode, When: time.Now(),
		})
		return SyncVerdict{Verdict: "skipped_ignored", Signature: r.Signature}
	}

	// Real infected verdict: quarantine a copy (the original spool belongs to
	// the caller), notify, persist — then block unless burning in.
	evidence := ""
	if job.InfectedDir != "" {
		_ = os.MkdirAll(job.InfectedDir, 0o700)
		candidate := filepath.Join(job.InfectedDir, filepath.Base(job.Path))
		if cerr := copyFileContents(job.Path, candidate); cerr == nil {
			evidence = candidate
		}
	}
	m.safeNotifyInfected(job, r, evidence, mode)
	publishScanEvent(ScanEvent{
		EventType: "clam_infected", Host: job.Host, IP: job.IP, URI: job.URI,
		FileName: jobFileName(job), Signature: r.Signature, Evidence: evidence,
		Mode: mode, When: time.Now(),
	})

	if m.cfg.InlineDryRun {
		m.health.inlineDryRunHits.Add(1)
		logf("[clam_inline] result=would_block (DRY_RUN) ip=%s host=%s uri=%s sig=%q",
			job.IP, job.Host, job.URI, r.Signature)
		return SyncVerdict{Verdict: "infected", Signature: r.Signature, WouldBlock: true}
	}
	m.health.inlineBlocked.Add(1)
	logf("[clam_inline] result=blocked ip=%s host=%s uri=%s sig=%q evidence=%s",
		job.IP, job.Host, job.URI, r.Signature, evidence)
	return SyncVerdict{Verdict: "infected", Signature: r.Signature, Block: true, WouldBlock: true}
}

// enqueueAsyncFallback copies the spool into the pending dir and queues a
// normal async job, so an inline transport failure degrades to notify-only
// coverage instead of no coverage. Best-effort: a full queue drops it (and
// counts the drop) exactly like any async enqueue.
func (m *Manager) enqueueAsyncFallback(job Job) {
	if m.cfg.PendingDir == "" {
		return
	}
	_ = os.MkdirAll(m.cfg.PendingDir, 0o700)
	dst := filepath.Join(m.cfg.PendingDir, "inline_fb_"+filepath.Base(job.Path))
	if err := copyFileContents(job.Path, dst); err != nil {
		return
	}
	fb := job
	fb.Path = dst
	fb.TempCopy = true
	if !m.Enqueue(fb) {
		_ = os.Remove(dst)
	}
}

func copyFileContents(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}
