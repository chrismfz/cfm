package mailtraffic

import (
	"bufio"
	"os"
	"sync"
	"syscall"
	"time"

	"cfm/internal/logging"
	"cfm/internal/mailmeter"
)

const (
	// pollInterval is how often the mail logs are checked for new lines.
	pollInterval = 60 * time.Second
	// maxChunk bounds bytes read per poll per file so a huge backlog (or a log
	// that grew a lot between polls) can't stall a single poll.
	maxChunk = 8 << 20 // 8 MB
)

// Candidate log paths, first-existing wins per set. Exim's mainlog carries the
// `<=` submission lines; the syslog maillog carries Postfix (on DA hosts) and
// Dovecot login summaries (on any host). A cPanel host typically has both.
var (
	eximPaths    = []string{"/var/log/exim_mainlog", "/var/log/exim4/mainlog", "/var/log/exim/mainlog"}
	maillogPaths = []string{"/var/log/maillog", "/var/log/mail.log"}
)

type parseFn func(string) mailmeter.Event

// Collector tails the mail logs each minute and folds new lines into per-hour
// counters in the Store. It resumes from persisted inode/offset positions so a
// restart never re-scans history; a brand-new file starts at EOF.
type Collector struct {
	st   *Store
	corr map[string]*mailmeter.Correlator // per resolved log path (Postfix QID correlation)
	stop chan struct{}
	done chan struct{}
}

func newCollector(st *Store) *Collector {
	return &Collector{
		st:   st,
		corr: map[string]*mailmeter.Correlator{},
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
}

func (c *Collector) run() {
	defer close(c.done)
	c.pollOnce(time.Now())
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			c.pollOnce(time.Now())
		}
	}
}

func (c *Collector) pollOnce(now time.Time) {
	if p := firstExisting(eximPaths); p != "" {
		c.pollFile(now, p, mailmeter.ParseEximLine)
	}
	if p := firstExisting(maillogPaths); p != "" {
		c.pollFile(now, p, mailmeter.ParseMaillogLine)
	}
}

// pollFile ingests new lines from one log and flushes the poll's counters. The
// rotation/resume logic mirrors CFM's other tailers: first sight starts at EOF;
// a new inode (logrotate `create`) or a shrunk file (`copytruncate`) resets to
// offset 0.
//
// Known tolerances (visibility meter, never data): a copytruncate that regrows
// past the old offset within one poll window skips that window's head; a
// rotation with a new inode drops the pre-rotation tail of the old file. Both
// undercount at most one interval. On a (rare) DB write error the counters and
// the offset advance atomically (Store.Flush is one transaction), so nothing is
// double-counted; the chunk is re-read next poll and the QID→sender map may have
// already advanced past a freed QID, undercounting at most the sends whose
// submission was in an earlier already-persisted poll — acceptable here.
func (c *Collector) pollFile(now time.Time, path string, parse parseFn) {
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	inode := fileInode(fi)
	size := fi.Size()

	savedInode, offset, ok := c.st.LoadTailPos(path)
	switch {
	case !ok:
		offset = size // first sight: start at EOF, don't re-scan history
	case savedInode != inode || size < offset:
		offset = 0 // rotated (new inode) or truncated (copytruncate)
	}
	if offset >= size {
		_ = c.st.SaveTailPos(path, inode, size)
		return
	}

	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Seek(offset, 0); err != nil {
		return
	}
	limit := size - offset
	if limit > maxChunk {
		limit = maxChunk
	}

	corr := c.corr[path]
	if corr == nil {
		corr = mailmeter.NewCorrelator()
		c.corr[path] = corr
	}
	r := mailmeter.NewReport()

	rd := bufio.NewReaderSize(f, 256<<10)
	var consumed int64
	for consumed < limit {
		line, err := rd.ReadString('\n')
		if err != nil {
			break // incomplete trailing line — leave it for the next poll
		}
		consumed += int64(len(line))
		corr.Feed(parse(line), &r)
	}

	// Counters + new offset commit together (Flush is one transaction); on error
	// neither lands, so the chunk is simply re-read next poll — never double-counted.
	if err := c.st.Flush(now, r, path, inode, offset+consumed); err != nil {
		logging.Logf("[mailtraffic] flush failed for %s: %v", path, err)
	}
}

func firstExisting(paths []string) string {
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

func fileInode(fi os.FileInfo) int64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int64(st.Ino)
	}
	return 0
}

// ---- process-wide singleton (daemon boot) ----

var (
	sharedMu sync.RWMutex
	shared   *Store
	coll     *Collector
)

// Enable opens the mail-traffic store at path (once) and starts the collector
// goroutine. Best-effort: on failure it returns the error and leaves the
// subsystem disabled, so the read endpoint reports available:false. Intended to
// be called once at daemon startup; the CLI and tests do not call it.
func Enable(path string) error {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if shared != nil {
		return nil // already enabled
	}
	st, err := Open(path)
	if err != nil {
		return err
	}
	shared = st
	coll = newCollector(st)
	go coll.run()
	logging.Logf("[mailtraffic] enabled: %s", path)
	return nil
}

// SharedStore returns the process-wide store, or nil when the subsystem was
// never enabled (CLI / tests / a failed Open).
func SharedStore() *Store {
	sharedMu.RLock()
	defer sharedMu.RUnlock()
	return shared
}

// Shutdown stops the collector and closes the store if enabled (no-op
// otherwise). Intended for daemon shutdown.
func Shutdown() {
	sharedMu.Lock()
	st, c := shared, coll
	shared, coll = nil, nil
	sharedMu.Unlock()
	if c != nil {
		close(c.stop)
		<-c.done
	}
	if st != nil {
		_ = st.Close()
	}
}
