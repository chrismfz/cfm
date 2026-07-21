package clam

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cfm/internal/enrich"
	"cfm/internal/notify"
)

type Config struct {
	Enabled     bool
	Network     string
	Address     string
	Timeout     time.Duration
	MaxWorkers  int
	QueueSize   int
	PendingDir  string
	InfectedDir string

	// ScanScope gates upload jobs by magic bytes (see scope.go). Only the
	// explicit ScanScopeArchives value gates; "" behaves like ScanScopeAll so
	// non-daemon constructions (CLI client, tests) keep full coverage.
	ScanScope string
	// SigIgnore holds the baseline CLAM_SIG_IGNORE globs (see sigignore.go).
	SigIgnore []string

	// Inline (blocking) mode — see inline.go. ScanMode is the GLOBAL default
	// ("async"|"inline"); the per-vhost flip lives edge-side (webdetector mode
	// override store). InlineTimeout bounds one synchronous scan (default 3s);
	// InlineDryRun scans inline but never blocks (burn-in).
	ScanMode      string
	InlineTimeout time.Duration
	InlineDryRun  bool
}

type Client struct {
	cfg Config
}

type Result struct {
	Path      string
	Infected  bool
	Signature string
	Raw       string
}

type Job struct {
	Path        string
	IP          string
	Host        string
	URI         string
	FileName    string
	Reason      string
	TempCopy    bool   // worker must handle file after scan
	InfectedDir string // where to move infected evidence
}

type Manager struct {
	cfg     Config
	client  *Client
	enr     *enrich.Enricher
	jobs    chan Job
	stopCh  chan struct{}
	started bool
	health  *scanHealth
}

type Enqueuer interface {
	Enqueue(Job) bool
	Enabled() bool
	PendingDir() string
	InfectedDir() string
}

var logf = func(format string, args ...interface{}) {}

func SetLogger(fn func(string, ...interface{})) {
	if fn != nil {
		logf = fn
	}
}

func New(cfg Config) *Client {
	if cfg.Network == "" {
		cfg.Network = "unix"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxWorkers <= 0 {
		cfg.MaxWorkers = 2
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 256
	}
	return &Client{cfg: cfg}
}

func NewManager(cfg Config) *Manager {
	if cfg.Network == "" {
		cfg.Network = "unix"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxWorkers <= 0 {
		cfg.MaxWorkers = 2
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 256
	}
	return &Manager{
		cfg:    cfg,
		client: New(cfg),
		jobs:   make(chan Job, cfg.QueueSize),
		stopCh: make(chan struct{}),
		health: &scanHealth{},
	}
}

func (c *Client) Enabled() bool {
	return c != nil && c.cfg.Enabled && strings.TrimSpace(c.cfg.Address) != ""
}

func (c *Client) dial() (net.Conn, error) {
	return c.dialTimeout(c.cfg.Timeout)
}

func (c *Client) dialTimeout(d time.Duration) (net.Conn, error) {
	if c == nil {
		return nil, errors.New("clam: nil client")
	}
	if !c.Enabled() {
		return nil, errors.New("clam: disabled or missing address")
	}
	if d <= 0 {
		d = c.cfg.Timeout
	}
	return net.DialTimeout(c.cfg.Network, c.cfg.Address, d)
}

func (c *Client) cmd(command string) (string, error) {
	return c.cmdTimeout(command, c.cfg.Timeout)
}

// cmdTimeout runs one clamd command bounded by d (dial + read deadline) instead
// of the full Config.Timeout — used by the health prober and `cfm clam status`
// so a hung/absent clamd never blocks them for the scan timeout.
func (c *Client) cmdTimeout(command string, d time.Duration) (string, error) {
	if d <= 0 {
		d = c.cfg.Timeout
	}
	conn, err := c.dialTimeout(d)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(d))

	if _, err := fmt.Fprintf(conn, "%s\n", command); err != nil {
		return "", err
	}

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func (c *Client) Ping() error {
	return c.PingWithTimeout(c.cfg.Timeout)
}

// PingWithTimeout pings clamd with a bounded dial+read timeout. Callers that
// must stay responsive (status output, the background health prober) pass a
// short d rather than the full scan Config.Timeout.
func (c *Client) PingWithTimeout(d time.Duration) error {
	resp, err := c.cmdTimeout("PING", d)
	if err != nil {
		return err
	}
	if resp != "PONG" {
		return fmt.Errorf("clam: unexpected ping response: %q", resp)
	}
	return nil
}

func (c *Client) Version() (string, error) {
	return c.cmd("VERSION")
}

func (c *Client) ScanFile(path string) (*Result, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" {
		return nil, fmt.Errorf("clam: empty path")
	}

	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("clam: %s is a directory, use ScanPath()", path)
	}

	resp, err := c.cmd("SCAN " + path)
	if err != nil {
		return nil, err
	}
	return parseScanResponse(path, resp), nil
}

func (c *Client) ScanPath(path string) ([]Result, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" {
		return nil, fmt.Errorf("clam: empty path")
	}

	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !fi.IsDir() {
		r, err := c.ScanFile(path)
		if err != nil {
			return nil, err
		}
		return []Result{*r}, nil
	}

	var out []Result
	err = filepath.Walk(path, func(p string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			out = append(out, Result{
				Path: p,
				Raw:  "walk error: " + walkErr.Error(),
			})
			return nil
		}
		if info == nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		mode := info.Mode()
		if mode&os.ModeSymlink != 0 {
			return nil
		}
		if !mode.IsRegular() {
			return nil
		}

		r, err := c.ScanFile(p)
		if err != nil {
			out = append(out, Result{
				Path: p,
				Raw:  "scan error: " + err.Error(),
			})
			return nil
		}
		out = append(out, *r)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (m *Manager) Start() {
	if m == nil || m.started || !m.client.Enabled() {
		return
	}
	m.started = true
	for i := 0; i < m.cfg.MaxWorkers; i++ {
		go m.worker(i + 1)
	}
	go m.healthLoop()
}

func (m *Manager) Stop() {
	if m == nil || !m.started {
		return
	}
	close(m.stopCh)
	m.started = false
}

func (m *Manager) Enqueue(job Job) bool {
	if m == nil || !m.started {
		return false
	}

	job.Path = filepath.Clean(strings.TrimSpace(job.Path))
	if job.Path == "" {
		return false
	}

	select {
	case m.jobs <- job:
		return true
	default:
		m.health.queueDrops.Add(1)
		logf("[clam] result=queue_full path=%s ip=%s host=%s uri=%s reason=%s",
			job.Path, job.IP, job.Host, job.URI, job.Reason)
		return false
	}
}

func (m *Manager) Enabled() bool {
	return m != nil && m.started && m.client.Enabled()
}

func (m *Manager) PendingDir() string {
	if m == nil {
		return ""
	}
	return m.cfg.PendingDir
}

func (m *Manager) InfectedDir() string {
	if m == nil {
		return ""
	}
	return m.cfg.InfectedDir
}

// QueueDepth returns the current number of jobs buffered in the worker
// channel and its capacity. Both zero when the manager is nil. Cheap
// snapshot intended for `cfm clam status`; not for hot-path metrics.
func (m *Manager) QueueDepth() (int, int) {
	if m == nil || m.jobs == nil {
		return 0, 0
	}
	return len(m.jobs), cap(m.jobs)
}

func (m *Manager) SetEnricher(e *enrich.Enricher) {
	if m == nil {
		return
	}
	m.enr = e
}

func (m *Manager) worker(id int) {
	for {
		select {
		case <-m.stopCh:
			return
		case job, ok := <-m.jobs:
			if !ok {
				return
			}
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						logf("[clam_worker] panic worker=%d path=%s ip=%s host=%s uri=%s err=%v",
							id, job.Path, job.IP, job.Host, job.URI, rec)
					}
				}()
				m.process(job)
			}()
		}
	}
}

func (m *Manager) process(job Job) {
	fi, err := os.Stat(job.Path)
	if err != nil {
		logf("[clam_scan] result=error ip=%s host=%s uri=%s reason=%s err=%q",
			job.IP, job.Host, job.URI, job.Reason, err)
		if job.TempCopy {
			_ = os.Remove(job.Path)
		}
		return
	}

	// Circuit breaker: clamd is known-down, so don't dial it per-job (each dial
	// would block up to Config.Timeout). Fast-skip and clean up the temp copy;
	// the health prober re-checks clamd and closes the breaker on recovery.
	if m.health.isOpen() {
		m.health.skippedBreaker.Add(1)
		logf("[clam_scan] result=skipped_clamd_down ip=%s host=%s uri=%s reason=%s",
			job.IP, job.Host, job.URI, job.Reason)
		if job.TempCopy {
			_ = os.Remove(job.Path)
		}
		return
	}

	if fi.IsDir() {
		// Directory jobs don't occur in the async upload path (uploads are
		// single temp files) and ScanPath swallows per-file transport errors
		// into results (returning nil), so its error is a walk/stat signal, not
		// clamd reachability — don't feed the breaker from here. The single-file
		// path below and the health prober drive it.
		results, err := m.client.ScanPath(job.Path)
		if err != nil {
			logf("[clam_scan] result=error ip=%s host=%s uri=%s reason=%s err=%q",
				job.IP, job.Host, job.URI, job.Reason, err)
			return
		}
		for i := range results {
			logResult(job, &results[i])
		}
		return
	}

	// Scope gate (CLAM_SCAN_SCOPE=archives): only container/archive uploads are
	// worth clamd's time — the class the WAF's signature layer can't inspect.
	// Decided by magic bytes (extensions are forgeable). A read error falls
	// through to the scan: fail toward coverage, never silently skip.
	if m.cfg.ScanScope == ScanScopeArchives {
		if isArch, aerr := isArchiveFile(job.Path); aerr == nil && !isArch {
			m.health.skippedScope.Add(1)
			logf("[clam_scan] result=skipped_scope ip=%s host=%s uri=%s reason=%s",
				job.IP, job.Host, job.URI, job.Reason)
			if job.TempCopy {
				_ = os.Remove(job.Path)
			}
			return
		}
	}

	r, err := m.client.ScanFile(job.Path)
	if err != nil {
		m.recordScan(false, err.Error())
		logf("[clam_scan] result=error ip=%s host=%s uri=%s reason=%s err=%q",
			job.IP, job.Host, job.URI, job.Reason, err)
		if job.TempCopy {
			_ = os.Remove(job.Path)
		}
		return
	}
	m.recordScan(true, "")

	// Signature-trust downgrade: an ignored signature's infected verdict is
	// handled log-only — recorded (log + history, flagged) but neither
	// notified nor quarantined. Decided BEFORE logging so the log line and
	// the published event both carry the downgrade.
	sigIgnoredHit, sigIgnoredBy := false, ""
	if r.Infected {
		sigIgnoredHit, sigIgnoredBy = m.sigIgnored(job.Host, r.Signature)
	}

	// Always log result first.
	logResult(job, r)

	if sigIgnoredHit {
		m.health.sigIgnored.Add(1)
		logf("[clam_scan] result=infected_ignored ip=%s host=%s uri=%s sig=%q by=%s",
			job.IP, job.Host, job.URI, r.Signature, sigIgnoredBy)
	} else {
		// Best-effort notify for test mode. Skipped for a downgraded verdict —
		// its result=infected/critical framing IS the notification we suppress.
		m.safeNotifyUpload(job, r)
	}

	if !job.TempCopy {
		return
	}

	if r.Infected && !sigIgnoredHit {
		dest := job.Path // fallback if rename fails
		if job.InfectedDir != "" {
			_ = os.MkdirAll(job.InfectedDir, 0o700)
			candidate := filepath.Join(job.InfectedDir, filepath.Base(job.Path))
			if rerr := os.Rename(job.Path, candidate); rerr == nil {
				dest = candidate
			}
		}
		logf("[clam_scan] evidence kept path=%s ip=%s host=%s sig=%q",
			dest, job.IP, job.Host, r.Signature)

		m.safeNotifyInfected(job, r, dest, "async")

		publishScanEvent(ScanEvent{
			EventType: "clam_infected",
			Host:      job.Host,
			IP:        job.IP,
			URI:       job.URI,
			FileName:  jobFileName(job),
			Signature: r.Signature,
			Evidence:  dest,
			Mode:      "async",
			When:      time.Now(),
		})
		return
	}

	if r.Infected && sigIgnoredHit {
		// Keep the hit queryable (greyed on the ClamAV page) but treat the
		// file like a clean upload: no quarantine copy — the whole point is
		// that legitimate customer files must not be retained as "evidence".
		publishScanEvent(ScanEvent{
			EventType:  "clam_infected",
			Host:       job.Host,
			IP:         job.IP,
			URI:        job.URI,
			FileName:   jobFileName(job),
			Signature:  r.Signature,
			SigIgnored: true,
			IgnoredBy:  sigIgnoredBy,
			Mode:       "async",
			When:       time.Now(),
		})
	}

	_ = os.Remove(job.Path)
}

// jobFileName is the operator-facing file label: the multipart filename when
// the edge captured one, else the spool basename.
func jobFileName(job Job) string {
	if fn := strings.TrimSpace(job.FileName); fn != "" {
		return fn
	}
	return filepath.Base(job.Path)
}

func (m *Manager) safeNotifyUpload(job Job, r *Result) {
	defer func() {
		if rec := recover(); rec != nil {
			logf("[clam_notify] panic kind=CLAM/UPLOAD ip=%s host=%s uri=%s err=%v",
				job.IP, job.Host, job.URI, rec)
		}
	}()
	m.notifyUpload(job, r)
}

func (m *Manager) safeNotifyInfected(job Job, r *Result, evidencePath, mode string) {
	defer func() {
		if rec := recover(); rec != nil {
			logf("[clam_notify] panic kind=CLAM/INFECTED ip=%s host=%s uri=%s err=%v",
				job.IP, job.Host, job.URI, rec)
		}
	}()
	m.notifyInfected(job, r, evidencePath, mode)
}

func (m *Manager) notifyUpload(job Job, r *Result) {
	if m == nil || r == nil {
		return
	}

	asnText, countryText, ptr := m.enrichIP(job.IP)

	filename := strings.TrimSpace(job.FileName)
	if filename == "" {
		filename = filepath.Base(job.Path)
	}

	result := "clean"
	severity := "info"
	if r.Infected {
		result = "infected"
		severity = "critical"
	}

	notify.Enqueue(notify.Event{
		Host:     job.Host,
		Kind:     "CLAM/UPLOAD",
		SrcIP:    job.IP,
		ASN:      asnText,
		Country:  countryText,
		PTR:      ptr,
		Reason:   "UPLOAD",
		When:     time.Now(),
		Section:  "clam",
		Severity: severity,
		Samples: []string{
			"uri=" + job.URI,
			"host=" + job.Host,
			"file=" + filename,
			"result=" + result,
		},
		Extra: map[string]string{
			"uri":      job.URI,
			"filename": filename,
			"result":   result,
			"key":      job.IP,
		},
	})
}

// mode records how the verdict was handled: "async" (notify-only pipeline),
// "inline" (request blocked) or "inline_dryrun" (would have blocked).
func (m *Manager) notifyInfected(job Job, r *Result, evidencePath, mode string) {
	if m == nil || r == nil || !r.Infected {
		return
	}
	if mode == "" {
		mode = "async"
	}

	asnText, countryText, ptr := m.enrichIP(job.IP)

	filename := strings.TrimSpace(job.FileName)
	if filename == "" {
		filename = filepath.Base(job.Path)
	}

	notify.Enqueue(notify.Event{
		Host:     job.Host,
		Kind:     "CLAM/INFECTED",
		SrcIP:    job.IP,
		ASN:      asnText,
		Country:  countryText,
		PTR:      ptr,
		Reason:   r.Signature,
		When:     time.Now(),
		Section:  "clam",
		Severity: "critical",
		Samples: []string{
			"uri=" + job.URI,
			"host=" + job.Host,
			"file=" + filename,
			"sig=" + r.Signature,
			"evidence=" + evidencePath,
		},
		Extra: map[string]string{
			"uri":      job.URI,
			"filename": filename,
			"sig":      r.Signature,
			"evidence": evidencePath,
			"key":      job.IP,
		},
	})
}

func (m *Manager) enrichIP(ip string) (asnText, countryText, ptr string) {
	if m == nil || m.enr == nil || strings.TrimSpace(ip) == "" {
		return "", "", ""
	}

	er := m.enr.Lookup(ip)
	if er.ASN > 0 {
		if er.ASNName != "" {
			asnText = fmt.Sprintf("AS%d %s", er.ASN, er.ASNName)
		} else {
			asnText = fmt.Sprintf("AS%d", er.ASN)
		}
	}

	switch {
	case er.City != "" && er.Country != "":
		countryText = er.City + ", " + er.Country
	case er.Country != "":
		countryText = er.Country
	}

	ptr = er.PTR
	return asnText, countryText, ptr
}

func logResult(job Job, r *Result) {
	if r == nil {
		return
	}
	switch {
	case r.Infected:
		logf("[clam_scan] ip=%s host=%s uri=%s reason=%s result=INFECTED sig=%q",
			job.IP, job.Host, job.URI, job.Reason, r.Signature)
	case strings.HasSuffix(r.Raw, " OK"):
		logf("[clam_scan] ip=%s host=%s uri=%s reason=%s result=clean",
			job.IP, job.Host, job.URI, job.Reason)
	default:
		logf("[clam_scan] ip=%s host=%s uri=%s reason=%s result=error raw=%q",
			job.IP, job.Host, job.URI, job.Reason, r.Raw)
	}
}

func parseScanResponse(path, resp string) *Result {
	r := &Result{
		Path: path,
		Raw:  resp,
	}

	parts := strings.SplitN(resp, ": ", 2)
	body := resp
	if len(parts) == 2 {
		body = parts[1]
	}
	body = strings.TrimSpace(body)

	switch {
	case strings.HasSuffix(body, " OK"):
		r.Infected = false
		return r
	case strings.HasSuffix(body, " FOUND"):
		r.Infected = true
		r.Signature = strings.TrimSpace(strings.TrimSuffix(body, " FOUND"))
		return r
	default:
		return r
	}
}

// Optional later helper if you decide to switch dirs to clamd recursion.
func (c *Client) ContScan(path string) ([]Result, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" {
		return nil, fmt.Errorf("clam: empty path")
	}

	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(c.cfg.Timeout))

	if _, err := fmt.Fprintf(conn, "CONTSCAN %s\n", path); err != nil {
		return nil, err
	}

	var out []Result
	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, *parseScanResponse(path, line))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return out, err
		}
	}
	return out, nil
}
