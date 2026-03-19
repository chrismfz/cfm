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
)

type Config struct {
	Enabled    bool
	Network    string
	Address    string
	Timeout    time.Duration
	MaxWorkers int
	QueueSize  int
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
	Path   string
	IP     string
	Host   string
	URI    string
	Reason string
	TempCopy    bool   // worker must handle file after scan
	InfectedDir string // where to move infected evidence
}

type Manager struct {
	cfg     Config
	client  *Client
	jobs    chan Job
	stopCh  chan struct{}
	started bool
}

type Enqueuer interface {
    Enqueue(Job) bool
    Enabled() bool
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
	}
}

func (c *Client) Enabled() bool {
	return c != nil && c.cfg.Enabled && strings.TrimSpace(c.cfg.Address) != ""
}

func (c *Client) dial() (net.Conn, error) {
	if c == nil {
		return nil, errors.New("clam: nil client")
	}
	if !c.Enabled() {
		return nil, errors.New("clam: disabled or missing address")
	}
	return net.DialTimeout(c.cfg.Network, c.cfg.Address, c.cfg.Timeout)
}

func (c *Client) cmd(command string) (string, error) {
	conn, err := c.dial()
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(c.cfg.Timeout))

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
	resp, err := c.cmd("PING")
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
		logf("[clam] result=queue_full path=%s ip=%s host=%s uri=%s reason=%s",
			job.Path, job.IP, job.Host, job.URI, job.Reason)
		return false
	}
}

func (m *Manager) Enabled() bool {
    return m != nil && m.started && m.client.Enabled()
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
			m.process(job)
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

    if fi.IsDir() {
        // dir scans don't use TempCopy — nothing to clean up
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

    r, err := m.client.ScanFile(job.Path)
    if err != nil {
        logf("[clam_scan] result=error ip=%s host=%s uri=%s reason=%s err=%q",
            job.IP, job.Host, job.URI, job.Reason, err)
        if job.TempCopy {
            _ = os.Remove(job.Path)
        }
        return
    }

    logResult(job, r)

    if job.TempCopy {
        if r.Infected {
            // Move to infected dir for manual inspection, don't delete.
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
        } else {
            _ = os.Remove(job.Path)
        }
    }
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
