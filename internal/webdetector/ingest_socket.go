// internal/webdetector/ingest_socket.go
package webdetector

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"cfm/internal/logging"
	"cfm/internal/sslcollector"
	"cfm/internal/telemetry"
)

// DefaultIngestSockPath is the Unix stream socket path used by log_by_lua_block
// senders (configs/log-cfm.lua) to push TSV log lines into webdetector.
// Hardcoded by design: the arbiter in Engine.RunOnce selects socket-over-file
// automatically based on whether lines arrive here, so users never have to
// flip a config knob when switching between OpenResty/Angie (socket) and
// plain nginx/httpd (file tail) deployments.
const DefaultIngestSockPath = "/run/cfm/ingest.sock"

// SocketActiveWindow is the arbiter's silence threshold. If a line was
// received over the socket within this window, the file tailer output is
// suppressed. When the socket goes quiet for longer than this, the file
// tailer resumes feeding the pipeline.
const SocketActiveWindow = 30 * time.Second

// IngestSocket listens on a Unix stream socket for TSV log lines and feeds
// them into the webdetector Engine using the same parser as the file tailer.
// It also tracks LastReceived so the arbiter (and the `cfm webtop source`
// CLI) can decide whether to prefer the socket or fall back to the file.
type IngestSocket struct {
	sockPath string

	lastReceived atomic.Int64 // unix seconds; 0 == never
	listening    atomic.Bool
}

// NewIngestSocket creates a listener bound to the default socket path.
func NewIngestSocket() *IngestSocket {
	return &IngestSocket{sockPath: DefaultIngestSockPath}
}

// SockPath returns the filesystem path the listener is (or will be) bound to.
func (s *IngestSocket) SockPath() string {
	if s == nil {
		return DefaultIngestSockPath
	}
	return s.sockPath
}

// LastReceived returns the time of the last successfully ingested socket line.
// Zero value means "never".
func (s *IngestSocket) LastReceived() time.Time {
	if s == nil {
		return time.Time{}
	}
	t := s.lastReceived.Load()
	if t == 0 {
		return time.Time{}
	}
	return time.Unix(t, 0)
}

// Listening reports whether the accept loop currently holds the socket.
func (s *IngestSocket) Listening() bool {
	if s == nil {
		return false
	}
	return s.listening.Load()
}

// Active reports whether the socket has received a line within the
// arbiter window, i.e. whether it should be treated as the authoritative
// source for log ingestion right now.
func (s *IngestSocket) Active(now time.Time) bool {
	if s == nil {
		return false
	}
	t := s.lastReceived.Load()
	if t == 0 {
		return false
	}
	return now.Unix()-t <= int64(SocketActiveWindow.Seconds())
}

// Serve binds the Unix stream socket and accepts connections until ctx
// is cancelled. Each connection is handled by its own goroutine. On
// shutdown the listener is closed and the socket file removed.
func (s *IngestSocket) Serve(ctx context.Context, e *Engine) error {
	if s == nil || e == nil {
		return nil
	}

	// Ensure the parent directory exists (tmpfs under systemd is wiped on boot).
	// 0750 root:cfm — workers (cfm group) traverse in to reach the socket, no
	// other user needs access. main.go normally does the Chmod+Chown at daemon
	// start; this is a defensive fallback if webdetector comes up first.
	_ = os.MkdirAll("/run/cfm", 0o750)
	if gid := sslcollector.CfmGroupID(); gid > 0 {
		_ = os.Chown("/run/cfm", 0, gid)
	}

	// Remove any stale socket file from a previous run.
	_ = os.Remove(s.sockPath)

	ln, err := net.Listen("unix", s.sockPath)
	if err != nil {
		return fmt.Errorf("ingest_socket listen %s: %w", s.sockPath, err)
	}
	// root:cfm 0660 — same pattern as the nginx_bridge decision socket, lets
	// OpenResty/Angie workers (cfm group) connect without running as root.
	_ = os.Chmod(s.sockPath, 0o660)
	if gid := sslcollector.CfmGroupID(); gid > 0 {
		_ = os.Chown(s.sockPath, 0, gid)
	}

	s.listening.Store(true)
	defer s.listening.Store(false)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
		_ = os.Remove(s.sockPath)
	}()

	logging.Logf("[webdetector] ingest socket listening on unix:%s", s.sockPath)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logging.Logf("[webdetector] ingest accept: %v", err)
			// Avoid a tight error loop if the listener goes unhealthy.
			time.Sleep(250 * time.Millisecond)
			continue
		}
		go s.serveConn(ctx, e, conn)
	}
}

func (s *IngestSocket) serveConn(ctx context.Context, e *Engine, conn net.Conn) {
	defer conn.Close()

	// 256 KB matches the FileTailer buffer so a pathological oversized line
	// doesn't hang this goroutine — bufio.Reader will return ErrBufferFull
	// and we drop the fragment.
	br := bufio.NewReaderSize(conn, 256*1024)
	for {
		if ctx.Err() != nil {
			return
		}
		// Idle read deadline so abandoned keepalive connections release resources.
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		line, err := br.ReadString('\n')
		if len(line) > 0 {
			if line[len(line)-1] == '\n' {
				line = line[:len(line)-1]
			}
			s.handleLine(e, line)
		}
		if err != nil {
			return
		}
	}
}

// handleLine parses a single TSV line and feeds it through the same ingest
// path as the file tailer. On success it marks the socket as active so the
// arbiter will suppress the file tailer until the socket goes quiet again.
func (s *IngestSocket) handleLine(e *Engine, line string) {
	if line == "" {
		return
	}
	rec, ok := e.adapter.Parse(line)
	if !ok {
		telemetry.RecordWebdetParseFailure()
		return
	}
	telemetry.RecordWebdetLineParsed()

	e.ingest(rec, line)

	// Mark activity AFTER a successful ingest — a malformed line doesn't
	// count as "socket alive" for arbitration.
	s.lastReceived.Store(time.Now().Unix())
	e.noteActiveSource("socket")
}

// ── Engine-side arbiter helpers ──────────────────────────────────────────────

// SetIngestSocket wires the listener into the engine so the file-tailer loop
// can consult it for arbitration.
func (e *Engine) SetIngestSocket(s *IngestSocket) { e.ingestSock = s }

// IngestSocketRef returns the currently wired IngestSocket (may be nil).
func (e *Engine) IngestSocketRef() *IngestSocket { return e.ingestSock }

// fileSourceConfigured reports whether a file/folder log source has been
// configured via detectors.conf.
func (e *Engine) fileSourceConfigured() bool {
	mode := strings.ToLower(strings.TrimSpace(e.cfg.Mode))
	if mode == "folder" {
		return strings.TrimSpace(e.cfg.LogDir) != ""
	}
	return strings.TrimSpace(e.cfg.LogPath) != ""
}

// ActiveLogSource returns the arbiter's current view: "socket" if the
// socket has received a line within SocketActiveWindow; otherwise "file" if
// a file/folder source is configured; otherwise "none".
//
// This is the same decision the RunOnce tight loop uses to gate file-tailer
// output, so CLI/HTTP consumers see exactly what the pipeline is doing.
func (e *Engine) ActiveLogSource() string {
	now := time.Now()
	if e.ingestSock != nil && e.ingestSock.Active(now) {
		return "socket"
	}
	if e.fileSourceConfigured() {
		return "file"
	}
	return "none"
}

// ConfiguredLogFile returns the log file path from detectors.conf, or ""
// when folder mode is used / nothing is configured. Used by the CLI.
func (e *Engine) ConfiguredLogFile() string {
	if strings.ToLower(strings.TrimSpace(e.cfg.Mode)) == "folder" {
		return ""
	}
	return strings.TrimSpace(e.cfg.LogPath)
}

// ── Source-transition debounce logging ───────────────────────────────────────

// noteActiveSource is called every time a line is actually accepted into the
// pipeline, tagged with "socket" or "file". On transition it logs a single
// INFO line; subsequent lines from the same source are silent.
func (e *Engine) noteActiveSource(src string) {
	e.activeSrcMu.Lock()
	changed := e.activeSrcName != src
	e.activeSrcName = src
	e.activeSrcMu.Unlock()
	if !changed {
		return
	}
	switch src {
	case "socket":
		logging.Logf("[webdetector] log source: socket active")
	case "file":
		logging.Logf("[webdetector] log source: file fallback")
	}
}
