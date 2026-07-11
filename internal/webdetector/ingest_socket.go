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
// senders (configs/lua/log-cfm.lua) to push TSV log lines into webdetector.
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

	lastReceived     atomic.Int64 // unix seconds; 0 == never
	listening        atomic.Bool
	lastOversizedLog atomic.Int64 // unix seconds of the last "oversized line" WARN (throttle)
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

// serveConn reads newline-delimited TSV lines off one connection. Line length is
// bounded: bufio.ReadString/ReadBytes accumulate an un-delimited stream WITHOUT
// bound (the buffer size only limits a single fill, and collectFragments grows a
// []byte until it finds the delimiter or EOF), so a sender that never writes '\n'
// could OOM the daemon. ReadSlice instead returns ErrBufferFull once the line
// exceeds the buffer, which lets us drop the oversized line and resync at the
// next newline while keeping memory bounded to maxLine.
//
// Scope: this bounds per-line MEMORY (the OOM vector). It does not add a
// per-connection or goroutine cap — a cfm-group peer can still hold a connection
// and busy one goroutine (streaming valid lines, or repeated oversized+'\n'). That
// is an accepted, pre-existing exposure: the socket is root:cfm 0660, so any caller
// is already trusted at nginx-worker level.
func (s *IngestSocket) serveConn(ctx context.Context, e *Engine, conn net.Conn) {
	defer conn.Close()

	const (
		maxLine  = 256 * 1024      // per-line memory bound (matches the FileTailer buffer)
		maxDrain = 8 * 1024 * 1024 // give up + close if ONE oversized line runs past this
		// readBudget is an ABSOLUTE deadline per ReadSlice call, not a pure idle
		// timer: it caps how long one read may take, which is what bounds a
		// slow-drip sender (a line that trickles in forever). A legit sender emits
		// whole small lines, so it never pauses >readBudget mid-line.
		readBudget = 60 * time.Second
	)

	br := bufio.NewReaderSize(conn, maxLine)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(readBudget))

		line, err := br.ReadSlice('\n')

		if err == bufio.ErrBufferFull {
			// Oversized line: > maxLine with no newline yet. Drop it and resync at
			// the next newline so the connection keeps ingesting; give up (close)
			// if a single line floods past maxDrain. Memory stays bounded to maxLine.
			s.noteOversizedLine()
			dropped := len(line)
			for err == bufio.ErrBufferFull {
				if ctx.Err() != nil {
					return
				}
				if dropped > maxDrain {
					return // unbounded newline-free stream on one line → close
				}
				_ = conn.SetReadDeadline(time.Now().Add(readBudget))
				line, err = br.ReadSlice('\n')
				dropped += len(line)
			}
			if err != nil {
				return // EOF or read error while draining
			}
			continue // resynced at a newline; the oversized line was dropped
		}

		if len(line) > 0 {
			if line[len(line)-1] == '\n' {
				line = line[:len(line)-1]
			}
			// ReadSlice returns a slice into br's buffer, invalidated by the next
			// read — copy to a string before handing it downstream, which retains it.
			s.handleLine(e, string(line))
		}
		if err != nil {
			return
		}
	}
}

// noteOversizedLine records a dropped oversized ingest line: it counts as a
// parse failure for telemetry and emits a throttled WARN (at most once per
// minute) so an attack or a broken sender is visible without flooding the log.
func (s *IngestSocket) noteOversizedLine() {
	telemetry.RecordWebdetParseFailure()
	now := time.Now().Unix()
	last := s.lastOversizedLog.Load()
	if now-last >= 60 && s.lastOversizedLog.CompareAndSwap(last, now) {
		logging.Logf("[webdetector] ingest socket dropped a line exceeding the " +
			"256 KB buffer (no newline); resyncing")
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

// IngestSourceState is the shared arbiter view used by the HTTP API, CLI, and
// health collectors. It intentionally mirrors /api/v1/webdet/ingest-source.
type IngestSourceState struct {
	Active           string `json:"active"`
	SockPath         string `json:"sock_path"`
	SockListening    bool   `json:"sock_listening"`
	LastReceivedUnix int64  `json:"last_received_unix"`
	LogFile          string `json:"log_file"`
	FileActive       bool   `json:"file_active"`
}

var currentIngestSourceEngine atomic.Pointer[Engine]

// CurrentIngestSourceState returns the latest package-level arbiter state from
// the webdetector engine currently wired into the daemon. The boolean is false
// when no engine has registered yet.
func CurrentIngestSourceState() (IngestSourceState, bool) {
	e := currentIngestSourceEngine.Load()
	if e == nil {
		return IngestSourceState{}, false
	}
	return e.IngestSourceState(), true
}

// IngestSourceState returns this engine's current arbiter state. It is the
// single source used by /api/v1/webdet/ingest-source and health snapshots.
func (e *Engine) IngestSourceState() IngestSourceState {
	if e == nil {
		return IngestSourceState{Active: "none", SockPath: DefaultIngestSockPath}
	}
	active := e.ActiveLogSource()
	state := IngestSourceState{
		Active:     active,
		SockPath:   DefaultIngestSockPath,
		LogFile:    e.ConfiguredLogFile(),
		FileActive: active == "file",
	}
	if s := e.IngestSocketRef(); s != nil {
		state.SockPath = s.SockPath()
		state.SockListening = s.Listening()
		if t := s.LastReceived(); !t.IsZero() {
			state.LastReceivedUnix = t.Unix()
		}
	}
	return state
}

// SetIngestSocket wires the listener into the engine so the file-tailer loop
// can consult it for arbitration.
func (e *Engine) SetIngestSocket(s *IngestSocket) {
	if e == nil {
		return
	}
	e.ingestSock = s
	currentIngestSourceEngine.Store(e)
}

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
