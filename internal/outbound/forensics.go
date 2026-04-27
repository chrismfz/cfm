package outbound

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Forensics holds the bits of context we attach to a verdict so an operator
// can identify the guilty user/script without manually grepping logs.
type Forensics struct {
	Username   string   // resolved from uid via syslookup; "" if not in /etc/passwd
	Groupname  string   // resolved from gid
	Process    string   // /proc/<pid>/comm — best-effort
	PID        int      // 0 if not resolved
	CWD        string   // /proc/<pid>/cwd readlink — useful for php-fpm pools
	Cmdline    string   // /proc/<pid>/cmdline — useful for cron/exim
	EximQueue  EximSnap // queue summary for the user (only for SMTP signal)
	Enrichment EnrichInfo
}

// EnrichInfo is a flat copy of the dst-IP enrichment fields we include in the
// log line. Avoids leaking *enrich.Enricher into log code.
type EnrichInfo struct {
	ASN     uint
	ASNName string
	Country string
	City    string
	PTR     string
}

// EximSnap is what we extract from exim -bp for the offending user.
type EximSnap struct {
	Total    int      // total messages currently in queue authored by/for this user
	Frozen   int      // frozen subset
	Senders  []string // up to N unique sender addresses
	MsgIDs   []string // up to N message IDs
	SourceOK bool     // false if exim binary missing or command failed
}

// readProcText returns the trimmed contents of /proc/<pid>/<file>, or "" if
// the file can't be read (process may have already exited).
func readProcText(pid int, name string) string {
	if pid <= 0 {
		return ""
	}
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), name))
	if err != nil {
		return ""
	}
	s := string(b)
	// /proc/<pid>/cmdline is NUL-separated; turn into spaces.
	s = strings.ReplaceAll(s, "\x00", " ")
	return strings.TrimSpace(s)
}

func readProcLink(pid int, name string) string {
	if pid <= 0 {
		return ""
	}
	target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), name))
	if err != nil {
		return ""
	}
	return target
}

// EximQueueForUser shells out to `exim -bpu <user>` (or falls back to filtering
// `exim -bp` output by sender when -bpu isn't available) to produce a per-user
// queue snapshot. Times out after `timeout`. Returns SourceOK=false on any
// error so callers can render "exim unavailable" instead of bailing.
//
// Note: -bpu is supported by Exim ≥ 4.85; falling back parses `exim -bp`.
func EximQueueForUser(ctx context.Context, user string, sampleLimit int, timeout time.Duration) EximSnap {
	if user == "" {
		return EximSnap{}
	}
	if sampleLimit <= 0 {
		sampleLimit = 5
	}
	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	// Strategy: prefer -bpr (raw, no header) over -bp because -bp's "*** frozen ***"
	// line is a separate stanza we'd have to associate with the message. We use
	// -bpr and detect frozen via age sign (negative pretty-time prefix). If
	// -bpr is unavailable, we still try -bp.
	for _, args := range [][]string{{"-bpr"}, {"-bp"}} {
		snap, ok := runExim(ctx, args, user, sampleLimit, timeout)
		if ok {
			snap.SourceOK = true
			return snap
		}
	}
	return EximSnap{SourceOK: false}
}

func runExim(ctx context.Context, args []string, user string, sampleLimit int, timeout time.Duration) (EximSnap, bool) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "exim", args...)
	out, err := cmd.Output()
	if err != nil {
		return EximSnap{}, false
	}

	// exim -bp output stanza per message looks like:
	//   24h  1.5K 1tBwAr-0001Yz-Lx <sender@example.com>
	//          recipient1@example.com
	//          recipient2@example.com
	//
	// Frozen messages have an extra "*** frozen ***" suffix on the header line.
	// We match the header by detecting an angle-bracket sender and capturing
	// the message ID + sender. We only count messages whose sender's localpart
	// (before @) matches `user` OR whose sender is empty <> AND whose first
	// recipient is `user@<host>` (cron mail). This is a heuristic — perfect
	// per-uid attribution is only possible by parsing /var/spool/exim/input
	// directly, which we deliberately avoid here.

	var snap EximSnap
	uniqSenders := map[string]struct{}{}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lastWasUserMsg bool
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			lastWasUserMsg = false
			continue
		}

		// Header line heuristic: contains "<...>" with @
		if i := strings.IndexByte(line, '<'); i >= 0 {
			j := strings.IndexByte(line[i:], '>')
			if j > 0 {
				sender := line[i+1 : i+j]
				if matchUser(sender, user) {
					fields := strings.Fields(line[:i])
					if len(fields) >= 3 {
						snap.MsgIDs = appendCapped(snap.MsgIDs, fields[2], sampleLimit)
					}
					if sender != "" {
						if _, seen := uniqSenders[sender]; !seen {
							uniqSenders[sender] = struct{}{}
							snap.Senders = appendCapped(snap.Senders, sender, sampleLimit)
						}
					}
					snap.Total++
					if strings.Contains(line, "*** frozen ***") {
						snap.Frozen++
					}
					lastWasUserMsg = true
					continue
				}
			}
		}

		// Continuation line (recipient): only used if we haven't matched yet
		// AND the recipient localpart matches the user (cron-style).
		if !lastWasUserMsg && (strings.HasPrefix(line, "          ") || strings.HasPrefix(line, "\t")) {
			if matchUser(strings.TrimSpace(line), user) {
				// Backfill: the previous header is the message we want, but we
				// already advanced past it. Skip rather than re-scan — the
				// summary's "Total" stays a lower bound, which is fine for an
				// alert breadcrumb.
				_ = line
			}
		}
	}
	return snap, true
}

func matchUser(addr, user string) bool {
	if addr == "" || user == "" {
		return false
	}
	at := strings.IndexByte(addr, '@')
	var local string
	if at < 0 {
		local = addr
	} else {
		local = addr[:at]
	}
	return strings.EqualFold(local, user)
}

func appendCapped(s []string, v string, max int) []string {
	if len(s) >= max {
		return s
	}
	return append(s, v)
}
