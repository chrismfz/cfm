// Package srcresolve picks a detector's log source (journald unit, log file,
// or docker container) from its config plus per-detector candidate lists, so
// every register shares ONE resolution semantic instead of re-implementing it.
// Design: docs/detectors-config-unification.md §3 (Mechanism A).
//
// Semantics:
//
//   - Explicit beats auto. A concrete MODE restricts resolution to that source
//     kind, and a concrete DOCKER_CONTAINER / JOURNAL_UNIT / LOG_PATH (checked
//     in that precedence order) short-circuits MODE=auto and is used verbatim,
//     never probed — the operator's word is final. The one exception: an
//     explicit unit under MODE=journal falls back to the file chain when
//     journalctl itself is unusable on the host (JournalReadable), matching
//     the historical dovecot register.
//   - MODE auto (or absent): explicit container/unit/path → journal candidates
//     (units with journal entries, then merely-active units resolved to their
//     canonical name) → docker discovery → file candidates → none. Discovery
//     runs BEFORE file candidates: a containerized service must not lose to a
//     stale host log file that merely exists (e.g. mailcow's dovecot vs an
//     idle host /var/log/mail.log).
//   - MODE journal with DOCKER_CONTAINER set resolves to docker: historically
//     "journal" was the implicit register default, so existing configs that
//     only added DOCKER_CONTAINER relied on this flip.
//   - MODE docker without a container falls back to the auto chain after
//     discovery fails (matches the historical dovecot fallback).
//   - Docker discovery never guesses: two or more matching containers is a
//     terminal non-result telling the operator to set DOCKER_CONTAINER.
//
// Parity invariant (see the design doc): each detector's first auto candidate
// is its previous hard default, so hosts whose config omits the source keys
// resolve to the same source as before wherever that source actually works.
// KindNone means "nothing could be confirmed"; registers are expected to fall
// back to their historical blind default rather than start inert, so a source
// that appears later still self-heals (resolution runs only at registration).
//
// The resolver is pure — all environment access goes through Probes — so the
// full decision table is unit-testable without systemd/docker.
package srcresolve

import (
	"fmt"
	"strings"
)

// Kind is the resolved source kind.
type Kind string

const (
	KindJournal Kind = "journal"
	KindFile    Kind = "file"
	KindDocker  Kind = "docker"
	KindNone    Kind = "none"
)

// Spec is one detector's source configuration plus its candidate lists.
// Mode/JournalUnit/LogPath/DockerContainer carry the (cleaned) config values;
// empty or "auto" means "resolve for me".
type Spec struct {
	Service string // label for Reason strings, e.g. "ssh_auth"

	Mode            string // "", auto, journal, file, docker
	JournalUnit     string // "", "auto", or an explicit unit
	LogPath         string // "", "auto", or an explicit path
	DockerContainer string // "" or an explicit container name

	JournalCandidates []string // tried in order; first = historical default
	FileCandidates    []string // tried in order; first = historical default
	DockerPatterns    []string // case-insensitive substrings of container names
}

// Probes abstracts the environment checks so Resolve stays pure. A nil
// function is treated conservatively: boolean probes read false (candidate
// not confirmed), ListContainers reads empty, JournalReadable reads TRUE
// (assume journalctl works, keeping explicit units verbatim), CanonicalUnit
// reads identity.
type Probes struct {
	JournalHasEntries func(unit string) bool // journal has ≥1 entry for unit
	UnitActive        func(unit string) bool // systemd reports the unit active
	CanonicalUnit     func(unit string) string // resolve Alias= to the real unit name ("" = unknown)
	JournalReadable   func() bool            // journalctl exists and can read the journal at all
	FileExists        func(path string) bool // path is an existing regular file
	ListContainers    func() []string        // names of running docker containers
}

// Result is the resolved source. Exactly one of Unit/Path/Container is set
// for the matching Kind; Reason is a one-line human trace for logs.
type Result struct {
	Kind      Kind
	Unit      string
	Path      string
	Container string
	Reason    string
}

func isAuto(v string) bool { return v == "" || strings.EqualFold(v, "auto") }

// Resolve applies the semantics documented on the package.
func Resolve(s Spec, p Probes) Result {
	mode := strings.ToLower(strings.TrimSpace(s.Mode))
	if mode == "" {
		mode = "auto"
	}
	unit := strings.TrimSpace(s.JournalUnit)
	path := strings.TrimSpace(s.LogPath)
	container := strings.TrimSpace(s.DockerContainer)
	if isAuto(unit) {
		unit = ""
	}
	if isAuto(path) {
		path = ""
	}

	switch mode {
	case "auto":
		// Explicit values short-circuit, most specific first.
		if container != "" {
			return Result{Kind: KindDocker, Container: container, Reason: "explicit DOCKER_CONTAINER"}
		}
		if unit != "" {
			return Result{Kind: KindJournal, Unit: unit, Reason: "explicit JOURNAL_UNIT"}
		}
		if path != "" {
			return Result{Kind: KindFile, Path: path, Reason: "explicit LOG_PATH"}
		}
		if r, ok := journalCandidate(s, p); ok {
			return r
		}
		// Discovery before files: a containerized service must beat a stale
		// host log that merely exists.
		if r, ok := discoverDocker(s, p); ok {
			return r
		}
		if r, ok := fileCandidate(s, p); ok {
			return r
		}
		return Result{Kind: KindNone, Reason: fmt.Sprintf(
			"auto: nothing found (tried units %v, container patterns %v, files %v)",
			s.JournalCandidates, s.DockerPatterns, s.FileCandidates)}

	case "journal":
		if container != "" {
			// Historical register behaviour: journal was the implicit default,
			// so DOCKER_CONTAINER alone meant docker.
			return Result{Kind: KindDocker, Container: container,
				Reason: "explicit DOCKER_CONTAINER (overrides MODE=journal for compatibility)"}
		}
		if !journalReadable(p) {
			// Historical dovecot behaviour: MODE=journal on a host where
			// journalctl cannot run at all fell back to the mail log file.
			if r, ok := fileExplicitOrCandidate(s, p, path); ok {
				r.Reason = "journalctl unavailable; " + r.Reason
				return r
			}
			return Result{Kind: KindNone, Reason: fmt.Sprintf(
				"journal mode: journalctl unavailable and no log file found (tried %v)", s.FileCandidates)}
		}
		if unit != "" {
			return Result{Kind: KindJournal, Unit: unit, Reason: "explicit JOURNAL_UNIT"}
		}
		if r, ok := journalCandidate(s, p); ok {
			return r
		}
		return Result{Kind: KindNone, Reason: fmt.Sprintf(
			"journal mode: no unit found (tried %v); set JOURNAL_UNIT", s.JournalCandidates)}

	case "file":
		if r, ok := fileExplicitOrCandidate(s, p, path); ok {
			return r
		}
		return Result{Kind: KindNone, Reason: fmt.Sprintf(
			"file mode: no log file found (tried %v); set LOG_PATH", s.FileCandidates)}

	case "docker":
		if container != "" {
			return Result{Kind: KindDocker, Container: container, Reason: "explicit DOCKER_CONTAINER"}
		}
		if r, ok := discoverDocker(s, p); ok {
			return r // single match, or terminal ambiguity
		}
		// No container found: fall back to the auto chain (historical dovecot
		// behaviour for MODE=docker with an empty container).
		if r, ok := journalCandidate(s, p); ok {
			r.Reason = "docker mode: no container found; " + r.Reason
			return r
		}
		if r, ok := fileExplicitOrCandidate(s, p, path); ok {
			r.Reason = "docker mode: no container found; " + r.Reason
			return r
		}
		return Result{Kind: KindNone, Reason: fmt.Sprintf(
			"docker mode: no container matched %v and no journal/file fallback; set DOCKER_CONTAINER",
			s.DockerPatterns)}

	default:
		return Result{Kind: KindNone, Reason: fmt.Sprintf(
			"unknown MODE %q; use auto, journal, file or docker", s.Mode)}
	}
}

func journalReadable(p Probes) bool {
	if p.JournalReadable == nil {
		return true
	}
	return p.JournalReadable()
}

// journalCandidate picks a journal unit from the candidates: first the units
// whose journal actually holds entries, then merely-active units (running but
// nothing logged since boot / volatile journal just rotated). An active unit
// is resolved to its canonical name first: on Debian `systemctl is-active
// sshd.service` succeeds through the Alias= while journalctl indexes only
// ssh.service — accepting the alias would tail an empty stream forever.
func journalCandidate(s Spec, p Probes) (Result, bool) {
	if p.JournalHasEntries != nil {
		for _, u := range s.JournalCandidates {
			if p.JournalHasEntries(u) {
				return Result{Kind: KindJournal, Unit: u, Reason: "journal entries found for " + u}, true
			}
		}
	}
	if p.UnitActive != nil {
		for _, u := range s.JournalCandidates {
			if !p.UnitActive(u) {
				continue
			}
			real := u
			if p.CanonicalUnit != nil {
				if c := strings.TrimSpace(p.CanonicalUnit(u)); c != "" {
					real = c
				}
			}
			reason := real + " active (no recent journal entries yet)"
			if real != u {
				reason = u + " active, canonical unit " + real + " (no recent journal entries yet)"
			}
			return Result{Kind: KindJournal, Unit: real, Reason: reason}, true
		}
	}
	return Result{}, false
}

// fileExplicitOrCandidate returns the explicit path verbatim, else the first
// existing candidate.
func fileExplicitOrCandidate(s Spec, p Probes, path string) (Result, bool) {
	if path != "" {
		return Result{Kind: KindFile, Path: path, Reason: "explicit LOG_PATH"}, true
	}
	return fileCandidate(s, p)
}

func fileCandidate(s Spec, p Probes) (Result, bool) {
	if p.FileExists != nil {
		for _, f := range s.FileCandidates {
			if p.FileExists(f) {
				return Result{Kind: KindFile, Path: f, Reason: "log file " + f + " exists"}, true
			}
		}
	}
	return Result{}, false
}

// discoverDocker matches running container names against DockerPatterns.
// Exactly one match resolves; two or more return a terminal KindNone result
// (ok=true) so callers stop instead of guessing; zero matches return ok=false
// so callers may continue their chain.
func discoverDocker(s Spec, p Probes) (Result, bool) {
	if len(s.DockerPatterns) == 0 || p.ListContainers == nil {
		return Result{}, false
	}
	names := p.ListContainers()
	if len(names) == 0 {
		return Result{}, false
	}
	var matches []string
	for _, n := range names {
		ln := strings.ToLower(n)
		for _, pat := range s.DockerPatterns {
			if pat != "" && strings.Contains(ln, strings.ToLower(pat)) {
				matches = append(matches, n)
				break
			}
		}
	}
	switch len(matches) {
	case 0:
		return Result{}, false
	case 1:
		return Result{Kind: KindDocker, Container: matches[0],
			Reason: fmt.Sprintf("discovered container %s (patterns %v)", matches[0], s.DockerPatterns)}, true
	default:
		return Result{Kind: KindNone, Reason: fmt.Sprintf(
			"docker discovery ambiguous: %d containers match %v (%s); set DOCKER_CONTAINER explicitly",
			len(matches), s.DockerPatterns, strings.Join(matches, ", "))}, true
	}
}
