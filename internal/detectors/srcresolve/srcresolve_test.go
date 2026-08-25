package srcresolve

import (
	"strings"
	"testing"
)

// fakeProbes builds Probes from simple sets: units with journal entries,
// active-only units, existing files, running containers. JournalReadable
// defaults to nil (= readable) and CanonicalUnit to nil (= identity); tests
// override the returned struct's fields for the special cases.
func fakeProbes(entries, active, files []string, containers []string) Probes {
	in := func(set []string) func(string) bool {
		return func(v string) bool {
			for _, s := range set {
				if s == v {
					return true
				}
			}
			return false
		}
	}
	return Probes{
		JournalHasEntries: in(entries),
		UnitActive:        in(active),
		FileExists:        in(files),
		ListContainers:    func() []string { return containers },
	}
}

// sshSpec mirrors the ssh_auth register's candidates.
func sshSpec(mode, unit, path string) Spec {
	return Spec{
		Service: "ssh_auth", Mode: mode, JournalUnit: unit, LogPath: path,
		JournalCandidates: []string{"sshd.service", "ssh.service"},
		FileCandidates:    []string{"/var/log/secure", "/var/log/auth.log"},
	}
}

// dovecotSpec mirrors the dovecot_auth register's candidates.
func dovecotSpec(mode, unit, path, container string) Spec {
	return Spec{
		Service: "dovecot_auth", Mode: mode, JournalUnit: unit, LogPath: path,
		DockerContainer:   container,
		JournalCandidates: []string{"dovecot.service"},
		FileCandidates:    []string{"/var/log/maillog", "/var/log/mail.log"},
		DockerPatterns:    []string{"dovecot"},
	}
}

func TestResolveAuto(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
		p    Probes
		want Result
	}{
		{
			// Parity invariant: first journal candidate == historical default.
			name: "el host picks sshd.service",
			spec: sshSpec("auto", "", ""),
			p:    fakeProbes([]string{"sshd.service"}, nil, []string{"/var/log/secure"}, nil),
			want: Result{Kind: KindJournal, Unit: "sshd.service"},
		},
		{
			// The saf case: Debian logs under ssh.service; sshd.service is an
			// alias with no journal entries of its own.
			name: "debian host picks ssh.service by entries",
			spec: sshSpec("auto", "", ""),
			p:    fakeProbes([]string{"ssh.service"}, []string{"sshd.service", "ssh.service"}, []string{"/var/log/auth.log"}, nil),
			want: Result{Kind: KindJournal, Unit: "ssh.service"},
		},
		{
			name: "active unit accepted when journal has no entries yet",
			spec: sshSpec("auto", "", ""),
			p:    fakeProbes(nil, []string{"sshd.service"}, nil, nil),
			want: Result{Kind: KindJournal, Unit: "sshd.service"},
		},
		{
			name: "file fallback when no unit",
			spec: sshSpec("auto", "", ""),
			p:    fakeProbes(nil, nil, []string{"/var/log/auth.log"}, nil),
			want: Result{Kind: KindFile, Path: "/var/log/auth.log"},
		},
		{
			name: "file candidate order respected",
			spec: dovecotSpec("auto", "", "", ""),
			p:    fakeProbes(nil, nil, []string{"/var/log/mail.log", "/var/log/maillog"}, nil),
			want: Result{Kind: KindFile, Path: "/var/log/maillog"},
		},
		{
			name: "explicit JOURNAL_UNIT short-circuits auto",
			spec: sshSpec("auto", "my-sshd.service", ""),
			p:    fakeProbes(nil, nil, []string{"/var/log/secure"}, nil),
			want: Result{Kind: KindJournal, Unit: "my-sshd.service"},
		},
		{
			name: "explicit LOG_PATH short-circuits auto",
			spec: sshSpec("auto", "", "/custom/ssh.log"),
			p:    fakeProbes([]string{"sshd.service"}, nil, nil, nil),
			want: Result{Kind: KindFile, Path: "/custom/ssh.log"},
		},
		{
			name: "explicit unit beats explicit path",
			spec: sshSpec("auto", "sshd.service", "/custom/ssh.log"),
			p:    fakeProbes(nil, nil, nil, nil),
			want: Result{Kind: KindJournal, Unit: "sshd.service"},
		},
		{
			// The mailcow case: an idle host mail log merely existing must not
			// preempt the running dovecot container — discovery runs first.
			name: "docker discovery beats stale host file",
			spec: dovecotSpec("auto", "", "", ""),
			p:    fakeProbes(nil, nil, []string{"/var/log/mail.log"}, []string{"mailcowdockerized-dovecot-mailcow-1", "mailcowdockerized-postfix-mailcow-1"}),
			want: Result{Kind: KindDocker, Container: "mailcowdockerized-dovecot-mailcow-1"},
		},
		{
			name: "journal beats docker discovery",
			spec: dovecotSpec("auto", "", "", ""),
			p:    fakeProbes([]string{"dovecot.service"}, nil, nil, []string{"other-dovecot-1"}),
			want: Result{Kind: KindJournal, Unit: "dovecot.service"},
		},
		{
			name: "explicit container short-circuits auto",
			spec: dovecotSpec("auto", "", "", "my-dovecot"),
			p:    fakeProbes([]string{"dovecot.service"}, nil, nil, nil),
			want: Result{Kind: KindDocker, Container: "my-dovecot"},
		},
		{
			name: "nothing found",
			spec: sshSpec("auto", "", ""),
			p:    fakeProbes(nil, nil, nil, nil),
			want: Result{Kind: KindNone},
		},
		{
			name: "empty mode means auto",
			spec: sshSpec("", "", ""),
			p:    fakeProbes([]string{"sshd.service"}, nil, nil, nil),
			want: Result{Kind: KindJournal, Unit: "sshd.service"},
		},
	}
	runResolveCases(t, cases)
}

// TestResolveDebianAliasActive covers the alias trap with an EMPTY journal:
// is-active succeeds for both names via Alias=, but only the canonical unit
// is indexed by journald — the resolver must return the canonical name.
func TestResolveDebianAliasActive(t *testing.T) {
	p := fakeProbes(nil, []string{"sshd.service", "ssh.service"}, nil, nil)
	p.CanonicalUnit = func(unit string) string {
		if unit == "sshd.service" || unit == "ssh.service" {
			return "ssh.service"
		}
		return ""
	}
	got := Resolve(sshSpec("auto", "", ""), p)
	if got.Kind != KindJournal || got.Unit != "ssh.service" {
		t.Fatalf("alias resolution: want journal ssh.service, got %+v", got)
	}
	if !strings.Contains(got.Reason, "canonical") {
		t.Fatalf("alias reason should mention the canonical resolution, got %q", got.Reason)
	}
}

func TestResolveExplicitModes(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
		p    Probes
		want Result
	}{
		{
			name: "journal mode explicit unit verbatim, never probed",
			spec: sshSpec("journal", "sshd.service", ""),
			p:    fakeProbes(nil, nil, nil, nil),
			want: Result{Kind: KindJournal, Unit: "sshd.service"},
		},
		{
			name: "journal mode auto unit resolves candidates",
			spec: sshSpec("journal", "auto", ""),
			p:    fakeProbes([]string{"ssh.service"}, nil, nil, nil),
			want: Result{Kind: KindJournal, Unit: "ssh.service"},
		},
		{
			name: "journal mode without any unit is none (no file fallback while journalctl works)",
			spec: sshSpec("journal", "", ""),
			p:    fakeProbes(nil, nil, []string{"/var/log/secure"}, nil),
			want: Result{Kind: KindNone},
		},
		{
			name: "journal mode with container flips to docker (historical compat)",
			spec: dovecotSpec("journal", "", "", "dovecot-mailcow"),
			p:    fakeProbes([]string{"dovecot.service"}, nil, nil, nil),
			want: Result{Kind: KindDocker, Container: "dovecot-mailcow"},
		},
		{
			name: "file mode explicit path verbatim",
			spec: sshSpec("file", "", "/var/log/secure"),
			p:    fakeProbes(nil, nil, nil, nil),
			want: Result{Kind: KindFile, Path: "/var/log/secure"},
		},
		{
			name: "file mode auto path resolves candidates",
			spec: sshSpec("file", "", "auto"),
			p:    fakeProbes(nil, nil, []string{"/var/log/auth.log"}, nil),
			want: Result{Kind: KindFile, Path: "/var/log/auth.log"},
		},
		{
			name: "file mode without any file is none",
			spec: sshSpec("file", "", ""),
			p:    fakeProbes([]string{"sshd.service"}, nil, nil, nil),
			want: Result{Kind: KindNone},
		},
		{
			name: "docker mode explicit container verbatim",
			spec: dovecotSpec("docker", "", "", "mailcowdockerized-dovecot-mailcow-1"),
			p:    fakeProbes(nil, nil, nil, nil),
			want: Result{Kind: KindDocker, Container: "mailcowdockerized-dovecot-mailcow-1"},
		},
		{
			name: "docker mode discovery single match",
			spec: dovecotSpec("docker", "", "", ""),
			p:    fakeProbes(nil, nil, nil, []string{"mailcowdockerized-dovecot-mailcow-1"}),
			want: Result{Kind: KindDocker, Container: "mailcowdockerized-dovecot-mailcow-1"},
		},
		{
			name: "docker mode no container falls back to auto chain (historical)",
			spec: dovecotSpec("docker", "", "", ""),
			p:    fakeProbes([]string{"dovecot.service"}, nil, nil, nil),
			want: Result{Kind: KindJournal, Unit: "dovecot.service"},
		},
		{
			name: "docker mode nothing anywhere is none",
			spec: dovecotSpec("docker", "", "", ""),
			p:    fakeProbes(nil, nil, nil, nil),
			want: Result{Kind: KindNone},
		},
		{
			name: "unknown mode is none",
			spec: sshSpec("folder", "", ""),
			p:    fakeProbes([]string{"sshd.service"}, nil, nil, nil),
			want: Result{Kind: KindNone},
		},
	}
	runResolveCases(t, cases)
}

// TestResolveJournalUnreadable covers the historical dovecot fallback: an
// explicitly configured journal source on a host where journalctl cannot run
// at all (non-systemd) falls back to the file chain instead of going dead.
func TestResolveJournalUnreadable(t *testing.T) {
	notReadable := func() bool { return false }

	p := fakeProbes(nil, nil, []string{"/var/log/maillog"}, nil)
	p.JournalReadable = notReadable
	got := Resolve(dovecotSpec("journal", "dovecot.service", "", ""), p)
	if got.Kind != KindFile || got.Path != "/var/log/maillog" {
		t.Fatalf("journal-unreadable file fallback: got %+v", got)
	}
	if !strings.Contains(got.Reason, "journalctl unavailable") {
		t.Fatalf("fallback reason should say why, got %q", got.Reason)
	}

	// Explicit LOG_PATH is honoured in the fallback.
	p = fakeProbes(nil, nil, nil, nil)
	p.JournalReadable = notReadable
	got = Resolve(dovecotSpec("journal", "dovecot.service", "/custom/mail.log", ""), p)
	if got.Kind != KindFile || got.Path != "/custom/mail.log" {
		t.Fatalf("journal-unreadable explicit-path fallback: got %+v", got)
	}

	// Nothing to fall back to → none.
	p = fakeProbes(nil, nil, nil, nil)
	p.JournalReadable = notReadable
	if got = Resolve(dovecotSpec("journal", "dovecot.service", "", ""), p); got.Kind != KindNone {
		t.Fatalf("journal-unreadable without files: want KindNone, got %+v", got)
	}
}

// TestResolveJournalSignature: with a JournalSignature set, a unit passes the
// entries step only when its recent entries match the service pattern — mere
// entry existence (e.g. another service's lines attributed to the unit via
// cgroup, or startup noise) is NOT enough.
func TestResolveJournalSignature(t *testing.T) {
	spec := Spec{
		Service: "postfix_security", Mode: "auto",
		JournalCandidates: []string{"postfix@-.service", "postfix.service"},
		JournalSignature:  `postfix(/[a-z0-9-]+)?\[\d+\]:`,
		FileCandidates:    []string{"/var/log/maillog", "/var/log/mail.log"},
		DockerPatterns:    []string{"postfix"},
	}

	// Second candidate matches the signature → chosen over the first, which
	// has entries (would win an existence-only probe) but no service lines.
	p := fakeProbes([]string{"postfix@-.service"}, nil, nil, nil)
	p.JournalMatches = func(unit, sig string) bool { return unit == "postfix.service" }
	got := Resolve(spec, p)
	if got.Kind != KindJournal || got.Unit != "postfix.service" {
		t.Fatalf("signature probe should pick the matching unit, got %+v", got)
	}
	if !strings.Contains(got.Reason, "signature") {
		t.Fatalf("signature reason expected, got %q", got.Reason)
	}

	// No unit matches the signature → active pass still applies (service runs
	// but has not logged since boot), then files.
	p = fakeProbes([]string{"postfix.service"}, []string{"postfix.service"}, nil, nil)
	p.JournalMatches = func(unit, sig string) bool { return false }
	got = Resolve(spec, p)
	if got.Kind != KindJournal || got.Unit != "postfix.service" {
		t.Fatalf("active fallback with signature set: got %+v", got)
	}

	// Signature set but JournalMatches probe nil → entries step skipped
	// entirely (existence is NOT trusted as a substitute), falls through.
	p = fakeProbes([]string{"postfix.service"}, nil, []string{"/var/log/maillog"}, nil)
	p.JournalMatches = nil
	got = Resolve(spec, p)
	if got.Kind != KindFile || got.Path != "/var/log/maillog" {
		t.Fatalf("nil JournalMatches with signature: want file fallback, got %+v", got)
	}
}

func TestResolveDockerAmbiguity(t *testing.T) {
	two := []string{"dovecot-a", "dovecot-b"}

	// Explicit docker mode: ambiguity is terminal.
	got := Resolve(dovecotSpec("docker", "", "", ""), fakeProbes([]string{"dovecot.service"}, nil, nil, two))
	if got.Kind != KindNone {
		t.Fatalf("docker mode ambiguous: want KindNone, got %+v", got)
	}
	if !strings.Contains(got.Reason, "ambiguous") || !strings.Contains(got.Reason, "DOCKER_CONTAINER") {
		t.Fatalf("ambiguous reason should name the fix, got %q", got.Reason)
	}

	// Auto mode: ambiguity is terminal there too (file candidates are NOT
	// tried after an ambiguous discovery — no guessing, no silent pick).
	got = Resolve(dovecotSpec("auto", "", "", ""), fakeProbes(nil, nil, []string{"/var/log/maillog"}, two))
	if got.Kind != KindNone || !strings.Contains(got.Reason, "ambiguous") {
		t.Fatalf("auto ambiguous: want terminal KindNone/ambiguous, got %+v", got)
	}
}

func TestResolveNilProbes(t *testing.T) {
	// Nil probe functions must behave as "not confirmed", never panic.
	got := Resolve(sshSpec("auto", "", ""), Probes{})
	if got.Kind != KindNone {
		t.Fatalf("nil probes: want KindNone, got %+v", got)
	}
	// Explicit values still resolve verbatim with nil probes (nil
	// JournalReadable reads as readable).
	got = Resolve(sshSpec("journal", "sshd.service", ""), Probes{})
	if got.Kind != KindJournal || got.Unit != "sshd.service" {
		t.Fatalf("explicit with nil probes: got %+v", got)
	}
}

func TestResolveReasonAlwaysSet(t *testing.T) {
	specs := []Spec{
		sshSpec("auto", "", ""),
		sshSpec("journal", "", ""),
		sshSpec("file", "", ""),
		dovecotSpec("docker", "", "", ""),
		sshSpec("bogus", "", ""),
	}
	for _, s := range specs {
		if r := Resolve(s, Probes{}); r.Reason == "" {
			t.Fatalf("empty Reason for spec %+v (result %+v)", s, r)
		}
	}
}

func runResolveCases(t *testing.T, cases []struct {
	name string
	spec Spec
	p    Probes
	want Result
}) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Resolve(tc.spec, tc.p)
			if got.Kind != tc.want.Kind || got.Unit != tc.want.Unit ||
				got.Path != tc.want.Path || got.Container != tc.want.Container {
				t.Fatalf("Resolve(%+v)\n got %+v\nwant kind=%s unit=%q path=%q container=%q (reason %q)",
					tc.spec, got, tc.want.Kind, tc.want.Unit, tc.want.Path, tc.want.Container, got.Reason)
			}
			if got.Reason == "" {
				t.Fatalf("Resolve(%+v): empty Reason", tc.spec)
			}
		})
	}
}

// TestMemoProbes: each underlying probe runs at most once per distinct
// question, and results are stable across repeats.
func TestMemoProbes(t *testing.T) {
	calls := map[string]int{}
	p := MemoProbes(Probes{
		JournalHasEntries: func(u string) bool { calls["entries:"+u]++; return u == "a" },
		JournalMatches:    func(u, sig string) bool { calls["match:"+u+":"+sig]++; return true },
		UnitActive:        func(u string) bool { calls["active:"+u]++; return false },
		CanonicalUnit:     func(u string) string { calls["canon:"+u]++; return u },
		JournalReadable:   func() bool { calls["readable"]++; return true },
		FileExists:        func(f string) bool { calls["file:"+f]++; return false },
		ListContainers:    func() []string { calls["containers"]++; return []string{"c1"} },
	})
	for i := 0; i < 3; i++ {
		if !p.JournalHasEntries("a") || p.JournalHasEntries("b") {
			t.Fatal("memo changed results")
		}
		p.JournalMatches("u", "sig")
		p.UnitActive("x")
		p.CanonicalUnit("x")
		p.JournalReadable()
		p.FileExists("/f")
		p.ListContainers()
	}
	for k, n := range calls {
		if n != 1 {
			t.Fatalf("probe %s ran %d times, want 1", k, n)
		}
	}
	// Nil probes stay nil.
	if mp := MemoProbes(Probes{}); mp.JournalHasEntries != nil || mp.ListContainers != nil {
		t.Fatal("nil probes must stay nil")
	}
}
