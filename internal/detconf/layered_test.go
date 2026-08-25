package detconf

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const layeredBase = `
[global]
IGNORE_NETS = 10.0.0.0/8

[ssh_auth]
ENABLED = 1
AUTHFAIL_IP = 8

[webdetector]
CHALLENGE_VHOST_IGNORE = api.example.gr
`

func layeredFixture(t *testing.T, overlays map[string]string) (base, dropin string) {
	t.Helper()
	dir := t.TempDir()
	base = filepath.Join(dir, "detectors.conf")
	writeFile(t, base, layeredBase)
	dropin = filepath.Join(dir, "detectors.d")
	if overlays != nil {
		if err := os.Mkdir(dropin, 0o700); err != nil {
			t.Fatal(err)
		}
		for name, content := range overlays {
			writeFile(t, filepath.Join(dropin, name), content)
		}
	}
	return base, dropin
}

// Parity: no overlay dir, and an existing-but-empty one, must both yield a
// result identical to the plain reader — the base conffile alone stays the
// single source of truth until an overlay actually exists.
func TestReadLayeredParity(t *testing.T) {
	base, dropin := layeredFixture(t, nil)
	plain, rawPlain, err := ReadSections(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, mkdir := range []bool{false, true} {
		if mkdir {
			if err := os.Mkdir(dropin, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		layered, raw, err := ReadLayered(base, dropin)
		if err != nil {
			t.Fatalf("mkdir=%v: %v", mkdir, err)
		}
		if !reflect.DeepEqual(plain, layered) {
			t.Fatalf("mkdir=%v: layered result diverged from plain read\nplain:   %+v\nlayered: %+v", mkdir, plain, layered)
		}
		if string(raw) != string(rawPlain) {
			t.Fatalf("mkdir=%v: raw bytes must be the base file's", mkdir)
		}
	}
}

func TestReadLayeredMerge(t *testing.T) {
	base, dropin := layeredFixture(t, map[string]string{
		"10-tuning.conf": `
[ssh_auth]
AUTHFAIL_IP = 4
BLOCK = 1h

[custom:extra]
ENABLED = 1
`,
		"20-lists.conf": `
[global]
IGNORE_NETS += 192.0.2.0/24

[webdetector]
CHALLENGE_VHOST_IGNORE += shop.example.gr
`,
		"README.txt": "not a conf; ignored",
	})
	s, _, err := ReadLayered(base, dropin)
	if err != nil {
		t.Fatal(err)
	}

	// Replace: overlay wins over base.
	if got := s.ByName["ssh_auth"]["AUTHFAIL_IP"]; got != "4" {
		t.Fatalf("override: AUTHFAIL_IP=%q", got)
	}
	// New key in an existing section.
	if got := s.ByName["ssh_auth"]["BLOCK"]; got != "1h" {
		t.Fatalf("new key: BLOCK=%q", got)
	}
	// Base keys the overlay didn't touch survive.
	if got := s.ByName["ssh_auth"]["ENABLED"]; got != "1" {
		t.Fatalf("untouched key lost: ENABLED=%q", got)
	}
	// Overlay-only section is adopted and registered by type.
	if got := s.ByName["custom:extra"]["ENABLED"]; got != "1" {
		t.Fatalf("overlay-only section: %+v", s.ByName["custom:extra"])
	}
	found := false
	for _, n := range s.ByType["custom"] {
		if n == "custom:extra" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ByType missing overlay section: %+v", s.ByType)
	}
	// += appends to the base list — global and plain sections alike — and the
	// Global alias sees it.
	if got := s.Global["IGNORE_NETS"]; got != "10.0.0.0/8, 192.0.2.0/24" {
		t.Fatalf("global +=: %q", got)
	}
	if got := s.ByName["webdetector"]["CHALLENGE_VHOST_IGNORE"]; got != "api.example.gr, shop.example.gr" {
		t.Fatalf("section +=: %q", got)
	}
}

// Lexicographic order: 10- applies before 20-, so on the same key the later
// file wins (replace) and += chains in order.
func TestReadLayeredOrder(t *testing.T) {
	base, dropin := layeredFixture(t, map[string]string{
		"20-b.conf": "[ssh_auth]\nAUTHFAIL_IP = 20\nTAGS += b\n",
		"10-a.conf": "[ssh_auth]\nAUTHFAIL_IP = 10\nTAGS += a\n",
	})
	s, _, err := ReadLayered(base, dropin)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.ByName["ssh_auth"]["AUTHFAIL_IP"]; got != "20" {
		t.Fatalf("later file must win: %q", got)
	}
	if got := s.ByName["ssh_auth"]["TAGS"]; got != "a, b" {
		t.Fatalf("+= chain order: %q", got)
	}
}

// += on a key no earlier layer holds degrades to a plain set (nothing to
// append to), and += within ONE file self-appends.
func TestReadLayeredAppendEdge(t *testing.T) {
	base, dropin := layeredFixture(t, map[string]string{
		"10-x.conf": "[ssh_auth]\nFRESH += one\nFRESH += two\n",
	})
	s, _, err := ReadLayered(base, dropin)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.ByName["ssh_auth"]["FRESH"]; got != "one, two" {
		t.Fatalf("fresh +=: %q", got)
	}
}

// Multiline blocks (rule lists) appended with += stack with newlines, so
// QUERY_RULES-style values keep their per-line structure.
func TestReadLayeredAppendMultiline(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "detectors.conf")
	writeFile(t, base, "[mysql_governor]\nQUERY_RULES =\n  a : 5m : notify\n")
	dropin := filepath.Join(dir, "detectors.d")
	if err := os.Mkdir(dropin, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dropin, "10-r.conf"), "[mysql_governor]\nQUERY_RULES +=\n  b : 9m : kill_query\n")
	s, _, err := ReadLayered(base, dropin)
	if err != nil {
		t.Fatal(err)
	}
	got := s.ByName["mysql_governor"]["QUERY_RULES"]
	if !strings.Contains(got, "a : 5m : notify") || !strings.Contains(got, "b : 9m : kill_query") {
		t.Fatalf("multiline +=: %q", got)
	}
	if strings.Contains(got, ", ") {
		t.Fatalf("multiline must join with newlines, not commas: %q", got)
	}
}

// LayerSig must change whenever the overlay SET changes — including the cases
// max-mtime (StampNS) cannot see: a file added with an mtime OLDER than the
// base (mv / cp -p / rsync -a), removed, or renamed.
func TestReadLayeredLayerSig(t *testing.T) {
	base, dropin := layeredFixture(t, nil)
	s0, _, err := ReadLayered(base, dropin)
	if err != nil {
		t.Fatal(err)
	}
	if s0.LayerSig != 0 {
		t.Fatalf("no overlays must leave LayerSig 0, got %d", s0.LayerSig)
	}

	// Install an overlay whose mtime predates the base: StampNS stays the
	// base's, so only LayerSig can signal the change.
	if err := os.Mkdir(dropin, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dropin, "10-x.conf")
	writeFile(t, p, "[ssh_auth]\nBLOCK = 1h\n")
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(p, past, past); err != nil {
		t.Fatal(err)
	}
	s1, _, err := ReadLayered(base, dropin)
	if err != nil {
		t.Fatal(err)
	}
	if s1.StampNS != s0.StampNS {
		t.Fatalf("old-mtime overlay must not move StampNS: %d vs %d", s1.StampNS, s0.StampNS)
	}
	if s1.LayerSig == 0 || s1.LayerSig == s0.LayerSig {
		t.Fatalf("adding an overlay must change LayerSig: %d -> %d", s0.LayerSig, s1.LayerSig)
	}

	// Rename: same content, same mtime — still a different set.
	p2 := filepath.Join(dropin, "20-x.conf")
	if err := os.Rename(p, p2); err != nil {
		t.Fatal(err)
	}
	s2, _, err := ReadLayered(base, dropin)
	if err != nil {
		t.Fatal(err)
	}
	if s2.LayerSig == s1.LayerSig {
		t.Fatal("renaming an overlay must change LayerSig")
	}

	// Remove: back to the no-overlay signature.
	if err := os.Remove(p2); err != nil {
		t.Fatal(err)
	}
	s3, _, err := ReadLayered(base, dropin)
	if err != nil {
		t.Fatal(err)
	}
	if s3.LayerSig != 0 {
		t.Fatalf("removing the last overlay must reset LayerSig, got %d", s3.LayerSig)
	}
}

// += onto a value carrying an inline ";"/"#" comment must not append AFTER the
// comment — scalar readers cut at the first ";"/"#", which would silently
// discard everything appended (CLAUDE.md §5). The comment is dropped instead.
func TestReadLayeredAppendAfterInlineComment(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "detectors.conf")
	writeFile(t, base, "[global]\nIGNORE_NETS = 10.0.0.0/8 ; office lan\nEMPTYISH = ; note only\n")
	dropin := filepath.Join(dir, "detectors.d")
	if err := os.Mkdir(dropin, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dropin, "10-a.conf"), "[global]\nIGNORE_NETS += 203.0.113.0/24 ; branch\nEMPTYISH += real\n")
	writeFile(t, filepath.Join(dropin, "20-b.conf"), "[global]\nIGNORE_NETS += 198.51.100.0/24\n")
	s, _, err := ReadLayered(base, dropin)
	if err != nil {
		t.Fatal(err)
	}
	// The 20- append must also survive the 10- overlay's trailing comment.
	if got := s.Global["IGNORE_NETS"]; got != "10.0.0.0/8, 203.0.113.0/24, 198.51.100.0/24" {
		t.Fatalf("comment-adjacent +=: %q", got)
	}
	// A value that was ONLY a comment appends to nothing.
	if got := s.Global["EMPTYISH"]; got != "real" {
		t.Fatalf("comment-only prev: %q", got)
	}
}

// Hidden files are ignored (systemd .d convention): editor lock files like
// emacs' ".#name.conf" are dangling symlinks and must not fail the read.
func TestListDropinsSkipsHiddenFiles(t *testing.T) {
	base, dropin := layeredFixture(t, map[string]string{"10-x.conf": "[ssh_auth]\nBLOCK = 1h\n"})
	if err := os.Symlink("user@host.12345", filepath.Join(dropin, ".#10-x.conf")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dropin, ".hidden.conf"), "[ssh_auth]\nBLOCK = 9h\n")
	names, err := ListDropins(dropin)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "10-x.conf" {
		t.Fatalf("hidden entries must be skipped: %v", names)
	}
	s, _, err := ReadLayered(base, dropin)
	if err != nil {
		t.Fatalf("dangling hidden symlink must not fail the read: %v", err)
	}
	if got := s.ByName["ssh_auth"]["BLOCK"]; got != "1h" {
		t.Fatalf("hidden overlay must not apply: %q", got)
	}
}

// Only real regular *.conf files are read. Directories, symlinks of ANY kind
// (including to a real *.conf file), dangling links and special files are
// ignored — not an error: one stray entry must never drop the other overlays,
// and the reader must never follow a link out to an arbitrary target.
func TestListDropinsRegularFilesOnly(t *testing.T) {
	base, dropin := layeredFixture(t, map[string]string{"10-ok.conf": "[ssh_auth]\nBLOCK = 1h\n"})
	// A directory named like an overlay.
	if err := os.Mkdir(filepath.Join(dropin, "20-dir.conf"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A symlink to that directory.
	if err := os.Symlink(filepath.Join(dropin, "20-dir.conf"), filepath.Join(dropin, "30-link-to-dir.conf")); err != nil {
		t.Fatal(err)
	}
	// A dangling (non-hidden) symlink.
	if err := os.Symlink(filepath.Join(dropin, "does-not-exist"), filepath.Join(dropin, "40-dangling.conf")); err != nil {
		t.Fatal(err)
	}
	// A symlink to a REAL overlay file — ignored too (we do not follow links).
	realTarget := filepath.Join(t.TempDir(), "real.conf")
	writeFile(t, realTarget, "[ssh_auth]\nAUTHFAIL_IP = 3\n")
	if err := os.Symlink(realTarget, filepath.Join(dropin, "50-link-to-file.conf")); err != nil {
		t.Fatal(err)
	}

	names, err := ListDropins(dropin)
	if err != nil {
		t.Fatalf("stray non-regular entries must not error the listing: %v", err)
	}
	if len(names) != 1 || names[0] != "10-ok.conf" {
		t.Fatalf("ListDropins = %v, want [10-ok.conf] only (symlinks/dirs ignored)", names)
	}
	s, _, err := ReadLayered(base, dropin)
	if err != nil {
		t.Fatalf("stray non-regular entries must not abort the read: %v", err)
	}
	if got := s.ByName["ssh_auth"]["BLOCK"]; got != "1h" {
		t.Fatalf("regular overlay lost: BLOCK=%q", got)
	}
	// The base sets AUTHFAIL_IP=8; the symlink-to-file overlay would set 3.
	// It must NOT be followed, so the base value stands.
	if got := s.ByName["ssh_auth"]["AUTHFAIL_IP"]; got != "8" {
		t.Fatalf("symlink-to-file overlay must NOT be followed/applied: AUTHFAIL_IP=%q", got)
	}
}

// A later plain "=" in the SAME overlay converts an append into a replace: the
// += mark must not survive it.
func TestReadLayeredAppendThenReplace(t *testing.T) {
	base, dropin := layeredFixture(t, map[string]string{
		"10-x.conf": "[ssh_auth]\nAUTHFAIL_IP += 4\nAUTHFAIL_IP = 2\n",
	})
	s, _, err := ReadLayered(base, dropin)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.ByName["ssh_auth"]["AUTHFAIL_IP"]; got != "2" {
		t.Fatalf("plain = after += must replace, not append: %q", got)
	}
}

// StampNS is the BASE file's mtime and is NEVER raised to a newer overlay's:
// a max would let a newer overlay mask a base edit deployed with an older
// preserved mtime (rsync -a / cp -p), so the base change would not hot-reload.
// The newer overlay is instead reflected in LayerSig.
// A rule-block key (kvLines-read, e.g. QUERY_RULES) appended via "+=" in the
// INLINE single-rule form across overlays must join with NEWLINES, not ", " —
// a comma-joined block collapses into one line the rule reader can't split, so
// every rule is silently lost. The decision is by KEY NAME (a rule
// "u:5m:kill" is indistinguishable from an IPv6 CIDR by content).
func TestReadLayeredAppendRuleBlockInline(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "detectors.conf")
	writeFile(t, base, "[mysql_governor]\nENABLED = 1\n")
	dropin := filepath.Join(dir, "detectors.d")
	if err := os.Mkdir(dropin, 0o700); err != nil {
		t.Fatal(err)
	}
	// Two overlays each contributing ONE inline rule (no newline on either).
	writeFile(t, filepath.Join(dropin, "10-a.conf"), "[mysql_governor]\nQUERY_RULES += appA : 5m : notify\n")
	writeFile(t, filepath.Join(dropin, "20-b.conf"), "[mysql_governor]\nQUERY_RULES += appB : 10m : kill_query\n")
	s, _, err := ReadLayered(base, dropin)
	if err != nil {
		t.Fatal(err)
	}
	got := s.ByName["mysql_governor"]["QUERY_RULES"]
	if got != "appA : 5m : notify\nappB : 10m : kill_query" {
		t.Fatalf("rule-block += must newline-join, not comma-join: %q", got)
	}
	// A list key (comma-read) with the same inline shape still comma-joins.
	writeFile(t, filepath.Join(dropin, "30-nets.conf"), "[global]\nIGNORE_NETS += 10.0.0.0/8\n")
	writeFile(t, filepath.Join(dropin, "40-nets.conf"), "[global]\nIGNORE_NETS += 192.0.2.0/24\n")
	s, _, err = ReadLayered(base, dropin)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Global["IGNORE_NETS"]; got != "10.0.0.0/8, 192.0.2.0/24" {
		t.Fatalf("list key must comma-join: %q", got)
	}
}

func TestReadLayeredStampNSIsBaseMtime(t *testing.T) {
	base, dropin := layeredFixture(t, map[string]string{"10-x.conf": "[ssh_auth]\nBLOCK = 1h\n"})
	// Make the overlay decisively newer than the base.
	future := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(filepath.Join(dropin, "10-x.conf"), future, future); err != nil {
		t.Fatal(err)
	}
	s, _, err := ReadLayered(base, dropin)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := ReadSectionsFile(base)
	if s.StampNS != plain.StampNS {
		t.Fatalf("StampNS must equal the base mtime, not be raised by a newer overlay: layered=%d base=%d", s.StampNS, plain.StampNS)
	}
	if s.LayerSig == 0 {
		t.Fatal("a present overlay must set LayerSig (the overlay-change signal)")
	}
}

// A broken overlay is an ERROR, never silently skipped configuration.
func TestReadLayeredBrokenOverlay(t *testing.T) {
	base, dropin := layeredFixture(t, map[string]string{"10-x.conf": "[ssh_auth]\nBLOCK = 1h\n"})
	if err := os.Chmod(filepath.Join(dropin, "10-x.conf"), 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("chmod 000 is not an obstacle for root")
	}
	if _, _, err := ReadLayered(base, dropin); err == nil {
		t.Fatal("unreadable overlay must error")
	}
}

func TestDefaultDropinDir(t *testing.T) {
	if got := DefaultDropinDir("/etc/cfm/detectors.conf"); got != "/etc/cfm/detectors.d" {
		t.Fatalf("got %q", got)
	}
}
