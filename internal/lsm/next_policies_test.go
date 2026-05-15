package lsm

import (
	"strings"
	"testing"
)

// TestNewPoliciesRegistered confirms FS-005 and credential policies are in
// AllPolicies with reasonable metadata. A renamed PolicyID would
// break every operator's lsm.conf — the test ensures the constants
// stay stable.
func TestNewPoliciesRegistered(t *testing.T) {
	want := map[PolicyID]string{
		PolicyDeletedFileExec:     "CFML-EXEC-004",
		PolicyInterpreterNetStdio: "CFML-EXEC-005",
		PolicyEphemeralExec:       "CFML-EXEC-006",
		PolicySensitiveWrite:      "CFML-FS-005",
		PolicyFdCredMismatch:      "CFML-FS-006",
		PolicyCredEscal:           "CFML-CRED-002",
		PolicyDirectCredInstall:   "CFML-CRED-003",
		PolicyUnexpectedBPF:       "CFML-BPF-001",
	}
	got := map[PolicyID]bool{}
	for _, p := range AllPolicies() {
		got[p.ID] = true
		if p.Title == "" || p.Hook == "" || p.Description == "" {
			t.Errorf("policy %s: missing Title / Hook / Description", p.ID)
		}
	}
	for id, name := range want {
		if !got[id] {
			t.Errorf("policy %s (%s) missing from AllPolicies()", id, name)
		}
		if string(id) != name {
			t.Errorf("policy constant drift: PolicyID = %q, expected %q (operators reference this in lsm.conf)", string(id), name)
		}
	}
}

func TestFSOp_StringRoundTrip(t *testing.T) {
	cases := []struct {
		op   FSOp
		want string
	}{
		{FSOpNone, "none"},
		{FSOpSetattr, "setattr"},
		{FSOpCreate, "create"},
		{FSOpUnlink, "unlink"},
		{FSOpLink, "link"},
		{FSOpRename, "rename"},
		{FSOpSetxattr, "setxattr"},
		{BPFOpMapCreate, "bpf_map_create"},
		{BPFOpProgLoad, "bpf_prog_load"},
	}
	for _, tc := range cases {
		if got := tc.op.String(); got != tc.want {
			t.Errorf("FSOp(%d).String() = %q, want %q", tc.op, got, tc.want)
		}
	}
}

func TestParseEvent_FS005WithOp(t *testing.T) {
	// Synthesise an FS-005 event with op=create.
	raw := make([]byte, wireEventSize)
	// ts_ns big enough to be plausible
	for i := 0; i < 8; i++ {
		raw[i] = byte(i)
	}
	// policy_id = bpfPolicySensitiveWrite (5), little-endian
	raw[8] = 5
	// pid
	raw[12] = 0x39
	raw[13] = 0x30
	// op (offset 28) = CREATE
	raw[28] = bpfFSOpCreate
	// flags zero
	raw[29] = 0
	// comm starting at 32
	copy(raw[32:48], "php-fpm")
	// filename starting at 48
	copy(raw[48:48+bpfFilenameLen], "/etc/sudoers.d/backdoor")

	ev, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if ev.PolicyID != PolicySensitiveWrite {
		t.Errorf("PolicyID: got %q, want %q", ev.PolicyID, PolicySensitiveWrite)
	}
	if ev.Op != FSOpCreate {
		t.Errorf("Op: got %v, want FSOpCreate", ev.Op)
	}
	if ev.Comm != "php-fpm" {
		t.Errorf("Comm: got %q, want php-fpm", ev.Comm)
	}
	if ev.Filename != "/etc/sudoers.d/backdoor" {
		t.Errorf("Filename: got %q, want /etc/sudoers.d/backdoor", ev.Filename)
	}
}

func TestParseEvent_CredEscal(t *testing.T) {
	raw := make([]byte, wireEventSize)
	// policy_id = bpfPolicyCredEscal (7)
	raw[8] = 7
	// op zero (CRED-002 doesn't use op)
	copy(raw[32:48], "pkexec")
	copy(raw[48:48+bpfFilenameLen], "pkexec")

	ev, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if ev.PolicyID != PolicyCredEscal {
		t.Errorf("PolicyID: got %q, want %q", ev.PolicyID, PolicyCredEscal)
	}
	if ev.Op != FSOpNone {
		t.Errorf("Op: got %v, want FSOpNone for non-FS policy", ev.Op)
	}
}

func TestWireEventSize_StableAfterOpField(t *testing.T) {
	// Splitting _pad into op + flags + 2 trailing pad bytes must
	// NOT change the wire size. If this fires the BPF struct
	// changed in an incompatible way and existing operators'
	// pinned BPF objects will produce events that this Go parser
	// misreads.
	if wireEventSize != 112 {
		t.Errorf("wireEventSize drifted: got %d, want 112", wireEventSize)
	}
}

func TestIsWebUserName(t *testing.T) {
	cases := map[string]bool{
		"apache":          true,
		"nginx":           true,
		"www-data":        true,
		"http":            true,
		"php":             true,
		"lsphp":           true,
		"proxy":           true,
		"alt-php-N81":     true,
		"alt-php-fpm-N81": true,
		"root":            false,
		"systemd":         false,
		"random":          false,
		"":                false,
	}
	for name, want := range cases {
		if got := isWebUserName(name); got != want {
			t.Errorf("isWebUserName(%q) = %t, want %t", name, got, want)
		}
	}
}

func TestDefaultSensitivePaths_NoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range DefaultSensitivePaths {
		if seen[p] {
			t.Errorf("duplicate sensitive path: %q", p)
		}
		seen[p] = true
		if !strings.HasPrefix(p, "/") {
			t.Errorf("sensitive path %q is not absolute", p)
		}
	}
}
