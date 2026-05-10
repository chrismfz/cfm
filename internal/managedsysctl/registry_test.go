package managedsysctl

import (
	"errors"
	"strings"
	"testing"
)

// stubCatalog is a test-only Catalog implementation.
type stubCatalog struct {
	owner Owner
	keys  []string
}

func (c stubCatalog) Owner() Owner    { return c.owner }
func (c stubCatalog) Keys() []string  { return c.keys }

func TestRegistry_RegisterAndOwnerOf(t *testing.T) {
	r := NewRegistry()
	r.Register(stubCatalog{
		owner: OwnerSysTweaks,
		keys:  []string{"net.ipv4.tcp_syncookies", "net.ipv4.rp_filter"},
	})
	r.Register(stubCatalog{
		owner: OwnerKernsec,
		keys:  []string{"kernel.kptr_restrict"},
	})

	tests := []struct {
		key  string
		want Owner
	}{
		{"net.ipv4.tcp_syncookies", OwnerSysTweaks},
		{"net.ipv4.rp_filter", OwnerSysTweaks},
		{"kernel.kptr_restrict", OwnerKernsec},
		{"net.never.registered", ""},
	}
	for _, tc := range tests {
		if got := r.OwnerOf(tc.key); got != tc.want {
			t.Errorf("OwnerOf(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func TestRegistry_IsExternallyOwned(t *testing.T) {
	r := NewRegistry()
	r.Register(stubCatalog{
		owner: OwnerSysTweaks,
		keys:  []string{"net.ipv4.tcp_syncookies"},
	})

	// kernsec asking "is this key managed by someone else?"
	if !r.IsExternallyOwned("net.ipv4.tcp_syncookies", OwnerKernsec) {
		t.Error("kernsec should see tcp_syncookies as externally owned")
	}
	// sys_tweaks asking the same key — it owns it itself.
	if r.IsExternallyOwned("net.ipv4.tcp_syncookies", OwnerSysTweaks) {
		t.Error("sys_tweaks should NOT see its own key as externally owned")
	}
	// Unowned key.
	if r.IsExternallyOwned("kernel.never_seen", OwnerKernsec) {
		t.Error("unowned key should not register as externally owned")
	}
}

func TestRegistry_ConflictDetection(t *testing.T) {
	// Two catalogs claim the same key: ownership conflict.
	r := NewRegistry()
	r.Register(stubCatalog{owner: OwnerSysTweaks, keys: []string{"net.ipv4.rp_filter"}})
	r.Register(stubCatalog{owner: OwnerKernsec, keys: []string{"net.ipv4.rp_filter"}})

	conflicts := r.Conflicts()
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d: %v", len(conflicts), conflicts)
	}
	c := conflicts[0]
	if c.Key != "net.ipv4.rp_filter" {
		t.Errorf("conflict key = %q, want net.ipv4.rp_filter", c.Key)
	}
	if !containsOwner(c.Owners, OwnerSysTweaks) || !containsOwner(c.Owners, OwnerKernsec) {
		t.Errorf("conflict owners = %v, want both sys_tweaks and kernsec", c.Owners)
	}
	// First registrant wins for OwnerOf — deterministic across init order.
	if got := r.OwnerOf("net.ipv4.rp_filter"); got != OwnerSysTweaks {
		t.Errorf("OwnerOf during conflict = %q, want sys_tweaks (first registrant)", got)
	}
	// Conflict.Error renders both owners.
	msg := c.Error()
	if !strings.Contains(msg, "rp_filter") {
		t.Errorf("Conflict.Error should name the key: %v", msg)
	}
	if !strings.Contains(msg, "sysctl-tweaks") || !strings.Contains(msg, "kernsec") {
		t.Errorf("Conflict.Error should name both owners: %v", msg)
	}
}

func TestRegistry_SameOwnerReregisterIsIdempotent(t *testing.T) {
	r := NewRegistry()
	r.Register(stubCatalog{owner: OwnerSysTweaks, keys: []string{"a", "b"}})
	r.Register(stubCatalog{owner: OwnerSysTweaks, keys: []string{"a", "b"}})

	if conflicts := r.Conflicts(); len(conflicts) != 0 {
		t.Errorf("same-owner re-registration should not conflict, got: %v", conflicts)
	}
}

func TestRegistry_AllKeysSorted(t *testing.T) {
	r := NewRegistry()
	r.Register(stubCatalog{owner: OwnerSysTweaks, keys: []string{"z", "a", "m"}})
	r.Register(stubCatalog{owner: OwnerKernsec, keys: []string{"b"}})

	got := r.AllKeys()
	want := []string{"a", "b", "m", "z"}
	if len(got) != len(want) {
		t.Fatalf("AllKeys() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AllKeys()[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestRegistry_NilCatalogIgnored(t *testing.T) {
	r := NewRegistry()
	r.Register(nil) // must not panic
	if got := r.OwnerOf("anything"); got != "" {
		t.Errorf("OwnerOf on empty registry = %q, want empty", got)
	}
}

func TestRegistry_EmptyKeyIgnored(t *testing.T) {
	r := NewRegistry()
	r.Register(stubCatalog{owner: OwnerSysTweaks, keys: []string{"", "real.key"}})
	if got := r.OwnerOf(""); got != "" {
		t.Errorf("empty key should not be registered, got owner %q", got)
	}
	if got := r.OwnerOf("real.key"); got != OwnerSysTweaks {
		t.Errorf("real.key should be registered, got %q", got)
	}
}

func TestApplyKeys_HappyPath(t *testing.T) {
	orig := SetCommand
	defer func() { SetCommand = orig }()
	calls := []string{}
	SetCommand = func(key, value string) ([]byte, error) {
		calls = append(calls, key+"="+value)
		return []byte(key + " = " + value + "\n"), nil
	}

	res := ApplyKeys([]KeyValuePair{
		{"a", "1"},
		{"b", "2"},
	})
	if res.Applied != 2 {
		t.Errorf("Applied = %d, want 2", res.Applied)
	}
	if len(res.Failures) != 0 {
		t.Errorf("expected no failures, got %v", res.Failures)
	}
	if len(calls) != 2 || calls[0] != "a=1" || calls[1] != "b=2" {
		t.Errorf("calls = %v, want [a=1 b=2]", calls)
	}
}

func TestApplyKeys_ContinueOnError(t *testing.T) {
	orig := SetCommand
	defer func() { SetCommand = orig }()
	failKey := "net.bad"
	SetCommand = func(key, value string) ([]byte, error) {
		if key == failKey {
			return []byte("permission denied"), errors.New("exit 1")
		}
		return []byte(""), nil
	}

	res := ApplyKeys([]KeyValuePair{
		{"net.good1", "1"},
		{failKey, "99"},
		{"net.good2", "2"},
	})
	if res.Applied != 2 {
		t.Errorf("Applied = %d, want 2 (good1 + good2)", res.Applied)
	}
	if len(res.Failures) != 1 {
		t.Fatalf("expected 1 failure, got %d", len(res.Failures))
	}
	if res.Failures[0].Key != failKey {
		t.Errorf("failure key = %q, want %q", res.Failures[0].Key, failKey)
	}
	if !strings.Contains(res.Err().Error(), "permission denied") {
		t.Errorf("aggregated error should include kernel response: %v", res.Err())
	}
}

func TestApplyKeys_EmptyKeyMarkedSkipped(t *testing.T) {
	orig := SetCommand
	defer func() { SetCommand = orig }()
	SetCommand = func(string, string) ([]byte, error) { return nil, nil }

	res := ApplyKeys([]KeyValuePair{
		{"", "99"},
		{"valid.key", "1"},
	})
	if res.Applied != 1 {
		t.Errorf("Applied = %d, want 1", res.Applied)
	}
	if len(res.Skipped) != 1 {
		t.Errorf("expected 1 skipped (empty key), got %v", res.Skipped)
	}
}

func TestParseFileToPairs(t *testing.T) {
	content := []byte(`# header
# managed by cfm
kernel.kptr_restrict = 2

fs.protected_hardlinks=1
malformed_line_no_equals
= 99
empty_value =
`)
	pairs, skipped := ParseFileToPairs(content)
	wantPairs := []KeyValuePair{
		{"kernel.kptr_restrict", "2"},
		{"fs.protected_hardlinks", "1"},
		{"empty_value", ""},
	}
	if len(pairs) != len(wantPairs) {
		t.Fatalf("pairs = %v, want %v", pairs, wantPairs)
	}
	for i := range wantPairs {
		if pairs[i] != wantPairs[i] {
			t.Errorf("pair[%d] = %+v, want %+v", i, pairs[i], wantPairs[i])
		}
	}
	if len(skipped) != 2 {
		t.Errorf("expected 2 skipped (malformed + empty key), got %v", skipped)
	}
}
