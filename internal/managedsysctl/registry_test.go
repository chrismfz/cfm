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

func TestRegistry_ThreeWayConflict(t *testing.T) {
	// Three catalogs claiming the same key. recordConflictLocked
	// merges via containsOwner so the resulting Conflict names all
	// three owners; first-registrant wins for OwnerOf.
	r := NewRegistry()
	r.Register(stubCatalog{owner: OwnerSysTweaks, keys: []string{"k"}})
	r.Register(stubCatalog{owner: OwnerKernsec, keys: []string{"k"}})
	r.Register(stubCatalog{owner: OwnerFirewall, keys: []string{"k"}})

	conflicts := r.Conflicts()
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict (merged), got %d: %v", len(conflicts), conflicts)
	}
	c := conflicts[0]
	if len(c.Owners) < 3 {
		t.Errorf("conflict should name all 3 owners, got %v", c.Owners)
	}
	for _, want := range []Owner{OwnerSysTweaks, OwnerKernsec, OwnerFirewall} {
		if !containsOwner(c.Owners, want) {
			t.Errorf("conflict missing owner %q (got %v)", want, c.Owners)
		}
	}
	if got := r.OwnerOf("k"); got != OwnerSysTweaks {
		t.Errorf("OwnerOf in 3-way conflict = %q, want first registrant OwnerSysTweaks", got)
	}
}

func TestRegistry_ConcurrentRegisterAndOwnerOf(t *testing.T) {
	// Race-detector smoke: parallel writers + readers must not race.
	// Run with `go test -race` to actually exercise.
	r := NewRegistry()
	const n = 100
	done := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			r.Register(stubCatalog{owner: OwnerSysTweaks, keys: []string{"k1"}})
		}
		done <- struct{}{}
	}()
	go func() {
		for i := 0; i < n; i++ {
			_ = r.OwnerOf("k1")
			_ = r.Conflicts()
			_ = r.AllKeys()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
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
	calls := []string{}
	SetSetCommandForTest(t, func(key, value string) ([]byte, error) {
		calls = append(calls, key+"="+value)
		return []byte(key + " = " + value + "\n"), nil
	})

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
	failKey := "net.bad"
	SetSetCommandForTest(t, func(key, value string) ([]byte, error) {
		if key == failKey {
			return []byte("permission denied"), errors.New("exit 1")
		}
		return []byte(""), nil
	})

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
	SetSetCommandForTest(t, func(string, string) ([]byte, error) { return nil, nil })

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

func TestParseFileToPairs_BOMStripped(t *testing.T) {
	// Hand-edited file from a BOM-emitting editor would otherwise
	// fold the BOM bytes into the first key.
	content := []byte("\xef\xbb\xbfkernel.foo = 1\n")
	pairs, skipped := ParseFileToPairs(content)
	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d (skipped=%v)", len(pairs), skipped)
	}
	if pairs[0].Key != "kernel.foo" {
		t.Errorf("BOM not stripped: got key %q, want kernel.foo", pairs[0].Key)
	}
}

func TestParseFileToPairs_CRLFLineEndings(t *testing.T) {
	content := []byte("kernel.a = 1\r\nkernel.b = 2\r\n")
	pairs, _ := ParseFileToPairs(content)
	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(pairs))
	}
	if pairs[0].Value != "1" || pairs[1].Value != "2" {
		t.Errorf("CRLF not stripped from value: %+v", pairs)
	}
}

func TestParseFileToPairs_EqualsInValue(t *testing.T) {
	// Some sysctls (e.g. kernel.modprobe) take command-line values
	// that contain `=`. Split must use first `=` only.
	content := []byte("kernel.modprobe = /sbin/modprobe -k=yes\n")
	pairs, _ := ParseFileToPairs(content)
	if len(pairs) != 1 || pairs[0].Key != "kernel.modprobe" || pairs[0].Value != "/sbin/modprobe -k=yes" {
		t.Errorf("equals-in-value: got %+v", pairs)
	}
}

func TestApplyKeys_AllFailures(t *testing.T) {
	SetSetCommandForTest(t, func(string, string) ([]byte, error) {
		return []byte("EPERM"), errAllFail
	})
	res := ApplyKeys([]KeyValuePair{{"a", "1"}, {"b", "2"}})
	if res.Applied != 0 {
		t.Errorf("Applied = %d, want 0", res.Applied)
	}
	if len(res.Failures) != 2 {
		t.Errorf("Failures = %d, want 2", len(res.Failures))
	}
	if res.Err() == nil {
		t.Error("Err() should aggregate failures")
	}
}

func TestApplyKeys_EmptyInput(t *testing.T) {
	res := ApplyKeys(nil)
	if res.Applied != 0 || len(res.Failures) != 0 || len(res.Skipped) != 0 {
		t.Errorf("empty input should produce zero result, got %+v", res)
	}
	if res.Err() != nil {
		t.Errorf("Err() on empty result should be nil, got %v", res.Err())
	}
}

var errAllFail = stringError("simulated failure")

type stringError string

func (e stringError) Error() string { return string(e) }
