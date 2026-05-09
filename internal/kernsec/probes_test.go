package kernsec

import "testing"

func TestHasKernelConfigIn(t *testing.T) {
	cfg := `# comment
CONFIG_SHUFFLE_PAGE_ALLOCATOR=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
# CONFIG_RANDOMIZE_KSTACK_OFFSET is not set
CONFIG_SLUB=y
`
	tests := []struct {
		name string
		want bool
	}{
		{"SHUFFLE_PAGE_ALLOCATOR", true},
		{"INIT_ON_ALLOC_DEFAULT_ON", true},
		{"RANDOMIZE_KSTACK_OFFSET", false}, // commented out
		{"SLUB", true},
		{"NOT_PRESENT", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasKernelConfigIn(cfg, tc.name); got != tc.want {
				t.Fatalf("HasKernelConfigIn(_, %q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestIsPageAllocShuffleOn(t *testing.T) {
	for _, on := range []string{"1", "Y", "y", "on", "true"} {
		if !IsPageAllocShuffleOn(on) {
			t.Errorf("IsPageAllocShuffleOn(%q) = false, want true", on)
		}
	}
	for _, off := range []string{"0", "N", "n", "off", "false", "", "garbage"} {
		if IsPageAllocShuffleOn(off) {
			t.Errorf("IsPageAllocShuffleOn(%q) = true, want false", off)
		}
	}
}

func TestMemAutoInitLine(t *testing.T) {
	log := `[    0.000000] Linux version 6.1.0
[    0.001234] mem auto-init: stack:off, heap alloc:on, heap free:off
[    0.123456] some other line
[    1.000000] mem auto-init: stack:off, heap alloc:on, heap free:on
[    1.500000] tail
`
	got := MemAutoInitLine(log)
	want := "[    1.000000] mem auto-init: stack:off, heap alloc:on, heap free:on"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if !IsInitOnAllocActive(got) {
		t.Errorf("IsInitOnAllocActive returned false on heap alloc:on line")
	}
}

func TestMemAutoInitLine_None(t *testing.T) {
	if got := MemAutoInitLine("nothing relevant here\n"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestUnknownArgWarnings(t *testing.T) {
	log := `[    0.123] Hardware name: foo
[    0.456] Unknown kernel command line parameters "slab_nomerge bogusarg=1", will be passed to user space.
[    0.789] some unrelated line
[    0.999] Malformed early option 'init_on_alloc'
[    1.111] unknown parameter 'completely_unrelated' ignored
`
	matched := UnknownArgWarnings(log, ManagedBootArgKeys)
	if len(matched) != 2 {
		t.Fatalf("got %d matches, want 2: %v", len(matched), matched)
	}
}

func TestUnknownArgWarnings_None(t *testing.T) {
	log := `regular boot, nothing wrong
some other line
`
	if got := UnknownArgWarnings(log, ManagedBootArgKeys); len(got) != 0 {
		t.Fatalf("expected no matches, got %v", got)
	}
}
