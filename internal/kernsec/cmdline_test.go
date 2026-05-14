package kernsec

import (
	"reflect"
	"testing"
)

func TestParseCmdline(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty", in: "", want: []string{}},
		{name: "single", in: "ro", want: []string{"ro"}},
		{name: "multi", in: "ro quiet splash", want: []string{"ro", "quiet", "splash"}},
		{name: "extra spaces", in: "  a   b\tc  ", want: []string{"a", "b", "c"}},
		{
			name: "kspp args",
			in:   "BOOT_IMAGE=/vmlinuz ro slab_nomerge init_on_alloc=1 page_alloc.shuffle=1",
			want: []string{"BOOT_IMAGE=/vmlinuz", "ro", "slab_nomerge", "init_on_alloc=1", "page_alloc.shuffle=1"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseCmdline(tc.in)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParseCmdline(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestCheckBootArg(t *testing.T) {
	tokens := ParseCmdline("ro quiet slab_nomerge init_on_alloc=1 page_alloc.shuffle=0 randomize_kstack_offset=on")

	tests := []struct {
		name      string
		want      BootArg
		wantState CmdlineArgState
		wantFound string
	}{
		{
			name:      "bare key OK",
			want:      BootArg{Key: "slab_nomerge"},
			wantState: ArgOK,
		},
		{
			name:      "kv OK",
			want:      BootArg{Key: "init_on_alloc", Value: "1"},
			wantState: ArgOK,
			wantFound: "1",
		},
		{
			name:      "kv DIFF",
			want:      BootArg{Key: "page_alloc.shuffle", Value: "1"},
			wantState: ArgDiff,
			wantFound: "0",
		},
		{
			name:      "missing",
			want:      BootArg{Key: "initcall_blacklist", Value: "algif_aead_init"},
			wantState: ArgMissing,
		},
		{
			name:      "kv OK string",
			want:      BootArg{Key: "randomize_kstack_offset", Value: "on"},
			wantState: ArgOK,
			wantFound: "on",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st, found := CheckBootArg(tokens, tc.want)
			if st != tc.wantState {
				t.Fatalf("state = %v, want %v", st, tc.wantState)
			}
			if tc.wantState != ArgOK && found != tc.wantFound {
				t.Fatalf("found = %q, want %q", found, tc.wantFound)
			}
		})
	}
}

func TestRemoveManagedArgs(t *testing.T) {
	in := ParseCmdline("BOOT_IMAGE=/vmlinuz ro slab_nomerge init_on_alloc=0 page_alloc.shuffle=1 quiet randomize_kstack_offset=off initcall_blacklist=foo,bar")
	got := RemoveManagedArgs(in)
	want := []string{"BOOT_IMAGE=/vmlinuz", "ro", "quiet"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RemoveManagedArgs = %v, want %v", got, want)
	}

	// Idempotent on already-clean cmdlines.
	got2 := RemoveManagedArgs(got)
	if !reflect.DeepEqual(got2, want) {
		t.Fatalf("RemoveManagedArgs idempotent = %v, want %v", got2, want)
	}
}

func TestIsManagedKey(t *testing.T) {
	for _, k := range ManagedBootArgKeys {
		if !IsManagedKey(k) {
			t.Errorf("IsManagedKey(%q) = false, want true", k)
		}
	}
	for _, k := range []string{"ro", "quiet", "BOOT_IMAGE", "splash"} {
		if IsManagedKey(k) {
			t.Errorf("IsManagedKey(%q) = true, want false", k)
		}
	}
}

func TestManagedBootArgKeysExactOwnedSet(t *testing.T) {
	want := []string{
		"slab_nomerge",
		"init_on_alloc",
		"page_alloc.shuffle",
		"randomize_kstack_offset",
		"initcall_blacklist",
		"kfence.sample_interval",
		"efi",
		"tsx",
		"unprivileged_bpf_disabled",
		"oops",
		"init_on_free",
	}
	if !reflect.DeepEqual(ManagedBootArgKeys, want) {
		t.Fatalf("ManagedBootArgKeys changed:\ngot  %#v\nwant %#v", ManagedBootArgKeys, want)
	}

	removed := "spec" + "_store" + "_bypass" + "_disable"
	if IsManagedKey(removed) {
		t.Fatalf("removed boot arg key %q is still managed", removed)
	}
}

func TestBootArgString(t *testing.T) {
	tests := []struct {
		in   BootArg
		want string
	}{
		{BootArg{Key: "slab_nomerge"}, "slab_nomerge"},
		{BootArg{Key: "init_on_alloc", Value: "1"}, "init_on_alloc=1"},
		{BootArg{Key: "initcall_blacklist", Value: "algif_aead_init"}, "initcall_blacklist=algif_aead_init"},
	}
	for _, tc := range tests {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("%+v.String() = %q, want %q", tc.in, got, tc.want)
		}
	}
}
