package detectors

import (
	"testing"
	"time"
)

// TestSectionBlockPolicyTypeDefaults: a section that omits BLOCK /
// BLOCK_COOLDOWN runs its type's default; one that sets the key, even to an
// empty value, keeps it; a type without an entry keeps the framework default.
func TestSectionBlockPolicyTypeDefaults(t *testing.T) {
	cases := []struct {
		name    string
		section string
		kv      KV
		want    blockPolicy
	}{
		{"ssh absent → type default", "ssh_auth", KV{}, blockPolicy{Mode: "permanent", Cooldown: 30 * time.Minute}},
		{"ssh named instance → type default", "ssh_auth:secondary", KV{}, blockPolicy{Mode: "permanent", Cooldown: 30 * time.Minute}},
		{"ssh explicit no wins", "ssh_auth", KV{"BLOCK": "no"}, blockPolicy{Mode: "no", Cooldown: 30 * time.Minute}},
		{"ssh explicit empty wins", "ssh_auth", KV{"BLOCK": ""}, blockPolicy{Mode: "no", Cooldown: 30 * time.Minute}},
		{"ssh explicit ttl + cooldown win", "ssh_auth", KV{"BLOCK": "4h", "BLOCK_COOLDOWN": "5m"}, blockPolicy{Mode: "ttl", TTL: 4 * time.Hour, Cooldown: 5 * time.Minute}},
		{"other type keeps framework default", "dovecot_auth", KV{}, blockPolicy{Mode: "no", Cooldown: 15 * time.Minute}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sectionBlockPolicy(tc.section, tc.kv); got != tc.want {
				t.Errorf("sectionBlockPolicy(%q, %v) = %+v, want %+v", tc.section, tc.kv, got, tc.want)
			}
		})
	}

	// The defaults are applied to a copy: the caller's KV is never mutated.
	kv := KV{"ENABLED": "1"}
	sectionBlockPolicy("ssh_auth", kv)
	if _, leaked := kv["BLOCK"]; leaked {
		t.Error("sectionBlockPolicy wrote the type default into the caller's KV")
	}
}
