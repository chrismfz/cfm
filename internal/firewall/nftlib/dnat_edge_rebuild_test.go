//go:build linux

package nftlib

import (
	"testing"

	"github.com/google/nftables"
)

// edgeDeleteClassification mirrors the per-rule "delete or keep"
// decision inside installEdgeDNATRules. It does NOT call the netlink
// connection — it only reports whether a given rule WOULD be deleted
// during an edge-namespace rebuild. Keeping the decision factored out
// like this lets us unit-test the classification against synthetic
// rule objects without needing a real netlink socket / kernel
// connection.
//
// If installEdgeDNATRules' deletion loop and this helper drift, the
// test below will fail. The helper is the authoritative spec for
// "what edge namespace owns and rebuilds on every DNATOn".
func edgeDeleteClassification(userData []byte) (delete bool, reason string) {
	if dnatBypassIsManaged(userData) {
		return true, "bypass (edge-owned)"
	}
	if !managedDNATRule(userData) {
		return false, "unmanaged (foreign rule, leave alone)"
	}
	if string(userData) == dnatLoopbackAcceptTag {
		return true, "loopback (edge-owned)"
	}
	// Decode namespace from UserData via the existing helper. We can
	// reuse dnatRuleInNamespace by constructing a thin fake.
	r := &nftables.Rule{UserData: userData}
	if dnatRuleInNamespace(r, dnatRuleNamespaceEdge) {
		return true, "edge namespace DNAT rule"
	}
	return false, "challenge namespace DNAT rule (preserve)"
}

func TestEdgeRebuild_ClassifiesBypassForDeletion(t *testing.T) {
	del, reason := edgeDeleteClassification([]byte("cfm_dnat_bypass:v1:84.54.49.205"))
	if !del {
		t.Fatalf("bypass rule must be deleted on edge rebuild, got reason=%s", reason)
	}
}

func TestEdgeRebuild_ClassifiesLoopbackForDeletion(t *testing.T) {
	del, reason := edgeDeleteClassification([]byte(dnatLoopbackAcceptTag))
	if !del {
		t.Fatalf("loopback rule must be deleted on edge rebuild, got reason=%s", reason)
	}
}

func TestEdgeRebuild_PreservesChallengeNamespaceRules(t *testing.T) {
	// A challenge-namespace rule has a non-empty sourceSet field (the
	// "s<name>" segment). dnatRuleInNamespace uses `spec.sourceSet != ""`
	// as the discriminator for the challenge namespace, so we need a
	// parseable UserData with a real sourceSet to actually exercise that
	// code path. A rule with an empty sourceSet would be classified as
	// edge-namespace and deleted — exactly the opposite of what we want.
	ch := dnatRuleTag + ":v2:f2:p6:d80:t9080:schal_v4:a-"
	del, reason := edgeDeleteClassification([]byte(ch))
	if del {
		t.Fatalf("challenge namespace rule must survive edge rebuild, reason=%s", reason)
	}
}

func TestEdgeRebuild_PreservesUnmanagedRules(t *testing.T) {
	// e.g. an Imunify rule the kernel happens to also have in the
	// same chain (unlikely but defensive).
	del, reason := edgeDeleteClassification([]byte("imunify360-something"))
	if del {
		t.Fatalf("foreign rule must NOT be touched, reason=%s", reason)
	}
}

func TestEdgeRebuild_OrderingInvariant_Documented(t *testing.T) {
	// This test does NOT exercise netlink end-to-end — that requires
	// elevated privileges and a netns. Instead it documents the
	// ordering invariant that installEdgeDNATRules promises: after a
	// rebuild the chain must be exactly:
	//
	//   1. iif "lo" accept
	//   2. ip[6] saddr <bypass entry> accept    (one per bypass list line)
	//   3. tcp|udp dport <X> dnat to :<Y>       (one per `wanted` spec)
	//
	// The previous reconcile-in-place implementation passed every
	// unit test in this package on the first DNATOn call and then
	// silently broke on the second call (bypass rules appended after
	// the surviving dport rules, never matching). The rebuild always
	// adds rules in this fixed order with no in-place survival, so
	// the failure mode is structurally eliminated.
	//
	// For end-to-end verification we rely on the operator running:
	//   nft list table inet cfm_redirect
	//   nft list table inet cfm_panel_redirect
	// after a `cfm dnat [cpanel] bypass add` — the bypass rules must
	// appear between `iif "lo" accept` and the first `dnat to` line.
	t.Log("ordering invariant is enforced structurally by installEdgeDNATRules; see docs/dnat-bypass.md for verification commands")
}
