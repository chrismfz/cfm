// Package managedsysctl is the cfm-internal coordination point for
// any cfm component that writes /proc/sys/* or /etc/sysctl.d/*.
// Multiple cfm components manage sysctls today:
//
//   - internal/sysctl/sys_tweaks.go: TCP/conntrack/rp_filter,
//     RAM-derived nf_conntrack_max, persisted to
//     /etc/sysctl.d/99-cfm.conf when the daemon starts.
//   - internal/kernsec: the KSPP profile + Tier 2 namespace kill,
//     persisted to /etc/sysctl.d/99-cfm-kernsec.conf when
//     `cfm kernsec apply` runs.
//   - cfm-firewall (future): may eventually claim more.
//
// Without coordination they could legitimately try to write the
// same key with different values, with no operator-visible warning.
// This package owns the cross-component registry: each component
// registers a Catalog via init() that declares the keys it owns.
// kernsec.Resolve consults OwnerOf() to mark rules whose key is
// owned by another component as "externally managed" — kernsec
// AUDITS them but never writes them.
//
// The package also provides shared primitives (canonical /proc/sys
// paths, per-key apply with continue-on-error, drift detection) so
// kernsec and sys_tweaks share one implementation rather than
// drift-prone copies.
package managedsysctl

import (
	"fmt"
	"sort"
	"sync"
)

// Owner identifies the cfm component that registered a key.
// Stable string label so status output can name the owner directly.
type Owner string

const (
	// OwnerKernsec is the kernsec package — KSPP profile + Tier 2.
	OwnerKernsec Owner = "kernsec"
	// OwnerSysTweaks is internal/sysctl/sys_tweaks.go — daemon-startup
	// imperative TCP/conntrack tuning.
	OwnerSysTweaks Owner = "cfm-sysctl-tweaks"
	// OwnerFirewall is cfm-firewall — placeholder for future
	// migration; not currently registered.
	OwnerFirewall Owner = "cfm-firewall"
)

// Catalog describes the static set of sysctl keys a cfm component
// claims ownership of. Implementations register themselves with the
// default Registry at init() time so kernsec.Resolve (which runs in a
// separate process invocation from the daemon) can still know what
// the daemon's sys_tweaks owns — both processes re-register the same
// catalog list when their init() functions fire.
//
// Static key set: implementations MUST return the same string slice
// across calls (no runtime computation, no config-conditional keys).
// The values a component writes can be runtime-computed; what it
// CLAIMS to own must be compile-time-stable.
type Catalog interface {
	Owner() Owner
	Keys() []string
}

// Conflict is reported when two catalogs claim the same key. Both
// owners are named so the operator can resolve the ownership
// disagreement (typically by editing the conf of one of the
// components to drop its claim).
type Conflict struct {
	Key    string
	Owners []Owner
}

func (c Conflict) Error() string {
	return fmt.Sprintf("managedsysctl: key %q claimed by multiple owners: %v",
		c.Key, c.Owners)
}

// Registry holds the union of registered catalogs and answers
// ownership queries. Tests construct their own; production code uses
// the default singleton.
type Registry struct {
	mu        sync.RWMutex
	catalogs  []Catalog
	keyToOwn  map[string]Owner
	conflicts []Conflict
}

// NewRegistry returns an empty registry. Tests use this to avoid
// touching the package-default singleton.
func NewRegistry() *Registry {
	return &Registry{keyToOwn: map[string]Owner{}}
}

// Register adds c to the registry. Conflicts (same key claimed by a
// previously-registered catalog with a DIFFERENT owner) are recorded
// in Conflicts() and surfaced; first owner wins for OwnerOf lookups,
// to keep behaviour deterministic across init() ordering. Same-owner
// duplicate registrations are tolerated (idempotent).
func (r *Registry) Register(c Catalog) {
	if c == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	owner := c.Owner()
	r.catalogs = append(r.catalogs, c)
	for _, k := range c.Keys() {
		if k == "" {
			continue
		}
		if existing, ok := r.keyToOwn[k]; ok {
			if existing == owner {
				continue // same owner re-registering — idempotent
			}
			r.recordConflictLocked(k, []Owner{existing, owner})
			continue // first registration wins
		}
		r.keyToOwn[k] = owner
	}
}

// recordConflictLocked must be called with r.mu held. Merges into an
// existing Conflict for the same key if present, otherwise appends.
func (r *Registry) recordConflictLocked(key string, owners []Owner) {
	for i := range r.conflicts {
		if r.conflicts[i].Key == key {
			for _, o := range owners {
				if !containsOwner(r.conflicts[i].Owners, o) {
					r.conflicts[i].Owners = append(r.conflicts[i].Owners, o)
				}
			}
			return
		}
	}
	cp := make([]Owner, len(owners))
	copy(cp, owners)
	r.conflicts = append(r.conflicts, Conflict{Key: key, Owners: cp})
}

// OwnerOf returns the Owner that registered key, or "" if no catalog
// claims it. Lookups are O(1).
func (r *Registry) OwnerOf(key string) Owner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.keyToOwn[key]
}

// IsExternallyOwned returns true iff key is owned by some Owner OTHER
// than `self`. Used by kernsec.Resolve to mark rules whose key is in
// another cfm component's catalog (e.g. KSEC-SCT-net.* rules whose
// key is owned by cfm-sysctl-tweaks) as audit-only.
func (r *Registry) IsExternallyOwned(key string, self Owner) bool {
	owner := r.OwnerOf(key)
	return owner != "" && owner != self
}

// Conflicts returns the list of detected ownership conflicts in
// stable order. Empty slice when there are none.
func (r *Registry) Conflicts() []Conflict {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.conflicts) == 0 {
		return nil
	}
	out := make([]Conflict, len(r.conflicts))
	for i, c := range r.conflicts {
		out[i] = Conflict{
			Key:    c.Key,
			Owners: append([]Owner(nil), c.Owners...),
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// AllKeys returns every registered key in sorted order. Useful for
// audit/status surfaces that want to enumerate the cross-component
// view.
func (r *Registry) AllKeys() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := make([]string, 0, len(r.keyToOwn))
	for k := range r.keyToOwn {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// defaultRegistry is the package-global registry every cfm binary
// shares. init() functions in sys_tweaks / kernsec / etc register
// their catalogs here at startup.
var defaultRegistry = NewRegistry()

// Default returns the package-global registry. CLI commands and
// daemon code call Default().OwnerOf(key) for cross-component
// ownership checks.
func Default() *Registry {
	return defaultRegistry
}

// RegisterCatalog is a shortcut for Default().Register(c). Catalogs
// register themselves from package-init() functions, e.g.:
//
//	func init() {
//	    managedsysctl.RegisterCatalog(myCatalog{})
//	}
func RegisterCatalog(c Catalog) {
	defaultRegistry.Register(c)
}

func containsOwner(s []Owner, want Owner) bool {
	for _, o := range s {
		if o == want {
			return true
		}
	}
	return false
}
