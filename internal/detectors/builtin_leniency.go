// internal/detectors/builtin_leniency.go
//
// The built-in GR/CY leniency: every section that bans an address gets a soft
// tier for Greek and Cypriot addresses unless it has its own companion.

package detectors

import (
	"strings"

	"cfm/internal/detectors/meta"
)

// builtinLeniencyDefaults is the [<section>.leniency] a section runs with when
// detectors.conf gives it none: a Greek or Cypriot address (most of the
// customers) gets a 15 minute local ban, recorded on cfm-web's "lenient" list
// (support and unblock lookups) and never served to the fleet. Country only,
// no MATCH_ASN: these sections fire on cloud scanners too, and a Greek
// hosting ASN would carry them into the soft tier ([webdetector.leniency]
// made the same call).
//
// Before it, a section without a companion ([modsec], [ssh_auth], [ftpd],
// [cpanel], [mysql], [postfix_security], ...) banned a Greek customer with its
// full policy and reported the address to the fleet blocklist: on 2026-11-26
// MYBLOCK held permanent MODSEC/403 bans on a Cosmote CGNAT address
// (cgn.athe.cosmote.net), a Vodafone and two Nova ones, which every node then
// dropped for every subscriber behind them.
func builtinLeniencyDefaults() KV {
	return KV{
		"MATCH_COUNTRY":     "GR,CY",
		"BLOCK":             "15m",
		"BLOCK_COOLDOWN":    "15m",
		"SEND_TO_API":       "yes",
		"SEND_TO_BLOCKLIST": "lenient",
	}
}

// builtinLeniencyTypes is the set of detector types that take the built-in
// leniency: the catalog's LeniencySupported ones, except login_bruteforce,
// whose own built-in companion (applyBuiltinLoginBruteforce) also matches
// the Greek eyeball ASNs.
func builtinLeniencyTypes() map[string]bool {
	out := map[string]bool{}
	for _, m := range meta.Catalog() {
		if m.LeniencySupported && m.TypeKey != loginBruteforceType {
			out[m.TypeKey] = true
		}
	}
	return out
}

// applyBuiltinLeniency gives every section of a leniency-supporting type the
// built-in companion when detectors.conf has none. A written companion is
// kept as written, with two exceptions:
//   - ENABLED = 0 turns it off (the only way to run a section with no
//     leniency);
//   - one with neither MATCH_COUNTRY nor MATCH_ASN (cfm-admin's "Add leniency
//     companion" writes MATCH_COUNTRY = "") takes the built-in values for the
//     keys it leaves empty.
//
// Run it after applyBuiltinLoginBruteforce, on a config that was read.
func applyBuiltinLeniency(secs *Sections) {
	if secs == nil || len(secs.ByName) == 0 {
		return
	}
	types := builtinLeniencyTypes()
	var sections []string
	for name := range secs.ByName {
		if name == "global" || strings.HasSuffix(name, ".leniency") {
			continue
		}
		if typ, _ := SplitTypeInstance(name); types[typ] {
			sections = append(sections, name)
		}
	}
	for _, name := range sections {
		lk := name + ".leniency"
		lkv, ok := secs.ByName[lk]
		switch {
		case !ok:
			secs.ByName[lk] = builtinLeniencyDefaults()
		case !kvBool(lkv, "ENABLED", true):
			secs.ByName[lk] = KV{} // no criteria: parseLeniencyPolicy turns it off
		case kvStrClean(lkv, "MATCH_COUNTRY", "") == "" && kvStrClean(lkv, "MATCH_ASN", "") == "":
			merged := builtinLeniencyDefaults()
			for k, v := range lkv {
				if cleanScalar(v) != "" {
					merged[k] = v
				}
			}
			secs.ByName[lk] = merged
		}
	}
}

// softerPolicy is the policy a leniency match applies: the companion's, but
// never harsher than the section's own. A section that only logs (dryrun)
// keeps logging, a permanent companion under a TTL section takes the TTL, and
// a TTL longer than the section's is cut to it. The cooldown is the
// companion's.
func softerPolicy(section, lenient blockPolicy) blockPolicy {
	switch section.Mode {
	case "no", "dryrun":
		return section
	}
	out := lenient
	switch lenient.Mode {
	case "permanent":
		if section.Mode == "ttl" {
			out.Mode, out.TTL = "ttl", section.TTL
		}
	case "ttl":
		if section.Mode == "ttl" && section.TTL > 0 && (lenient.TTL <= 0 || lenient.TTL > section.TTL) {
			out.TTL = section.TTL
		}
	}
	return out
}
