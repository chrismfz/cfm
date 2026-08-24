// Package configdrift compares STOCK reference configs shipped with the CFM
// package (/usr/share/cfm/configs/) against the LIVE configs under /etc/cfm/.
//
// Why: /etc/cfm/*.conf are conffiles — package upgrades seed them once and
// never touch them again, so every NEW knob a release ships (a whole
// [waf_security] section, challenge_cookie_discard, a new [global] key …)
// silently never reaches hosts whose live config predates it. This package is
// the "which features did I never get?" read that backs the config_drift MCP
// tool.
//
// detectors.conf is parsed with the SAME reader the daemon's manager uses
// (internal/detconf.ReadSectionsFile), so the comparison is semantic —
// comment style, quoting, inline comments and multiline rule blocks are
// normalised identically on both sides, and commented-out stock sections
// correctly do NOT count as expected.
//
// cfm.conf is a documented-flat file where most knobs ship COMMENTED; there we
// only report stock-known keys that are absent from the live file entirely
// (not even as a comment) — values are deliberately never compared (host-
// specific and often secret).
//
// Pure functions only; file IO stays with the caller.
package configdrift

import (
	"regexp"
	"sort"
	"strings"

	"cfm/internal/detconf"
)

// KeyRef points at one key inside one detectors.conf section.
type KeyRef struct {
	Section string `json:"section"`
	Key     string `json:"key"`
}

// ValueRef is a key whose value differs between stock and live. Values are
// informational (live values legitimately differ per host); the COUNT is what
// matters, samples exist to spot copy-paste mistakes.
type ValueRef struct {
	Section string `json:"section"`
	Key     string `json:"key"`
	Stock   string `json:"stock"`
	Live    string `json:"live"`
}

// DetectorsReport is the stock-vs-live comparison for one detectors.conf pair.
type DetectorsReport struct {
	MissingSections []string   `json:"missing_sections,omitempty"` // whole [section] in stock, absent live
	MissingKeys     []KeyRef   `json:"missing_keys,omitempty"`     // section exists both sides; key only in stock
	ExtraSections   []string   `json:"extra_sections,omitempty"`   // live-only sections (instances/operator extras)
	ExtraKeys       []KeyRef   `json:"extra_keys,omitempty"`       // live-only keys (informational)
	ValueDiffs      int        `json:"value_diffs"`                // same section+key, different value
	ValueSamples    []ValueRef `json:"value_samples,omitempty"`    // worst-first capped peek at ValueDiffs
}

const valueSampleCap = 10

// DiffDetectorsSections compares parsed stock/live detectors.conf sections.
// Keys are compared case-insensitively (the parser uppercases both sides, so
// this is belt-and-braces for direct callers).
func DiffDetectorsSections(stock, live detconf.Sections) DetectorsReport {
	return DiffDetectorsSectionsIgnoring(stock, live, nil)
}

// DiffDetectorsSectionsIgnoring applies the normal semantic comparison while
// omitting section families whose runtime defaults make their conffile entries
// optional. The caller owns product-specific alias policy.
func DiffDetectorsSectionsIgnoring(stock, live detconf.Sections, ignore func(string) bool) DetectorsReport {
	var r DetectorsReport

	stockNames := sortedSectionNames(stock)
	for _, name := range stockNames {
		if ignore != nil && ignore(name) {
			continue
		}
		liveKV, ok := live.ByName[name]
		if !ok {
			r.MissingSections = append(r.MissingSections, name)
			continue
		}
		stockKV := stock.ByName[name]
		for _, k := range sortedKeys(stockKV) {
			if _, ok := liveKV[k]; !ok {
				r.MissingKeys = append(r.MissingKeys, KeyRef{Section: name, Key: k})
			} else if normalizeValue(stockKV[k]) != normalizeValue(liveKV[k]) {
				r.ValueDiffs++
				if len(r.ValueSamples) < valueSampleCap {
					r.ValueSamples = append(r.ValueSamples, ValueRef{
						Section: name, Key: k,
						Stock: truncate(normalizeValue(stockKV[k])),
						Live:  truncate(normalizeValue(liveKV[k])),
					})
				}
			}
		}
	}

	liveNames := sortedSectionNames(live)
	for _, name := range liveNames {
		if ignore != nil && ignore(name) {
			continue
		}
		if _, ok := stock.ByName[name]; !ok {
			r.ExtraSections = append(r.ExtraSections, name)
			continue
		}
		stockKV := stock.ByName[name]
		for _, k := range sortedKeys(live.ByName[name]) {
			if _, ok := stockKV[k]; !ok {
				r.ExtraKeys = append(r.ExtraKeys, KeyRef{Section: name, Key: k})
			}
		}
	}
	return r
}

// FlatMissing is the cfm.conf-style result: which stock-documented keys are
// absent from the live file entirely.
type FlatReport struct {
	MissingKeys []string `json:"missing_keys,omitempty"` // documented in stock, nowhere in live
	StockKeys   int      `json:"stock_keys"`             // distinct known keys documented (active or commented) in stock
	LiveKeys    int      `json:"live_keys"`              // distinct known keys present in live (active or commented)
}

var (
	flatActiveRe    = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_]+)\s*=`)
	flatCommentedRe = regexp.MustCompile(`(?m)^\s*#\s*([A-Za-z0-9_]+)\s*=`)
)

// DiffFlat compares a commented-documentation-style flat conf against the live
// one. A stock key counts as "present" in live whether it appears active or
// commented-out there (an operator who deliberately commented a knob out HAS
// seen it); only keys absent from the live TEXT altogether are reported.
// Unknown identifiers (not real CFM keys, prose lines) are ignored via isKnown.
func DiffFlat(stockText, liveText string, isKnown func(string) bool) FlatReport {
	var r FlatReport
	type presence struct{ stock, live bool }
	seen := map[string]*presence{}

	collect := func(text, side string) {
		for _, re := range []*regexp.Regexp{flatActiveRe, flatCommentedRe} {
			for _, m := range re.FindAllStringSubmatch(text, -1) {
				key := strings.ToUpper(strings.TrimSpace(m[1]))
				if key == "" || (isKnown != nil && !isKnown(key)) {
					continue
				}
				p, ok := seen[key]
				if !ok {
					p = &presence{}
					seen[key] = p
				}
				if side == "stock" {
					p.stock = true
				} else {
					p.live = true
				}
			}
		}
	}
	collect(stockText, "stock")
	collect(liveText, "live")

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		p := seen[k]
		if p.live {
			r.LiveKeys++
			continue
		}
		if p.stock {
			r.MissingKeys = append(r.MissingKeys, k)
		}
	}
	for _, k := range keys {
		if seen[k].stock {
			r.StockKeys++
		}
	}
	return r
}

func sortedSectionNames(s detconf.Sections) []string {
	out := make([]string, 0, len(s.ByName))
	for name := range s.ByName {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(kv detconf.KV) []string {
	out := make([]string, 0, len(kv))
	for k := range kv {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// normalizeValue trims space and surrounding quotes so cosmetic differences
// don't count as value drift (mirrors the parser's own quote-stripping).
func normalizeValue(v string) string {
	return strings.Trim(strings.TrimSpace(v), `"`)
}

func truncate(s string) string {
	const max = 80
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
