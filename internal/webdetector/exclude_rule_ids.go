package webdetector

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// parseRuleIDSpec expands a single specifier into the rule IDs it covers.
// Accepted forms:
//
//	"320"     -> [320]
//	"3xx"     -> 300..399 (group prefix; first digit + "xx")
//	"310-317" -> 310..317 (inclusive range)
//
// Whitespace is trimmed. Specifiers are case-insensitive ("3XX" works).
// IDs are constrained to 100..999 (the WAF rule-ID space). Specifiers that
// expand outside that range are clipped to it; specifiers that yield no IDs
// inside the range are an error.
func parseRuleIDSpec(spec string) ([]int, error) {
	s := strings.ToLower(strings.TrimSpace(spec))
	if s == "" {
		return nil, fmt.Errorf("empty rule spec")
	}

	if strings.HasSuffix(s, "xx") && len(s) >= 3 {
		head := s[:len(s)-2]
		n, err := strconv.Atoi(head)
		if err != nil || n < 1 || n > 9 {
			return nil, fmt.Errorf("invalid group prefix %q (expected 1xx..9xx)", spec)
		}
		out := make([]int, 0, 100)
		for i := n * 100; i < (n+1)*100; i++ {
			out = append(out, i)
		}
		return out, nil
	}

	if i := strings.IndexByte(s, '-'); i >= 0 {
		lo, errLo := strconv.Atoi(strings.TrimSpace(s[:i]))
		hi, errHi := strconv.Atoi(strings.TrimSpace(s[i+1:]))
		if errLo != nil || errHi != nil {
			return nil, fmt.Errorf("invalid range %q", spec)
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		if hi < 100 || lo > 999 {
			return nil, fmt.Errorf("range %q outside 100..999", spec)
		}
		if lo < 100 {
			lo = 100
		}
		if hi > 999 {
			hi = 999
		}
		out := make([]int, 0, hi-lo+1)
		for i := lo; i <= hi; i++ {
			out = append(out, i)
		}
		return out, nil
	}

	n, err := strconv.Atoi(s)
	if err != nil {
		return nil, fmt.Errorf("invalid rule id %q", spec)
	}
	if n < 100 || n > 999 {
		return nil, fmt.Errorf("rule id %d outside 100..999", n)
	}
	return []int{n}, nil
}

// parseRuleIDs accepts a comma-separated string of specifiers and returns the
// sorted, de-duplicated union of rule IDs they expand to. Empty/whitespace
// input returns (nil, nil) to mean "no rule scoping" (whole-WAF exclude).
func parseRuleIDs(spec string) ([]int, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	seen := make(map[int]struct{})
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ids, err := parseRuleIDSpec(p)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			seen[id] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil, nil
	}
	out := make([]int, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Ints(out)
	return out, nil
}

// normalizeRuleIDs returns a sorted, de-duplicated copy of ids. nil/empty
// input returns nil. IDs outside 100..999 are dropped silently to keep
// store/load idempotent against malformed JSON on disk.
func normalizeRuleIDs(ids []int) []int {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(ids))
	for _, id := range ids {
		if id < 100 || id > 999 {
			continue
		}
		seen[id] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]int, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Ints(out)
	return out
}

// ruleIDsKey returns a stable string used as part of the exclude-store map
// key, so different rule-ID sets on the same (type, value, scope) tuple are
// distinct entries. Empty input returns "" (whole-WAF skip).
func ruleIDsKey(ids []int) string {
	if len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(id)
	}
	return strings.Join(parts, ",")
}
