package webdetector

import "strings"

// pathMatcher answers "which is the FIRST rule (in list order) whose
// substring occurs in this path" in one pass over the path, whatever the
// number of rules. It replaces the linear strings.Contains loops over the
// malpath list (MALPATH flood counter and CHALLENGE_PATHS), which ran twice
// per ingested access-log line under the engine lock and grew with the list.
//
// It is an Aho-Corasick automaton compiled to a DFA over byte classes:
//   - bytes that occur in no pattern share class 0, which always leads back
//     to the root, so the table is states x (distinct pattern bytes + 1);
//   - each state carries the lowest rule index among every pattern that ends
//     there, directly or through its failure chain (a suffix match).
//
// The scan keeps the minimum over every position, so the answer is exactly
// that of `for i, sub := range subs { if strings.Contains(s, sub) { return i } }`:
// a rule matches iff its pattern occurs somewhere in s, and the lowest
// matching index wins (per-rule `N:pattern` thresholds depend on it). Empty
// patterns never match (the loops skipped them). Matching is on bytes: callers
// lower-case both sides with strings.ToLower, as the loops did.
//
// The table is dense, so its size is bounded by pathMatcherMaxCells: a list
// whose worst-case table would exceed it (an operator's very large
// MALPATH_LIST / file) keeps the linear loop instead, same answers.
//
// A pathMatcher is immutable once built and safe for concurrent use.
type pathMatcher struct {
	subs    []string   // the patterns, in rule order (sharing; the linear fallback)
	linear  bool       // table over the cap: answer with the linear loop
	class   [256]uint8 // byte -> class; 0 = byte in no pattern
	nclass  int
	delta   []int32 // state*nclass + class -> next state
	minRule []int32 // per state: lowest rule index ending here, or -1
}

// pathMatcherMaxCells caps the transition table at 4 Mi int32 cells (16 MB).
// The shipped list needs ~0.12 Mi (335 entries: 2 794 states x 42 classes).
// A var so tests can lower it.
var pathMatcherMaxCells = 4 << 20

// newPathMatcher compiles subs (already lower-cased; rule order). It returns
// nil when no pattern is non-empty, so callers keep their len()==0 fast path.
func newPathMatcher(subs []string) *pathMatcher {
	has := false
	for _, s := range subs {
		if s != "" {
			has = true
			break
		}
	}
	if !has {
		return nil
	}
	m := &pathMatcher{subs: append([]string(nil), subs...)}

	// Byte classes: one per distinct byte used by a pattern.
	nc := 1
	for _, s := range subs {
		for i := 0; i < len(s); i++ {
			if m.class[s[i]] == 0 {
				m.class[s[i]] = uint8(nc) // wraps only at nc==256, replaced below
				nc++
			}
		}
	}
	// Patterns using all 256 byte values leave no room for class 0: give
	// every byte its own class instead.
	if nc > 256 {
		for b := 0; b < 256; b++ {
			m.class[b] = uint8(b)
		}
		nc = 256
	}
	m.nclass = nc

	// Worst case: one state per pattern byte, plus the root.
	states := 1
	for _, s := range subs {
		states += len(s)
	}
	if states*nc > pathMatcherMaxCells {
		m.linear = true
		return m
	}

	// Trie (goto function) with -1 for a missing edge.
	newState := func() int32 {
		for c := 0; c < nc; c++ {
			m.delta = append(m.delta, -1)
		}
		m.minRule = append(m.minRule, -1)
		return int32(len(m.minRule) - 1)
	}
	newState() // root = 0
	for ridx, s := range subs {
		if s == "" {
			continue
		}
		st := int32(0)
		for i := 0; i < len(s); i++ {
			c := int(m.class[s[i]])
			nx := m.delta[int(st)*nc+c]
			if nx < 0 {
				nx = newState()
				m.delta[int(st)*nc+c] = nx
			}
			st = nx
		}
		if m.minRule[st] < 0 || int32(ridx) < m.minRule[st] {
			m.minRule[st] = int32(ridx)
		}
	}

	// BFS: failure links, completed transitions, and min-rule propagation
	// along the failure chain (a state's fail is shallower, so it is final
	// when the state is dequeued).
	fail := make([]int32, len(m.minRule))
	queue := make([]int32, 0, len(m.minRule))
	for c := 0; c < nc; c++ {
		nx := m.delta[c]
		if nx < 0 {
			m.delta[c] = 0
			continue
		}
		fail[nx] = 0
		queue = append(queue, nx)
	}
	for qi := 0; qi < len(queue); qi++ {
		st := queue[qi]
		if f := m.minRule[fail[st]]; f >= 0 && (m.minRule[st] < 0 || f < m.minRule[st]) {
			m.minRule[st] = f
		}
		for c := 0; c < nc; c++ {
			nx := m.delta[int(st)*nc+c]
			fs := m.delta[int(fail[st])*nc+c] // already complete (shallower)
			if nx < 0 {
				m.delta[int(st)*nc+c] = fs
				continue
			}
			fail[nx] = fs
			queue = append(queue, nx)
		}
	}
	return m
}

// first returns the lowest rule index whose pattern occurs in s, or -1.
func (m *pathMatcher) first(s string) int {
	if m == nil {
		return -1
	}
	if m.linear {
		for i, sub := range m.subs {
			if sub != "" && strings.Contains(s, sub) {
				return i
			}
		}
		return -1
	}
	best := int32(-1)
	st := int32(0)
	nc := m.nclass
	for i := 0; i < len(s); i++ {
		st = m.delta[int(st)*nc+int(m.class[s[i]])]
		if r := m.minRule[st]; r >= 0 && (best < 0 || r < best) {
			best = r
			if best == 0 {
				break
			}
		}
	}
	return int(best)
}

// sameSubs reports whether m was compiled from exactly subs (same order).
func (m *pathMatcher) sameSubs(subs []string) bool {
	if m == nil || len(m.subs) != len(subs) {
		return false
	}
	for i := range subs {
		if m.subs[i] != subs[i] {
			return false
		}
	}
	return true
}

// pathMatchOnce lower-cases one request path at most once and remembers the
// answer of the last matcher asked, so the two malpath checks of one ingested
// line share a single scan when they share a matcher.
type pathMatchOnce struct {
	p       string // the path as ingest normalized it (query already cut)
	pl      string
	lowered bool
	m       *pathMatcher
	ridx    int
	// The challenge store's path-exclude answer for this request, asked at
	// most once and only once a malpath rule matched (malpathExcluded).
	exclChecked bool
	excluded    bool
	exclValue   string
}

func (o *pathMatchOnce) first(m *pathMatcher) int {
	if m == nil {
		return -1
	}
	if o.m == m {
		return o.ridx
	}
	if !o.lowered {
		o.pl = strings.ToLower(o.p)
		o.lowered = true
	}
	o.m, o.ridx = m, m.first(o.pl)
	return o.ridx
}
