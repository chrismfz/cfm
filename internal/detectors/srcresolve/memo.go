package srcresolve

// memo.go — MemoProbes wraps a Probes set so every distinct probe question is
// asked at most once per wrapper lifetime. Registers resolve one section each
// and don't need it; the dry-run source REPORT resolves every section in one
// pass, and without memoization each section would re-exec the same
// host-global probes (docker ps, journalctl for the same units) — on a wedged
// docker/systemd that multiplies 3s timeouts into a stalled admin request.
// Not safe for reuse across runs (host state changes); build one per report.

import "sync"

// MemoProbes returns p with every probe memoized by its argument. The zero
// probes stay nil (callers already treat nil as "unavailable").
func MemoProbes(p Probes) Probes {
	var mu sync.Mutex
	boolMemo := func(fn func(string) bool) func(string) bool {
		if fn == nil {
			return nil
		}
		cache := map[string]bool{}
		return func(k string) bool {
			mu.Lock()
			defer mu.Unlock()
			if v, ok := cache[k]; ok {
				return v
			}
			v := fn(k)
			cache[k] = v
			return v
		}
	}
	strMemo := func(fn func(string) string) func(string) string {
		if fn == nil {
			return nil
		}
		cache := map[string]string{}
		return func(k string) string {
			mu.Lock()
			defer mu.Unlock()
			if v, ok := cache[k]; ok {
				return v
			}
			v := fn(k)
			cache[k] = v
			return v
		}
	}

	out := Probes{
		JournalHasEntries: boolMemo(p.JournalHasEntries),
		UnitActive:        boolMemo(p.UnitActive),
		CanonicalUnit:     strMemo(p.CanonicalUnit),
		FileExists:        boolMemo(p.FileExists),
	}
	if p.JournalMatches != nil {
		cache := map[[2]string]bool{}
		fn := p.JournalMatches
		out.JournalMatches = func(unit, sig string) bool {
			mu.Lock()
			defer mu.Unlock()
			k := [2]string{unit, sig}
			if v, ok := cache[k]; ok {
				return v
			}
			v := fn(unit, sig)
			cache[k] = v
			return v
		}
	}
	if p.JournalReadable != nil {
		var done bool
		var val bool
		fn := p.JournalReadable
		out.JournalReadable = func() bool {
			mu.Lock()
			defer mu.Unlock()
			if !done {
				val, done = fn(), true
			}
			return val
		}
	}
	if p.ListContainers != nil {
		var done bool
		var val []string
		fn := p.ListContainers
		out.ListContainers = func() []string {
			mu.Lock()
			defer mu.Unlock()
			if !done {
				val, done = fn(), true
			}
			return val
		}
	}
	return out
}
