package apiserver

// UID→username resolution for the LVE per-tenant CPU view. LVE reports each
// tenant by numeric Linux uid; resolving it to the login name answers "WHO is
// this?" — and on cPanel/DirectAdmin the Linux user IS the hosting account, so
// the login name is the account. Resolution lives here (API layer), not in the
// pure lvestat leaf, which must stay side-effect-free (no /etc/passwd reads).
//
// Bounded cost: a short-TTL cache of BOTH hits and misses, so repeated
// /api/v1/system/lve-cpu polls (every ~15s) don't re-read passwd per row, while a
// newly-created account still appears within the TTL.

import (
	"os/user"
	"strconv"
	"sync"
	"time"
)

// lveDefaultUID is CloudLinux's LVE_DEFAULT (0xFFFFFFFF): the aggregate/default
// LVE bucket for everything not inside a specific tenant LVE — NOT a real
// account, so it is labelled rather than looked up (LookupId would just fail).
const lveDefaultUID = 4294967295

// uidLookup resolves a numeric uid to a login name; a package var so tests can
// substitute a fixture without touching the host's /etc/passwd.
var uidLookup = func(uid int64) (string, bool) {
	u, err := user.LookupId(strconv.FormatInt(uid, 10))
	if err != nil || u == nil || u.Username == "" {
		return "", false
	}
	return u.Username, true
}

const uidCacheTTL = 5 * time.Minute

var (
	uidCacheMu sync.Mutex
	uidCache   = map[int64]uidCacheEntry{}
)

type uidCacheEntry struct {
	name string
	exp  time.Time
}

// resolveLVEUsername maps an LVE uid to its login/account name, cached. Returns
// a label for the default/aggregate LVE and "" for a uid with no passwd entry
// (the caller shows the bare uid then). now is passed in so the cache is
// testable without a real clock.
func resolveLVEUsername(uid int64, now time.Time) string {
	if uid == lveDefaultUID {
		return "(default LVE / outside)"
	}
	uidCacheMu.Lock()
	if e, ok := uidCache[uid]; ok && now.Before(e.exp) {
		name := e.name
		uidCacheMu.Unlock()
		return name
	}
	uidCacheMu.Unlock()

	name, _ := uidLookup(uid) // "" (miss) is cached too, to bound repeated lookups

	uidCacheMu.Lock()
	uidCache[uid] = uidCacheEntry{name: name, exp: now.Add(uidCacheTTL)}
	uidCacheMu.Unlock()
	return name
}
