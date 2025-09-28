package syslookup

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Map provides CGO-free UID/GID -> name lookups using /etc/passwd and /etc/group.
type Map struct {
	mu         sync.RWMutex
	byUID      map[uint32]string
	byGID      map[uint32]string
	lastReload time.Time
	interval   time.Duration
}

// New returns a Map and performs an initial load.
func New() *Map {
	m := &Map{
		byUID:    make(map[uint32]string),
		byGID:    make(map[uint32]string),
		interval: 5 * time.Minute,
	}
	_ = m.reload()
	return m
}

// User returns the username for uid, or empty string if unknown.
func (m *Map) User(uid uint32) string {
	m.maybeReload()
	m.mu.RLock()
	name := m.byUID[uid]
	m.mu.RUnlock()
	return name
}

// Group returns the group name for gid, or empty string if unknown.
func (m *Map) Group(gid uint32) string {
	m.maybeReload()
	m.mu.RLock()
	name := m.byGID[gid]
	m.mu.RUnlock()
	return name
}

func (m *Map) maybeReload() {
	m.mu.RLock()
	stale := time.Since(m.lastReload) > m.interval
	m.mu.RUnlock()
	if stale {
		_ = m.reload()
	}
}

func (m *Map) reload() error {
	uidMap, _ := readPasswd("/etc/passwd")
	gidMap, _ := readGroup("/etc/group")
	m.mu.Lock()
	m.byUID = uidMap
	m.byGID = gidMap
	m.lastReload = time.Now()
	m.mu.Unlock()
	return nil
}

func readPasswd(path string) (map[uint32]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return map[uint32]string{}, err
	}
	defer f.Close()
	m := make(map[uint32]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		name := parts[0]
		uidStr := parts[2]
		if uid64, err := strconv.ParseUint(uidStr, 10, 32); err == nil {
			m[uint32(uid64)] = name
		}
	}
	return m, nil
}

func readGroup(path string) (map[uint32]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return map[uint32]string{}, err
	}
	defer f.Close()
	m := make(map[uint32]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
        // name:x:gid:members
		name := parts[0]
		gidStr := parts[2]
		if gid64, err := strconv.ParseUint(gidStr, 10, 32); err == nil {
			m[uint32(gid64)] = name
		}
	}
	return m, nil
}
