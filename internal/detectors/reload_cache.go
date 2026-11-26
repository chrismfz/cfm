package detectors

import (
	"encoding/binary"
	"hash/fnv"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"cfm/internal/detconf"
)

// The manager polls detectors.conf every 2.5 s, and a poll used to parse the
// whole file and its overlays each time: on a quiet node that read (the
// per-key secret check's regexp most of all) was 6-8 % of the daemon's CPU
// (qualityweb, 2026-11-24). A poll now stats the files first and parses only
// when one moved; the rest of the poll (the tailed logs' inodes, the source
// probes) still runs every tick, so a rotated log is followed as before.
//
// The stamp is also part of the reload signature (cfgSig): a file replaced
// with its mtime kept (rsync -a, cp -p, a rename into place) moves the
// stamp's inode or size, so it is both read and applied. An edit no stat
// shows (same size, mtime and inode) is neither, as before this cache.

// reloadCache is the last successful layered read and the stamp of the files
// it read. Poll goroutine only.
type reloadCache struct {
	ok    bool
	stamp uint64
	secs  Sections
	// files is the stamp the latest poll took (0 when it could not stat
	// the files), for the reload signature.
	files uint64
}

// configFilesStamp hashes what a layered read of path depends on: the base
// file's and every overlay's identity, size and mtime, and the overlay names.
// It fails when a file it names cannot be stat'ed (the caller reads then).
func configFilesStamp(path, dropinDir string) (uint64, error) {
	h := fnv.New64a()
	var b [8]byte
	put := func(st os.FileInfo) {
		binary.LittleEndian.PutUint64(b[:], uint64(st.Size()))
		_, _ = h.Write(b[:])
		binary.LittleEndian.PutUint64(b[:], uint64(st.ModTime().UnixNano()))
		_, _ = h.Write(b[:])
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			binary.LittleEndian.PutUint64(b[:], uint64(sys.Dev))
			_, _ = h.Write(b[:])
			binary.LittleEndian.PutUint64(b[:], uint64(sys.Ino))
			_, _ = h.Write(b[:])
		}
	}
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	put(st)
	names, err := detconf.ListDropins(dropinDir)
	if err != nil {
		return 0, err
	}
	for _, n := range names {
		st, err := os.Stat(filepath.Join(dropinDir, n))
		if err != nil {
			return 0, err
		}
		_, _ = h.Write([]byte(n))
		_, _ = h.Write([]byte{0})
		put(st)
	}
	return h.Sum64(), nil
}

// readForReload is readSectionsForReload behind the stamp: the last read is
// reused (a copy: the poll adds the built-in sections to what it gets) while
// the files' stamp is unchanged. Only a clean read is reused.
func (m *manager) readForReload(path string) (Sections, error, bool) {
	stamp, serr := configFilesStamp(path, detconf.DefaultDropinDir(path))
	c := &m.readCache
	c.files = 0
	if serr == nil {
		c.files = stamp
	}
	if serr == nil && c.ok && c.stamp == stamp {
		return cloneSections(c.secs), nil, false
	}
	secs, err, fallback := readSectionsForReload(path, m.running)
	c.ok = serr == nil && err == nil && !fallback
	if c.ok {
		// The stamp from before the read: a write during it moves the
		// stamp, and the next poll reads again.
		c.stamp, c.secs = stamp, cloneSections(secs)
	}
	return secs, err, fallback
}

// cloneSections copies s deep enough that changes to the copy's maps (the
// poll's built-in sections) never reach s. Global aliases ByName["global"]
// in a read, and does in the copy too.
func cloneSections(s Sections) Sections {
	out := s
	out.Global = cloneKV(s.Global)
	if s.ByName != nil {
		out.ByName = make(map[string]KV, len(s.ByName))
		for k, v := range s.ByName {
			if s.Global != nil && sameKV(v, s.Global) {
				out.ByName[k] = out.Global
				continue
			}
			out.ByName[k] = cloneKV(v)
		}
	}
	if s.ByType != nil {
		out.ByType = make(map[string][]string, len(s.ByType))
		for k, v := range s.ByType {
			out.ByType[k] = append([]string(nil), v...)
		}
	}
	if s.AppendKeys != nil {
		out.AppendKeys = make(map[string]map[string]bool, len(s.AppendKeys))
		for k, v := range s.AppendKeys {
			m := make(map[string]bool, len(v))
			for kk, vv := range v {
				m[kk] = vv
			}
			out.AppendKeys[k] = m
		}
	}
	return out
}

// sameKV reports whether a and b are the same map (not equal contents).
func sameKV(a, b KV) bool {
	return reflect.ValueOf(a).UnsafePointer() == reflect.ValueOf(b).UnsafePointer()
}

func cloneKV(kv KV) KV {
	if kv == nil {
		return nil
	}
	out := make(KV, len(kv))
	for k, v := range kv {
		out[k] = v
	}
	return out
}
