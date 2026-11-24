package webdetector

// Persistence of the traffic mix (traffic_mix.go) across a daemon restart.
//
// The mix is an in-memory 24 h ring, so every restart (an upgrade, a config
// change that restarts, `systemctl reload cfm`, which ends the daemon) emptied
// the Web Traffic page and the 24 h it explains. The ring is saved every few
// minutes and on shutdown (cmd/cfm's signal handler, next to the TTL bans) to
// TrafficMixPath, gzipped JSON, and loaded once at startup: buckets older than
// 24 h are dropped, and a bucket the daemon already counted into since its
// start is ADDED to (the saved counts are requests before the stop, the live
// ones after it: no request is counted twice). The per-IP behaviour state
// (10 minutes) is not saved: a restarted daemon re-learns it, as before.
//
// Reporting data only: a missing, unreadable or foreign file starts the ring
// empty, never fails the daemon.

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// TrafficMixPath is where the daemon persists the mix. A var so tests point
// it at a temp dir (they call the *To / *From variants with their own path;
// nothing in the test suite writes the default).
var TrafficMixPath = "/var/lib/cfm/traffic_mix.json.gz"

// TrafficMixSaveEvery is the periodic save interval: what a crash (no
// shutdown save) can lose.
const TrafficMixSaveEvery = 5 * time.Minute

const tmFileVersion = 1

// tmFileMaxBytes bounds what a load decompresses (the ring's worst case is
// tens of MB of JSON; a file far past it is not ours).
const tmFileMaxBytes = 512 << 20

type tmFile struct {
	Version int            `json:"version"`
	SavedAt time.Time      `json:"saved_at"`
	Buckets []tmFileBucket `json:"buckets"`
	Minutes []tmFileMinute `json:"minutes"`
}

type tmFileBucket struct {
	ID      int64                              `json:"id"`
	Compact bool                               `json:"compact,omitempty"`
	C       [tmClasses]tmCounters              `json:"c"`
	Hosts   map[string][tmClasses]tmSmall      `json:"hosts,omitempty"`
	Clients [tmClasses]map[string]tmFileClient `json:"clients"`
}

type tmFileClient struct {
	tmSmall
	IPs map[string]int64 `json:"ips,omitempty"`
}

type tmFileMinute struct {
	ID  int64            `json:"id"`
	Req [tmClasses]int64 `json:"req"`
}

// snapshotFile copies the live buckets and minutes of the last 24 h. It takes
// the lock per bucket (observe needs it on every request), like Snapshot.
func (s *trafficMixStore) snapshotFile(now time.Time) tmFile {
	f := tmFile{Version: tmFileVersion, SavedAt: now.UTC()}
	nowB := now.Unix() / tmBucketSec
	for i := range s.buckets {
		s.mu.Lock()
		b := &s.buckets[i]
		if b.id == 0 || b.id <= nowB-tmBuckets || b.id > nowB {
			s.mu.Unlock()
			continue
		}
		fb := tmFileBucket{ID: b.id, Compact: b.compact, C: b.c, Hosts: make(map[string][tmClasses]tmSmall, len(b.hosts))}
		for k, v := range b.hosts {
			fb.Hosts[k] = *v
		}
		for c := 0; c < tmClasses; c++ {
			if len(b.clients[c]) == 0 {
				continue
			}
			fb.Clients[c] = make(map[string]tmFileClient, len(b.clients[c]))
			for k, cl := range b.clients[c] {
				fc := tmFileClient{tmSmall: cl.tmSmall}
				if len(cl.ips) > 0 {
					fc.IPs = make(map[string]int64, len(cl.ips))
					for ip, n := range cl.ips {
						fc.IPs[ip] = n
					}
				}
				fb.Clients[c][k] = fc
			}
		}
		s.mu.Unlock()
		f.Buckets = append(f.Buckets, fb)
	}
	nowM := now.Unix() / 60
	s.mu.Lock()
	for _, m := range s.minutes {
		if m.id == 0 || m.id <= nowM-tmMinutes || m.id > nowM {
			continue
		}
		f.Minutes = append(f.Minutes, tmFileMinute{ID: m.id, Req: m.req})
	}
	s.mu.Unlock()
	return f
}

// saveTo writes the mix to path atomically (temp file + rename in its dir).
func (s *trafficMixStore) saveTo(path string, now time.Time) error {
	f := s.snapshotFile(now)
	// No MkdirAll: /var/lib/cfm is the package's (systemd StateDirectory).
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".traffic_mix-*.json.gz")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after the rename
	zw := gzip.NewWriter(tmp)
	if err := json.NewEncoder(zw).Encode(f); err != nil {
		tmp.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil { // client IPs inside: root only
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// loadFrom merges the saved mix at path into the store. A missing file is no
// error (a first start); anything else that is wrong with it is.
func (s *trafficMixStore) loadFrom(path string, now time.Time) (buckets int, err error) {
	fh, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		return 0, fmt.Errorf("traffic mix file: %w", err)
	}
	defer zr.Close()
	var f tmFile
	if err := json.NewDecoder(io.LimitReader(zr, tmFileMaxBytes)).Decode(&f); err != nil {
		return 0, fmt.Errorf("traffic mix file: %w", err)
	}
	if f.Version != tmFileVersion {
		return 0, fmt.Errorf("traffic mix file: version %d, this build reads %d", f.Version, tmFileVersion)
	}
	nowB := now.Unix() / tmBucketSec
	nowM := now.Unix() / 60
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, fb := range f.Buckets {
		if fb.ID <= nowB-tmBuckets || fb.ID > nowB {
			continue // older than the ring, or from a clock that ran ahead
		}
		b := &s.buckets[fb.ID%tmBuckets]
		if b.id > fb.ID {
			continue // the slot holds a newer bucket already
		}
		if b.id != fb.ID {
			*b = tmBucket{id: fb.ID, compact: fb.Compact, hosts: make(map[string]*[tmClasses]tmSmall)}
		}
		mergeFileBucket(b, fb)
		buckets++
	}
	for _, fm := range f.Minutes {
		if fm.ID <= nowM-tmMinutes || fm.ID > nowM {
			continue
		}
		m := &s.minutes[fm.ID%tmMinutes]
		if m.id > fm.ID {
			continue
		}
		if m.id != fm.ID {
			*m = tmMinute{id: fm.ID}
		}
		for c := 0; c < tmClasses; c++ {
			m.req[c] += fm.Req[c]
		}
	}
	return buckets, nil
}

// mergeFileBucket adds a saved bucket into a live one of the same id, within
// the live store's caps (an entry past a cap goes to "_other", as observe
// would put it). Caller holds s.mu.
func mergeFileBucket(b *tmBucket, fb tmFileBucket) {
	for c := 0; c < tmClasses; c++ {
		b.c[c].add(fb.C[c])
	}
	hostCap := tmMaxHosts
	if b.compact {
		hostCap = tmOldMaxHosts
	}
	for k, v := range fb.Hosts {
		hk := k
		if _, ok := b.hosts[hk]; !ok && len(b.hosts) >= hostCap {
			hk = tmOtherKey
		}
		h := b.hosts[hk]
		if h == nil {
			h = &[tmClasses]tmSmall{}
			b.hosts[hk] = h
		}
		for c := 0; c < tmClasses; c++ {
			h[c].Req += v[c].Req
			h[c].OriginMs += v[c].OriginMs
			h[c].Bytes += v[c].Bytes
		}
	}
	clientCap := tmMaxClients
	if b.compact {
		clientCap = tmOldMaxClients
	}
	for c := 0; c < tmClasses; c++ {
		for k, fc := range fb.Clients[c] {
			cm := b.clients[c]
			if cm == nil {
				cm = make(map[string]*tmClient)
				b.clients[c] = cm
			}
			ck := k
			if _, ok := cm[ck]; !ok && len(cm) >= clientCap {
				ck = tmOtherKey
			}
			cl := cm[ck]
			if cl == nil {
				cl = &tmClient{}
				cm[ck] = cl
			}
			cl.Req += fc.Req
			cl.OriginMs += fc.OriginMs
			cl.Bytes += fc.Bytes
			if len(fc.IPs) > 0 && !b.compact && (c == tmAutomation || c == tmBot) {
				if cl.ips == nil {
					cl.ips = make(map[string]int64)
				}
				for ip, n := range fc.IPs {
					if _, ok := cl.ips[ip]; ok || len(cl.ips) < tmMaxClientIPs {
						cl.ips[ip] += n
					}
				}
			}
		}
	}
}

// LoadTrafficMix restores the saved mix into the daemon's store (startup,
// before the log tailers count anything; a bucket counted meanwhile is merged).
func LoadTrafficMix() (int, error) { return trafficMix.loadFrom(TrafficMixPath, time.Now()) }

// SaveTrafficMix writes the daemon's mix to TrafficMixPath (periodic and
// shutdown saves).
func SaveTrafficMix() error { return trafficMix.saveTo(TrafficMixPath, time.Now()) }
