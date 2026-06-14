package sslcollector

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"

	"github.com/fsnotify/fsnotify"

	"io/fs"
	"os"
)

type Watcher struct {
	col *Collector

	mu        sync.Mutex
	timer     *time.Timer
	delay     time.Duration
	running   bool
	lastExact int
	lastWild  int
	haveLast  bool

	// shallowRoots are watched one level deep only (a single fs.Add per
	// path, no recursion). Used for /home* mount tops and per-user home
	// dirs so that the creation of a NEW user or a NEW ssl/ dir fires a
	// Create event without recursively watching entire home/web trees.
	shallowRoots []string

	fs *fsnotify.Watcher
}

// SetShallowRoots registers directories to be watched one level deep
// (non-recursive). Call before Start. See the Watcher.shallowRoots field.
func (w *Watcher) SetShallowRoots(dirs []string) {
	w.shallowRoots = dirs
}

func NewWatcher(col *Collector, delay time.Duration) (*Watcher, error) {
	if delay <= 0 {
		delay = 2 * time.Second
	}

	fs, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return &Watcher{
		col:   col,
		delay: delay,
		fs:    fs,
	}, nil
}

func (w *Watcher) Start(ctx context.Context, roots []string) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = true
	w.mu.Unlock()

	// add all roots recursively
	for _, root := range roots {
		_ = w.addRecursive(root)
	}

	// Shallow watch points (single fs.Add, no recursion): /home* mount
	// tops and existing per-user home dirs. Watching these one level deep
	// lets us see the creation of a NEW user (under /home*) or a NEW
	// ssl/certs/letsencrypt dir / per-domain dir (under a user's home)
	// and react via handleNewDir — WITHOUT recursively watching entire
	// home trees (public_html, mail, wp-content, ...), which would add an
	// inotify watch per file across every customer site.
	for _, d := range w.shallowRoots {
		_ = w.fs.Add(d)
	}

	go w.loop(ctx)
	if logging.DebugEnabled() {
		logging.Logf("[sslcollector] watcher started roots=%v", roots)
	} else {
		logging.Logf("[sslcollector] watcher started %s", summarizeWatcherRoots(roots))
	}
	return nil
}

var homeSSLRootRE = regexp.MustCompile(`^/home([^/]*)/[^/]+/ssl$`)

func summarizeWatcherRoots(roots []string) string {
	buckets := make([]string, 0, len(roots))
	seen := make(map[string]struct{}, len(roots))

	for _, root := range roots {
		bucket := watcherRootBucket(root)
		if _, ok := seen[bucket]; ok {
			continue
		}
		seen[bucket] = struct{}{}
		buckets = append(buckets, bucket)
	}

	return fmt.Sprintf("roots=[%s] expanded=%d", strings.Join(buckets, " "), len(roots))
}

func watcherRootBucket(root string) string {
	if m := homeSSLRootRE.FindStringSubmatch(root); m != nil {
		return "/home" + m[1]
	}

	switch root {
	case "/etc/letsencrypt", "/var/cpanel/ssl", "/usr/local/directadmin", "/etc/ssl":
		return root
	default:
		return root
	}
}

func (w *Watcher) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			_ = w.fs.Close()
			return

		case ev, ok := <-w.fs.Events:
			if !ok {
				return
			}

			// New-directory creation MUST be handled before the
			// isRelevant() name filter. Panels create per-domain and
			// per-user directories named after the domain/user (e.g.
			// /etc/letsencrypt/live/<domain>, /var/cpanel/ssl/apache_tls/
			// <domain>, /home/<user>) whose paths contain none of the
			// cert/key/pem substrings isRelevant() looks for. Dropping
			// them here meant the directory was never added to the watch,
			// the cert files written inside generated no events (fsnotify
			// is not recursive), and the new domain stayed invisible until
			// the next full DiscoveryEvery rescan — up to hours. See
			// handleNewDir for the per-directory watch/rescan decision.
			if ev.Op&fsnotify.Create != 0 {
				if fi, err := os.Stat(ev.Name); err == nil && fi.IsDir() {
					w.handleNewDir(ev.Name)
					continue
				}
			}

			// File events: keep the cheap name filter so unrelated write
			// churn (locks, caches, wp-content, ...) does not trigger a
			// rescan on every tick.
			if !w.isRelevant(ev) {
				continue
			}

			w.trigger("fsnotify:" + ev.Name)

		case err := <-w.fs.Errors:
			logging.Logf("[sslcollector] watcher error: %v", err)
		}
	}
}

func (w *Watcher) trigger(reason string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.timer != nil {
		w.timer.Stop()
	}

	w.timer = time.AfterFunc(w.delay, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		err := w.col.Refresh(ctx)
		if err != nil {
			logging.Logf("[sslcollector] watcher refresh failed reason=%s err=%v", reason, err)
			return
		}

		st := w.col.Stats()
		w.mu.Lock()
		changed := !w.haveLast || st.ExactHosts != w.lastExact || st.WildcardZones != w.lastWild
		w.lastExact = st.ExactHosts
		w.lastWild = st.WildcardZones
		w.haveLast = true
		w.mu.Unlock()

		if changed {
			logging.Logf("[sslcollector] watcher refresh changed reason=%s exact=%d wild=%d files=%d",
				reason, st.ExactHosts, st.WildcardZones, st.KnownFiles)
		}
	})
}

func (w *Watcher) isRelevant(ev fsnotify.Event) bool {
	if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename|fsnotify.Remove) == 0 {
		return false
	}

	name := strings.ToLower(ev.Name)

	// filter obvious noise but keep generic
	if strings.HasSuffix(name, ".tmp") ||
		strings.HasSuffix(name, ".swp") ||
		strings.HasSuffix(name, ".bak") {
		return false
	}

	// positive matches
	if strings.Contains(name, ".cert") ||
		strings.Contains(name, "cert") ||
		strings.Contains(name, ".crt") ||
		strings.Contains(name, ".cer") ||
		strings.Contains(name, ".key") ||
		strings.Contains(name, "key") ||
		strings.Contains(name, "pem") ||
		strings.Contains(name, "privkey") ||
		strings.Contains(name, "fullchain") {
		return true
	}

	// Ignore unrelated file churn (locks, caches, journals, wp-content noise, etc).
	return false
}

// certRootPrefixes are the non-home roots that only ever hold certificate
// material, so any newly-created subdirectory under them is safe to watch
// recursively and to rescan on.
var certRootPrefixes = []string{
	"/etc/letsencrypt",
	"/var/cpanel/ssl",
	"/usr/local/directadmin",
	"/etc/ssl",
}

// homeMountTopRE matches a home mount top: /home, /home2, /home3, ...
var homeMountTopRE = regexp.MustCompile(`^/home[0-9]*$`)

func underCertRoot(path string) bool {
	for _, r := range certRootPrefixes {
		if path == r || strings.HasPrefix(path, r+"/") {
			return true
		}
	}
	return false
}

// isCertDirName reports whether base is a per-user directory that holds
// certificate material across the panels we support
// (cPanel/DirectAdmin/Virtualmin/LE home layouts).
func isCertDirName(base string) bool {
	switch base {
	case "ssl", "certs", "letsencrypt":
		return true
	}
	return false
}

// handleNewDir decides how to watch a newly-created directory and whether
// to schedule a rescan. It is the counterpart to the dir-create fix in
// loop(): every new directory gets an explicit decision here instead of
// being silently dropped by the isRelevant() name filter.
//
// The trigger()ed Refresh runs a full discoverPairs() ~delay later, which
// also closes the race where cert files are written into the directory
// between os.Stat and fs.Add.
func (w *Watcher) handleNewDir(path string) {
	base := filepath.Base(path)
	parentBase := filepath.Base(filepath.Dir(path))

	switch {
	// 1) Pure cert trees (LE/cPanel/DA/...) and per-user cert dirs:
	//    watch fully and rescan.
	case underCertRoot(path) || isCertDirName(base):
		_ = w.addRecursive(path)
		w.trigger("fsnotify:newdir:" + path)

	// 2) Home-layout containers that sit one level above per-domain cert
	//    material: a brand-new user home (under a /home* mount), a user's
	//    "domains" container, or an individual domain dir. Watch SHALLOWLY
	//    so the eventual ssl/ dir or ssl.key/ssl.cert file creation fires
	//    an event, without recursing whole home/web trees (public_html,
	//    wp-content, mail, ...). Rescan too, in case the cert already
	//    landed before we got here.
	case homeMountTopRE.MatchString(filepath.Dir(path)), // new user home
		base == "domains",       // user's domains container
		parentBase == "domains": // an individual domain dir
		_ = w.fs.Add(path)
		w.trigger("fsnotify:newhome:" + path)

	default:
		// Unrelated new dir under a watched home (public_html, mail, ...).
		// Not cert material — do not watch or rescan; doing so would only
		// add inotify pressure and refresh churn.
	}
}

func (w *Watcher) addRecursive(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			_ = w.fs.Add(path)
		}
		return nil
	})
}
