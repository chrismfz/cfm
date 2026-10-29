package originrealip

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// directive is one configuration statement the probe cares about, in load
// order, with whether it sits inside a <VirtualHost> / server{} block (where it
// applies to that site only, and a list there REPLACES the global one).
type directive struct {
	file   string
	name   string // lower-cased directive name
	args   []string
	scoped bool
}

// Walk limits: deeper include chains or more files than any panel generates
// mean a loop or a pathological config, and the probe stops there.
const (
	walkMaxDepth = 16
	walkMaxFiles = 20000
)

type walker struct {
	l     layout
	seen  map[string]bool
	files int
	out   []directive
	want  map[string]bool
}

func newWalker(l layout, names ...string) *walker {
	w := &walker{l: l, seen: map[string]bool{}, want: map[string]bool{}}
	for _, n := range names {
		w.want[n] = true
	}
	return w
}

// readConf reads one config file (rooted path), size-capped, once per walk.
func (w *walker) readConf(path string) ([]byte, bool) {
	if w.seen[path] || w.files >= walkMaxFiles {
		return nil, false
	}
	w.seen[path] = true
	w.files++
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > grepMaxBytes {
		return nil, false
	}
	b, err := os.ReadFile(path) // #nosec G304 -- web-server config paths
	if err != nil {
		return nil, false
	}
	return b, true
}

// expand resolves an include pattern (logical path, relative to base when not
// absolute) to the rooted files it loads, sorted as both servers load them. A
// directory loads every file in it (Apache).
func (w *walker) expand(pattern, base string) []string {
	pattern = strings.Trim(strings.TrimSpace(pattern), `"'`)
	if pattern == "" {
		return nil
	}
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(base, pattern)
	}
	rooted := w.l.fs(pattern)
	if fi, err := os.Stat(rooted); err == nil && fi.IsDir() {
		rooted = filepath.Join(rooted, "*")
	}
	m, _ := filepath.Glob(rooted)
	sort.Strings(m)
	return m
}

// ── Apache ──────────────────────────────────────────────────────────────────

// apacheDirectives walks an Apache main config through its Include /
// IncludeOptional chain, the way Apache loads it. Directives inside a
// <VirtualHost> are marked scoped.
func (l layout) apacheDirectives(main, serverRoot string, names ...string) []directive {
	w := newWalker(l, names...)
	root := serverRoot
	w.apacheFile(l.fs(main), &root, false, 0)
	return w.out
}

func (w *walker) apacheFile(path string, serverRoot *string, inVhost bool, depth int) {
	if depth > walkMaxDepth {
		return
	}
	b, ok := w.readConf(path)
	if !ok {
		return
	}
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "<virtualhost"):
			inVhost = true
			continue
		case strings.HasPrefix(lower, "</virtualhost"):
			inVhost = false
			continue
		}
		f := strings.Fields(line)
		name := strings.ToLower(f[0])
		switch name {
		case "serverroot":
			if len(f) > 1 && !inVhost {
				*serverRoot = strings.Trim(f[1], `"'`)
			}
		case "include", "includeoptional":
			if len(f) > 1 {
				for _, inc := range w.expand(strings.Join(f[1:], " "), *serverRoot) {
					w.apacheFile(inc, serverRoot, inVhost, depth+1)
				}
			}
		}
		if w.want[name] {
			w.out = append(w.out, directive{file: path, name: name, args: unquote(f[1:]), scoped: inVhost})
		}
	}
}

// ── nginx ───────────────────────────────────────────────────────────────────

// nginxDirectives walks nginx.conf through its include chain, tracking the block
// each statement is in. Statements inside a server{} (or location{}) block are
// marked scoped; anything under stream{} / mail{} is not the HTTP origin and is
// dropped.
func (l layout) nginxDirectives(main, prefix string, names ...string) []directive {
	w := newWalker(l, names...)
	w.nginxFile(l.fs(main), prefix, nil, 0)
	return w.out
}

func (w *walker) nginxFile(path, prefix string, stack []string, depth int) {
	if depth > walkMaxDepth {
		return
	}
	b, ok := w.readConf(path)
	if !ok {
		return
	}
	var stmt strings.Builder
	inComment := false
	for _, c := range string(b) {
		switch {
		case inComment:
			if c == '\n' {
				inComment = false
			}
		case c == '#':
			inComment = true
		case c == ';':
			w.nginxStatement(path, prefix, stack, strings.Fields(stmt.String()), depth)
			stmt.Reset()
		case c == '{':
			f := strings.Fields(stmt.String())
			name := ""
			if len(f) > 0 {
				name = strings.ToLower(f[0])
			}
			stack = append(append([]string(nil), stack...), name)
			stmt.Reset()
		case c == '}':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			stmt.Reset()
		default:
			stmt.WriteRune(c)
		}
	}
}

func (w *walker) nginxStatement(path, prefix string, stack, f []string, depth int) {
	if len(f) == 0 {
		return
	}
	for _, b := range stack {
		if b == "stream" || b == "mail" {
			return
		}
	}
	name := strings.ToLower(f[0])
	if name == "include" && len(f) > 1 {
		for _, inc := range w.expand(f[1], prefix) {
			w.nginxFile(inc, prefix, stack, depth+1)
		}
		return
	}
	if !w.want[name] {
		return
	}
	scoped := false
	for _, b := range stack {
		if b == "server" || b == "location" {
			scoped = true
		}
	}
	w.out = append(w.out, directive{file: path, name: name, args: unquote(f[1:]), scoped: scoped})
}

func unquote(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = strings.Trim(a, `"'`)
	}
	return out
}
