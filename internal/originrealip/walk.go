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
	file     string
	name     string // lower-cased directive name
	args     []string
	scoped   bool
	server   int  // nginx: index into walker.servers of the server{} it is in, -1 at http level
	location bool // nginx: inside a location{} (not counted for the site)
}

// nginxServer is one server{} block as nginx loads it: its names and the
// directories of the files it includes (cPanel's server-includes/ is the one
// that reaches every site block).
type nginxServer struct {
	names       []string
	includeDirs []string // rooted
	listens     []string // each listen's address argument ("80", "[::]:443", "unix:/x")
}

// listenPort is a listen address's port: "80", "*:443", "[::]:80",
// "127.0.0.1:8090"; an address with no port listens on 80, as in nginx.
func listenPort(l string) string {
	if strings.HasSuffix(l, "]") { // "[::1]": an IPv6 address alone
		return "80"
	}
	if i := strings.LastIndex(l, ":"); i >= 0 {
		return l[i+1:]
	}
	for _, c := range l {
		if c < '0' || c > '9' {
			return "80" // "localhost", "10.0.0.1": an address alone
		}
	}
	return l
}

// edgeFacing reports whether the edge can reach this server{}: it proxies to
// the origin's :80 and :443 only. No listen is nginx's default, *:80.
func (s nginxServer) edgeFacing() bool {
	if len(s.listens) == 0 {
		return true
	}
	for _, l := range s.listens {
		if strings.HasPrefix(l, "unix:") {
			continue
		}
		if listenPort(l) == "80" || listenPort(l) == "443" {
			return true
		}
	}
	return false
}

// Walk limits: deeper include chains, more files or more inclusions than any
// panel generates mean a loop or a pathological config, and the probe stops
// there. A file is read once but walked at every place it is included: nginx
// applies a server-level file (cPanel's cloudflare.conf) to each server{} that
// includes it, so the walk has to see it in each (earth: ~2 000 blocks).
const (
	walkMaxDepth    = 16
	walkMaxFiles    = 20000
	walkMaxIncludes = 200000
)

type confFile struct {
	b  []byte
	ok bool
}

type walker struct {
	l        layout
	cache    map[string]confFile
	active   map[string]bool // the include chain being walked (a loop guard)
	files    int
	includes int
	out      []directive
	want     map[string]bool
	servers  []nginxServer
	cur      int // nginx: the server{} being walked, -1 outside one
	// truncated: a walk limit refused a file, so the verdict reads a part
	// of the configuration only.
	truncated bool
	// reinclude: walk a file at every place it is included (nginx, where a
	// server-level file applies to each server{} that includes it). Apache's
	// verdict is server-level only, so its walk reads each file once.
	reinclude bool
}

func newWalker(l layout, names ...string) *walker {
	w := &walker{l: l, cache: map[string]confFile{}, active: map[string]bool{}, want: map[string]bool{}, cur: -1}
	for _, n := range names {
		w.want[n] = true
	}
	return w
}

// enter reads one config file (rooted path), size-capped and read once per
// walk, for one inclusion of it. A file already on the include chain (a loop)
// is refused. Every successful enter is paired with leave.
func (w *walker) enter(path string) ([]byte, bool) {
	if w.active[path] {
		return nil, false
	}
	if w.includes >= walkMaxIncludes {
		w.truncated = true
		return nil, false
	}
	cf, cached := w.cache[path]
	if cached && !w.reinclude {
		return nil, false
	}
	if !cached {
		if w.files >= walkMaxFiles {
			w.truncated = true
			return nil, false
		}
		w.files++
		cf = readConfFile(path)
		w.cache[path] = cf
	}
	if !cf.ok {
		return nil, false
	}
	w.includes++
	w.active[path] = true
	return cf.b, true
}

func (w *walker) leave(path string) { delete(w.active, path) }

func readConfFile(path string) confFile {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > grepMaxBytes {
		return confFile{}
	}
	b, err := os.ReadFile(path) // #nosec G304 -- web-server config paths
	if err != nil {
		return confFile{}
	}
	return confFile{b: b, ok: true}
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
func (l layout) apacheDirectives(main, serverRoot string, names ...string) ([]directive, bool) {
	w := newWalker(l, names...)
	root := serverRoot
	w.apacheFile(l.fs(main), &root, false, 0)
	return w.out, w.truncated
}

func (w *walker) apacheFile(path string, serverRoot *string, inVhost bool, depth int) {
	if depth > walkMaxDepth {
		w.truncated = true
		return
	}
	b, ok := w.enter(path)
	if !ok {
		return
	}
	defer w.leave(path)
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
			w.out = append(w.out, directive{file: path, name: name, args: unquote(f[1:]), scoped: inVhost, server: -1})
		}
	}
}

// ── nginx ───────────────────────────────────────────────────────────────────

// nginxDirectives walks nginx.conf through its include chain, tracking the block
// each statement is in. Statements inside a server{} (or location{}) block are
// marked scoped, with the server{} they belong to; anything under stream{} /
// mail{} is not the HTTP origin and is dropped. It also returns every http
// server{} block.
func (l layout) nginxDirectives(main, prefix string, names ...string) ([]directive, []nginxServer, bool) {
	w := newWalker(l, append(names, "server_name")...)
	w.reinclude = true
	w.nginxFile(l.fs(main), prefix, nil, 0)
	asked := map[string]bool{}
	for _, n := range names {
		asked[n] = true
	}
	var out []directive
	for _, d := range w.out {
		if d.name == "server_name" && d.server >= 0 && !d.location {
			w.servers[d.server].names = append(w.servers[d.server].names, d.args...)
		}
		if asked[d.name] {
			out = append(out, d)
		}
	}
	return out, w.servers, w.truncated
}

func inLocation(stack []string) bool {
	for _, b := range stack {
		if b == "location" {
			return true
		}
	}
	return false
}

func nonHTTP(stack []string) bool {
	for _, b := range stack {
		if b == "stream" || b == "mail" {
			return true
		}
	}
	return false
}

func (w *walker) nginxFile(path, prefix string, stack []string, depth int) {
	if depth > walkMaxDepth {
		w.truncated = true
		return
	}
	b, ok := w.enter(path)
	if !ok {
		return
	}
	defer w.leave(path)
	// Tokenized the way nginx's ngx_conf_read_token does: inside '...' or
	// "..." (with backslash escapes) nothing is syntax, `${var}` belongs to
	// its token, and `#` starts a comment only at the start of a token. A
	// quoted regex with a quantifier (`location ~ "^/(\d{4})/"`) used to
	// open and close blocks here, and the server{} the following directives
	// were attributed to drifted.
	var stmt strings.Builder
	inComment, escaped, varBrace := false, false, false
	var quote rune
	lastSpace := true
	var prev rune
	for _, c := range string(b) {
		switch {
		case inComment:
			if c == '\n' {
				inComment = false
				lastSpace = true
			}
			continue
		case quote != 0:
			stmt.WriteRune(c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == quote:
				quote = 0
			}
		case varBrace:
			stmt.WriteRune(c)
			if c == '}' {
				varBrace = false
			}
		case c == '#' && lastSpace:
			inComment = true
		case (c == '"' || c == '\'') && lastSpace:
			quote = c
			stmt.WriteRune(c)
		case c == '{' && prev == '$':
			varBrace = true
			stmt.WriteRune(c)
		case c == ';':
			w.nginxStatement(path, prefix, stack, strings.Fields(stmt.String()), depth)
			stmt.Reset()
		case c == '{':
			f := strings.Fields(stmt.String())
			name := ""
			if len(f) > 0 {
				name = strings.ToLower(f[0])
			}
			if name == "server" && !nonHTTP(stack) {
				w.servers = append(w.servers, nginxServer{})
				w.cur = len(w.servers) - 1
			}
			stack = append(append([]string(nil), stack...), name)
			stmt.Reset()
		case c == '}':
			if len(stack) > 0 {
				if stack[len(stack)-1] == "server" && !nonHTTP(stack) {
					w.cur = -1
				}
				stack = stack[:len(stack)-1]
			}
			stmt.Reset()
		default:
			stmt.WriteRune(c)
		}
		lastSpace = c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ';' || c == '{' || c == '}'
		prev = c
	}
}

func (w *walker) nginxStatement(path, prefix string, stack, f []string, depth int) {
	if len(f) == 0 || nonHTTP(stack) {
		return
	}
	name := strings.ToLower(f[0])
	if name == "listen" && len(f) > 1 && w.cur >= 0 && !inLocation(stack) {
		s := &w.servers[w.cur]
		s.listens = append(s.listens, strings.Trim(f[1], `"'`))
		return
	}
	if name == "include" && len(f) > 1 {
		if w.cur >= 0 && !inLocation(stack) {
			pat := strings.Trim(f[1], `"'`)
			if !filepath.IsAbs(pat) {
				pat = filepath.Join(prefix, pat)
			}
			s := &w.servers[w.cur]
			s.includeDirs = append(s.includeDirs, filepath.Dir(w.l.fs(pat)))
		}
		for _, inc := range w.expand(f[1], prefix) {
			w.nginxFile(inc, prefix, stack, depth+1)
		}
		return
	}
	if !w.want[name] {
		return
	}
	scoped, loc := false, false
	for _, b := range stack {
		switch b {
		case "server":
			scoped = true
		case "location":
			scoped, loc = true, true
		}
	}
	srv := -1
	if scoped {
		srv = w.cur
	}
	w.out = append(w.out, directive{file: path, name: name, args: unquote(f[1:]), scoped: scoped, server: srv, location: loc})
}

func unquote(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = strings.Trim(a, `"'`)
	}
	return out
}
