// internal/detectors/config.go
//
// Multiline continuation support for readSections.
//
// A line that:
//   • does not start with [     (not a section header)
//   • is not a real key=value   (candidate before "=" must be a plain identifier)
//   • is not blank / comment
// ...is treated as a continuation of the previous key's value.
// Each continuation line is appended with \n so callers can split on \n.
//
// This makes QUERY_RULES = and CONN_RULES = blocks work naturally:
//
//   QUERY_RULES =
//       mathemat_db : 30s : notify
//       mathemat_db : 60s : kill_query : lock_fanout=5   ← contains "=" but NOT a key
//       mathemat_db : 90s : kill_query
//
//   CONN_RULES =
//       nixpal_stress   : max=10  : reap_sleep            ← contains "=" but NOT a key
//       mathemat_db     : max=80  : alter_user
//       *               : max=25  : reap_sleep : conn_pct=70
//
// The KV map will contain QUERY_RULES → "\nmathematt_db : 30s : notify\n..."
// Use kvLines(kv, "QUERY_RULES") to get []string of non-empty rule lines.
//
// Key=value detection uses isConfigKey() which accepts only letters, digits and
// underscores.  Rule lines like "nixpal_stress : max=10 : reap_sleep" have a
// candidate "nixpal_stress : max" (contains spaces and colon) which fails the
// check, so they correctly fall through to continuation handling.

package detectors

import (
	"bufio"
	"bytes"
	"os"
	"strings"
)

type KV = map[string]string

type Sections struct {
	Global  KV
	ByName  map[string]KV
	ByType  map[string][]string
	StampNS int64
}

func readSections(path string) (Sections, []byte, error) {
	var s Sections
	s.ByName = make(map[string]KV)
	s.ByType = make(map[string][]string)

	fi, err := os.Stat(path)
	if err != nil {
		return s, nil, err
	}
	s.StampNS = fi.ModTime().UnixNano()

	b, err := os.ReadFile(path)
	if err != nil {
		return s, nil, err
	}
	cur := "global"
	s.ByName[cur] = make(KV)

	var lastKey string

	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)

		// Blank lines and comments do NOT reset lastKey.
		// This allows multiline blocks (QUERY_RULES, CONN_RULES) to contain
		// blank spacer lines and ; comments between rule entries without
		// breaking the continuation.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// [section] header — always resets continuation context.
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			cur = strings.TrimSpace(line[1 : len(line)-1])
			if _, ok := s.ByName[cur]; !ok {
				s.ByName[cur] = make(KV)
			}
			typ, _ := splitTypeInstance(cur)
			s.ByType[typ] = append(s.ByType[typ], cur)
			lastKey = ""
			continue
		}

		// Real key=value pair — only when the text before "=" is a plain
		// identifier (letters, digits, underscores).
		//
		// Rule lines such as:
		//   nixpal_stress : max=10 : reap_sleep
		//   mathemat_db   : 60s   : kill_query : lock_fanout=5
		//   *             : max=25 : reap_sleep : conn_pct=70
		// all contain "=" but their candidate ("nixpal_stress : max",
		// "mathemat_db   : 60s   : kill_query : lock_fanout", etc.) contains
		// spaces, colons or wildcards — isConfigKey rejects them so they fall
		// through to continuation handling below.
		if i := strings.Index(line, "="); i > 0 {
			candidate := strings.TrimSpace(line[:i])
			if isConfigKey(candidate) {
				k := strings.ToUpper(candidate)
				v := strings.Trim(strings.TrimSpace(line[i+1:]), `"`)
				s.ByName[cur][k] = v
				lastKey = k
				if cur == "global" {
					s.Global = s.ByName[cur]
				}
				continue
			}
			// Has "=" but not a real key → fall through to continuation.
		}

		// Continuation line — append to the current multiline key.
		if lastKey != "" {
			existing := s.ByName[cur][lastKey]
			s.ByName[cur][lastKey] = existing + "\n" + line
			if cur == "global" {
				s.Global = s.ByName[cur]
			}
		}
		// If lastKey == "" and line has no "=" and is not a header:
		// unknown syntax — silently skip.
	}
	return s, b, nil
}

// ReadSectionsFile exposes detectors.conf parsing for CLI diagnostics.
func ReadSectionsFile(path string) (Sections, error) {
	s, _, err := readSections(path)
	return s, err
}

// SplitTypeInstance splits section name into type + optional instance name.
func SplitTypeInstance(section string) (typ, inst string) {
	return splitTypeInstance(section)
}

// isConfigKey returns true if s is a valid bare config identifier —
// only ASCII letters, digits and underscores are allowed.
//
// This is what distinguishes a real key like CONN_WARN_PCT from the
// left-hand side of a rule line like "nixpal_stress : max" (which
// contains spaces and a colon).
func isConfigKey(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// kvLines splits a multiline KV value (joined with \n) into individual
// non-empty, comment-stripped lines.  Use for QUERY_RULES / CONN_RULES blocks.
func kvLines(kv KV, key string) []string {
	raw, ok := kv[strings.ToUpper(key)]
	if !ok || raw == "" {
		return nil
	}
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(stripInlineComment(line))
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func splitTypeInstance(section string) (typ, inst string) {
	parts := strings.FieldsFunc(section, func(r rune) bool {
		return r == ':' || r == ' ' || r == '\t'
	})
	if len(parts) == 0 {
		return section, ""
	}
	typ = parts[0]
	if len(parts) > 1 {
		inst = strings.Join(parts[1:], " ")
	}
	return
}
