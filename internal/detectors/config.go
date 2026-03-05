// internal/detectors/config.go
// CHANGE: add multiline continuation support to readSections.
//
// A line that:
//   • does not start with [  (not a section header)
//   • does not contain =     (not a key=value pair)
//   • is not blank / comment
// ...is treated as a continuation of the previous key's value.
// Each continuation line is appended with \n so callers can split on \n.
//
// This makes QUERY_RULES = and CONN_RULES = blocks work naturally:
//
//   QUERY_RULES =
//       mathemat_db : 30s : notify
//       mathemat_db : 90s : kill_query
//
// The KV map will contain QUERY_RULES → "\nmathematt_db : 30s : notify\n..."
// Use kvLines(kv, "QUERY_RULES") to get []string of non-empty rule lines.

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

	var lastKey string // track previous key for continuation lines

	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)

		// blank or comment → reset continuation context
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			lastKey = ""
			continue
		}

		// [section] header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			cur = strings.TrimSpace(line[1 : len(line)-1])
			if _, ok := s.ByName[cur]; !ok {
				s.ByName[cur] = make(KV)
			}
			typ, _ := splitTypeInstance(cur)
			s.ByType[typ] = append(s.ByType[typ], cur)
			lastKey = "" // new section resets context
			continue
		}

		// key = value
		if i := strings.Index(line, "="); i > 0 {
			k := strings.ToUpper(strings.TrimSpace(line[:i]))
			v := strings.Trim(strings.TrimSpace(line[i+1:]), `"`)
			s.ByName[cur][k] = v
			lastKey = k
			if cur == "global" {
				s.Global = s.ByName[cur]
			}
			continue
		}

		// No = sign and not a header → continuation of the previous key.
		// Only treat as continuation if we have a lastKey in the current section.
		if lastKey != "" {
			existing := s.ByName[cur][lastKey]
			s.ByName[cur][lastKey] = existing + "\n" + line
			if cur == "global" {
				s.Global = s.ByName[cur]
			}
		}
		// (If lastKey == "" and no = sign: unknown syntax, silently skip.)
	}
	return s, b, nil
}

// kvLines splits a multiline KV value (joined with \n) into individual
// non-empty, comment-stripped lines. Use for QUERY_RULES / CONN_RULES blocks.
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
