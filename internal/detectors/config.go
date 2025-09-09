package detectors

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
	"time"
)

type KV = map[string]string

type Sections struct {
	Global  KV
	ByName  map[string]KV // πλήρες όνομα section -> KV
	ByType  map[string][]string // τύπος -> λίστα section names
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

	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// [section]
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			cur = strings.TrimSpace(line[1 : len(line)-1])
			if _, ok := s.ByName[cur]; !ok {
				s.ByName[cur] = make(KV)
			}
			typ, _ := splitTypeInstance(cur)
			s.ByType[typ] = append(s.ByType[typ], cur)
			continue
		}
		// key = value
		if i := strings.Index(line, "="); i > 0 {
			k := strings.ToUpper(strings.TrimSpace(line[:i]))
			v := strings.Trim(strings.TrimSpace(line[i+1:]), `"`)
			s.ByName[cur][k] = v
			if cur == "global" {
				s.Global = s.ByName[cur]
			}
		}
	}
	return s, b, nil
}

func splitTypeInstance(section string) (typ, inst string) {
	// υποστηρίζει "type", "type:inst", 'type inst'
	parts := strings.FieldsFunc(section, func(r rune) bool { return r == ':' || r == ' ' || r == '\t' })
	if len(parts) == 0 { return section, "" }
	typ = parts[0]
	if len(parts) > 1 { inst = strings.Join(parts[1:], " ") }
	return
}

// helpers
func kvBool(kv KV, key string, def bool) bool {
	v, ok := kv[strings.ToUpper(key)]
	if !ok { return def }
	switch strings.ToLower(v) {
	case "1","true","yes","on": return true
	case "0","false","no","off": return false
	}
	return def
}
func kvInt(kv KV, key string, def int) int {
	v, ok := kv[strings.ToUpper(key)]
	if !ok { return def }
	if n, err := strconv.Atoi(v); err == nil { return n }
	return def
}
func kvDur(kv KV, key string, def time.Duration) time.Duration {
	v, ok := kv[strings.ToUpper(key)]
	if !ok || v == "" { return def }
	if d, err := time.ParseDuration(v); err == nil { return d }
	return def
}
func kvStr(kv KV, key, def string) string {
	v, ok := kv[strings.ToUpper(key)]
	if !ok || v == "" { return def }
	return v
}
