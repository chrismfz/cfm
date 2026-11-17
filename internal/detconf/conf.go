// Package detconf holds the detectors.conf STRUCTURAL reader: the section /
// key=value parser shared by everyone who must read that file with the exact
// semantics the detector manager uses — CLI drift checks, status views, and
// config-diff tooling — without importing the detectors package itself (which
// reaches back into the API server and therefore cannot be a dependency of
// anything under it).
//
// Multiline continuation support:
//
// A line that:
//   - does not start with [     (not a section header)
//   - is not a real key=value   (candidate before "=" must be a plain identifier)
//   - is not blank / comment
//
// ...is treated as a continuation of the previous key's value.
// Each continuation line is appended with \n so callers can split on \n.
//
// This makes QUERY_RULES = and CONN_RULES = blocks work naturally:
//
//	QUERY_RULES =
//	    mathemat_db : 30s : notify
//	    mathemat_db : 60s : kill_query : lock_fanout=5   ← contains "=" but NOT a key
//	    mathemat_db : 90s : kill_query
//
// The KV map will contain QUERY_RULES → "\nmathemat_db : 30s : notify\n...".
//
// Key=value detection uses isConfigKey() which accepts only letters, digits
// and underscores. Rule lines like "nixpal_stress : max=10 : reap_sleep" have
// a candidate "nixpal_stress : max" (contains spaces and colon) which fails
// the check, so they correctly fall through to continuation handling.
package detconf

import (
	"bufio"
	"bytes"
	"log"
	"os"
	"strings"
	"sync"

	"cfm/internal/secretkeys"
)

type KV = map[string]string

type Sections struct {
	Global  KV
	ByName  map[string]KV
	ByType  map[string][]string
	StampNS int64

	// AppendKeys marks keys written with "+=" in THIS file's parse
	// (section → KEY → true). Within one file "+=" behaves like "=" (plus
	// self-append when the key repeats); its real meaning is for the layer
	// merger: ReadLayered appends a marked overlay value onto the earlier
	// layers' value (list keys join with ", ", multiline blocks with a
	// newline) instead of replacing it. Nil when no "+=" was used.
	AppendKeys map[string]map[string]bool

	// LayerSig identifies the overlay SET a layered read merged: a hash of
	// each overlay's filename, mtime and size, 0 when no overlays were read
	// (plain ReadSections always leaves it 0, preserving layered/plain
	// parity). It is the sole overlay-change signal — StampNS stays the BASE
	// file's mtime so a base edit is never masked — and reload signatures must
	// fold it in, since it is what sees an overlay removed, renamed, or added
	// with an older mtime (mv / cp -p / rsync -a all preserve one).
	LayerSig uint64
}

// ReadSections parses one detectors.conf file. Returns the parsed sections,
// the raw file bytes (callers that want the untouched text), and any IO error.
func ReadSections(path string) (Sections, []byte, error) {
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

		if i := strings.Index(line, "="); i > 0 {
			candidate := strings.TrimSpace(line[:i])
			// "KEY += value" append syntax (overlay layering). Historically a
			// "+=" line fell through to continuation handling — no shipped or
			// fleet config ever used it — so claiming it is safe.
			appendOp := false
			if trimmed := strings.TrimSpace(strings.TrimSuffix(candidate, "+")); strings.HasSuffix(candidate, "+") && isConfigKey(trimmed) {
				candidate, appendOp = trimmed, true
			}
			if isConfigKey(candidate) {
				k := strings.ToUpper(candidate)
				raw := strings.TrimSpace(line[i+1:])
				v := unquoteValue(raw)
				warnSecretReadChanged(k, raw, v)
				if appendOp {
					if prev, ok := s.ByName[cur][k]; ok && prev != "" {
						v = joinAppend(k, prev, v)
					}
					if s.AppendKeys == nil {
						s.AppendKeys = make(map[string]map[string]bool)
					}
					if s.AppendKeys[cur] == nil {
						s.AppendKeys[cur] = make(map[string]bool)
					}
					s.AppendKeys[cur][k] = true
				} else {
					// A later plain "=" reassignment is a REPLACE: it must also
					// clear an earlier "+=" mark, or the merger would append the
					// final value onto the earlier layers' one.
					delete(s.AppendKeys[cur], k)
				}
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

// ReadSectionsFile exposes detectors.conf parsing for external readers.
func ReadSectionsFile(path string) (Sections, error) {
	s, _, err := ReadSections(path)
	return s, err
}

// SplitTypeInstance splits a section name into type + optional instance name
// ("exim_security:secondary" → "exim_security", "secondary").
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

// unquoteValue returns a raw value as the readers should see it. A value in
// double quotes followed only by an inline comment (`KEY = "15m"  ; note`)
// is the text between the quotes. It used to keep the closing quote and the
// comment (`15m"  ; note`), and the string readers (detconf.CleanValue, which
// is quote-aware) took that closing quote as an OPENING one and kept the
// comment as part of the value: `[cfm_endpoints] BLOCK = "15m" ; …`, shipped
// in the stock detectors.conf, read as an unparseable TTL, so that detector
// never banned. Any other value keeps the old reading (surrounding double
// quotes trimmed), so a quoted value with no comment and an unquoted one are
// read exactly as before.
func unquoteValue(raw string) string {
	if len(raw) >= 2 && raw[0] == '"' {
		if j := strings.IndexByte(raw[1:], '"'); j >= 0 {
			rest := strings.TrimSpace(raw[2+j:])
			if rest == "" || rest[0] == ';' || rest[0] == '#' {
				return raw[1 : 1+j]
			}
		}
	}
	return strings.Trim(raw, `"`)
}

// warnedSecretRead: once per key per process (the file is read on every
// reload and by most CLI commands).
var warnedSecretRead sync.Map

// warnSecretReadChanged logs, never the value, when a SECRET key written as
// `KEY = "value" ; comment` now reads differently than it did before
// unquoteValue (which kept the closing quote and the comment). A token that
// changes on upgrade changes what is derived from it (the challenge HMAC key,
// the edge bridge token), so the operator should know why.
func warnSecretReadChanged(key, raw, v string) {
	if !secretkeys.IsSecret(key) || v == strings.Trim(raw, `"`) {
		return
	}
	if _, seen := warnedSecretRead.LoadOrStore(key, true); !seen {
		log.Printf("detconf: warning: %s is written as a quoted value followed by a comment; since 2026-11-17 it reads as the text between the quotes, no longer with the closing quote and comment appended. If that changed the effective secret, move the comment to its own line and check what is derived from it", key)
	}
}
