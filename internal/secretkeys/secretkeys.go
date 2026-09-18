// Package secretkeys centralises the heuristic for "does this config key NAME
// hold a secret value that must be redacted before it is displayed or exported?"
//
// Single source of truth on purpose: the CLI debug bundle (`cfm debug`, which
// sanitises cfm.conf-style text) and the read-only MCP surface (which redacts
// the parsed detectors.conf before returning it) must not drift apart on what
// counts as a secret — a divergence there is how a token leaks out of one path
// after the other was hardened. CLAUDE.md §5: never keep a second copy of a
// matcher that can drift.
package secretkeys

import "regexp"

// re matches config key names that hold secrets (case-insensitive, substring):
// token, secret, password, hmac, api_key/apikey, private_key/privatekey. It is
// deliberately BROAD / fail-safe — over-matching a non-secret is safe (it just
// gets redacted), under-matching leaks a credential. A caller that must keep a
// specific non-secret key visible even though its name matches (e.g. a numeric
// threshold called TOKEN_IP) applies its own small allowlist on top; it must
// never loosen this pattern.
var re = regexp.MustCompile(`(?i)(token|secret|password|hmac|api_?key|private_?key)`)

// IsSecret reports whether a config key name looks like it holds a secret value.
func IsSecret(key string) bool { return re.MatchString(key) }
