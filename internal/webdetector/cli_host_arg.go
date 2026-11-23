package webdetector

import (
	"fmt"
	"strings"
)

// The ONE check for a `cfm webtop` positional host argument (challenge
// add/remove/status/host/tier/lockdown, attack on|off, site-cache
// get/set/off/remove/purge, the exclude/override value and --scope hosts).
//
// Without it a flag in the host position was taken as the host: on a live node
// `cfm webtop challenge add --help` armed manual challenges for "--help" and
// "www.--help", and `challenge remove -- --help` removed host "--".

// isCLIHelpArg reports whether a positional argument asks for usage.
func isCLIHelpArg(s string) bool {
	switch s {
	case "-h", "--help", "help":
		return true
	}
	return false
}

// cliHostArg checks the positional host argument of a subcommand whose usage
// line is usage. It returns ok=true with the host when arg is a valid hostname.
// On a help request it prints usage and returns ok=false, err=nil (the caller
// returns nil without calling the API); on an invalid host it returns
// ok=false and a usage error. The caller always does:
//
//	host, ok, err := cliHostArg(args[0], usage)
//	if !ok {
//		return err
//	}
func cliHostArg(arg, usage string) (string, bool, error) {
	return cliHostArgGlob(arg, usage, false)
}

// cliHostArgGlob is cliHostArg for an exclude/override host value or a
// --scope host, which the stores match as a glob: '*' and '?' are accepted in
// any label there (scopedExcludeHostAllowed / filepath.Match).
func cliHostArgGlob(arg, usage string, glob bool) (string, bool, error) {
	if isCLIHelpArg(arg) {
		fmt.Println(usage)
		return "", false, nil
	}
	if err := validateCLIHost(arg, glob); err != nil {
		return "", false, fmt.Errorf("invalid host %q: %v\n%s", arg, err, usage)
	}
	return arg, true, nil
}

// validateCLIHost accepts letters, digits, dots and hyphens in dot-separated
// labels (1-63 chars, none starting or ending with a hyphen, 253 chars in
// all), an optional leading "*." wildcard and an optional trailing dot. glob
// also accepts '*' and '?' anywhere in a label.
func validateCLIHost(h string, glob bool) error {
	if h == "" {
		return fmt.Errorf("empty")
	}
	if strings.HasPrefix(h, "-") {
		return fmt.Errorf("looks like a flag (the host comes first)")
	}
	// One trailing dot (an FQDN) is fine: the daemon trims it
	// (normalizeControlHost).
	rest := strings.TrimSuffix(h, ".")
	if !glob {
		rest = strings.TrimPrefix(rest, "*.")
	}
	if rest == "" {
		return fmt.Errorf("no name")
	}
	if len(rest) > 253 {
		return fmt.Errorf("longer than 253 characters")
	}
	for _, label := range strings.Split(rest, ".") {
		if label == "" {
			return fmt.Errorf("empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("label %q longer than 63 characters", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("label %q starts or ends with a hyphen", label)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			case glob && (c == '*' || c == '?'):
			default:
				return fmt.Errorf("character %q not allowed (letters, digits, dots, hyphens, a leading *.)", c)
			}
		}
	}
	return nil
}
