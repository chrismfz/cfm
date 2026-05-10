package kernsec

import (
	"fmt"
	"path/filepath"
	"strings"
)

// shellMetaUnsafeForCmdline lists the runes that would cause the
// /etc/default/grub line to mean something different on re-parse than
// what we intended. Operators with cmdlines containing any of these
// get a clear error from `apply` rather than a silently-corrupted
// rewrite. The list is conservative: we reject characters our
// minimal escaper cannot round-trip.
//
//	$  shell variable expansion
//	`  command substitution (backtick form)
//	'  single quote — would terminate the wrong context if our
//	   double-quoted output were read by a shell that prefers single
//	   quotes; also unhandled by our parser
//
// Backslash and double-quote ARE allowed; we escape them safely on
// write. Whitespace within a token (kernel-style `module.param="x y"`)
// is harder — we don't try to support it; reject if seen.
var shellMetaUnsafeForCmdline = []string{"$", "`", "'", "$(", "${"}

// GRUBBackend implements BootBackend for legacy GRUB installs
// (Debian/Ubuntu and RHEL non-BLS). Reads GRUB_CMDLINE_LINUX from
// /etc/default/grub; writes the same. Refresh runs the appropriate
// config generator (update-grub / grub2-mkconfig / grub-mkconfig).
type GRUBBackend struct {
	FS FS
}

func (g *GRUBBackend) Label() string {
	return "Legacy GRUB"
}

func (g *GRUBBackend) NextBootCmdline() (string, error) {
	if !g.FS.Exists(PathDefaultGrub) {
		return "", nil
	}
	b, err := g.FS.ReadFile(PathDefaultGrub)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "GRUB_CMDLINE_LINUX=") {
			continue
		}
		val := strings.TrimPrefix(t, "GRUB_CMDLINE_LINUX=")
		decoded, err := decodeGrubCmdlineValue(val)
		if err != nil {
			return "", fmt.Errorf("%s: GRUB_CMDLINE_LINUX: %w", PathDefaultGrub, err)
		}
		return decoded, nil
	}
	return "", nil
}

// decodeGrubCmdlineValue reverses grubCmdlineLine for a single
// GRUB_CMDLINE_LINUX assignment value (the right-hand-side of `=`).
// Strips one layer of outer single OR double quotes, then unescapes
// `\"` and `\\` if the outer quotes were double. Rejects values with
// shell metacharacters our writer cannot safely round-trip — the
// operator gets an explicit error pointing at the offending character
// rather than a silently-corrupted rewrite.
func decodeGrubCmdlineValue(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		inner := s[1 : len(s)-1]
		// Inside double quotes: \" → " and \\ → \. Other escapes are
		// shell-specific; if we see one, refuse rather than guess.
		decoded, err := decodeDoubleQuoted(inner)
		if err != nil {
			return "", err
		}
		if err := rejectUnsafeShellMeta(decoded); err != nil {
			return "", err
		}
		return decoded, nil
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		// Single-quoted in shell: no expansion, no escapes. Inner is
		// literal. We still reject shell metachars in the literal so
		// our writer (which uses double quotes) doesn't have to deal
		// with them.
		inner := s[1 : len(s)-1]
		if err := rejectUnsafeShellMeta(inner); err != nil {
			return "", err
		}
		return inner, nil
	}
	// Unquoted (rare in practice). Reject if it contains anything that
	// would mean something to a shell parser — operator likely wrote
	// it that way intentionally and we don't want to mangle it.
	if err := rejectUnsafeShellMeta(s); err != nil {
		return "", err
	}
	return s, nil
}

// decodeDoubleQuoted unescapes a double-quoted shell string body. Only
// `\"` and `\\` are recognised; any other backslash sequence is a
// shell escape we don't support and surfaces as an error.
func decodeDoubleQuoted(s string) (string, error) {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		if i+1 >= len(s) {
			return "", fmt.Errorf("trailing backslash in double-quoted value")
		}
		next := s[i+1]
		switch next {
		case '"', '\\':
			b.WriteByte(next)
			i++
		default:
			return "", fmt.Errorf("unsupported backslash escape \\%c — kernsec cannot safely round-trip this cmdline; edit /etc/default/grub manually",
				next)
		}
	}
	return b.String(), nil
}

// rejectUnsafeShellMeta returns an error if s contains any character
// kernsec's GRUB rewriter cannot safely round-trip. Operator-actionable
// message: tells them which char and where to fix it.
func rejectUnsafeShellMeta(s string) error {
	for _, m := range shellMetaUnsafeForCmdline {
		if strings.Contains(s, m) {
			return fmt.Errorf("kernel cmdline contains shell metacharacter %q — kernsec cannot safely round-trip this through GRUB_CMDLINE_LINUX; edit /etc/default/grub manually and re-run apply",
				m)
		}
	}
	return nil
}

// encodeGrubCmdlineValue is the inverse of decodeGrubCmdlineValue:
// returns the right-hand-side of a GRUB_CMDLINE_LINUX= assignment
// for the given inner kernel-cmdline string. Always emits double-
// quoted form with `\` and `"` escaped. Refuses to encode strings
// with unsafe shell metacharacters (same set as the read side) so
// the writer never produces output it can't read back.
func encodeGrubCmdlineValue(inner string) (string, error) {
	if err := rejectUnsafeShellMeta(inner); err != nil {
		return "", err
	}
	escaped := strings.ReplaceAll(inner, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`, nil
}

// WriteCmdline rewrites GRUB_CMDLINE_LINUX in /etc/default/grub with
// the managed-keys workflow. Mirrors kspp.sh apply_boot_args_grub +
// set_grub_cmdline.
//
// Returns an explicit error if the current cmdline value contains
// shell metacharacters our minimal escaper cannot safely round-trip
// (`$`, backtick, single quote, unsupported `\` escapes). Operators
// with such cmdlines see a clear "edit /etc/default/grub manually"
// message rather than a silently-corrupted rewrite.
func (g *GRUBBackend) WriteCmdline(args []BootArg) error {
	if !g.FS.Exists(PathDefaultGrub) {
		return fmt.Errorf("%s not found", PathDefaultGrub)
	}
	b, err := g.FS.ReadFile(PathDefaultGrub)
	if err != nil {
		return err
	}
	current, err := g.NextBootCmdline()
	if err != nil {
		// Surface the read failure rather than silently treating
		// "couldn't read" as "empty cmdline" — that path leads to
		// writing a cmdline containing only managed args (i.e.
		// dropping root=, ro, console=, etc).
		return fmt.Errorf("read current cmdline: %w", err)
	}
	tokens := rebuildManagedCmdline(ParseCmdline(current), args)
	newLine := strings.Join(tokens, " ")
	encoded, err := encodeGrubCmdlineValue(newLine)
	if err != nil {
		return fmt.Errorf("encode GRUB_CMDLINE_LINUX: %w", err)
	}

	out, found := rewriteGrubCmdlineLinux(string(b), encoded)
	if !found {
		out += "\n" + grubCmdlineLineEncoded(encoded) + "\n"
	}

	if err := BackupOnce(PathDefaultGrub, PathDefaultGrub+BackupSuffix); err != nil {
		return err
	}
	return AtomicWriteFile(PathDefaultGrub, []byte(out), 0o644)
}

// Refresh tries update-grub first (Debian/Ubuntu wrapper), then
// grub2-mkconfig / grub-mkconfig with the right output path. Mirrors
// kspp.sh update_grub_cfg.
func (g *GRUBBackend) Refresh() error {
	if g.FS.LookPath("update-grub") {
		if out, err := g.FS.RunCapture("update-grub"); err != nil {
			return fmt.Errorf("update-grub: %v: %s", err, strings.TrimSpace(out))
		}
		return nil
	}
	cfg := g.findGrubCfgPath()
	if cfg == "" {
		return fmt.Errorf("could not determine GRUB config output path")
	}
	for _, name := range []string{"grub2-mkconfig", "grub-mkconfig"} {
		if !g.FS.LookPath(name) {
			continue
		}
		if out, err := g.FS.RunCapture(name, "-o", cfg); err != nil {
			return fmt.Errorf("%s -o %s: %v: %s", name, cfg, err, strings.TrimSpace(out))
		}
		return nil
	}
	return fmt.Errorf("no GRUB config generator found (update-grub / grub2-mkconfig / grub-mkconfig)")
}

// findGrubCfgPath picks the most plausible grub.cfg output path.
// Mirrors kspp.sh update_grub_cfg fallback chain.
func (g *GRUBBackend) findGrubCfgPath() string {
	if g.FS.Exists(PathGrub2Cfg) || g.FS.IsDir("/boot/grub2") {
		return PathGrub2Cfg
	}
	if g.FS.Exists(PathGrubCfg) || g.FS.IsDir("/boot/grub") {
		return PathGrubCfg
	}
	// EFI fallback: /boot/efi/EFI/<distro>/grub.cfg
	candidates, _ := filepath.Glob(filepath.Join(PathEFIGrubGlob, "*", "grub.cfg"))
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

// rewriteGrubCmdlineLinux replaces the GRUB_CMDLINE_LINUX assignment in
// content with `GRUB_CMDLINE_LINUX=<encodedValue>`, preserving every
// other line as-is. encodedValue is expected to come from
// encodeGrubCmdlineValue (i.e. already shell-quoted with embedded
// `"`/`\` escaped). Returns the rewritten content and whether the
// assignment was found.
func rewriteGrubCmdlineLinux(content, encodedValue string) (string, bool) {
	lines := strings.Split(content, "\n")
	found := false
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "GRUB_CMDLINE_LINUX=") {
			lines[i] = grubCmdlineLineEncoded(encodedValue)
			found = true
		}
	}
	return strings.Join(lines, "\n"), found
}

// grubCmdlineLineEncoded composes a complete GRUB_CMDLINE_LINUX=...
// shell assignment given an already-encoded value (output of
// encodeGrubCmdlineValue).
func grubCmdlineLineEncoded(encodedValue string) string {
	return "GRUB_CMDLINE_LINUX=" + encodedValue
}

// grubCmdlineLine is a convenience wrapper that encodes inner first.
// Tests use it for asserting end-to-end output. Production callers
// should call encodeGrubCmdlineValue + grubCmdlineLineEncoded so they
// can react to the encode error explicitly.
func grubCmdlineLine(inner string) string {
	v, err := encodeGrubCmdlineValue(inner)
	if err != nil {
		return "GRUB_CMDLINE_LINUX=" + `"` + inner + `"` // best effort; caller saw error elsewhere
	}
	return grubCmdlineLineEncoded(v)
}
