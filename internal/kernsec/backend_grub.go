package kernsec

import (
	"fmt"
	"path/filepath"
	"strings"
)

const tunedParamsToken = "$tuned_params"

// shellMetaUnsafeForCmdline lists shell syntax that would cause the
// /etc/default/grub line to mean something different on re-parse than
// what we intended. Operators with cmdlines containing any of these
// get a clear error from `apply` rather than a silently-corrupted
// rewrite. The list is conservative: we reject characters our
// minimal escaper cannot round-trip.
//
//	$  shell variable expansion (except the literal $tuned_params token)
//	`  command substitution (backtick form)
//	'  single quote — would terminate the wrong context if our
//	   double-quoted output were read by a shell that prefers single
//	   quotes; also unhandled by our parser
//
// Backslash and double-quote ARE allowed; we escape them safely on
// write. Whitespace within a token (kernel-style `module.param="x y"`)
// is harder — we don't try to support it; reject if seen.
var shellMetaUnsafeForCmdline = []string{"`", "'"}

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

// NextBootCmdline returns the union of GRUB_CMDLINE_LINUX and
// GRUB_CMDLINE_LINUX_DEFAULT from /etc/default/grub.
//
// SAFETY (Phase 6 audit C3): on Debian/Ubuntu the live kernel
// cmdline is the concatenation of both; reading only
// GRUB_CMDLINE_LINUX (the previous behaviour) caused the drift
// check to silently miss managed args sitting in _DEFAULT, leading
// to spurious DRIFT reports + duplicate-token rewrites at boot.
//
// kernsec WRITES only to GRUB_CMDLINE_LINUX (see WriteCmdline) so
// `disable` cannot strip args an operator hand-placed in
// _DEFAULT — that's documented as an undo gap in
// docs/kernsec.md. The READ side here is the safety-side
// completeness fix: drift detection sees the full picture even if
// it can't fully reverse it.
func (g *GRUBBackend) NextBootCmdline() (string, error) {
	if !g.FS.Exists(PathDefaultGrub) {
		return "", nil
	}
	b, err := g.FS.ReadFile(PathDefaultGrub)
	if err != nil {
		return "", err
	}
	return readGrubEffectiveCmdline(string(b))
}

// readGrubCmdlineLinux returns only GRUB_CMDLINE_LINUX. WriteCmdline uses
// this narrow read path so GRUB_CMDLINE_LINUX_DEFAULT remains an operator-
// owned input: its tokens are visible through NextBootCmdline, but are not
// copied into the kernsec-managed GRUB_CMDLINE_LINUX rewrite.
func readGrubCmdlineLinux(content string) (string, error) {
	return readGrubCmdlineVar(content, "GRUB_CMDLINE_LINUX")
}

// readGrubCmdlineLinuxDefault returns only GRUB_CMDLINE_LINUX_DEFAULT.
func readGrubCmdlineLinuxDefault(content string) (string, error) {
	return readGrubCmdlineVar(content, "GRUB_CMDLINE_LINUX_DEFAULT")
}

// readGrubEffectiveCmdline returns the union that GRUB will use on the next
// boot. Drift/status call through NextBootCmdline and therefore still show
// managed args an operator manually placed in GRUB_CMDLINE_LINUX_DEFAULT.
func readGrubEffectiveCmdline(content string) (string, error) {
	linuxArgs, err := readGrubCmdlineLinux(content)
	if err != nil {
		return "", err
	}
	defaultArgs, err := readGrubCmdlineLinuxDefault(content)
	if err != nil {
		return "", err
	}
	// Concatenate _LINUX and _DEFAULT in the order GRUB itself uses
	// (Debian/Ubuntu /etc/grub.d/10_linux: _DEFAULT comes after
	// _LINUX in the generated grub.cfg). Either may be empty;
	// strings.TrimSpace + strings.Join handles that cleanly.
	parts := make([]string, 0, 2)
	if linuxArgs != "" {
		parts = append(parts, linuxArgs)
	}
	if defaultArgs != "" {
		parts = append(parts, defaultArgs)
	}
	return strings.TrimSpace(strings.Join(parts, " ")), nil
}

// readGrubCmdlineVar locates the named GRUB_CMDLINE_LINUX* variable
// in /etc/default/grub content, decodes its value, and returns it.
// "" + nil if the variable is absent (some distros don't ship a
// _DEFAULT line).
func readGrubCmdlineVar(content, varName string) (string, error) {
	prefix := varName + "="
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, prefix) {
			continue
		}
		val := strings.TrimPrefix(t, prefix)
		decoded, err := decodeGrubCmdlineValue(val)
		if err != nil {
			return "", fmt.Errorf("%s: %s: %w", PathDefaultGrub, varName, err)
		}
		return decoded, nil
	}
	return "", nil
}

// decodeGrubCmdlineValue reverses grubCmdlineLine for a single
// GRUB_CMDLINE_LINUX assignment value (the right-hand-side of `=`).
// Strips one layer of outer single OR double quotes, then unescapes
// `\"`, `\\`, and `\$` if the outer quotes were double. Rejects values with
// shell metacharacters our writer cannot safely round-trip — the
// operator gets an explicit error pointing at the offending character
// rather than a silently-corrupted rewrite.
func decodeGrubCmdlineValue(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if s[0] == '"' && (len(s) < 2 || s[len(s)-1] != '"') {
		return "", fmt.Errorf("malformed double-quoted value")
	}
	if s[0] == '\'' && (len(s) < 2 || s[len(s)-1] != '\'') {
		return "", fmt.Errorf("malformed single-quoted value")
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		inner := s[1 : len(s)-1]
		// Inside double quotes: \" → ", \\ → \, and \$ → $. Other escapes are
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
// `\"`, `\\`, and `\$` are recognised; any other backslash sequence is
// a shell escape we don't support and surfaces as an error.
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
		case '"', '\\', '$':
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
	if strings.Contains(s, "${") {
		return fmt.Errorf("kernel cmdline contains shell metacharacter %q — kernsec cannot safely round-trip this through GRUB_CMDLINE_LINUX; edit /etc/default/grub manually and re-run apply", "${")
	}
	if strings.Contains(s, "$(") {
		return fmt.Errorf("kernel cmdline contains shell metacharacter %q — kernsec cannot safely round-trip this through GRUB_CMDLINE_LINUX; edit /etc/default/grub manually and re-run apply", "$(")
	}
	for _, tok := range strings.Fields(s) {
		if !strings.Contains(tok, "$") {
			continue
		}
		if tok == tunedParamsToken {
			continue
		}
		return fmt.Errorf("kernel cmdline contains shell metacharacter %q — kernsec only preserves literal %s in GRUB_CMDLINE_LINUX; edit /etc/default/grub manually and re-run apply",
			tok, tunedParamsToken)
	}
	return nil
}

// encodeGrubCmdlineValue is the inverse of decodeGrubCmdlineValue:
// returns the right-hand-side of a GRUB_CMDLINE_LINUX= assignment
// for the given inner kernel-cmdline string. Always emits double-
// quoted form with `\`, `"`, and literal `$` escaped. Refuses to
// encode strings with unsafe shell metacharacters (same set as the
// read side) so the writer never produces output it can't read back.
func encodeGrubCmdlineValue(inner string) (string, error) {
	if err := rejectUnsafeShellMeta(inner); err != nil {
		return "", err
	}
	escaped := strings.ReplaceAll(inner, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	// Keep the literal tuned token from becoming shell expansion when
	// grub-mkconfig/update-grub source /etc/default/grub.
	escaped = strings.ReplaceAll(escaped, `$`, `\$`)
	return `"` + escaped + `"`, nil
}

// WriteCmdline rewrites GRUB_CMDLINE_LINUX in /etc/default/grub with
// the managed-keys workflow. Mirrors kspp.sh apply_boot_args_grub +
// set_grub_cmdline.
//
// kernsec writes ONLY to GRUB_CMDLINE_LINUX, never to
// GRUB_CMDLINE_LINUX_DEFAULT. The read side (NextBootCmdline) reads
// both — see its docstring for the rationale. Consequence: an
// operator who hand-edits managed kernsec keys into
// GRUB_CMDLINE_LINUX_DEFAULT will see them flagged as drift but
// `cfm kernsec disable` cannot strip them (the disable code path
// only modifies _LINUX). docs/kernsec.md flags this as a known
// undo gap.
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
	currentLinux, err := readGrubCmdlineLinux(string(b))
	if err != nil {
		// Surface the read failure rather than silently treating
		// "couldn't read" as "empty cmdline" — that path leads to
		// writing a cmdline containing only managed args (i.e.
		// dropping root=, ro, console=, etc). Read only _LINUX here:
		// _DEFAULT is part of the effective next-boot view, but is not
		// owned by kernsec's GRUB writer.
		return fmt.Errorf("read current GRUB_CMDLINE_LINUX: %w", err)
	}
	// Best-effort pre-apply managed-args snapshot for rollback. Legacy
	// full-file backups are still written below for manual recovery.
	_ = writeManagedBootArgSnapshot(GRUBManagedBackupPath, ParseCmdline(currentLinux))

	tokens := rebuildManagedCmdline(ParseCmdline(currentLinux), args)
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
	name, args, err := g.refreshCommand()
	if err != nil {
		return err
	}
	if out, err := g.FS.RunCapture(name, args...); err != nil {
		return fmt.Errorf("%s: %v: %s", grubRefreshDisplay(name, args), err, strings.TrimSpace(out))
	}
	return nil
}

// refreshCommand returns the GRUB config generator command and argv.
// update-grub is intentionally returned with no arguments. The mkconfig
// variants require an explicit -o path selected by findGrubCfgPath.
func (g *GRUBBackend) refreshCommand() (string, []string, error) {
	if g.FS.LookPath("update-grub") {
		return "update-grub", nil, nil
	}
	for _, name := range []string{"grub2-mkconfig", "grub-mkconfig"} {
		if !g.FS.LookPath(name) {
			continue
		}
		cfg := g.findGrubCfgPath()
		if cfg == "" {
			return "", nil, fmt.Errorf("could not determine GRUB config output path")
		}
		return name, []string{"-o", cfg}, nil
	}
	return "", nil, fmt.Errorf("no GRUB config generator found (update-grub / grub2-mkconfig / grub-mkconfig)")
}

func grubRefreshDisplay(name string, args []string) string {
	if len(args) == 0 {
		return name
	}
	return name + " " + strings.Join(args, " ")
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
