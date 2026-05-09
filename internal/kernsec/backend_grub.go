package kernsec

import (
	"fmt"
	"path/filepath"
	"strings"
)

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
		val = strings.Trim(val, `"`)
		return val, nil
	}
	return "", nil
}

// WriteCmdline rewrites GRUB_CMDLINE_LINUX in /etc/default/grub with
// the managed-keys workflow. Mirrors kspp.sh apply_boot_args_grub +
// set_grub_cmdline.
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

	out, found := rewriteGrubCmdlineLinux(string(b), newLine)
	if !found {
		out += "\n" + grubCmdlineLine(newLine) + "\n"
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
// content with `GRUB_CMDLINE_LINUX="<newLine>"`, preserving every
// other line as-is. Returns the rewritten content and whether the
// assignment was found.
func rewriteGrubCmdlineLinux(content, newLine string) (string, bool) {
	lines := strings.Split(content, "\n")
	found := false
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "GRUB_CMDLINE_LINUX=") {
			lines[i] = grubCmdlineLine(newLine)
			found = true
		}
	}
	return strings.Join(lines, "\n"), found
}

func grubCmdlineLine(s string) string {
	return `GRUB_CMDLINE_LINUX="` + s + `"`
}
