package kernsec

import (
	"fmt"
	"strings"
)

// BLSBackend implements BootBackend for BLS / grubby installs
// (RHEL/Alma/Rocky and similar). Reads next-boot args via
// `grubby --info=DEFAULT`; writes via `grubby --update-kernel=ALL`.
type BLSBackend struct {
	FS FS
}

func (b *BLSBackend) Label() string {
	return "BLS / grubby"
}

func (b *BLSBackend) NextBootCmdline() (string, error) {
	out, err := b.FS.RunCapture("grubby", "--info=DEFAULT")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "args=") {
			continue
		}
		val := strings.TrimPrefix(t, "args=")
		val = strings.Trim(val, `"`)
		return val, nil
	}
	return "", nil
}

// WriteCmdline calls grubby --update-kernel=ALL, first to remove every
// managed-keys token then to add the requested set. Mirrors kspp.sh
// apply_boot_args_bls.
//
// grubby commits to the active BLS entries immediately, so Refresh()
// is a no-op on this backend.
func (b *BLSBackend) WriteCmdline(args []BootArg) error {
	removeArgs := strings.Join(ManagedBootArgKeys, " ")
	if out, err := b.FS.RunCapture(
		"grubby",
		"--update-kernel=ALL",
		"--remove-args="+removeArgs,
	); err != nil {
		return fmt.Errorf("grubby --remove-args: %v: %s", err, strings.TrimSpace(out))
	}
	if len(args) == 0 {
		return nil
	}

	addArgs := make([]string, 0, len(args))
	for _, a := range args {
		addArgs = append(addArgs, a.String())
	}
	if out, err := b.FS.RunCapture(
		"grubby",
		"--update-kernel=ALL",
		"--args="+strings.Join(addArgs, " "),
	); err != nil {
		return fmt.Errorf("grubby --args: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// Refresh is a no-op on BLS — grubby already committed.
func (b *BLSBackend) Refresh() error {
	return nil
}
