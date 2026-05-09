package kernsec

// BootBackend abstracts the bootloader-specific operations kernsec
// needs. Three implementations: Proxmox boot tool / systemd-boot,
// BLS / grubby, legacy GRUB. Detection logic lives in DetectBackend.
//
// Phase 1 used only the read-only methods (Label, NextBootCmdline).
// Phase 2b adds WriteCmdline and Refresh — the write half lifted from
// kspp.sh's apply_boot_args_* functions. WriteCmdline is responsible
// for stripping any existing managed-keys tokens before adding the
// desired set; this preserves operator-set args outside the managed
// set.
type BootBackend interface {
	// Label is the human-readable backend name shown in status output.
	Label() string

	// NextBootCmdline returns the kernel cmdline that will be used on
	// the next boot, as a single string. Empty string if it cannot be
	// determined.
	NextBootCmdline() (string, error)

	// WriteCmdline updates the next-boot cmdline so that the managed
	// keys (ManagedBootArgKeys) are exactly the supplied set. Any
	// stale tokens for managed keys are removed first; everything else
	// on the cmdline is preserved untouched. Takes a one-shot backup
	// before first edit. Caller invokes Refresh afterwards.
	WriteCmdline(args []BootArg) error

	// Refresh causes the bootloader to pick up the cmdline change
	// (proxmox-boot-tool refresh, update-grub, grub-mkconfig). On
	// backends where WriteCmdline already commits to the active
	// config (BLS / grubby), this is a no-op.
	Refresh() error
}

// FS abstracts the filesystem reads and command executions backends
// need, so detection and read methods are unit-testable without a
// real bootloader present. Production code uses RealFS; tests use
// fakeFS implementations.
type FS interface {
	// ReadFile reads a file's contents. Same semantics as os.ReadFile.
	ReadFile(path string) ([]byte, error)
	// Exists reports whether path exists.
	Exists(path string) bool
	// IsDir reports whether path exists and is a directory.
	IsDir(path string) bool
	// LookPath reports whether the named binary is in $PATH.
	LookPath(name string) bool
	// RunCapture runs a command and returns its combined stdout/stderr.
	// Used for proxmox-boot-tool status / grubby --info etc.
	RunCapture(name string, args ...string) (string, error)
}

// rebuildManagedCmdline applies the managed-keys workflow to a
// tokenized cmdline: strip every managed-key token, then append the
// requested args in order. Pure helper shared across backends.
func rebuildManagedCmdline(tokens []string, args []BootArg) []string {
	out := RemoveManagedArgs(tokens)
	for _, a := range args {
		out = append(out, a.String())
	}
	return out
}
