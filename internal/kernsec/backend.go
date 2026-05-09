package kernsec

// BootBackend abstracts the bootloader-specific operations kernsec
// needs. Three implementations: Proxmox boot tool / systemd-boot,
// BLS / grubby, legacy GRUB. Detection logic lives in DetectBackend.
//
// Phase 1 only uses the read-only methods (Label, NextBootCmdline).
// Phase 3 will add WriteCmdline and Refresh for enable/disable.
type BootBackend interface {
	// Label is the human-readable backend name shown in status output.
	Label() string

	// NextBootCmdline returns the kernel cmdline that will be used on
	// the next boot, as a single string. Empty string if it cannot be
	// determined.
	NextBootCmdline() (string, error)
}

// FS abstracts the filesystem reads and command executions backends
// need, so detection and read methods are unit-testable without a
// real bootloader present. Production code uses RealFS; tests use
// fakeFS implementations.
type FS interface {
	// ReadFile reads a file's contents. Same semantics as os.ReadFile.
	ReadFile(path string) ([]byte, error)
	// Stat reports whether path exists.
	Exists(path string) bool
	// IsDir reports whether path exists and is a directory.
	IsDir(path string) bool
	// LookPath reports whether the named binary is in $PATH.
	LookPath(name string) bool
	// RunCapture runs a command and returns its combined stdout/stderr.
	// Used for proxmox-boot-tool status / grubby --info etc.
	RunCapture(name string, args ...string) (string, error)
}
