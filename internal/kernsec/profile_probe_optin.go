package kernsec

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// This file carries the host-profile probes for the opt-in hardening
// borrowed from the afflicted.sh "every kernel mitigation on Resolute"
// writeup:
//
//   - ioUringProbe       (Tier 2 — gates kernel.io_uring_disabled=2)
//   - legacyBinaryProbe  (Tier 3 — gates vsyscall=none)
//   - debugfsConsumerProbe (Tier 3 — gates debugfs=off)
//
// All three follow the same shape as usernsProbe: a small struct with
// the paths to probe, a detect() method that returns (bool, summary),
// and a defaultXProbe() constructor that wires the real /proc, /sys,
// /etc paths through hostProfilePath() so the package test harness can
// substitute fixtures.

// ---------------------------------------------------------------------
// ioUringProbe
// ---------------------------------------------------------------------

// ioUringProbe walks /proc/*/fd/* looking for symlinks that resolve to
// "anon_inode:[io_uring]" — the kernel's stable representation of an
// io_uring fd. Definitive: catches custom and renamed binaries that
// any process-name allowlist would miss.
type ioUringProbe struct {
	procDir string
}

func defaultIoUringProbe() ioUringProbe {
	return ioUringProbe{
		procDir: hostProfilePath("/proc"),
	}
}

func (p ioUringProbe) detect() (bool, string) {
	entries, err := os.ReadDir(p.procDir)
	if err != nil {
		return false, ""
	}
	// Aggregate up to 3 distinct comm names that hold an io_uring fd
	// and the total pid count so the audit-side note is informative
	// without being unbounded on a busy box.
	seenComm := map[string]struct{}{}
	var sampleNames []string
	totalPids := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		if _, err := strconvAtoi(pid); err != nil {
			continue
		}
		fdDir := filepath.Join(p.procDir, pid, "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		found := false
		for _, fd := range fds {
			tgt, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if strings.Contains(tgt, "io_uring") {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		totalPids++
		comm := pid
		if b, err := os.ReadFile(filepath.Join(p.procDir, pid, "comm")); err == nil {
			if c := strings.TrimSpace(string(b)); c != "" {
				comm = c
			}
		}
		if _, ok := seenComm[comm]; ok {
			continue
		}
		seenComm[comm] = struct{}{}
		if len(sampleNames) < 3 {
			sampleNames = append(sampleNames, comm)
		}
	}
	if totalPids == 0 {
		return false, ""
	}
	suffix := ""
	if len(seenComm) > len(sampleNames) {
		suffix = ", …"
	}
	return true, fmt.Sprintf("%d process(es) holding io_uring fds (e.g. %s%s)",
		totalPids, strings.Join(sampleNames, ", "), suffix)
}

// ---------------------------------------------------------------------
// legacyBinaryProbe
// ---------------------------------------------------------------------

// legacyBinaryProbe scans configured paths for ELF binaries that either
// reference glibc < 2.14 in their .gnu.version_r section or carry no
// glibc dependency at all (statically linked). vsyscall=none breaks
// those binaries hard, so finding even one is reason enough to skip
// the Tier 3 entry.
//
// Scope is intentionally narrow (/usr/bin, /usr/local/bin) to keep the
// probe fast on a hosting box that may carry 10k+ files in /home or
// /opt. Operators with customer chroots can extend ScanRoots in a
// follow-up; the default catches the binaries that ship with the
// distro.
type legacyBinaryProbe struct {
	ScanRoots []string
	MaxFiles  int // belt-and-braces ceiling on total ELF inspections
}

func defaultLegacyBinaryProbe() legacyBinaryProbe {
	return legacyBinaryProbe{
		ScanRoots: []string{
			hostProfilePath("/usr/bin"),
			hostProfilePath("/usr/local/bin"),
		},
		MaxFiles: 4000,
	}
}

func (p legacyBinaryProbe) detect() (bool, string) {
	var samples []string
	inspected := 0
	for _, root := range p.ScanRoots {
		if inspected >= p.MaxFiles {
			break
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if inspected >= p.MaxFiles {
				return filepath.SkipAll
			}
			// Skip obvious non-ELF: scripts, manpages, data files.
			// We rely on debug/elf to reject non-ELFs cleanly; the
			// extension filter is purely a perf optimisation.
			name := d.Name()
			if strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".1") ||
				strings.HasSuffix(name, ".py") || strings.HasSuffix(name, ".sh") ||
				strings.HasSuffix(name, ".pl") {
				return nil
			}
			inspected++
			if legacy, _ := looksLikeLegacyELF(path); legacy {
				if len(samples) < 3 {
					samples = append(samples, filepath.Base(path))
				}
			}
			return nil
		})
	}
	if len(samples) == 0 {
		return false, ""
	}
	return true, fmt.Sprintf("e.g. %s", strings.Join(samples, ", "))
}

// looksLikeLegacyELF returns (true, "") when the ELF at path either
// references a glibc version < 2.14 in its .gnu.version_r entries or
// has no dynamic-link section at all (statically linked). It returns
// (false, _) for everything else — including files that aren't ELFs,
// which debug/elf rejects cleanly.
func looksLikeLegacyELF(path string) (bool, string) {
	f, err := elf.Open(path)
	if err != nil {
		return false, ""
	}
	defer f.Close()

	// Static binary detection: no PT_INTERP and no .dynamic section.
	hasDynamic := false
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_DYNAMIC {
			hasDynamic = true
			break
		}
	}
	if !hasDynamic {
		// Statically linked. Conservative: assume legacy until proven
		// otherwise — modern static Go binaries (post 1.6) use vDSO
		// and don't need vsyscall, but the safe call is to surface
		// them in the audit notice rather than silently disable a
		// hard-to-reverse boot arg.
		return true, ""
	}

	// Dynamic binary: check .gnu.version_r for GLIBC_2.x references.
	sect := f.Section(".gnu.version_r")
	if sect == nil {
		return false, ""
	}
	data, err := sect.Data()
	if err != nil {
		return false, ""
	}
	// .gnu.version_r is structured (Elf64_Verneed / Elf64_Vernaux),
	// but the strings live in the linked .dynstr section. Cheap path:
	// pull strings from .dynstr and look for "GLIBC_2.0" .. "GLIBC_2.13".
	// This catches pre-2.14 references without parsing the binary
	// version tables formally.
	_ = data
	dynstr := f.Section(".dynstr")
	if dynstr == nil {
		return false, ""
	}
	strs, err := dynstr.Data()
	if err != nil {
		return false, ""
	}
	for _, v := range []string{
		"GLIBC_2.0", "GLIBC_2.1", "GLIBC_2.2", "GLIBC_2.3",
		"GLIBC_2.4", "GLIBC_2.5", "GLIBC_2.6", "GLIBC_2.7",
		"GLIBC_2.8", "GLIBC_2.9", "GLIBC_2.10", "GLIBC_2.11",
		"GLIBC_2.12", "GLIBC_2.13",
	} {
		if bytes.Contains(strs, append([]byte(v), 0)) {
			// Found a pre-2.14 reference and no >=2.14 reference
			// would by itself rescue the binary — pre-2.14 uses
			// the vsyscall page even when newer libc is also
			// present. Surface it.
			return true, v
		}
	}
	return false, ""
}

// ---------------------------------------------------------------------
// debugfsConsumerProbe
// ---------------------------------------------------------------------

// debugfsConsumerProbe checks for installed debugfs-using tools and
// for any process currently holding an open fd under /sys/kernel/debug.
// debugfs=off would break those workflows; skip the Tier 3 entry
// rather than risk a silent observability regression.
type debugfsConsumerProbe struct {
	procDir string
	// BinaryPaths is the set of well-known debugfs-consumer executables
	// whose mere presence on disk is treated as evidence the operator
	// expects debugfs to remain available.
	BinaryPaths []string
}

func defaultDebugfsConsumerProbe() debugfsConsumerProbe {
	return debugfsConsumerProbe{
		procDir: hostProfilePath("/proc"),
		BinaryPaths: []string{
			"/usr/bin/bpftrace",
			"/usr/local/bin/bpftrace",
			"/usr/bin/bcc-tools",
			"/usr/share/bcc",
			"/usr/bin/intel_gpu_top",
			"/usr/bin/intel-gpu-tools",
			"/usr/sbin/libvirtd",
		},
	}
}

func (p debugfsConsumerProbe) detect() (bool, string) {
	var samples []string
	for _, bp := range p.BinaryPaths {
		if _, err := os.Stat(hostProfilePath(bp)); err == nil {
			samples = append(samples, filepath.Base(bp))
			if len(samples) >= 3 {
				break
			}
		}
	}

	// Walk /proc/*/fd looking for symlinks under /sys/kernel/debug.
	// Stop after first hit per pid; cap distinct comm samples.
	if len(samples) < 3 {
		seenComm := map[string]struct{}{}
		entries, err := os.ReadDir(p.procDir)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				pid := e.Name()
				if _, err := strconvAtoi(pid); err != nil {
					continue
				}
				fdDir := filepath.Join(p.procDir, pid, "fd")
				fds, err := os.ReadDir(fdDir)
				if err != nil {
					continue
				}
				hit := false
				for _, fd := range fds {
					tgt, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
					if err != nil {
						continue
					}
					if strings.HasPrefix(tgt, "/sys/kernel/debug/") || tgt == "/sys/kernel/debug" {
						hit = true
						break
					}
				}
				if !hit {
					continue
				}
				comm := pid
				if b, err := os.ReadFile(filepath.Join(p.procDir, pid, "comm")); err == nil {
					if c := strings.TrimSpace(string(b)); c != "" {
						comm = c
					}
				}
				if _, ok := seenComm[comm]; ok {
					continue
				}
				seenComm[comm] = struct{}{}
				samples = append(samples, comm)
				if len(samples) >= 3 {
					break
				}
			}
		}
	}

	if len(samples) == 0 {
		return false, ""
	}
	return true, strings.Join(samples, ", ")
}
