package kernsec

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ModuleSigBucket classifies a loaded module by the trust verdict
// kernsec assigns to its signature. The buckets are ordered from
// "most trusted" (Trusted) to "least trusted" (Unsigned), with
// Unknown reserved for entries we couldn't probe at all.
type ModuleSigBucket int

const (
	ModuleSigTrusted          ModuleSigBucket = iota // signed by a recognised kernel/distro signing key
	ModuleSigSignedUntrusted                         // signature present, signer not in kernsec's known-trusted list
	ModuleSigUnsigned                                // no signature trailer at all
	ModuleSigUnknown                                 // could not read the module file or modinfo failed
)

func (b ModuleSigBucket) String() string {
	switch b {
	case ModuleSigTrusted:
		return "trusted"
	case ModuleSigSignedUntrusted:
		return "signed-untrusted"
	case ModuleSigUnsigned:
		return "unsigned"
	default:
		return "unknown"
	}
}

// ModuleAuditEntry is the per-module signature record produced by
// CollectModuleAudit. All fields are best-effort: a missing modinfo
// binary or unreadable .ko leaves Path/Signer/SigHashAlgo/SigKeyID
// empty and surfaces the cause in ReadErr.
type ModuleAuditEntry struct {
	Name        string          // module name as it appears in /proc/modules
	Path        string          // resolved .ko[.xz|.zst] absolute path (modinfo -n)
	Size        int64           // file size in bytes (0 if unreadable)
	Signed      bool            // signature trailer present
	Signer      string          // CN/X509 description from `signer:` field
	SigHashAlgo string          // e.g. sha256
	SigKeyID    string          // raw sig_key hex (kernel keyring lookup hint)
	Bucket      ModuleSigBucket // verdict
	TrustReason string          // human-readable explanation for the bucket assignment
	ReadErr     string          // populated when modinfo or stat failed; module still listed
}

// ModuleAudit is the snapshot returned by CollectModuleAudit. Counts
// is keyed by bucket so callers (CLI, TUI) don't have to re-tally.
type ModuleAudit struct {
	Entries          []ModuleAuditEntry
	Counts           map[ModuleSigBucket]int
	TaintBitUnsigned bool   // /proc/sys/kernel/tainted bit 13 set
	TaintRaw         uint64 // raw value of /proc/sys/kernel/tainted (for forensics)
	ModinfoMissing   bool   // modinfo binary not found on $PATH; entries will mostly be Unknown
}

// trustedSignerPatterns is the case-insensitive substring set we treat
// as built-in / distro-vendor signing keys. Conservative on purpose:
// matching falsely as trusted gives a misleadingly green audit, so we
// only list the canonical kernel-build signing identities. Vendor-MOK
// signers (DKMS, ksplice, kernelcare, lvemanager build keys) are NOT
// listed — they end up in ModuleSigSignedUntrusted with the signer
// name preserved so the operator can decide whether to trust them.
var trustedSignerPatterns = []string{
	"red hat enterprise linux",
	"redhat",
	"centos",
	"rocky",
	"almalinux",
	"alma linux",
	"cloudlinux",
	"cloud linux",
	"oracle linux",
	"oracle corporation",
	"debian",
	"ubuntu",
	"canonical",
	"fedora",
	"suse",
	"sles",
	"opensuse",
}

// classifySigner returns (bucket, reason) for a parsed signer string.
// Empty signer means unsigned. Unknown signer is preserved verbatim in
// the reason so the operator sees exactly what the kernel saw.
func classifySigner(signer string) (ModuleSigBucket, string) {
	s := strings.TrimSpace(signer)
	if s == "" {
		return ModuleSigUnsigned, "no signature trailer"
	}
	low := strings.ToLower(s)
	for _, pat := range trustedSignerPatterns {
		if strings.Contains(low, pat) {
			return ModuleSigTrusted, "signer matches recognised kernel/distro signing key (" + pat + ")"
		}
	}
	return ModuleSigSignedUntrusted, "signed by " + s + " — not in kernsec's recognised trusted-signer list (could be a vendor MOK / DKMS key, or attacker-enrolled)"
}

// CollectModuleAudit walks /proc/modules and probes signature info
// for every loaded module via `modinfo`. Pure read-only, no fork
// hardening required (modinfo is a kmod tool, not a privileged op).
//
// Returns a fully-populated audit even when modinfo is missing or
// individual modules can't be probed — the failure mode is recorded
// per-entry rather than aborting the whole pass.
func CollectModuleAudit() *ModuleAudit {
	audit := &ModuleAudit{
		Counts: map[ModuleSigBucket]int{},
	}
	audit.TaintRaw, audit.TaintBitUnsigned = readKernelTaint()

	loaded := loadedModuleNames()
	sort.Strings(loaded)

	modinfo, modinfoErr := exec.LookPath("modinfo")
	if modinfoErr != nil {
		audit.ModinfoMissing = true
	}

	for _, name := range loaded {
		entry := ModuleAuditEntry{Name: name}
		if audit.ModinfoMissing {
			entry.Bucket = ModuleSigUnknown
			entry.TrustReason = "modinfo not found on $PATH; cannot probe signature"
			entry.ReadErr = "modinfo missing"
		} else {
			fillFromModinfo(modinfo, &entry)
		}
		audit.Entries = append(audit.Entries, entry)
		audit.Counts[entry.Bucket]++
	}
	return audit
}

// loadedModuleNames returns module names from /proc/modules in
// insertion order (we sort callers-side). Empty slice on read error.
func loadedModuleNames() []string {
	var names []string
	b, err := os.ReadFile("/proc/modules")
	if err != nil {
		return names
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			names = append(names, f[0])
		}
	}
	return names
}

// readKernelTaint returns (raw, unsignedBit). Bit 13 (= 0x2000) of
// /proc/sys/kernel/tainted is set when an unsigned module has ever
// been loaded into the running kernel, even if it was later rmmod'd.
func readKernelTaint() (uint64, bool) {
	b, err := os.ReadFile("/proc/sys/kernel/tainted")
	if err != nil {
		return 0, false
	}
	v, perr := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if perr != nil {
		return 0, false
	}
	return v, v&(1<<13) != 0
}

// fillFromModinfo runs `modinfo <name>` and parses the labeled output
// into the entry. modinfo emits one "field: value" line per attribute.
// Multiple values for the same field (alias:, depends:) are joined.
func fillFromModinfo(modinfoPath string, e *ModuleAuditEntry) {
	out, err := exec.Command(modinfoPath, e.Name).Output()
	if err != nil {
		e.Bucket = ModuleSigUnknown
		e.TrustReason = "modinfo failed: " + trimModinfoErr(err)
		e.ReadErr = trimModinfoErr(err)
		return
	}
	parseModinfo(string(out), e)
	if e.Path != "" {
		if st, serr := os.Stat(resolveModulePath(e.Path)); serr == nil {
			e.Size = st.Size()
		}
	}
	if e.Signer != "" || e.SigHashAlgo != "" || e.SigKeyID != "" {
		e.Signed = true
	}
	e.Bucket, e.TrustReason = classifySigner(e.Signer)
}

// trimModinfoErr reduces an exec.ExitError (which prints stderr noise)
// to a single short line for display.
func trimModinfoErr(err error) string {
	msg := err.Error()
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	return msg
}

// resolveModulePath strips a possible compression suffix the kernel
// adds when the module is actually loaded from a .ko.xz / .ko.zst /
// .ko.gz on disk; modinfo -n returns the on-disk path so the suffix
// is already there. Kept as a thin wrapper for future portability.
func resolveModulePath(p string) string {
	return filepath.Clean(p)
}

// parseModinfo extracts the fields kernsec cares about. modinfo's
// output format is `name:<spaces>value`, one field per line; multi-
// line values for `signature:` (long PEM-like blob) are folded by
// modinfo onto a single physical line, so a simple line-by-line
// parser is sufficient.
func parseModinfo(out string, e *ModuleAuditEntry) {
	for _, line := range strings.Split(out, "\n") {
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		switch key {
		case "filename":
			e.Path = val
		case "signer":
			e.Signer = val
		case "sig_hashalgo":
			e.SigHashAlgo = val
		case "sig_key":
			e.SigKeyID = val
		case "signature":
			// Don't store the full blob — it can be ~1KB per module
			// and we never display it. Presence is what matters; the
			// Signed flag is set once any sig_* field shows up.
			if val != "" {
				e.Signed = true
			}
		}
	}
}

// FormatTextAudit renders a ModuleAudit as a plain-text report for
// `cfm kernsec modules audit`. Grouped by bucket, summary first, then
// per-entry detail. No ANSI; pipeable.
func FormatTextAudit(a *ModuleAudit) string {
	var b strings.Builder
	fmt.Fprintln(&b, "===== CFM kernsec module signature audit =====")
	fmt.Fprintf(&b, "loaded modules:        %d\n", len(a.Entries))
	fmt.Fprintf(&b, "  trusted-signer:      %d\n", a.Counts[ModuleSigTrusted])
	fmt.Fprintf(&b, "  signed-untrusted:    %d\n", a.Counts[ModuleSigSignedUntrusted])
	fmt.Fprintf(&b, "  unsigned:            %d\n", a.Counts[ModuleSigUnsigned])
	if a.Counts[ModuleSigUnknown] > 0 {
		fmt.Fprintf(&b, "  read-error/unknown:  %d\n", a.Counts[ModuleSigUnknown])
	}
	fmt.Fprintf(&b, "kernel taint bit 13:   %s  (unsigned module loaded since boot)\n", yesNo(a.TaintBitUnsigned))
	fmt.Fprintf(&b, "kernel taint raw:      %d\n", a.TaintRaw)
	if a.ModinfoMissing {
		fmt.Fprintln(&b, "[!] modinfo not on $PATH — every entry classified as unknown.")
	}
	fmt.Fprintln(&b)

	for _, bucket := range []ModuleSigBucket{ModuleSigUnsigned, ModuleSigSignedUntrusted, ModuleSigUnknown, ModuleSigTrusted} {
		if a.Counts[bucket] == 0 {
			continue
		}
		fmt.Fprintf(&b, "[%s — %d]\n", bucket, a.Counts[bucket])
		for _, e := range a.Entries {
			if e.Bucket != bucket {
				continue
			}
			fmt.Fprintf(&b, "  %s\n", e.Name)
			if e.Path != "" {
				fmt.Fprintf(&b, "    path:       %s\n", e.Path)
			}
			if e.Signer != "" {
				fmt.Fprintf(&b, "    signer:     %s\n", e.Signer)
			}
			if e.SigHashAlgo != "" {
				fmt.Fprintf(&b, "    sig algo:   %s\n", e.SigHashAlgo)
			}
			if e.SigKeyID != "" {
				fmt.Fprintf(&b, "    sig key id: %s\n", e.SigKeyID)
			}
			if e.TrustReason != "" {
				fmt.Fprintf(&b, "    verdict:    %s\n", e.TrustReason)
			}
			if e.ReadErr != "" {
				fmt.Fprintf(&b, "    read err:   %s\n", e.ReadErr)
			}
		}
		fmt.Fprintln(&b)
	}
	fmt.Fprintln(&b, "===========================")
	return b.String()
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
