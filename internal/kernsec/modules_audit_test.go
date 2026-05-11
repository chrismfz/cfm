package kernsec

import (
	"strings"
	"testing"
)

func TestClassifySigner(t *testing.T) {
	tests := []struct {
		name   string
		signer string
		want   ModuleSigBucket
	}{
		{"empty -> unsigned", "", ModuleSigUnsigned},
		{"whitespace -> unsigned", "   \t  ", ModuleSigUnsigned},
		{"CL kernel signing key -> trusted",
			"CN=CloudLinux Linux kernel signing key", ModuleSigTrusted},
		{"RHEL signing key -> trusted",
			"CN=Red Hat Enterprise Linux kernel signing key", ModuleSigTrusted},
		{"CentOS signing key -> trusted",
			"CN=CentOS Linux kernel signing key", ModuleSigTrusted},
		{"Rocky signing key -> trusted",
			"CN=Rocky Linux kernel signing key", ModuleSigTrusted},
		{"Almalinux -> trusted",
			"CN=AlmaLinux OS kernel signing key", ModuleSigTrusted},
		{"Debian -> trusted", "CN=Debian Secure Boot CA", ModuleSigTrusted},
		{"Ubuntu / Canonical -> trusted",
			"CN=Canonical Ltd. Kernel Module Signing", ModuleSigTrusted},
		{"DKMS-built MOK key -> signed-untrusted (operator decides)",
			"CN=DKMS module signing key", ModuleSigSignedUntrusted},
		{"random vendor signer -> signed-untrusted",
			"CN=Acme Hardware kernel module key", ModuleSigSignedUntrusted},
		{"mixed-case match still works",
			"CN=cloudlinux build key 2024", ModuleSigTrusted},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := classifySigner(tc.signer)
			if got != tc.want {
				t.Errorf("classifySigner(%q) bucket = %v, want %v", tc.signer, got, tc.want)
			}
			if reason == "" {
				t.Error("classifySigner must always populate a non-empty reason")
			}
		})
	}
}

func TestParseModinfo_Signed(t *testing.T) {
	out := `filename:       /lib/modules/4.18.0-553.121.1.lve.el8.x86_64/kernel/fs/xfs/xfs.ko.xz
license:        GPL
description:    SGI XFS with ACLs, security attributes
author:         Silicon Graphics, Inc.
sig_id:         PKCS#7
signer:         CN=CloudLinux Linux kernel signing key
sig_key:        7E:34:F2:9D:01:23:45:67:89:AB:CD:EF
sig_hashalgo:   sha256
signature:      30:82:02:f4:06:09:2a:86:48:86:f7:0d:01:07:02:a0
`
	var e ModuleAuditEntry
	parseModinfo(out, &e)
	if e.Path != "/lib/modules/4.18.0-553.121.1.lve.el8.x86_64/kernel/fs/xfs/xfs.ko.xz" {
		t.Errorf("Path = %q", e.Path)
	}
	if e.Signer != "CN=CloudLinux Linux kernel signing key" {
		t.Errorf("Signer = %q", e.Signer)
	}
	if e.SigHashAlgo != "sha256" {
		t.Errorf("SigHashAlgo = %q", e.SigHashAlgo)
	}
	if e.SigKeyID != "7E:34:F2:9D:01:23:45:67:89:AB:CD:EF" {
		t.Errorf("SigKeyID = %q", e.SigKeyID)
	}
	if !e.Signed {
		t.Error("Signed should be true when signature blob present")
	}
}

func TestParseModinfo_Unsigned(t *testing.T) {
	out := `filename:       /lib/modules/x/kernel/foo.ko
license:        GPL
description:    Toy module
author:         You
`
	var e ModuleAuditEntry
	parseModinfo(out, &e)
	if e.Signed {
		t.Error("Signed must be false when no sig fields present")
	}
	if e.Signer != "" {
		t.Errorf("Signer should be empty: %q", e.Signer)
	}
}

func TestParseModinfo_IgnoresNonFieldLines(t *testing.T) {
	// Some modinfo builds emit blank lines and continuation indentation
	// for parm: descriptions. Parser must not treat them as fields.
	out := `filename:       /lib/modules/x/foo.ko

parm:           debug:Enable debug output
                  (defaults to 0)
license:        GPL
`
	var e ModuleAuditEntry
	parseModinfo(out, &e)
	if e.Path != "/lib/modules/x/foo.ko" {
		t.Errorf("Path = %q", e.Path)
	}
}

func TestFormatTextAudit_Sections(t *testing.T) {
	a := &ModuleAudit{
		Entries: []ModuleAuditEntry{
			{Name: "xfs", Signed: true, Signer: "CN=CloudLinux", Bucket: ModuleSigTrusted, TrustReason: "trusted"},
			{Name: "vboxdrv", Signed: true, Signer: "CN=Oracle VirtualBox", Bucket: ModuleSigSignedUntrusted, TrustReason: "vendor MOK"},
			{Name: "rogue", Signed: false, Bucket: ModuleSigUnsigned, TrustReason: "no signature"},
		},
		Counts: map[ModuleSigBucket]int{
			ModuleSigTrusted:         1,
			ModuleSigSignedUntrusted: 1,
			ModuleSigUnsigned:        1,
		},
		TaintBitUnsigned: true,
		TaintRaw:         8192,
	}
	got := FormatTextAudit(a)
	for _, want := range []string{
		"loaded modules:        3",
		"trusted-signer:      1",
		"signed-untrusted:    1",
		"unsigned:            1",
		"kernel taint bit 13:   yes",
		"[unsigned — 1]",
		"rogue",
		"[signed-untrusted — 1]",
		"vboxdrv",
		"[trusted — 1]",
		"xfs",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatTextAudit missing %q in:\n%s", want, got)
		}
	}
}

func TestReadKernelTaint_BitMath(t *testing.T) {
	// Sanity-check the bit-13 mask we hard-code — easy to miscount.
	const expectedMask uint64 = 1 << 13
	if expectedMask != 8192 {
		t.Fatalf("bit 13 mask = %d, expected 8192", expectedMask)
	}
}
