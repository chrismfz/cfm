//go:build !linux

package kernsec

// unameRelease returns "" on non-Linux. Kernel-config introspection
// is not meaningful off-Linux, but this lets the package build.
func unameRelease() string { return "" }

// ProbeAFAlg is a stub on non-Linux platforms.
func ProbeAFAlg(typ, name string) AFAlgBindResult {
	return AFAlgBindResult{
		Type:   typ,
		Name:   name,
		ErrStr: "AF_ALG not supported on this platform",
	}
}
