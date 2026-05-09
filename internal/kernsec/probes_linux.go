//go:build linux

package kernsec

import (
	"syscall"
	"unsafe"
)

// af_alg constants — not exposed by the syscall package on every Go
// version. AF_ALG=38, SOCK_SEQPACKET=5.
const (
	afAlg         = 38
	sockSeqpacket = 5
)

// sockaddrAlg matches the kernel struct sockaddr_alg layout from
// <linux/if_alg.h>.
type sockaddrAlg struct {
	family uint16
	typ    [14]byte
	feat   uint32
	mask   uint32
	name   [64]byte
}

// unameRelease returns the running kernel release string.
func unameRelease() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	out := make([]byte, 0, 64)
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}

// ProbeAFAlg attempts an AF_ALG bind for the given (type, name).
// Returns Bound=true if the bind succeeded — i.e. the algif_* module
// is loadable and the algorithm is registered. Bound=false with an
// error means the kernel rejected the bind, which is what we want
// when a blacklist or initcall_blacklist is in effect.
//
// Best-effort: any setup error returns Bound=false with the error text.
func ProbeAFAlg(typ, name string) AFAlgBindResult {
	res := AFAlgBindResult{Type: typ, Name: name}

	fd, err := syscall.Socket(afAlg, sockSeqpacket, 0)
	if err != nil {
		res.ErrStr = err.Error()
		return res
	}
	defer syscall.Close(fd)

	var sa sockaddrAlg
	sa.family = afAlg
	copy(sa.typ[:], typ)
	copy(sa.name[:], name)

	_, _, errno := syscall.Syscall(
		syscall.SYS_BIND,
		uintptr(fd),
		uintptr(unsafe.Pointer(&sa)),
		unsafe.Sizeof(sa),
	)
	if errno != 0 {
		res.ErrStr = errno.Error()
		return res
	}
	res.Bound = true
	return res
}
