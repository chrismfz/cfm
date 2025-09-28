package syslookup

import (
	"bufio"
	"encoding/hex"
	"fmt"
	
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcFinder maps a TCP 5-tuple to (pid, comm) by checking /proc.
type ProcFinder struct {
	mu    sync.Mutex
	cache map[string]entry // inode -> entry
	ttl   time.Duration
}

type entry struct {
	pid int
	cmd string
	t   time.Time
}

func NewProcFinder() *ProcFinder {
	return &ProcFinder{cache: make(map[string]entry), ttl: 5 * time.Second}
}

// Lookup tries to resolve the process owning (src,sport -> dst,dport). ipver=4 or 6.
func (pf *ProcFinder) Lookup(ipver int, src net.IP, sport uint16, dst net.IP, dport uint16) (int, string, bool) {
	var inode string
	switch ipver {
	case 4:
		inode = findInodeTCP("/proc/net/tcp", src.To4(), sport, dst.To4(), dport)
	case 6:
		inode = findInodeTCP6("/proc/net/tcp6", src, sport, dst, dport)
	default:
		return 0, "", false
	}
	if inode == "" {
		return 0, "", false
	}

	now := time.Now()
	pf.mu.Lock()
	if e, ok := pf.cache[inode]; ok && now.Sub(e.t) < pf.ttl {
		pf.mu.Unlock()
		return e.pid, e.cmd, true
	}
	pf.mu.Unlock()

	pid, comm, ok := pidFromInode(inode)
	if ok {
		pf.mu.Lock()
		pf.cache[inode] = entry{pid: pid, cmd: comm, t: now}
		pf.mu.Unlock()
	}
	return pid, comm, ok
}

// ---------- /proc/net/tcp (IPv4) ----------
func findInodeTCP(path string, src net.IP, sport uint16, dst net.IP, dport uint16) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	wantL := fmt.Sprintf("%02X%02X%02X%02X:%04X", src[3], src[2], src[1], src[0], sport)
	wantR := fmt.Sprintf("%02X%02X%02X%02X:%04X", dst[3], dst[2], dst[1], dst[0], dport)

	sc := bufio.NewScanner(f)
	if sc.Scan() { /* skip header */ }
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 10 {
			continue
		}
		laddr, raddr := fs[1], fs[2]
		// State is fs[3]; prefer SYN-SENT (02) but don’t require it.
		if laddr == wantL && raddr == wantR {
			return fs[9] // inode
		}
	}
	return ""
}

// ---------- /proc/net/tcp6 (IPv6) ----------
func findInodeTCP6(path string, src net.IP, sport uint16, dst net.IP, dport uint16) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	if sc.Scan() { /* skip header */ }
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 10 {
			continue
		}
		laddr, raddr := fs[1], fs[2]
		lip, lp, okL := parseProcAddr6(laddr)
		rip, rp, okR := parseProcAddr6(raddr)
		if !okL || !okR {
			continue
		}
		if lip.Equal(src) && rip.Equal(dst) && lp == sport && rp == dport {
			return fs[9] // inode
		}
	}
	return ""
}

func parseProcAddr6(s string) (net.IP, uint16, bool) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return nil, 0, false
	}
	ipHex, portHex := parts[0], parts[1]
	if len(ipHex) != 32 {
		return nil, 0, false
	}
	b, err := hex.DecodeString(ipHex)
	if err != nil || len(b) != 16 {
		return nil, 0, false
	}
	// Fix 32-bit word endianness (see SO answer referenced in docs)
	for i := 0; i < 16; i += 4 {
		b[i+0], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i+0]
	}
	ip := net.IP(b)
	pv, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return nil, 0, false
	}
	return ip, uint16(pv), true
}

// ---------- inode -> (pid,comm) ----------
func pidFromInode(inode string) (int, string, bool) {
	proc, _ := os.ReadDir("/proc")
	want := "socket:[" + inode + "]"
	for _, e := range proc {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // permission or gone
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == want {
				comm := readTrim(filepath.Join("/proc", e.Name(), "comm"))
				if comm == "" {
					comm = strings.ReplaceAll(readTrim(filepath.Join("/proc", e.Name(), "cmdline")), "\x00", " ")
				}
				return pid, comm, true
			}
		}
	}
	return 0, "", false
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
