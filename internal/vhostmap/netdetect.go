package vhostmap

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

func DetectDefaultIPv4() (string, error) {
	ifname, _ := defaultRouteIface("/proc/net/route")
	if ifname != "" {
		if ip := firstIfaceIPv4(ifname); ip != "" {
			return ip, nil
		}
	}
	if ip := firstGlobalIPv4(); ip != "" {
		return ip, nil
	}
	return "", fmt.Errorf("no usable IPv4 detected")
}

func defaultRouteIface(procRoute string) (string, error) {
	f, err := os.Open(procRoute)
	if err != nil {
		return "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	if !sc.Scan() { // header
		return "", fmt.Errorf("empty route file")
	}
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		iface := fields[0]
		dest := fields[1]
		if dest == "00000000" {
			return iface, nil
		}
	}
	return "", sc.Err()
}

func firstIfaceIPv4(ifname string) string {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return ""
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ip := addrToIP(a)
		if ip == nil {
			continue
		}
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		if isUsableIPv4(v4) {
			return v4.String()
		}
	}
	return ""
}

func firstGlobalIPv4() string {
	ifis, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifi := range ifis {
		if (ifi.Flags&net.FlagUp) == 0 || (ifi.Flags&net.FlagLoopback) != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ip := addrToIP(a)
			if ip == nil {
				continue
			}
			v4 := ip.To4()
			if v4 == nil {
				continue
			}
			if isUsableIPv4(v4) {
				return v4.String()
			}
		}
	}
	return ""
}

func addrToIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		return nil
	}
}

func isUsableIPv4(ip net.IP) bool {
	if ip[0] == 127 { // loopback
		return false
	}
	if ip[0] == 0 {
		return false
	}
	if ip[0] == 169 && ip[1] == 254 { // link-local
		return false
	}
	return true
}
