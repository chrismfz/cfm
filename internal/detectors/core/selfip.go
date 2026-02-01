package core

import (
	"net"
	"sync"
)

var (
	selfOnce sync.Once
	selfSet  map[string]struct{}
)

func SelfIPSet() map[string]struct{} {
	selfOnce.Do(func() {
		selfSet = make(map[string]struct{})

		ifaces, _ := net.Interfaces()
		for _, ifc := range ifaces {
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				var ip net.IP
				switch v := a.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil {
					continue
				}
				if v4 := ip.To4(); v4 != nil {
					selfSet[v4.String()] = struct{}{}
				} else {
					selfSet[ip.String()] = struct{}{}
				}
			}
		}
	})
	return selfSet
}

func IsSelfIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ipStr = v4.String()
	} else {
		ipStr = ip.String()
	}
	_, ok := SelfIPSet()[ipStr]
	return ok
}
