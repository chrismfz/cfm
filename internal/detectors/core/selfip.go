package core

import (
	"net"
	"sync"
	"time"
)

var (
	selfMu      sync.RWMutex
	selfSet     map[string]struct{}
	selfRefresh time.Time
	interfaces  = net.Interfaces
	addresses   = func(ifc net.Interface) ([]net.Addr, error) { return ifc.Addrs() }
)

const selfIPRefreshInterval = 30 * time.Second

func SelfIPSet() map[string]struct{} {
	now := time.Now()
	selfMu.RLock()
	set, fresh := selfSet, now.Before(selfRefresh)
	selfMu.RUnlock()
	if fresh {
		return set
	}

	selfMu.Lock()
	defer selfMu.Unlock()
	if selfSet != nil && now.Before(selfRefresh) {
		return selfSet
	}
	set = make(map[string]struct{})
	ifaces, err := interfaces()
	if err != nil {
		if selfSet == nil {
			selfSet = make(map[string]struct{})
		}
		selfRefresh = now.Add(time.Second)
		return selfSet
	}
	for _, ifc := range ifaces {
		addrs, err := addresses(ifc)
		if err != nil {
			if selfSet == nil {
				selfSet = make(map[string]struct{})
			}
			selfRefresh = now.Add(time.Second)
			return selfSet
		}
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
				set[v4.String()] = struct{}{}
			} else {
				set[ip.String()] = struct{}{}
			}
		}
	}
	selfSet = set
	selfRefresh = now.Add(selfIPRefreshInterval)
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
