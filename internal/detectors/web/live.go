package web

import "sync"

var mu sync.RWMutex
var live = map[Kind]*Detector{}

func Publish(kind Kind, d *Detector) {
	mu.Lock(); live[kind] = d; mu.Unlock()
}
func Live(kind Kind) *Detector {
	mu.RLock(); d := live[kind]; mu.RUnlock()
	return d
}
