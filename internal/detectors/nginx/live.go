package nginx

import "sync/atomic"

var live atomic.Value // stores *Detector

func Publish(d *Detector) { live.Store(d) }
func Live() *Detector {
    v := live.Load()
    if v == nil { return nil }
    return v.(*Detector)
}
