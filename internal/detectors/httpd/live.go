// internal/detectors/httpd/live.go
package httpd

import "sync/atomic"

var live atomic.Value // *Detector

func Publish(d *Detector) { live.Store(d) }

func Live() *Detector {
	v := live.Load()
	if v == nil {
		return nil
	}
	return v.(*Detector)
}
