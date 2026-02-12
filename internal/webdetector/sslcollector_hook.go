package webdetector

import "cfm/internal/sslcollector"

var globalSSL *sslcollector.Collector

func SetSSLCollector(c *sslcollector.Collector) {
	globalSSL = c
}

func SSLCollector() *sslcollector.Collector {
	return globalSSL
}
