package sslcollector

import (
	"errors"
)

func (c *Collector) Dump(host string) (*Entry, error) {
	h := normalizeHost(host)
	if h == "" {
		return nil, errors.New("empty host")
	}
	e, ok := c.getEntryLocked(h)
	if !ok {
		return nil, errors.New("not found")
	}
	return e, nil
}
