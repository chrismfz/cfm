package health

import (
	"io"
	"strings"
	"testing"
	"time"
)

func TestSnapshotNow_UsesSharedDetectorForThroughputDelta(t *testing.T) {
	snapshotCollectorMu.Lock()
	snapshotCollector = nil
	snapshotCollectorMu.Unlock()

	origNow := throughputNow
	origOpenNetDev := openNetDev
	t.Cleanup(func() {
		throughputNow = origNow
		openNetDev = origOpenNetDev
		snapshotCollectorMu.Lock()
		snapshotCollector = nil
		snapshotCollectorMu.Unlock()
	})

	times := []time.Time{
		time.Unix(100, 0),
		time.Unix(101, 0),
	}
	throughputNow = func() time.Time {
		if len(times) == 0 {
			t.Fatal("throughputNow called more than expected")
		}
		n := times[0]
		times = times[1:]
		return n
	}

	netDevSamples := []string{
		"Inter-|   Receive                                                |  Transmit\n" +
			" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
			"  eth0: 1000 0 0 0 0 0 0 0 500 0 0 0 0 0 0 0\n",
		"Inter-|   Receive                                                |  Transmit\n" +
			" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
			"  eth0: 201000 0 0 0 0 0 0 0 100500 0 0 0 0 0 0 0\n",
	}
	openNetDev = func() (io.ReadCloser, error) {
		if len(netDevSamples) == 0 {
			t.Fatal("openNetDev called more than expected")
		}
		s := netDevSamples[0]
		netDevSamples = netDevSamples[1:]
		return io.NopCloser(strings.NewReader(s)), nil
	}

	first := SnapshotNow()
	if first.RxMbps != 0 || first.TxMbps != 0 {
		t.Fatalf("first snapshot should seed throughput counters, got rx=%f tx=%f", first.RxMbps, first.TxMbps)
	}

	second := SnapshotNow()
	if second.RxMbps <= 0 {
		t.Fatalf("expected rx throughput > 0 on second snapshot, got %f", second.RxMbps)
	}
	if second.TxMbps <= 0 {
		t.Fatalf("expected tx throughput > 0 on second snapshot, got %f", second.TxMbps)
	}
}
