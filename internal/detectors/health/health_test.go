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

	// Settable fake clock: shared by the throughput AND disk-I/O delta
	// collectors, so it must tolerate multiple reads per snapshot.
	now := time.Unix(100, 0)
	throughputNow = func() time.Time { return now }

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
	if len(first.NICRates) != 0 {
		t.Fatalf("first snapshot should not report per-NIC rates, got %+v", first.NICRates)
	}

	now = time.Unix(101, 0)
	second := SnapshotNow()
	if second.RxMbps <= 0 {
		t.Fatalf("expected rx throughput > 0 on second snapshot, got %f", second.RxMbps)
	}
	if second.TxMbps <= 0 {
		t.Fatalf("expected tx throughput > 0 on second snapshot, got %f", second.TxMbps)
	}
	if len(second.NICRates) != 1 || second.NICRates[0].Name != "eth0" || second.NICRates[0].RxMbps <= 0 {
		t.Fatalf("expected per-NIC rate for eth0 on second snapshot, got %+v", second.NICRates)
	}
}
