package procbaseline

import (
	"testing"
	"time"
)

func TestDefaultRetentionIsThreeDays(t *testing.T) {
	if defaultRetention != 72*time.Hour {
		t.Fatalf("defaultRetention = %s, want 72h", defaultRetention)
	}
}
