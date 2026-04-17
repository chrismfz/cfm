package apiserver

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestParsePprofRequestedSeconds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want int
	}{
		{name: "default empty", raw: "", want: pprofRequestedSecondsDefault},
		{name: "default invalid", raw: "abc", want: pprofRequestedSecondsDefault},
		{name: "default non-positive", raw: "0", want: pprofRequestedSecondsDefault},
		{name: "valid", raw: "42", want: 42},
		{name: "cap", raw: "999", want: pprofRequestedSecondsMaxLimit},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := parsePprofRequestedSeconds(tc.raw); got != tc.want {
				t.Fatalf("parsePprofRequestedSeconds(%q)=%d want=%d", tc.raw, got, tc.want)
			}
		})
	}
}

func TestPprofRequestTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		target     string
		want       time.Duration
		wantActive bool
	}{
		{name: "non-pprof", target: "/api/v1/system/status", wantActive: false},
		{name: "pprof index", target: "/debug/pprof/", want: pprofMinWriteTimeout, wantActive: true},
		{
			name:       "profile uses requested seconds plus margin",
			target:     "/debug/pprof/profile?seconds=45",
			want:       45*time.Second + pprofRequestedSafetyMargin,
			wantActive: true,
		},
		{
			name:       "profile defaults when seconds missing",
			target:     "/debug/pprof/profile",
			want:       time.Duration(pprofRequestedSecondsDefault)*time.Second + pprofRequestedSafetyMargin,
			wantActive: true,
		},
		{
			name:       "trace caps requested seconds",
			target:     "/debug/pprof/trace?seconds=900",
			want:       time.Duration(pprofRequestedSecondsMaxLimit)*time.Second + pprofRequestedSafetyMargin,
			wantActive: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", tc.target, nil)
			got, active := pprofRequestTimeout(req)
			if active != tc.wantActive {
				t.Fatalf("pprofRequestTimeout(%q) active=%v want=%v", tc.target, active, tc.wantActive)
			}
			if got != tc.want {
				t.Fatalf("pprofRequestTimeout(%q) timeout=%s want=%s", tc.target, got, tc.want)
			}
		})
	}
}
