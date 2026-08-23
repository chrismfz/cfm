package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	cfgpkg "cfm/internal/config"
	"cfm/internal/firewall/netfilterdiag"
	webdet "cfm/internal/webdetector"
)

func TestNetfilterPathEndpoint(t *testing.T) {
	cfg := &cfgpkg.Config{}
	cfg.NFT.InputPriority = -50
	cfg.NFT.DNATPriority = -99
	collect := func(_ context.Context, expected netfilterdiag.Expected) (netfilterdiag.Report, error) {
		return netfilterdiag.Report{OK: true, Schema: netfilterdiag.Schema, Status: "ok", Expected: expected, Chains: []netfilterdiag.Chain{{Family: "inet", Table: "cfm_redirect", Name: "prerouting", Hook: "prerouting", Priority: -99, Owner: "cfm"}, {Family: "inet", Table: "cfm", Name: "input", Hook: "input", Priority: -50, Owner: "cfm"}}, Summary: netfilterdiag.Summary{BaseChains: 2}}, nil
	}
	rr := httptest.NewRecorder()
	makeNetfilterPathHandler(cfg, collect)(rr, httptest.NewRequest(http.MethodGet, "/api/v1/firewall/path?hook=prerouting", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out netfilterdiag.Report
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Chains) != 1 || out.Chains[0].Hook != "prerouting" || out.Expected.DNATPriority != -99 || out.Expected.PanelDNATPriority != -101 {
		t.Fatalf("response=%+v", out)
	}
}

func TestNetfilterPathEndpointRequiresAdmin(t *testing.T) {
	collect := func(context.Context, netfilterdiag.Expected) (netfilterdiag.Report, error) {
		return netfilterdiag.Report{OK: true, Schema: netfilterdiag.Schema, Status: "ok"}, nil
	}
	mux := http.NewServeMux()
	registerNetfilterPath(mux, &cfgpkg.Config{}, collect)
	for _, tc := range []struct {
		role string
		want int
	}{{"", http.StatusForbidden}, {webdet.CtxRoleScoped, http.StatusForbidden}, {webdet.CtxRoleAdmin, http.StatusOK}} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/firewall/path", nil)
		if tc.role != "" {
			req = req.WithContext(debugCtx(tc.role))
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Fatalf("role=%q status=%d want=%d body=%s", tc.role, rr.Code, tc.want, rr.Body.String())
		}
	}
}

func TestNetfilterPathEndpointErrors(t *testing.T) {
	collect := func(context.Context, netfilterdiag.Expected) (netfilterdiag.Report, error) {
		return netfilterdiag.Report{}, errors.New("nft unavailable")
	}
	for _, tc := range []struct {
		method, target string
		want           int
	}{
		{http.MethodPost, "/api/v1/firewall/path", http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/v1/firewall/path?hook=sideways", http.StatusBadRequest},
		{http.MethodGet, "/api/v1/firewall/path?dport=0", http.StatusBadRequest},
		{http.MethodGet, "/api/v1/firewall/path", http.StatusBadGateway},
	} {
		rr := httptest.NewRecorder()
		makeNetfilterPathHandler(nil, collect)(rr, httptest.NewRequest(tc.method, tc.target, nil))
		if rr.Code != tc.want {
			t.Fatalf("%s %s status=%d want=%d body=%s", tc.method, tc.target, rr.Code, tc.want, rr.Body.String())
		}
	}
}
