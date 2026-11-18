package detectors

import (
	"os"
	"strings"
	"testing"
)

// The solver-farm detector reads BOTH challenge streams: the solves, and the
// withheld solves (v2=unsolicited, failed Rung 1, no cookie). The farms'
// pre-solves on fresh IPs are what it convicts; until 2026-11-18 they came on
// the solve stream, and withholding their cookie must not hide them from it.
// The factory needs a live webdetector to drive, so this pins the wiring.
func TestSolverFarmSubscribesToSolvedAndWithheld(t *testing.T) {
	src, err := os.ReadFile("challenge_solver_farm_register.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SubscribeChallengeSolveEvents(", "SubscribeChallengeWithheldEvents("} {
		if !strings.Contains(string(src), want) {
			t.Errorf("challenge_solver_farm_register.go does not call webdetector.%s…) — the detector would miss that stream", want)
		}
	}
}
