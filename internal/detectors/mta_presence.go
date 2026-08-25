package detectors

// mta_presence.go — cached "is this MTA installed here?" probes shared by the
// exim and postfix registers' self-disable decisions. Results are cached
// briefly so one registration sweep (several sections probing the same MTA
// back-to-back) runs the exec probes once; a later hot reload re-probes, so
// installing the MTA and running `cfm detector reload` enables the sections
// without a daemon restart.

import (
	"os"
	"os/exec"
	"sync"
	"time"

	"cfm/internal/detectors/srcresolve"
)

const mtaPresenceTTL = 30 * time.Second

type presenceCache struct {
	probe func() bool

	mu  sync.Mutex
	val bool
	at  time.Time
}

func (c *presenceCache) get() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && time.Since(c.at) < mtaPresenceTTL {
		return c.val
	}
	c.val = c.probe()
	c.at = time.Now()
	return c.val
}

// binaryOrUnitPresent reports whether any of the binaries (via PATH or the
// given absolute locations) or systemd units exist/are active.
func binaryOrUnitPresent(binaries, paths, units []string) bool {
	for _, b := range binaries {
		if _, err := exec.LookPath(b); err == nil {
			return true
		}
	}
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return true
		}
	}
	ua := srcresolve.DefaultProbes().UnitActive
	for _, u := range units {
		if ua(u) {
			return true
		}
	}
	return false
}

// eximPresent: binary on PATH (exim, exim4 — Debian names the binary exim4)
// or at its standard location, or an active systemd unit.
var eximPresence = presenceCache{probe: func() bool {
	return binaryOrUnitPresent(
		[]string{"exim", "exim4"},
		[]string{"/usr/sbin/exim", "/usr/sbin/exim4"},
		[]string{"exim.service", "exim4.service"})
}}

func eximPresent() bool { return eximPresence.get() }

// postfixPresent: binary on PATH or at its standard location, or an active
// systemd unit. Containerized postfix is covered separately by docker
// discovery.
var postfixPresence = presenceCache{probe: func() bool {
	return binaryOrUnitPresent(
		[]string{"postfix"},
		[]string{"/usr/sbin/postfix"},
		postfixJournalUnits)
}}

func postfixPresent() bool { return postfixPresence.get() }

// dockerCLIPresent reports whether the docker CLI exists at all — used to
// distinguish "no docker on this host" from "docker daemon/containers not up
// yet" (boot ordering): with the CLI present, a failed container discovery is
// inconclusive and must not permanently self-disable a section.
func dockerCLIPresent() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

// registrationProbes returns the current registration sweep's shared memoized
// srcresolve probe set: one sweep resolves many sections back-to-back and must
// not repeat identical execs (docker ps, journal probes, unit canonicalization
// of the same units). The memo is scoped to ONE sweep — the manager calls
// resetRegistrationProbes() at the start of each (re)build, so a config reload
// re-probes current host state (a daemon/container that appeared since the last
// build is seen, honouring the "cfm detector reload re-resolves" contract),
// while sections within a sweep still share probes. Never a cross-sweep TTL
// cache: that would reuse stale host state across reloads (MemoProbes is
// explicitly "not safe for reuse across runs").
var regProbes struct {
	mu  sync.Mutex
	p   srcresolve.Probes
	set bool
}

// resetRegistrationProbes drops the memoized sweep probes so the next
// registrationProbes() rebuilds them against current host state.
func resetRegistrationProbes() {
	regProbes.mu.Lock()
	regProbes.p, regProbes.set = srcresolve.Probes{}, false
	regProbes.mu.Unlock()
}

func registrationProbes() srcresolve.Probes {
	regProbes.mu.Lock()
	defer regProbes.mu.Unlock()
	if !regProbes.set {
		regProbes.p = srcresolve.MemoProbes(srcresolve.DefaultProbes())
		regProbes.set = true
	}
	return regProbes.p
}
