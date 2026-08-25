package detectors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cfm/internal/detectors/srcresolve"
)

// Only a plan with bootRace set flags a retry — NOT every provisional plan.
// bootRace is the narrow "docker present, container not up yet" case; a plain
// provisional (host MTA present-but-unconfirmed, or a non-docker blind default)
// has no container coming, so retrying it would be pure churn.
func TestNotePlanBootRace(t *testing.T) {
	resetBootRacePending()
	notePlanBootRace(sourcePlan{provisional: true}) // provisional but NOT bootRace
	if bootRacePending() {
		t.Fatal("a plain provisional plan (no container coming) must not flag a retry")
	}
	notePlanBootRace(sourcePlan{}) // neither
	if bootRacePending() {
		t.Fatal("a resolved plan must not flag a retry")
	}
	notePlanBootRace(sourcePlan{provisional: true, bootRace: true})
	if !bootRacePending() {
		t.Fatal("a bootRace plan must flag a retry")
	}
	resetBootRacePending()
	if bootRacePending() {
		t.Fatal("reset must clear the flag")
	}
}

// The planners set bootRace ONLY in the genuine container-not-up-yet case, and
// never for host-MTA-present or non-docker provisional defaults.
func TestPlannerBootRaceArmingScope(t *testing.T) {
	// postfix: no host postfix + docker present + nothing resolved → bootRace.
	swapPresence(t, false, false, true)
	if p := planPostfixLogSource("postfix_security", KV{}, planProbes(nil, nil, nil, nil)); !p.bootRace {
		t.Fatalf("postfix container-not-found must arm bootRace: %+v", p)
	}
	// postfix installed on the host but not confirmed → provisional, NOT bootRace.
	swapPresence(t, false, true, true)
	if p := planPostfixLogSource("postfix_security", KV{}, planProbes(nil, nil, nil, nil)); p.bootRace || !p.provisional {
		t.Fatalf("host-postfix-present must be provisional but NOT bootRace: %+v", p)
	}
	// dovecot: docker present, no container → bootRace; no docker → not.
	swapPresence(t, false, false, true)
	if p := planDovecotSource("dovecot_auth", KV{}, planProbes(nil, nil, nil, nil)); !p.bootRace {
		t.Fatalf("dovecot container-not-found (docker present) must arm bootRace: %+v", p)
	}
	swapPresence(t, false, false, false)
	if p := planDovecotSource("dovecot_auth", KV{}, planProbes(nil, nil, nil, nil)); p.bootRace || !p.provisional {
		t.Fatalf("dovecot without docker must be provisional but NOT bootRace: %+v", p)
	}
}

func TestBootRaceRetryDue(t *testing.T) {
	m := &manager{}
	now := time.Unix(1_700_000_000, 0)
	if m.bootRaceRetryDue(now) {
		t.Fatal("zero reprobeAt is never due")
	}
	m.reprobeAt = now.Add(30 * time.Second)
	if m.bootRaceRetryDue(now) {
		t.Fatal("future reprobeAt is not yet due")
	}
	m.reprobeAt = now.Add(-time.Second)
	if !m.bootRaceRetryDue(now) {
		t.Fatal("past reprobeAt is due")
	}
}

// planProbes builds fake srcresolve probes from simple sets.
func planProbes(entries, active, files, containers []string) srcresolve.Probes {
	in := func(set []string) func(string) bool {
		return func(v string) bool {
			for _, s := range set {
				if s == v {
					return true
				}
			}
			return false
		}
	}
	return srcresolve.Probes{
		JournalHasEntries: in(entries),
		JournalMatches: func(unit, sig string) bool {
			return in(entries)(unit) // treat "has entries" as "matches" in tests
		},
		UnitActive:     in(active),
		FileExists:     in(files),
		ListContainers: func() []string { return containers },
	}
}

// swapPresence overrides the MTA/docker presence probes for one test.
func swapPresence(t *testing.T, exim, postfix, docker bool) {
	t.Helper()
	oe, op, od := eximPresentFn, postfixPresentFn, dockerCLIPresentFn
	eximPresentFn = func() bool { return exim }
	postfixPresentFn = func() bool { return postfix }
	dockerCLIPresentFn = func() bool { return docker }
	t.Cleanup(func() { eximPresentFn, postfixPresentFn, dockerCLIPresentFn = oe, op, od })
}

func TestPlanSSHSource(t *testing.T) {
	// EL host: journal resolves; no note, not provisional.
	p := planSSHSource("ssh_auth", KV{}, planProbes([]string{"sshd.service"}, nil, nil, nil))
	if p.res.Kind != srcresolve.KindJournal || p.res.Unit != "sshd.service" || p.provisional {
		t.Fatalf("ssh EL: %+v", p)
	}
	// Nothing anywhere: provisional journal default (auto), file default (MODE=file).
	p = planSSHSource("ssh_auth", KV{}, planProbes(nil, nil, nil, nil))
	if !p.provisional || p.res.Kind != srcresolve.KindJournal || p.res.Unit != "sshd.service" {
		t.Fatalf("ssh provisional auto: %+v", p)
	}
	p = planSSHSource("ssh_auth", KV{"MODE": "file"}, planProbes(nil, nil, nil, nil))
	if !p.provisional || p.res.Kind != srcresolve.KindFile || p.res.Path != "/var/log/secure" {
		t.Fatalf("ssh provisional file mode: %+v", p)
	}
}

func TestPlanDovecotSource(t *testing.T) {
	// mailcow: container discovered.
	p := planDovecotSource("dovecot_auth", KV{}, planProbes(nil, nil, nil, []string{"mailcowdockerized-dovecot-mailcow-1"}))
	if p.res.Kind != srcresolve.KindDocker || p.res.Container != "mailcowdockerized-dovecot-mailcow-1" {
		t.Fatalf("dovecot mailcow: %+v", p)
	}
	// Nothing: provisional maillog.
	p = planDovecotSource("dovecot_auth", KV{}, planProbes(nil, nil, nil, nil))
	if !p.provisional || p.res.Path != "/var/log/maillog" {
		t.Fatalf("dovecot provisional: %+v", p)
	}
}

func TestPlanEximLogSource(t *testing.T) {
	// cPanel: mainlog found.
	p := planEximLogSource("exim_security", KV{}, planProbes(nil, nil, []string{"/var/log/exim_mainlog"}, nil))
	if p.res.Kind != srcresolve.KindFile || p.res.Path != "/var/log/exim_mainlog" || p.disable {
		t.Fatalf("exim cpanel: %+v", p)
	}
	// postfix-only host: disable.
	swapPresence(t, false, true, false)
	p = planEximLogSource("exim_security", KV{}, planProbes(nil, nil, nil, nil))
	if !p.disable {
		t.Fatalf("exim on postfix host should disable: %+v", p)
	}
	// exim present, mainlog elsewhere: passthrough to internal autodetect.
	swapPresence(t, true, false, false)
	p = planEximLogSource("exim_security", KV{}, planProbes(nil, nil, nil, nil))
	if p.disable || !p.passthrough || !p.provisional {
		t.Fatalf("exim internal-autodetect passthrough: %+v", p)
	}
	// Explicit LOG_PATH verbatim, even when absent on disk.
	p = planEximLogSource("exim_security", KV{"LOG_PATH": "/custom/mainlog"}, planProbes(nil, nil, nil, nil))
	if p.res.Kind != srcresolve.KindFile || p.res.Path != "/custom/mainlog" {
		t.Fatalf("exim explicit path: %+v", p)
	}
}

func TestPlanEximQueues(t *testing.T) {
	swapPresence(t, false, true, false)
	if p := planEximQueues("exim_queues", KV{}); !p.disable {
		t.Fatalf("exim_queues without exim should disable: %+v", p)
	}
	// Explicit command keeps it running even without exim.
	if p := planEximQueues("exim_queues", KV{"TOTAL_CMD": "docker exec mx exim -bpc"}); p.disable {
		t.Fatalf("explicit cmd must keep exim_queues alive: %+v", p)
	}
	swapPresence(t, true, false, false)
	if p := planEximQueues("exim_queues", KV{}); p.disable || !p.passthrough {
		t.Fatalf("exim_queues with exim: %+v", p)
	}
}

func TestPlanPostfixLogSource(t *testing.T) {
	// EL journal by signature.
	p := planPostfixLogSource("postfix_security", KV{}, planProbes([]string{"postfix.service"}, nil, nil, nil))
	if p.res.Kind != srcresolve.KindJournal || p.res.Unit != "postfix.service" {
		t.Fatalf("postfix journal: %+v", p)
	}
	// mailcow: docker discovery (even with a stale host file present).
	p = planPostfixLogSource("postfix_security", KV{}, planProbes(nil, nil, []string{"/var/log/mail.log"}, []string{"mailcowdockerized-postfix-mailcow-1"}))
	if p.res.Kind != srcresolve.KindDocker {
		t.Fatalf("postfix mailcow: %+v", p)
	}
	// JOURNAL_MATCHES passes through.
	p = planPostfixLogSource("postfix_security", KV{"JOURNAL_MATCHES": "_SYSTEMD_UNIT=postfix@-.service"}, planProbes(nil, nil, nil, nil))
	if !p.passthrough {
		t.Fatalf("JOURNAL_MATCHES passthrough: %+v", p)
	}
	// Multiple explicit keys pass through (package precedence decides).
	p = planPostfixLogSource("postfix_security", KV{"JOURNAL_UNIT": "postfix.service", "DOCKER_CONTAINER": "x"}, planProbes(nil, nil, nil, nil))
	if !p.passthrough || !strings.Contains(p.note, "journald > docker > file") {
		t.Fatalf("multi-key passthrough: %+v", p)
	}
	// Explicit mode that resolves nothing: passthrough, never disable.
	swapPresence(t, false, false, false)
	p = planPostfixLogSource("postfix_security", KV{"MODE": "journal"}, planProbes(nil, nil, nil, nil))
	if !p.passthrough || p.disable {
		t.Fatalf("explicit-mode none: %+v", p)
	}
	// Auto + nothing + no postfix + no docker: disable.
	p = planPostfixLogSource("postfix_security", KV{}, planProbes(nil, nil, nil, nil))
	if !p.disable {
		t.Fatalf("postfix absent should disable: %+v", p)
	}
	// Auto + nothing + docker CLI present: provisional, NOT disabled (boot race).
	swapPresence(t, false, false, true)
	p = planPostfixLogSource("postfix_security", KV{}, planProbes(nil, nil, nil, nil))
	if p.disable || !p.provisional || p.res.Path != "/var/log/mail.log" {
		t.Fatalf("docker-present boot race: %+v", p)
	}
}

func TestPlanPostfixQueues(t *testing.T) {
	// Host postfix: empty commands (NewQueues fills exact defaults).
	swapPresence(t, false, true, false)
	p, total, list := planPostfixQueues("postfix_queues", KV{}, planProbes(nil, nil, nil, nil))
	if p.disable || total != "" || list != "" {
		t.Fatalf("host postfix queues: %+v %q %q", p, total, list)
	}
	// mailcow: dockerized header-count commands.
	swapPresence(t, false, false, true)
	p, total, list = planPostfixQueues("postfix_queues", KV{}, planProbes(nil, nil, nil, []string{"mailcowdockerized-postfix-mailcow-1"}))
	if p.disable || p.res.Kind != srcresolve.KindDocker {
		t.Fatalf("mailcow queues plan: %+v", p)
	}
	if !strings.Contains(total, "docker exec mailcowdockerized-postfix-mailcow-1 mailq") ||
		!strings.Contains(total, `grep -E '^[A-Za-z0-9]+ +[0-9]'`) {
		t.Fatalf("dockerized total must keep the exact header-count pipeline: %q", total)
	}
	if list != "docker exec mailcowdockerized-postfix-mailcow-1 mailq" {
		t.Fatalf("dockerized list: %q", list)
	}
	// docker CLI present, no container: provisional, alive.
	p, _, _ = planPostfixQueues("postfix_queues", KV{}, planProbes(nil, nil, nil, nil))
	if p.disable || !p.provisional {
		t.Fatalf("queues boot race: %+v", p)
	}
	// Nothing at all: disable.
	swapPresence(t, false, false, false)
	p, _, _ = planPostfixQueues("postfix_queues", KV{}, planProbes(nil, nil, nil, nil))
	if !p.disable {
		t.Fatalf("queues without postfix should disable: %+v", p)
	}
}

// TestSourceReport exercises the report end-to-end over a small config file.
// It uses the real DefaultProbes (environment-dependent), so it only asserts
// environment-independent facts: row set, engines, configured-key echo, and
// explicit-value resolution.
func TestSourceReport(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "detectors.conf")
	content := `
[ssh_auth]
ENABLED = 1
MODE = file
LOG_PATH = /custom/ssh.log

[ftpd]
ENABLED = 1

[health]
ENABLED = 0

[exim_security.leniency]
MATCH_COUNTRY = "GR"
`
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// The report reads the LAYERED view: an overlay overriding ssh_auth's
	// LOG_PATH must be what resolution sees.
	if err := os.Mkdir(filepath.Join(dir, "detectors.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "detectors.d", "10-local.conf"),
		[]byte("[ssh_auth]\nLOG_PATH = /overlay/ssh.log\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rows, err := SourceReport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]int{}
	for i, r := range rows {
		byName[r.Section] = i
	}
	if _, ok := byName["exim_security.leniency"]; ok {
		t.Fatalf("leniency sections must not appear in the report")
	}
	ssh := rows[byName["ssh_auth"]]
	if ssh.Engine != "srcresolve" || ssh.Kind != "file" || ssh.Target != "/overlay/ssh.log" {
		t.Fatalf("ssh row must reflect the overlay-merged view: %+v", ssh)
	}
	if ssh.Configured["MODE"] != "file" || ssh.Configured["LOG_PATH"] != "/overlay/ssh.log" {
		t.Fatalf("ssh configured echo: %+v", ssh.Configured)
	}
	if ftpd := rows[byName["ftpd"]]; ftpd.Engine != "legacy-auto" {
		t.Fatalf("ftpd row: %+v", ftpd)
	}
	health := rows[byName["health"]]
	if health.Enabled || health.Engine != "n/a" {
		t.Fatalf("health row: %+v", health)
	}
}
