package mailruntime

// Resource is one capacity-limited mail-runtime resource (inbound SMTP sessions,
// spamd scanner children) with its current-vs-max geometry and saturation class.
type Resource struct {
	Name string      `json:"name"`
	Util Utilisation `json:"util"`
	Sat  Saturation  `json:"sat"`
}

// Snapshot is the point-in-time mail-runtime saturation picture — a live gauge
// (like the MySQL governor's connection pressure), not a time series. Worst is
// the most severe class across the resources so a caller (what's_wrong) can gate
// a single finding on it.
type Snapshot struct {
	SMTP  Resource   `json:"smtp"`
	Spamd Resource   `json:"spamd"`
	Worst Saturation `json:"worst"`
}

// resolvedMax pairs a maximum with whether it was actually resolved from config;
// an unresolved max flows through to Utilisation.Known == false → SatUnknown.
type resolvedMax struct {
	Value int
	Known bool
}

// buildSnapshot assembles the geometry from the live current counts and the
// resolved maxima. Pure (no I/O) so the saturation logic is unit-tested in
// isolation; the live glue lives in Live below. An unresolved max yields an
// Unknown resource (never a false OK), and an "unlimited" cap (Exim
// smtp_accept_max = 0) is likewise Unknown — there is no ceiling to saturate.
func buildSnapshot(smtpCur int, smtpMax resolvedMax, spamdCur int, spamdMax resolvedMax) Snapshot {
	smtp := resource("smtp_connections", smtpCur, smtpMax)
	spamd := resource("spamd_children", spamdCur, spamdMax)
	return Snapshot{
		SMTP:  smtp,
		Spamd: spamd,
		Worst: worst(smtp.Sat, spamd.Sat),
	}
}

func resource(name string, current int, max resolvedMax) Resource {
	var u Utilisation
	if max.Known && max.Value > 0 {
		u = NewUtilisation(current, max.Value)
	} else {
		// Max unresolved, or "unlimited" (0 = no cap): carry the current count
		// for display but classify Unknown — never OK.
		u = Unknown(current)
	}
	return Resource{Name: name, Util: u, Sat: u.Classify()}
}

// worst returns the most severe class, keeping Unknown VISIBLE: a real problem
// (critical/warn) wins, but when nothing is a problem and something is Unknown,
// the result is Unknown (not OK) so the caller cannot read an un-judged resource
// as healthy. Order: critical > warn > unknown > ok.
func worst(a, b Saturation) Saturation {
	rank := func(s Saturation) int {
		switch s {
		case SatCritical:
			return 3
		case SatWarn:
			return 2
		case SatUnknown:
			return 1
		default: // SatOK
			return 0
		}
	}
	if rank(a) >= rank(b) {
		return a
	}
	return b
}

// EximMax turns parsed Exim maxima into a resolvedMax for the SMTP resource:
// resolved only when smtp_accept_max was found AND is a real cap (not 0 =
// unlimited).
func (m EximMaxima) EximMax() resolvedMax {
	if !m.SMTPAcceptMaxFound || m.Unlimited {
		return resolvedMax{Known: false}
	}
	return resolvedMax{Value: m.SMTPAcceptMax, Known: true}
}

// Live reads the current counts from /proc and assembles the snapshot against
// the supplied maxima. smtpPorts defaults to DefaultSMTPPorts when nil. This is
// the collector's core; config discovery (locating exim.conf / the spamd
// command line to fill the maxima) is the caller's job.
func Live(smtpPorts map[int]bool, smtpMax resolvedMax, spamdMax resolvedMax) Snapshot {
	if smtpPorts == nil {
		smtpPorts = DefaultSMTPPorts
	}
	smtpCur := SMTPEstablished(smtpPorts)
	spamdCur := CountComm(DefaultSpamdChildComm)
	return buildSnapshot(smtpCur, smtpMax, spamdCur, spamdMax)
}

// SpamdMax builds a resolvedMax for spamd children from a parsed --max-children
// value.
func SpamdMax(n int, found bool) resolvedMax {
	if !found || n <= 0 {
		return resolvedMax{Known: false}
	}
	return resolvedMax{Value: n, Known: true}
}
