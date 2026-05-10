package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"cfm/internal/logging"
	"cfm/internal/notify"
)

// Alerter renders verdicts as forensic log lines (cfm.smtp.log) and emits an
// admin notification. It owns no goroutines; Emit is called inline from the
// collector worker so log ordering matches event ordering.
type Alerter struct {
	rt      Runtime
	notifyT time.Duration // notify dedup TTL hint; reused as Event.TTL
}

// NewAlerter builds an alerter. The Runtime is captured by value.
func NewAlerter(rt Runtime) *Alerter {
	return &Alerter{
		rt:      rt,
		notifyT: rt.DedupCooldown,
	}
}

// Emit logs and notifies. ctx is used for the (short) exim queue snapshot only.
func (a *Alerter) Emit(ctx context.Context, v Verdict, ac alertContext) {
	// Resolve uid/gid to names.
	uname := ac.um.User(v.UID)
	gname := ac.um.Group(v.GID)
	if uname == "" {
		uname = strconv.FormatUint(uint64(v.UID), 10)
	}
	if gname == "" {
		gname = strconv.FormatUint(uint64(v.GID), 10)
	}

	// Resolve process owning the connection (best-effort).
	pid, comm, _ := ac.pf.Lookup(ac.ipver, ac.srcIP, ac.sport, ac.dstIP, ac.dport)
	cwd := ""
	cmdline := ""
	if pid > 0 {
		cwd = readProcLink(pid, "cwd")
		cmdline = readProcText(pid, "cmdline")
	}

	// Optional: enrichment on the destination IP.
	var enrInfo EnrichInfo
	if ac.en != nil && ac.dstIP != nil {
		info := ac.en.Lookup(ac.dstIP.String())
		enrInfo = EnrichInfo{
			ASN:     info.ASN,
			ASNName: info.ASNName,
			Country: info.Country,
			City:    info.City,
			PTR:     info.PTR,
		}
	}

	// Optional: per-user exim queue snapshot for SMTP signals.
	var queueSnap EximSnap
	if v.Signal == SignalSMTP && uname != "" {
		queueSnap = EximQueueForUser(ctx, uname, a.rt.QueueSampleLimit, 4*time.Second)
	}

	// Build the forensic log line. Single line so cfm.smtp.log stays grep-friendly.
	var b strings.Builder
	fmt.Fprintf(&b, "outbound signal=%s uid=%d (user:%s) gid=%d (group:%s) count=%d threshold=%d window=%s uniq_dst=%d",
		v.Signal, v.UID, uname, v.GID, gname,
		v.Count, v.Threshold, v.Window, v.UniqueDsts,
	)
	if pid > 0 {
		fmt.Fprintf(&b, " proc=%s pid=%d", comm, pid)
	}
	if cwd != "" {
		fmt.Fprintf(&b, " cwd=%q", cwd)
	}
	if cmdline != "" {
		// Truncate cmdline aggressively — long PHP CLI invocations dominate logs.
		if len(cmdline) > 200 {
			cmdline = cmdline[:200] + "…"
		}
		fmt.Fprintf(&b, " cmd=%q", cmdline)
	}
	if len(v.SamplePeers) > 0 {
		// Render readable peer list (raw bytes -> dotted IPs).
		fmt.Fprintf(&b, " peers=%s", renderPeers(v.SamplePeers))
	}
	if enrInfo.ASN != 0 || enrInfo.Country != "" || enrInfo.PTR != "" {
		fmt.Fprintf(&b, " | dst_asn=AS%d (%s) cc=%s city=%s ptr=%s",
			enrInfo.ASN, enrInfo.ASNName, enrInfo.Country, enrInfo.City, enrInfo.PTR)
	}
	if v.Signal == SignalSMTP {
		if queueSnap.SourceOK {
			fmt.Fprintf(&b, " | exim_queue total=%d frozen=%d", queueSnap.Total, queueSnap.Frozen)
			if len(queueSnap.MsgIDs) > 0 {
				fmt.Fprintf(&b, " msgids=%s", strings.Join(queueSnap.MsgIDs, ","))
			}
			if len(queueSnap.Senders) > 0 {
				fmt.Fprintf(&b, " senders=%s", strings.Join(queueSnap.Senders, ","))
			}
		} else {
			b.WriteString(" | exim_queue=unavailable")
		}
	}
	logging.LogfSMTP("%s", b.String())

	// Notify channel — best-effort, never blocks.
	dstIP := ""
	if ac.dstIP != nil {
		dstIP = ac.dstIP.String()
	}
	go a.dispatchNotify(v, uname, gname, comm, pid, cwd, cmdline, dstIP, ac.dport, enrInfo, queueSnap)
}

func (a *Alerter) dispatchNotify(
	v Verdict,
	uname, gname, comm string,
	pid int,
	cwd, cmdline string,
	dstIP string,
	dstPort uint16,
	enrInfo EnrichInfo,
	queueSnap EximSnap,
) {
	ev := a.buildNotifyEvent(v, uname, gname, comm, pid, cwd, cmdline, dstIP, dstPort, enrInfo, queueSnap)
	_ = notify.Emit(ev)
}

func (a *Alerter) buildNotifyEvent(
	v Verdict,
	uname, gname, comm string,
	pid int,
	cwd, cmdline string,
	dstIP string,
	dstPort uint16,
	enrInfo EnrichInfo,
	queueSnap EximSnap,
) notify.Event {
	extra := map[string]string{
		"signal":    string(v.Signal),
		"uid":       strconv.FormatUint(uint64(v.UID), 10),
		"user":      uname,
		"gid":       strconv.FormatUint(uint64(v.GID), 10),
		"group":     gname,
		"count":     strconv.Itoa(v.Count),
		"threshold": strconv.Itoa(v.Threshold),
		"window":    v.Window.String(),
		"uniq_dst":  strconv.Itoa(v.UniqueDsts),
	}
	if dstIP != "" {
		extra["dst_ip"] = dstIP
	}
	if dstPort > 0 {
		extra["dst_port"] = strconv.Itoa(int(dstPort))
	}
	if dstIP != "" && dstPort > 0 {
		extra["dst_endpoint"] = net.JoinHostPort(dstIP, strconv.Itoa(int(dstPort)))
	}
	if pid > 0 {
		extra["proc"] = comm
		extra["pid"] = strconv.Itoa(pid)
	}
	if cwd != "" {
		extra["cwd"] = cwd
	}
	if cmdline != "" {
		if len(cmdline) > 200 {
			cmdline = cmdline[:200] + "…"
		}
		extra["cmd"] = cmdline
	}
	if v.Signal == SignalSMTP && queueSnap.SourceOK {
		extra["exim_total"] = strconv.Itoa(queueSnap.Total)
		extra["exim_frozen"] = strconv.Itoa(queueSnap.Frozen)
		if len(queueSnap.Senders) > 0 {
			extra["exim_senders"] = strings.Join(queueSnap.Senders, ",")
		}
	}

	severity := v.Severity
	if severity == "" {
		severity = a.rt.NotifySeverity
	}
	if severity == "" {
		severity = "warning"
	}
	reason := fmt.Sprintf("uid=%s (%s) %s burst: %d in %s (threshold %d)", extra["uid"], uname, v.Signal, v.Count, v.Window, v.Threshold)
	if endpoint := extra["dst_endpoint"]; endpoint != "" {
		reason += " outbound_dst=" + endpoint
	}
	ev := notify.Event{
		Kind:     "outbound_abuse",
		Section:  "outbound",
		When:     v.When,
		Reason:   reason,
		Count:    v.Count,
		Severity: severity,
		Extra:    extra,
		TTL:      a.notifyT,
		Samples:  renderPeerSlice(v.SamplePeers),
	}
	if enrInfo.ASN != 0 {
		ev.ASN = fmt.Sprintf("AS%d %s", enrInfo.ASN, enrInfo.ASNName)
	}
	ev.Country = enrInfo.Country
	ev.PTR = enrInfo.PTR
	return ev
}

// renderPeer converts one analyzer raw-byte peer key ("\x7f\x00\x00\x01:80")
// back to printable "127.0.0.1:80" / "[::1]:80" form. Best-effort: if the key
// length is unexpected we fall back to the raw bytes.
func renderPeer(peer string) string {
	// Format: <ipBytes>:<asciiPort>
	colon := strings.LastIndexByte(peer, ':')
	if colon < 0 {
		return peer
	}
	ipPart := peer[:colon]
	portPart := peer[colon+1:]
	switch len(ipPart) {
	case 4, 16:
		return net.JoinHostPort(net.IP([]byte(ipPart)).String(), portPart)
	default:
		return peer
	}
}

func renderPeerSlice(peers []string) []string {
	if len(peers) == 0 {
		return nil
	}
	rendered := make([]string, len(peers))
	for i, p := range peers {
		rendered[i] = renderPeer(p)
	}
	return rendered
}

// renderPeers converts the analyzer's raw-byte peer keys into a comma-separated
// printable peer list for forensic logs.
func renderPeers(peers []string) string {
	return strings.Join(renderPeerSlice(peers), ",")
}
