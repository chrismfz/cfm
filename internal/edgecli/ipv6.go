package edgecli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"cfm/internal/dnat"
	"cfm/internal/edgeengine"
	"cfm/internal/originrealip"
)

// cfm edge ipv6 on|off [engine]: the EDGE_LISTEN_V6 line in cfm.conf, then
// the IPv6 listen script's `render`, which writes or removes the listen
// files, reloads a running edge and confirms it listens on IPv6 (else puts it
// back on IPv4). The decision itself stays in the script (docs/edge-ipv6.md);
// this only spares the hand edit and the long path.
//
// `on` never WRITES `EDGE_LISTEN_V6 = on`: with the default (no line) only a
// render turns IPv6 on, confirmed; `on` in cfm.conf would let every edge
// start turn it on too, unconfirmed, which the design avoids. So `on` removes
// a kill switch (an off-like or unreadable value) and leaves any other line
// as the operator wrote it.

// confPath is cfm.conf, in the config dir main gives `cfm dnat`
// (dnat.SetConfigDir): one copy. A seam for tests.
var confPath = func() string {
	dir := dnat.ConfigDir()
	if dir == "" {
		dir = "/etc/cfm"
	}
	return filepath.Join(dir, "cfm.conf")
}

// renderTimeout bounds one render: it reloads the edge and waits for its IPv6
// listen to show up.
var renderTimeout = 3 * time.Minute

// renderRunner runs the script's render; a seam for tests.
var renderRunner = func(conf string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), renderTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", append([]string{ListenV6Script}, args...)...) // #nosec G204 -- fixed packaged script, args validated
	cmd.Env = append(os.Environ(), "CFM_CONF="+conf)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// v6Update is the conf `cfm edge ipv6 on|off` writes: off sets the kill
// switch; on removes it when the conf holds one, else leaves the conf alone.
func v6Update(conf, sub string) string {
	if sub == "off" {
		return setEdgeListenV6(conf, "off")
	}
	if !originrealip.EdgeListenV6Allowed(conf) {
		return setEdgeListenV6(conf, "")
	}
	return conf
}

// setEdgeListenV6 returns conf with every active EDGE_LISTEN_V6 line set to
// value (""= removed: the default), the first kept in place and the others
// dropped, or one appended when there was none. Comments and every other
// line are untouched.
func setEdgeListenV6(conf, value string) string {
	lines := strings.SplitAfter(conf, "\n")
	var out []string
	done := false
	for _, l := range lines {
		if l == "" {
			continue
		}
		if _, ok := originrealip.EdgeListenV6Line(strings.TrimRight(l, "\n")); ok {
			if !done && value != "" {
				out = append(out, "EDGE_LISTEN_V6 = "+value+"\n")
			}
			done = true
			continue
		}
		out = append(out, l)
	}
	if !done && value != "" {
		if n := len(out); n > 0 && !strings.HasSuffix(out[n-1], "\n") {
			out[n-1] += "\n"
		}
		out = append(out, "\n# Set by `cfm edge ipv6 "+value+"` (docs/edge-ipv6.md).\n", "EDGE_LISTEN_V6 = "+value+"\n")
	}
	return strings.Join(out, "")
}

// writeConfAtomic replaces path with data, keeping its mode and owner; a
// rename in the same directory, so a reader never sees a half-written file.
func writeConfAtomic(path string, data []byte) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".cfm.conf.edge-ipv6.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, st.Mode().Perm()); err != nil {
		return err
	}
	if uid, gid, ok := fileOwner(st); ok {
		if err := os.Chown(tmpName, uid, gid); err != nil {
			return err
		}
	}
	return os.Rename(tmpName, path)
}

const ipv6Usage = `Usage: cfm edge ipv6 [status]
       cfm edge ipv6 on|off [engine]
  status    the IPv6 listen decision of every installed engine (changes nothing)
  on        remove an EDGE_LISTEN_V6 = off from cfm.conf (IPv6 is on by
            default), then render: the edge listens on IPv6 where the host,
            the ports and the origin's ::1 trust allow it (run cfm edge
            realip fix first)
  off       EDGE_LISTEN_V6 = off in cfm.conf (the kill switch), then render:
            back to IPv4
  engine    OpenResty, Angie or cfm-edge: render only that one
render RELOADS a running edge (and confirms the IPv6 listen, else goes back
to IPv4). docs/edge-ipv6.md.
`

func runIPv6(args []string, d deps) int {
	if len(args) == 0 || args[0] == "status" {
		if len(args) > 1 {
			fmt.Fprintln(d.errOut, "edge ipv6: status takes no arguments")
			return 2
		}
		lines, err := d.ipv6()
		for _, l := range lines {
			fmt.Fprintln(d.out, l)
		}
		if err != nil {
			fmt.Fprintln(d.errOut, "edge ipv6: status:", err)
			return 1
		}
		return 0
	}
	sub := args[0]
	switch sub {
	case "on", "off":
	case "help", "-h", "--help":
		fmt.Fprint(d.out, ipv6Usage)
		return 0
	default:
		fmt.Fprintf(d.errOut, "edge ipv6: unknown subcommand %q\n\n%s", args[0], ipv6Usage)
		return 2
	}
	renderArgs := []string{"render"}
	switch len(args) {
	case 1:
	case 2:
		name := scriptEngineName(args[1])
		if name == "" {
			fmt.Fprintf(d.errOut, "edge ipv6: unknown engine %q (OpenResty, Angie, cfm-edge); nothing changed\n", args[1])
			return 2
		}
		renderArgs = append(renderArgs, name)
	default:
		fmt.Fprintf(d.errOut, "edge ipv6: unexpected argument %q\n", args[2])
		return 2
	}
	return d.setIPv6(sub, renderArgs)
}

// scriptEngineName maps an engine name, any case, to the one the script
// takes ("OpenResty", "Angie", "cfm-edge"); "" for none.
func scriptEngineName(s string) string {
	p, ok := edgeengine.Lookup(strings.ToLower(strings.TrimSpace(s)))
	if !ok {
		return ""
	}
	switch p.Name {
	case "openresty":
		return "OpenResty"
	case "angie":
		return "Angie"
	default:
		return p.Name
	}
}

// setIPv6 is the production setIPv6 dep (sub is "on" or "off").
func setIPv6(d deps, sub string, renderArgs []string) int {
	if _, err := os.Stat(ListenV6Script); err != nil {
		fmt.Fprintf(d.errOut, "edge ipv6: %s not found; nothing changed\n", ListenV6Script)
		return 1
	}
	path := confPath()
	old, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(d.errOut, "edge ipv6: read %s: %v; nothing changed\n", path, err)
		return 1
	}
	updated := v6Update(string(old), sub)
	if updated == string(old) {
		fmt.Fprintf(d.out, "%s unchanged: %s\n", path, describeV6(updated))
	} else {
		if err := writeConfAtomic(path, []byte(updated)); err != nil {
			fmt.Fprintf(d.errOut, "edge ipv6: write %s: %v; nothing changed\n", path, err)
			return 1
		}
		fmt.Fprintf(d.out, "%s: %s\n", path, describeV6(updated))
	}
	fmt.Fprintf(d.out, "Running: sh %s %s (reloads a running edge)\n", ListenV6Script, strings.Join(renderArgs, " "))
	out, err := renderRunner(path, renderArgs...)
	for _, l := range ipv6Lines(out) {
		fmt.Fprintln(d.out, l)
	}
	if err != nil {
		fmt.Fprintf(d.errOut, "edge ipv6: render: %v (cfm.conf is changed; run `cfm edge ipv6` to see the decision)\n", err)
		return 1
	}
	return 0
}

// describeV6 says what cfm.conf now holds for EDGE_LISTEN_V6.
func describeV6(conf string) string {
	last, present := "", false
	for _, l := range strings.Split(conf, "\n") {
		if v, ok := originrealip.EdgeListenV6Line(l); ok {
			last, present = v, true
		}
	}
	switch {
	case !present:
		return "no EDGE_LISTEN_V6 line (the default: IPv6 on, turned on by a render)"
	case originrealip.EdgeListenV6Allowed(conf):
		return "EDGE_LISTEN_V6 = " + last + " (IPv6 allowed)"
	default:
		return "EDGE_LISTEN_V6 = " + last + " (IPv6 off)"
	}
}
