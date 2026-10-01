package hostsecrets

import (
	"errors"
	"fmt"
	"sync"
)

// Per-process dedupe state for Report: a resolution runs on every reload (a
// config save, a tailed-log rotation), and the lines are the same each time.
var (
	reportErr         sync.Map // key → last error reported (cleared on success)
	reportFromConf    sync.Map // key → copied-from-config hint reported
	reportConfIgnored sync.Map // key → config value last reported as ignored
	reportUnusable    sync.Map // key → unusable-config-value warning reported
)

// Report returns the log lines worth writing after one resolution of key
// (Resolve / ResolveConfUnknown returned tok, source, err; legacy is the
// config-file value it was given, confName that file's name). Nothing for the
// steady state (the stored token, nothing to say); otherwise: a token
// generated, copied from the config file (once per process), a config value
// that is ignored (once per value) or cannot be used as written (once), or a
// store problem (once per distinct error). One wording for every caller.
func Report(key, confName, legacy, tok, source string, err error) []string {
	var out []string
	if IsStrongToken(legacy) && !UsableFor(key, legacy) {
		if _, seen := reportUnusable.LoadOrStore(key, true); !seen {
			why := "it is too long for a token file, or the config reader would change it (a quoted ';', '#' or ' //', or stray quotes)"
			if key == SSLCollectorToken {
				why = "it is too long for a token file" // the only reason UsableFor has for it
			}
			out = append(out, fmt.Sprintf("%s in %s is not used: %s, so it cannot run as written", key, confName, why))
		}
	}
	var msg string
	switch {
	case errors.Is(err, ErrConfUnknown):
		msg = fmt.Sprintf("%s: %v — running it for now; retried each reload", key, err)
	case errors.Is(err, ErrStoreChanged):
		msg = fmt.Sprintf("%s: %v (%s) — running the %s token until then", key, err, Path(key), sourceName(source, confName))
	case errors.Is(err, ErrStoreUnusable), errors.Is(err, ErrStoreUnreadable):
		msg = fmt.Sprintf("%s: %v — the file is left alone; %s; retried each reload", key, err, storeFallback(source, confName))
	case err != nil && source == SourceConf:
		msg = fmt.Sprintf("%s from %s could not be copied into %s: %v — running with it; retried each reload", key, confName, Path(key), err)
	case err != nil:
		msg = fmt.Sprintf("%s source=%s NOT stored in %s: %v — kept for this process (retried each reload); a restart generates a new one", key, source, Path(key), err)
	}
	if msg != "" {
		// Keyed on the error, not the message: the source shifts between
		// reloads (generated/conf first, running after) for the same fault.
		if prev, ok := reportErr.Load(key); !ok || prev.(string) != err.Error() {
			reportErr.Store(key, err.Error())
			out = append(out, msg)
		}
		return out
	}
	reportErr.Delete(key)
	switch source {
	case SourceGenerated:
		out = append(out, fmt.Sprintf("%s generated and stored in %s", key, Path(key)))
	case SourceConf:
		if _, seen := reportFromConf.LoadOrStore(key, true); !seen {
			out = append(out, fmt.Sprintf("%s copied from %s into %s, which is now the one in use; the %s line can be set back to placeholder", key, confName, Path(key), confName))
		}
	case SourceStore:
		if UsableFor(key, legacy) && legacy != tok {
			// Once per distinct value: a later edit of the line logs again.
			if prev, seen := reportConfIgnored.Load(key); !seen || prev.(string) != legacy {
				reportConfIgnored.Store(key, legacy)
				out = append(out, fmt.Sprintf("%s in %s is ignored: the token in %s is the one in use. To switch to the %s value, delete that file and restart; otherwise set the line to placeholder", key, confName, Path(key), confName))
			}
		}
	}
	return out
}

func sourceName(source, confName string) string {
	if source == SourceConf {
		return confName
	}
	return source
}

// storeFallback says what the daemon runs while the token file cannot be used.
func storeFallback(source, confName string) string {
	switch source {
	case SourceRunning:
		return "keeping the running token"
	case SourceConf:
		return "running the " + confName + " token, not stored"
	default:
		return "running a generated token, not stored: a restart generates another"
	}
}
