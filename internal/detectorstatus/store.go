package detectorstatus

import (
	"cfm/internal/telemetry"
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

type SectionConfig struct {
	Section            string
	Type               string
	Configured         bool
	Enabled            bool
	SourceProbeOK      bool
	SourceProbeMessage string
}

type RuntimeStatus struct {
	Section            string     `json:"section"`
	Type               string     `json:"type"`
	Configured         bool       `json:"configured"`
	Enabled            bool       `json:"enabled"`
	Active             bool       `json:"active"`
	InitOK             bool       `json:"init_ok"`
	LastRunAt          *time.Time `json:"last_run_at,omitempty"`
	LastSuccessAt      *time.Time `json:"last_success_at,omitempty"`
	LastError          string     `json:"last_error,omitempty"`
	SourceProbeOK      bool       `json:"source_probe_ok"`
	SourceProbeMessage string     `json:"source_probe_message,omitempty"`
	Runs               uint64     `json:"runs"`
	Failures           uint64     `json:"failures"`
	Timeouts           uint64     `json:"timeouts"`
}

type RuntimeSummary struct {
	LoadedTypes int `json:"loaded_types"`
	Configured  int `json:"configured_sections"`
	Enabled     int `json:"enabled_sections"`
	Active      int `json:"active_sections"`
}

type Snapshot struct {
	Now      time.Time       `json:"now"`
	Summary  RuntimeSummary  `json:"summary"`
	Sections []RuntimeStatus `json:"sections"`
}

type runtimeState struct {
	Section            string
	Type               string
	Configured         bool
	Enabled            bool
	Active             bool
	InitOK             bool
	LastRunAt          time.Time
	LastSuccessAt      time.Time
	LastError          string
	SourceProbeOK      bool
	SourceProbeMessage string
}

type store struct {
	mu          sync.RWMutex
	loadedTypes int
	sections    map[string]*runtimeState
}

var global = &store{sections: map[string]*runtimeState{}}

func SetLoadedTypes(n int) {
	global.mu.Lock()
	defer global.mu.Unlock()
	global.loadedTypes = n
}

func ResetConfiguredSections(list []SectionConfig) {
	global.mu.Lock()
	defer global.mu.Unlock()
	next := map[string]*runtimeState{}
	for _, sec := range list {
		st, ok := global.sections[sec.Section]
		if !ok {
			st = &runtimeState{Section: sec.Section}
		}
		st.Section = sec.Section
		st.Type = sec.Type
		st.Configured = sec.Configured
		st.Enabled = sec.Enabled
		st.Active = false
		st.InitOK = false
		st.LastError = ""
		st.SourceProbeOK = sec.SourceProbeOK
		st.SourceProbeMessage = sec.SourceProbeMessage
		next[sec.Section] = st
	}
	global.sections = next
}

func MarkInitFailed(section, errText string) {
	global.mu.Lock()
	defer global.mu.Unlock()
	st := global.ensure(section)
	st.InitOK = false
	st.Active = false
	st.LastError = strings.TrimSpace(errText)
}

func MarkInitOK(section string) {
	global.mu.Lock()
	defer global.mu.Unlock()
	st := global.ensure(section)
	st.InitOK = true
	st.Active = true
	st.LastError = ""
}

func MarkRunStart(section string, at time.Time) {
	global.mu.Lock()
	defer global.mu.Unlock()
	st := global.ensure(section)
	st.Active = true
	st.LastRunAt = at.UTC()
}

func MarkRunComplete(section string, at time.Time, runErr error) {
	global.mu.Lock()
	defer global.mu.Unlock()
	st := global.ensure(section)
	st.LastRunAt = at.UTC()
	if runErr == nil {
		st.LastSuccessAt = at.UTC()
		st.LastError = ""
		return
	}
	if runErr != context.Canceled {
		st.LastError = strings.TrimSpace(runErr.Error())
	}
}

func MarkRunTimeout(section string) {
	global.mu.Lock()
	defer global.mu.Unlock()
	st := global.ensure(section)
	st.LastError = "run timeout"
}

func MarkExit(section string, runErr error) {
	global.mu.Lock()
	defer global.mu.Unlock()
	st := global.ensure(section)
	st.Active = false
	if runErr != nil && runErr != context.Canceled {
		st.LastError = strings.TrimSpace(runErr.Error())
	}
}

func GetSnapshot() Snapshot {
	out := Snapshot{Now: time.Now().UTC()}
	tel := telemetry.Snapshot()
	counters := map[string]telemetry.DetectorSnapshot{}
	for _, d := range tel.Detectors {
		counters[d.Name] = d
	}

	global.mu.RLock()
	defer global.mu.RUnlock()
	out.Summary.LoadedTypes = global.loadedTypes
	for _, st := range global.sections {
		row := RuntimeStatus{Section: st.Section, Type: st.Type, Configured: st.Configured, Enabled: st.Enabled, Active: st.Active, InitOK: st.InitOK, LastError: st.LastError, SourceProbeOK: st.SourceProbeOK, SourceProbeMessage: st.SourceProbeMessage}
		if !st.LastRunAt.IsZero() {
			t := st.LastRunAt
			row.LastRunAt = &t
		}
		if !st.LastSuccessAt.IsZero() {
			t := st.LastSuccessAt
			row.LastSuccessAt = &t
		}
		if c, ok := counters[st.Section]; ok {
			row.Runs = c.Runs
			row.Failures = c.Failures
			row.Timeouts = c.Timeouts
		}
		if row.Configured {
			out.Summary.Configured++
		}
		if row.Enabled {
			out.Summary.Enabled++
		}
		if row.Active {
			out.Summary.Active++
		}
		out.Sections = append(out.Sections, row)
	}
	sort.Slice(out.Sections, func(i, j int) bool { return out.Sections[i].Section < out.Sections[j].Section })
	return out
}

func (s *store) ensure(section string) *runtimeState {
	if st, ok := s.sections[section]; ok {
		return st
	}
	st := &runtimeState{Section: section, Configured: true, Enabled: true}
	s.sections[section] = st
	return st
}
