package meta

import "sort"

type Preset struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Template    map[string]string `json:"template"`
}

type DetectorMeta struct {
	TypeKey             string            `json:"type_key"`
	Title               string            `json:"title"`
	Description         string            `json:"description"`
	DefaultsTemplate    map[string]string `json:"defaults_template"`
	ExamplePresets      []Preset          `json:"example_presets,omitempty"`
	LeniencySupported   bool              `json:"leniency_supported"`
	LeniencyRecommended bool              `json:"leniency_recommended"`
}

var registry = map[string]DetectorMeta{}

func Register(m DetectorMeta) {
	if m.TypeKey == "" {
		return
	}
	if m.DefaultsTemplate == nil {
		m.DefaultsTemplate = map[string]string{}
	}
	if m.ExamplePresets == nil {
		m.ExamplePresets = []Preset{}
	}
	registry[m.TypeKey] = cloneMeta(m)
}

func Catalog() []DetectorMeta {
	out := make([]DetectorMeta, 0, len(registry))
	for _, m := range registry {
		out = append(out, cloneMeta(m))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TypeKey < out[j].TypeKey })
	return out
}

func cloneMeta(in DetectorMeta) DetectorMeta {
	out := in
	out.DefaultsTemplate = cloneMap(in.DefaultsTemplate)
	out.ExamplePresets = make([]Preset, 0, len(in.ExamplePresets))
	for _, p := range in.ExamplePresets {
		out.ExamplePresets = append(out.ExamplePresets, Preset{ID: p.ID, Title: p.Title, Description: p.Description, Template: cloneMap(p.Template)})
	}
	return out
}

func cloneMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
