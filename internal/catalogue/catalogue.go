// Package catalogue provides action metadata: valid names, wildcard
// expansion and access-level classification.
//
// The tool never needs to know what an action *does*. For expansion it
// needs only the valid names, so this is pattern matching over a list,
// not semantics.
package catalogue

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
)

// Level is the provider's own classification of an action. It gives a
// large part of the severity model without manual curation.
type Level string

const (
	LevelRead            Level = "Read"
	LevelList            Level = "List"
	LevelWrite           Level = "Write"
	LevelTagging         Level = "Tagging"
	LevelPermissionsMgmt Level = "PermissionsManagement"
	LevelUnknown         Level = "Unknown"
)

// Catalogue is implemented once per cloud.
type Catalogue interface {
	Expand(pattern string) ([]string, error)
	AccessLevel(action string) Level
	Version() string
}

// Action is one catalogue entry.
type Action struct {
	Name  string `json:"name"`
	Level Level  `json:"level"`
}

// Static is a catalogue backed by an embedded snapshot. All three clouds
// use it; only the data file differs.
type Static struct {
	version string
	actions []Action
	byName  map[string]Level
}

type snapshot struct {
	Version string   `json:"version"`
	Actions []Action `json:"actions"`
}

// Load parses an embedded catalogue snapshot.
func Load(raw []byte) (*Static, error) {
	var s snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("catalogue: parse snapshot: %w", err)
	}
	c := &Static{version: s.Version, actions: s.Actions, byName: make(map[string]Level, len(s.Actions))}
	for _, a := range s.Actions {
		c.byName[strings.ToLower(a.Name)] = a.Level
	}
	sort.Slice(c.actions, func(i, j int) bool { return c.actions[i].Name < c.actions[j].Name })
	return c, nil
}

func (c *Static) Version() string { return c.version }

// Expand resolves a possibly-wildcarded pattern into concrete actions.
// Matching is case-insensitive because policy documents are.
func (c *Static) Expand(pattern string) ([]string, error) {
	if pattern == "" {
		return nil, fmt.Errorf("catalogue: empty action pattern")
	}
	if pattern == "*" {
		out := make([]string, 0, len(c.actions))
		for _, a := range c.actions {
			out = append(out, a.Name)
		}
		return out, nil
	}
	if !strings.ContainsAny(pattern, "*?") {
		if _, ok := c.byName[strings.ToLower(pattern)]; !ok {
			// Unknown actions are passed through rather than dropped: a
			// stale catalogue must never silently hide a real permission.
			return []string{pattern}, nil
		}
		return []string{pattern}, nil
	}
	lower := strings.ToLower(pattern)
	var out []string
	for _, a := range c.actions {
		ok, err := path.Match(lower, strings.ToLower(a.Name))
		if err != nil {
			return nil, fmt.Errorf("catalogue: bad pattern %q: %w", pattern, err)
		}
		if ok {
			out = append(out, a.Name)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("catalogue: pattern %q matched no known action (catalogue %s)", pattern, c.version)
	}
	return out, nil
}

func (c *Static) AccessLevel(action string) Level {
	if l, ok := c.byName[strings.ToLower(action)]; ok {
		return l
	}
	return LevelUnknown
}
