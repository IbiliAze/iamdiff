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
	"sort"
	"strings"

	"github.com/IbiliAze/iamdiff/internal/glob"
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
	// Expand resolves a possibly-wildcarded pattern into the concrete
	// actions it names. A pattern that matches nothing yields an empty
	// slice and no error: the caller decides whether that is a gap.
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
	lower   []string // actions[i].Name lower-cased, for wildcard matching
	byName  map[string]Level
	canon   map[string]string // lower-cased name -> catalogue spelling
}

type snapshot struct {
	Version string   `json:"version"`
	Actions []Action `json:"actions"`
}

// Load parses an embedded catalogue snapshot. Names that differ only by
// case collapse to one entry, preferring whichever carries a level:
// policy documents are case-insensitive, so the catalogue must be too.
func Load(raw []byte) (*Static, error) {
	var s snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("catalogue: parse snapshot: %w", err)
	}
	c := &Static{
		version: s.Version,
		byName:  make(map[string]Level, len(s.Actions)),
		canon:   make(map[string]string, len(s.Actions)),
	}
	index := make(map[string]int, len(s.Actions))
	for _, a := range s.Actions {
		if a.Level == "" {
			a.Level = LevelUnknown
		}
		key := strings.ToLower(a.Name)
		if i, dup := index[key]; dup {
			if c.actions[i].Level == LevelUnknown && a.Level != LevelUnknown {
				c.actions[i] = a
				c.byName[key] = a.Level
				c.canon[key] = a.Name
			}
			continue
		}
		index[key] = len(c.actions)
		c.actions = append(c.actions, a)
		c.byName[key] = a.Level
		c.canon[key] = a.Name
	}
	sort.Slice(c.actions, func(i, j int) bool { return c.actions[i].Name < c.actions[j].Name })
	c.lower = make([]string, len(c.actions))
	for i, a := range c.actions {
		c.lower[i] = strings.ToLower(a.Name)
	}
	return c, nil
}

func (c *Static) Version() string { return c.version }

// Len reports the number of distinct actions in the catalogue.
func (c *Static) Len() int { return len(c.actions) }

// Expand resolves a possibly-wildcarded pattern into concrete actions.
// Matching is case-insensitive because policy documents are.
//
// A concrete action comes back in the catalogue's spelling, so two
// documents that write it differently agree. One the catalogue has never
// heard of is passed through rather than dropped: a stale catalogue must
// never silently hide a real permission. A wildcard that matches nothing
// returns an empty slice so the caller can record a gap.
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
	if glob.IsLiteral(pattern) {
		if name, ok := c.canon[strings.ToLower(pattern)]; ok {
			return []string{name}, nil
		}
		return []string{pattern}, nil
	}
	lower := strings.ToLower(pattern)
	var out []string
	for i, a := range c.actions {
		if glob.Match(lower, c.lower[i], false) {
			out = append(out, a.Name)
		}
	}
	return out, nil
}

func (c *Static) AccessLevel(action string) Level {
	if l, ok := c.byName[strings.ToLower(action)]; ok {
		return l
	}
	return LevelUnknown
}
