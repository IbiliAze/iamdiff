package provider

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Config is provider-agnostic construction input.
type Config struct {
	Profile  string
	Scope    string
	OrgScope string // where organisation-level guardrails are read from
	Offline  bool
}

// Factory constructs a provider.
type Factory func(Config) (Provider, error)

var (
	mu       sync.RWMutex
	registry = map[string]Factory{}
)

// Register wires a provider into the registry. Called from each
// provider package's init, mirroring database/sql drivers.
func Register(name string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[name]; dup {
		panic("provider: duplicate registration for " + name)
	}
	registry[name] = f
}

// Open constructs a registered provider by name.
func Open(name string, cfg Config) (Provider, error) {
	mu.RLock()
	f, ok := registry[name]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown provider %q (available: %s)", name, strings.Join(Available(), ", "))
	}
	return f(cfg)
}

// Available lists registered provider names.
func Available() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
