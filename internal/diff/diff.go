// Package diff compares two effective permission sets.
//
// It knows nothing about any cloud: it operates purely on model types.
// Adding a provider must never require a change in this package.
package diff

import (
	"sort"

	"github.com/IbiliAze/iamdiff/internal/model"
)

type Kind uint8

const (
	Added Kind = iota
	Removed
	ConditionChanged
)

func (k Kind) Symbol() string {
	switch k {
	case Added:
		return "+"
	case Removed:
		return "-"
	default:
		return "~"
	}
}

// Delta is one classified difference.
type Delta struct {
	Kind   Kind           `json:"kind"`
	Key    model.GrantKey `json:"key"`
	Before *model.Grant   `json:"before,omitempty"`
	After  *model.Grant   `json:"after,omitempty"`
}

// Result is the full comparison outcome.
type Result struct {
	Added   []Delta  `json:"added"`
	Removed []Delta  `json:"removed"`
	Changed []Delta  `json:"changed"`
	Partial bool     `json:"partial"`
	Gaps    []string `json:"gaps,omitempty"`
}

type Verdict string

const (
	VerdictUnchanged     Verdict = "unchanged"
	VerdictNarrowed      Verdict = "narrowed"
	VerdictWidened       Verdict = "widened"
	VerdictIndeterminate Verdict = "indeterminate"
	VerdictIncomplete    Verdict = "incomplete"
)

// Exit codes are part of the tool's public contract. Changing them is a
// breaking change for every pipeline that consumes the tool.
const (
	ExitUnchanged     = 0
	ExitNarrowed      = 1
	ExitWidened       = 2
	ExitIndeterminate = 3
	ExitIncomplete    = 4
)

// Compare produces the set difference between two evaluated sets.
func Compare(before, after *model.EffectiveSet) Result {
	res := Result{
		Partial: before.Partial || after.Partial,
		Gaps:    append(append([]string{}, before.Gaps...), after.Gaps...),
	}

	for _, k := range after.Allowed() {
		a := after.Grants[k]
		b, ok := before.Grants[k]
		switch {
		case !ok || b.Effect == model.Deny:
			g := a
			res.Added = append(res.Added, Delta{Kind: Added, Key: k, After: &g})
		case b.Condition.Fingerprint != a.Condition.Fingerprint:
			bb, aa := b, a
			res.Changed = append(res.Changed, Delta{Kind: ConditionChanged, Key: k, Before: &bb, After: &aa})
		}
	}

	for _, k := range before.Allowed() {
		if g, ok := after.Grants[k]; !ok || g.Effect == model.Deny {
			b := before.Grants[k]
			res.Removed = append(res.Removed, Delta{Kind: Removed, Key: k, Before: &b})
		}
	}

	sortDeltas(res.Added)
	sortDeltas(res.Removed)
	sortDeltas(res.Changed)
	return res
}

func sortDeltas(d []Delta) {
	sort.Slice(d, func(i, j int) bool {
		if d[i].Key.Action != d[j].Key.Action {
			return d[i].Key.Action < d[j].Key.Action
		}
		return d[i].Key.Resource < d[j].Key.Resource
	})
}

// Verdict collapses the result into a single judgement.
//
// Precedence is deliberate: incompleteness outranks everything, because
// a partial evaluation cannot honestly claim that access did not widen.
func (r Result) Verdict() Verdict {
	switch {
	case r.Partial:
		return VerdictIncomplete
	case len(r.Added) > 0:
		return VerdictWidened
	case len(r.Changed) > 0:
		return VerdictIndeterminate
	case len(r.Removed) > 0:
		return VerdictNarrowed
	default:
		return VerdictUnchanged
	}
}

func (r Result) ExitCode() int {
	switch r.Verdict() {
	case VerdictIncomplete:
		return ExitIncomplete
	case VerdictWidened:
		return ExitWidened
	case VerdictIndeterminate:
		return ExitIndeterminate
	case VerdictNarrowed:
		return ExitNarrowed
	default:
		return ExitUnchanged
	}
}

func (r Result) Empty() bool {
	return len(r.Added) == 0 && len(r.Removed) == 0 && len(r.Changed) == 0
}
