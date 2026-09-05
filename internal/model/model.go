// Package model defines the provider-neutral domain types.
//
// Nothing in this package may reference a specific cloud. No ARNs, no
// scopes, no subscription IDs, no role definitions. If a cloud-shaped
// concept appears here, the provider abstraction has leaked.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// Effect is the resolved effect of a grant.
type Effect uint8

const (
	Allow Effect = iota
	Deny
)

func (e Effect) String() string {
	if e == Deny {
		return "Deny"
	}
	return "Allow"
}

// SourceKind classifies where a grant came from. Deliberately generic:
// every cloud has identity-attached policy and organisation-level
// guardrails, whatever it happens to call them.
type SourceKind string

const (
	SourceIdentity  SourceKind = "identity"
	SourceGroup     SourceKind = "group"
	SourceBoundary  SourceKind = "boundary"
	SourceGuardrail SourceKind = "guardrail"
	SourceResource  SourceKind = "resource"
)

// Origin records provenance so explain mode can reconstruct a decision
// path without re-querying the cloud.
type Origin struct {
	SourceKind SourceKind `json:"source_kind"`
	SourceName string     `json:"source_name"`
	SourceRef  string     `json:"source_ref,omitempty"`
	Statement  int        `json:"statement"`
	Inherited  []string   `json:"inherited,omitempty"`
}

// Condition is opaque to the core. It is compared by fingerprint only;
// semantic equivalence is an explicit non-goal (see docs/adr/0002).
//
// A condition is either a statement's own condition block or a
// composition of clauses (see ComposeCondition); Parts is set only for
// the latter.
type Condition struct {
	Raw         json.RawMessage `json:"raw,omitempty"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	Summary     string          `json:"summary,omitempty"`
	Parts       []ConditionPart `json:"parts,omitempty"`
}

// NewCondition canonicalises a raw condition document and fingerprints it.
// Canonicalisation relies on encoding/json sorting object keys, so
// semantically identical documents with differing key order agree.
func NewCondition(raw json.RawMessage) Condition {
	if len(raw) == 0 {
		return Condition{}
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return Condition{Raw: raw, Fingerprint: hash(raw), Summary: "unparseable"}
	}
	canon, err := json.Marshal(v)
	if err != nil {
		return Condition{Raw: raw, Fingerprint: hash(raw)}
	}
	return Condition{Raw: raw, Fingerprint: hash(canon), Summary: string(canon)}
}

func (c Condition) Empty() bool { return c.Fingerprint == "" }

func hash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:8])
}

// GrantKey identifies a permission independently of its condition, so a
// condition-only change is detectable as its own category rather than as
// an unrelated addition plus removal.
type GrantKey struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

// Grant is a single atomic, fully resolved permission fact.
type Grant struct {
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Effect    Effect    `json:"-"`
	Condition Condition `json:"condition,omitempty"`
	Origin    Origin    `json:"origin"`
}

func (g Grant) Key() GrantKey { return GrantKey{Action: g.Action, Resource: g.Resource} }

// Principal is whatever the provider considers an identity.
type Principal struct {
	Provider string `json:"provider"`
	Kind     string `json:"kind"`
	Ref      string `json:"ref"`
}

// EffectiveSet is the fully resolved permission set for one principal.
//
// Partial must be set whenever any policy source could not be reached.
// Reporting an incomplete result as though it were complete is the one
// failure mode that would make the whole tool untrustworthy.
type EffectiveSet struct {
	Principal Principal          `json:"principal"`
	Grants    map[GrantKey]Grant `json:"-"`
	Partial   bool               `json:"partial"`
	Gaps      []string           `json:"gaps,omitempty"`
	Catalogue string             `json:"catalogue_version,omitempty"`
}

func NewEffectiveSet(p Principal) *EffectiveSet {
	return &EffectiveSet{Principal: p, Grants: map[GrantKey]Grant{}}
}

// Add inserts a grant, honouring universal deny precedence: an explicit
// deny on a key is never overwritten by a later allow. Every cloud
// examined shares this rule, so it belongs in the core rather than in
// each provider.
//
// Two allows on the same key merge to the broader one: an unconditional
// allow beats a conditional allow whatever order they arrive in, and two
// different conditions compose as "any", since the grant holds under
// either. Letting the later statement win would let a conditional grant
// hide an unconditional one behind a condition-changed verdict.
func (s *EffectiveSet) Add(g Grant) {
	k := g.Key()
	existing, ok := s.Grants[k]
	if !ok || existing.Effect == Deny {
		if !ok {
			s.Grants[k] = g
		}
		return
	}
	if g.Effect == Deny {
		s.Grants[k] = g
		return
	}
	switch {
	case existing.Condition.Empty():
		return
	case g.Condition.Empty():
		s.Grants[k] = g
	case existing.Condition.Fingerprint == g.Condition.Fingerprint:
		return
	default:
		merged := existing
		merged.Condition = Any(existing.Condition, g.Condition)
		s.Grants[k] = merged
	}
}

// MarkGap records an unreachable source and flags the set as partial.
func (s *EffectiveSet) MarkGap(reason string) {
	s.Partial = true
	s.Gaps = append(s.Gaps, reason)
}

// Allowed returns the sorted keys of grants that survive as allows.
func (s *EffectiveSet) Allowed() []GrantKey {
	keys := make([]GrantKey, 0, len(s.Grants))
	for k, g := range s.Grants {
		if g.Effect == Allow {
			keys = append(keys, k)
		}
	}
	sortKeys(keys)
	return keys
}

func sortKeys(keys []GrantKey) {
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Action != keys[j].Action {
			return keys[i].Action < keys[j].Action
		}
		return keys[i].Resource < keys[j].Resource
	})
}

// Trace is the output of explain mode: the layers that decided whether
// one principal may take one action on one resource.
//
// Conditional means the action is permitted only while some condition
// holds; which one is in Condition, opaque as ever. Partial means a
// source could not be read, so a denial may be wrong and a permission
// may be missing a restriction.
type Trace struct {
	Principal   Principal `json:"principal"`
	Action      string    `json:"action"`
	Resource    string    `json:"resource"`
	Permitted   bool      `json:"permitted"`
	Conditional bool      `json:"conditional,omitempty"`
	Condition   string    `json:"condition,omitempty"`
	Partial     bool      `json:"partial,omitempty"`
	Gaps        []string  `json:"gaps,omitempty"`
	Steps       []Step    `json:"steps"`
}

// Step is one layer's contribution to the decision.
type Step struct {
	Layer   string `json:"layer"`
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}
