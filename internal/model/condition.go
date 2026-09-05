package model

import (
	"encoding/json"
	"sort"
	"strings"
)

// Roles a clause can play inside a composed condition.
const (
	// RoleRequire: the grant holds only while this condition is met, as
	// with a conditional identity allow or a conditional guardrail allow.
	RoleRequire = "require"
	// RoleUnless: the grant is withdrawn while this condition is met, as
	// with a conditional explicit deny. A clause with a Note and no
	// condition is a carve-out: a deny that removes part of the grant's
	// resource pattern, which no single pattern can express.
	RoleUnless = "unless"
	// RoleAny: the grant holds under whichever of several conditions is
	// met, as when two statements allow the same key under different
	// conditions.
	RoleAny = "any"
)

// ConditionPart is one clause of a composed condition.
type ConditionPart struct {
	Role        string `json:"role"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Summary     string `json:"summary,omitempty"`
	Note        string `json:"note,omitempty"`
}

// Part builds a clause from a condition and an optional note.
func Part(role string, c Condition, note string) ConditionPart {
	return ConditionPart{Role: role, Fingerprint: c.Fingerprint, Summary: c.Summary, Note: note}
}

// ComposeCondition folds several clauses into one opaque condition.
//
// Conditions stay opaque (ADR-0002): composition never reasons about
// what a clause means, only about which clauses are present. The result
// is canonical, so the same clauses in any order produce the same
// fingerprint, and a change to any clause changes it. A lone "require"
// clause with no note is returned unchanged, so a grant carrying only
// its own statement's condition keeps that condition's fingerprint.
func ComposeCondition(parts ...ConditionPart) Condition {
	var kept []ConditionPart
	for _, p := range parts {
		if p.Fingerprint == "" && p.Note == "" {
			continue
		}
		kept = append(kept, p)
	}
	if len(kept) == 0 {
		return Condition{}
	}
	if len(kept) == 1 && kept[0].Role == RoleRequire && kept[0].Note == "" {
		return Condition{Fingerprint: kept[0].Fingerprint, Summary: kept[0].Summary, Raw: nil}
	}
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].Role != kept[j].Role {
			return kept[i].Role < kept[j].Role
		}
		if kept[i].Fingerprint != kept[j].Fingerprint {
			return kept[i].Fingerprint < kept[j].Fingerprint
		}
		return kept[i].Note < kept[j].Note
	})
	canon, _ := json.Marshal(kept)
	var summary []string
	for _, p := range kept {
		switch {
		case p.Note != "" && p.Summary != "":
			summary = append(summary, p.Role+" "+p.Summary+" ("+p.Note+")")
		case p.Note != "":
			summary = append(summary, p.Role+" "+p.Note)
		default:
			summary = append(summary, p.Role+" "+p.Summary)
		}
	}
	return Condition{
		Raw:         canon,
		Fingerprint: hash(canon),
		Summary:     strings.Join(summary, "; "),
		Parts:       kept,
	}
}

// Any composes two allow conditions on the same key: the grant holds
// under either. Flattening keeps the result independent of the order in
// which statements were seen.
func Any(a, b Condition) Condition {
	var parts []ConditionPart
	for _, c := range []Condition{a, b} {
		if len(c.Parts) > 0 && c.Parts[0].Role == RoleAny {
			parts = append(parts, c.Parts...)
			continue
		}
		parts = append(parts, Part(RoleAny, c, ""))
	}
	return ComposeCondition(dedupe(parts)...)
}

func dedupe(parts []ConditionPart) []ConditionPart {
	seen := map[ConditionPart]bool{}
	var out []ConditionPart
	for _, p := range parts {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
