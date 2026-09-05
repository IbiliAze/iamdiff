// Package conformance defines the behavioural contract that every
// provider must satisfy.
//
// This is the single most important guard on the plug-in seam. Each
// cloud expresses a scenario in its own vocabulary via a fixture, but
// the assertions live here and are shared. If a new provider passes
// this suite, its evaluation semantics agree with the others where it
// matters -- and where they legitimately differ, the difference is
// visible as a fixture, not as a silent behavioural fork.
package conformance

import (
	"github.com/IbiliAze/iamdiff/internal/model"
)

// TB is the subset of testing.TB used here, so this package does not
// import testing and stays linkable from non-test code.
type TB interface {
	Helper()
	Errorf(format string, args ...any)
}

// Expectation describes the required outcome of a scenario.
//
// Conditional keys must be permitted and carry a condition; Unconditional
// keys must be permitted without one. Both imply Contains.
type Expectation struct {
	Contains      []model.GrantKey
	Excludes      []model.GrantKey
	Conditional   []model.GrantKey
	Unconditional []model.GrantKey
	Partial       bool
}

// Case is one scenario. Every provider ships a fixture named Name.
type Case struct {
	Name      string
	Rationale string
	Want      Expectation
}

func key(action, resource string) model.GrantKey {
	return model.GrantKey{Action: action, Resource: resource}
}

// Cases returns the contract. Adding a case here obliges every provider
// to satisfy it, which is the intended cost.
func Cases() []Case {
	return []Case{
		{
			Name:      "deny_beats_allow",
			Rationale: "An explicit deny anywhere must override any allow, in every cloud.",
			Want: Expectation{
				Excludes: []model.GrantKey{key("s3:DeleteObject", "*")},
				Contains: []model.GrantKey{key("s3:GetObject", "*")},
			},
		},
		{
			Name:      "wildcard_expansion",
			Rationale: "A wildcard action must expand to every concrete action it covers, so set comparison is exact.",
			Want: Expectation{
				Contains: []model.GrantKey{
					key("s3:GetObject", "*"),
					key("s3:GetObjectAcl", "*"),
					key("s3:GetBucketPolicy", "*"),
				},
				Excludes: []model.GrantKey{key("s3:PutObject", "*")},
			},
		},
		{
			Name:      "guardrail_blocks_identity",
			Rationale: "An organisation guardrail must be able to remove access an identity policy grants. This is the behaviour a single-document linter cannot model.",
			Want: Expectation{
				Contains: []model.GrantKey{key("s3:GetObject", "*")},
				Excludes: []model.GrantKey{key("ec2:TerminateInstances", "*")},
			},
		},
		{
			Name:      "unreachable_source_marks_partial",
			Rationale: "If any policy source could not be read, the result must be flagged partial. Silently returning an incomplete set is the one unacceptable failure.",
			Want:      Expectation{Partial: true},
		},
		{
			Name:      "deny_pattern_covers_specific",
			Rationale: "A deny on a broad resource pattern must remove an allow on any resource inside it. Matching denies by exact key would let a specific allow slip past a general deny.",
			Want: Expectation{
				Excludes: []model.GrantKey{key("s3:DeleteObject", "arn:aws:s3:::bucket/*")},
				Contains: []model.GrantKey{key("s3:GetObject", "arn:aws:s3:::bucket/*")},
			},
		},
		{
			Name:      "deny_on_other_resource_is_disjoint",
			Rationale: "A deny on an unrelated resource must not touch a grant, conditionally or otherwise. Over-eager denies would hide real access.",
			Want: Expectation{
				Unconditional: []model.GrantKey{key("s3:GetObject", "arn:aws:s3:::a/*")},
			},
		},
		{
			Name:      "guardrail_levels_intersect",
			Rationale: "Guardrails attached at different levels of a hierarchy must all permit an action; one permissive level cannot restore what another removes.",
			Want: Expectation{
				Contains: []model.GrantKey{key("s3:GetObject", "*")},
				Excludes: []model.GrantKey{key("ec2:DescribeInstances", "*")},
			},
		},
		{
			Name:      "guardrail_same_level_unions",
			Rationale: "Guardrails attached at the same level union, exactly as several policies attached to one target do.",
			Want: Expectation{
				Contains: []model.GrantKey{key("s3:GetObject", "*"), key("ec2:DescribeInstances", "*")},
				Excludes: []model.GrantKey{key("iam:GetRole", "*")},
			},
		},
		{
			Name:      "guardrail_narrows_resource",
			Rationale: "A guardrail that permits a subset of the resources an identity grant names narrows the grant to that subset rather than dropping it or keeping it whole.",
			Want: Expectation{
				Contains: []model.GrantKey{key("s3:GetObject", "arn:aws:s3:::bucket/*")},
				Excludes: []model.GrantKey{key("s3:GetObject", "*")},
			},
		},
		{
			Name:      "conditional_deny_composes_not_suppresses",
			Rationale: "Conditions are opaque, so a conditional deny cannot be known to apply. It must attach to the grant as a condition, never silently remove it, and never be silently ignored.",
			Want: Expectation{
				Conditional: []model.GrantKey{key("s3:GetObject", "*")},
			},
		},
		{
			Name:      "unconditional_allow_wins",
			Rationale: "When one statement allows a key unconditionally and another allows it under a condition, the effective grant is unconditional whatever the statement order.",
			Want: Expectation{
				Unconditional: []model.GrantKey{key("s3:GetObject", "*")},
			},
		},
		{
			Name:      "unknown_wildcard_marks_partial",
			Rationale: "A wildcard the catalogue cannot expand grants something the tool cannot see. That is a gap, not an empty set.",
			Want: Expectation{
				Contains: []model.GrantKey{key("s3:GetObject", "*")},
				Partial:  true,
			},
		},
	}
}

// Check asserts a provider's output against a case.
func Check(t TB, c Case, got *model.EffectiveSet) {
	t.Helper()

	allowed := map[model.GrantKey]bool{}
	for _, k := range got.Allowed() {
		allowed[k] = true
	}
	for _, want := range c.Want.Contains {
		if !allowed[want] {
			t.Errorf("%s: expected %s on %s to be permitted, it was not", c.Name, want.Action, want.Resource)
		}
	}
	for _, notWant := range c.Want.Excludes {
		if allowed[notWant] {
			t.Errorf("%s: expected %s on %s NOT to be permitted, it was", c.Name, notWant.Action, notWant.Resource)
		}
	}
	for _, want := range c.Want.Conditional {
		if !allowed[want] {
			t.Errorf("%s: expected %s on %s to be permitted under a condition, it was not permitted", c.Name, want.Action, want.Resource)
		} else if got.Grants[want].Condition.Empty() {
			t.Errorf("%s: expected %s on %s to carry a condition, it was unconditional", c.Name, want.Action, want.Resource)
		}
	}
	for _, want := range c.Want.Unconditional {
		if !allowed[want] {
			t.Errorf("%s: expected %s on %s to be permitted, it was not", c.Name, want.Action, want.Resource)
		} else if !got.Grants[want].Condition.Empty() {
			t.Errorf("%s: expected %s on %s to be unconditional, it carries %q", c.Name, want.Action, want.Resource, got.Grants[want].Condition.Summary)
		}
	}
	if got.Partial != c.Want.Partial {
		t.Errorf("%s: partial = %v, want %v", c.Name, got.Partial, c.Want.Partial)
	}
}
