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
	"github.com/IbiliAze/iamdiff/internal/core/model"
)

// TB is the subset of testing.TB used here, so this package does not
// import testing and stays linkable from non-test code.
type TB interface {
	Helper()
	Errorf(format string, args ...any)
}

// Expectation describes the required outcome of a scenario.
type Expectation struct {
	Contains []model.GrantKey
	Excludes []model.GrantKey
	Partial  bool
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
	if got.Partial != c.Want.Partial {
		t.Errorf("%s: partial = %v, want %v", c.Name, got.Partial, c.Want.Partial)
	}
}
