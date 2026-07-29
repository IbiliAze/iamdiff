package diff

import (
	"encoding/json"
	"testing"

	"github.com/IbiliAze/iamdiff/internal/core/model"
)

func set(grants ...model.Grant) *model.EffectiveSet {
	s := model.NewEffectiveSet(model.Principal{Ref: "test"})
	for _, g := range grants {
		s.Add(g)
	}
	return s
}

func allow(action, resource string) model.Grant {
	return model.Grant{Action: action, Resource: resource, Effect: model.Allow}
}

func TestIdenticalSetsAreUnchanged(t *testing.T) {
	a := set(allow("s3:GetObject", "*"))
	b := set(allow("s3:GetObject", "*"))
	r := Compare(a, b)
	if !r.Empty() || r.Verdict() != VerdictUnchanged || r.ExitCode() != ExitUnchanged {
		t.Fatalf("expected unchanged, got %s (exit %d)", r.Verdict(), r.ExitCode())
	}
}

func TestAddedGrantWidens(t *testing.T) {
	before := set(allow("s3:GetObject", "*"))
	after := set(allow("s3:GetObject", "*"), allow("s3:DeleteObject", "*"))
	r := Compare(before, after)
	if r.Verdict() != VerdictWidened {
		t.Fatalf("verdict = %s, want widened", r.Verdict())
	}
	if r.ExitCode() != ExitWidened {
		t.Fatalf("exit = %d, want %d", r.ExitCode(), ExitWidened)
	}
	if len(r.Added) != 1 || r.Added[0].Key.Action != "s3:DeleteObject" {
		t.Fatalf("added = %+v", r.Added)
	}
}

func TestRemovedGrantNarrows(t *testing.T) {
	before := set(allow("s3:GetObject", "*"), allow("s3:DeleteObject", "*"))
	after := set(allow("s3:GetObject", "*"))
	if v := Compare(before, after).Verdict(); v != VerdictNarrowed {
		t.Fatalf("verdict = %s, want narrowed", v)
	}
}

// A condition-only change must be its own category. Treating it as an
// add plus a remove would be actively misleading in a review.
func TestConditionChangeIsIndeterminate(t *testing.T) {
	g := allow("sts:AssumeRole", "*")
	g.Condition = model.NewCondition(json.RawMessage(`{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`))
	before := set(g)
	after := set(allow("sts:AssumeRole", "*"))

	r := Compare(before, after)
	if r.Verdict() != VerdictIndeterminate {
		t.Fatalf("verdict = %s, want indeterminate", r.Verdict())
	}
	if len(r.Added) != 0 || len(r.Removed) != 0 || len(r.Changed) != 1 {
		t.Fatalf("expected exactly one changed delta, got +%d -%d ~%d", len(r.Added), len(r.Removed), len(r.Changed))
	}
}

// Key ordering inside a condition must not register as a change.
func TestConditionFingerprintIsOrderIndependent(t *testing.T) {
	a := model.NewCondition(json.RawMessage(`{"StringEquals":{"a":"1","b":"2"}}`))
	b := model.NewCondition(json.RawMessage(`{"StringEquals":{"b":"2","a":"1"}}`))
	if a.Fingerprint != b.Fingerprint {
		t.Fatalf("fingerprints differ: %s vs %s", a.Fingerprint, b.Fingerprint)
	}
}

// Incompleteness outranks every other verdict: a partial evaluation
// cannot honestly claim access did not widen.
func TestPartialOutranksEverything(t *testing.T) {
	before := set(allow("s3:GetObject", "*"))
	after := set(allow("s3:GetObject", "*"))
	after.MarkGap("SCPs unreachable")

	r := Compare(before, after)
	if r.Verdict() != VerdictIncomplete || r.ExitCode() != ExitIncomplete {
		t.Fatalf("verdict = %s exit = %d, want incomplete/%d", r.Verdict(), r.ExitCode(), ExitIncomplete)
	}
}

func TestDiffAgainstSelfIsEmpty(t *testing.T) {
	s := set(allow("iam:PassRole", "arn:aws:iam::123:role/x"), allow("s3:GetObject", "*"))
	if !Compare(s, s).Empty() {
		t.Fatal("diffing a set against itself must be empty")
	}
}
