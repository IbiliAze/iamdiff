package model

import (
	"encoding/json"
	"testing"
)

func cond(raw string) Condition { return NewCondition(json.RawMessage(raw)) }

func grant(action, resource string, c Condition) Grant {
	return Grant{Action: action, Resource: resource, Effect: Allow, Condition: c}
}

func TestAddUnconditionalAllowWinsInEitherOrder(t *testing.T) {
	mfa := cond(`{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`)
	for name, order := range map[string][]Grant{
		"conditional first":   {grant("s3:GetObject", "*", mfa), grant("s3:GetObject", "*", Condition{})},
		"unconditional first": {grant("s3:GetObject", "*", Condition{}), grant("s3:GetObject", "*", mfa)},
	} {
		s := NewEffectiveSet(Principal{Ref: "t"})
		for _, g := range order {
			s.Add(g)
		}
		if got := s.Grants[GrantKey{"s3:GetObject", "*"}]; !got.Condition.Empty() {
			t.Errorf("%s: condition survived: %s", name, got.Condition.Summary)
		}
	}
}

func TestAddTwoConditionsComposeAsAnyOrderIndependently(t *testing.T) {
	a := cond(`{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`)
	b := cond(`{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`)
	c := cond(`{"StringEquals":{"aws:PrincipalTag/team":"x"}}`)
	fp := func(order ...Condition) Condition {
		s := NewEffectiveSet(Principal{Ref: "t"})
		for _, c := range order {
			s.Add(grant("s3:GetObject", "*", c))
		}
		return s.Grants[GrantKey{"s3:GetObject", "*"}].Condition
	}
	x, y := fp(a, b, c), fp(c, b, a)
	if x.Fingerprint != y.Fingerprint {
		t.Fatalf("order-dependent fingerprint: %s vs %s", x.Fingerprint, y.Fingerprint)
	}
	if x.Fingerprint == a.Fingerprint || x.Fingerprint == b.Fingerprint {
		t.Fatal("composed condition must differ from its parts")
	}
	if len(x.Parts) != 3 || x.Parts[0].Role != RoleAny {
		t.Fatalf("parts = %+v", x.Parts)
	}
	if same := fp(a, a); same.Fingerprint != a.Fingerprint {
		t.Fatal("the same condition twice must not compose with itself")
	}
}

func TestAddDenyPrecedence(t *testing.T) {
	s := NewEffectiveSet(Principal{Ref: "t"})
	s.Add(grant("s3:GetObject", "*", Condition{}))
	s.Add(Grant{Action: "s3:GetObject", Resource: "*", Effect: Deny})
	s.Add(grant("s3:GetObject", "*", Condition{}))
	if len(s.Allowed()) != 0 {
		t.Fatal("deny was overwritten by a later allow")
	}
}

func TestComposeConditionIsCanonical(t *testing.T) {
	a := cond(`{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`)
	b := cond(`{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`)
	x := ComposeCondition(Part(RoleRequire, a, ""), Part(RoleUnless, b, ""))
	y := ComposeCondition(Part(RoleUnless, b, ""), Part(RoleRequire, a, ""))
	if x.Fingerprint != y.Fingerprint || x.Fingerprint == "" {
		t.Fatalf("fingerprints %q vs %q", x.Fingerprint, y.Fingerprint)
	}
	if !json.Valid(x.Raw) {
		t.Fatalf("raw is not JSON: %s", x.Raw)
	}
	if x.Summary == "" {
		t.Fatal("empty summary")
	}
}

func TestComposeConditionLoneRequireIsTransparent(t *testing.T) {
	a := cond(`{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`)
	if got := ComposeCondition(Part(RoleRequire, a, "")); got.Fingerprint != a.Fingerprint {
		t.Fatalf("lone require changed the fingerprint: %s vs %s", got.Fingerprint, a.Fingerprint)
	}
	if got := ComposeCondition(Part(RoleRequire, Condition{}, "")); !got.Empty() {
		t.Fatal("empty parts must compose to an empty condition")
	}
}

func TestComposeConditionCarveOutIsItsOwnClause(t *testing.T) {
	a := ComposeCondition(Part(RoleUnless, Condition{}, "except arn:aws:s3:::secret/*"))
	b := ComposeCondition(Part(RoleUnless, Condition{}, "except arn:aws:s3:::other/*"))
	if a.Empty() || a.Fingerprint == b.Fingerprint {
		t.Fatalf("carve-outs must be distinct, non-empty conditions: %+v %+v", a, b)
	}
}
