package aws

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/IbiliAze/iamdiff/internal/model"
	"github.com/IbiliAze/iamdiff/internal/provider"
)

func doc(kind model.SourceKind, name, target, body string) provider.Document {
	return provider.Document{Kind: kind, Name: name, Target: target, Body: json.RawMessage(body)}
}

func identity(name, body string) provider.Document { return doc(model.SourceIdentity, name, "", body) }
func boundary(name, body string) provider.Document { return doc(model.SourceBoundary, name, "", body) }
func guardrail(name, target, body string) provider.Document {
	return doc(model.SourceGuardrail, name, target, body)
}

func policy(statements ...string) string {
	return `{"Version":"2012-10-17","Statement":[` + strings.Join(statements, ",") + `]}`
}

func evaluate(t *testing.T, p *Provider, docs ...provider.Document) *model.EffectiveSet {
	t.Helper()
	raw := &provider.RawSet{Principal: model.Principal{Provider: Name, Kind: "role", Ref: "t"}, Documents: docs}
	got, err := p.Evaluate(context.Background(), raw)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return got
}

func key(action, resource string) model.GrantKey {
	return model.GrantKey{Action: action, Resource: resource}
}

func allowed(t *testing.T, set *model.EffectiveSet, k model.GrantKey) model.Grant {
	t.Helper()
	g, ok := set.Grants[k]
	if !ok || g.Effect != model.Allow {
		t.Fatalf("%s on %s should be allowed; allowed keys: %v", k.Action, k.Resource, set.Allowed())
	}
	return g
}

func notAllowed(t *testing.T, set *model.EffectiveSet, k model.GrantKey) {
	t.Helper()
	if g, ok := set.Grants[k]; ok && g.Effect == model.Allow {
		t.Fatalf("%s on %s should NOT be allowed (condition %q)", k.Action, k.Resource, g.Condition.Summary)
	}
}

const mfa = `"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`

// B1: a deny is applied by coverage, not by exact key.
func TestDenyOnBroaderResourceSuppressesSpecificAllow(t *testing.T) {
	p := newSeedProvider(t)
	set := evaluate(t, p,
		identity("allow", policy(`{"Effect":"Allow","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::b/*"}`)),
		identity("deny", policy(`{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}`)),
	)
	notAllowed(t, set, key("s3:DeleteObject", "arn:aws:s3:::b/*"))
	if set.Partial {
		t.Fatalf("unexpected gaps: %v", set.Gaps)
	}
}

func TestDenyOnDisjointResourceIsIgnored(t *testing.T) {
	p := newSeedProvider(t)
	set := evaluate(t, p,
		identity("allow", policy(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::a/*"}`)),
		identity("deny", policy(`{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`)),
	)
	g := allowed(t, set, key("s3:GetObject", "arn:aws:s3:::a/*"))
	if !g.Condition.Empty() {
		t.Fatalf("unexpected condition %q", g.Condition.Summary)
	}
}

// ADR-0005: a deny that removes only part of a grant becomes a carve-out
// clause, never silence.
func TestDenyNarrowerThanGrantBecomesCarveOut(t *testing.T) {
	p := newSeedProvider(t)
	set := evaluate(t, p,
		identity("allow", policy(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`)),
		identity("deny", policy(`{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/secret/*"}`)),
	)
	g := allowed(t, set, key("s3:GetObject", "arn:aws:s3:::b/*"))
	if g.Condition.Empty() || !strings.Contains(g.Condition.Summary, "except arn:aws:s3:::b/secret/*") {
		t.Fatalf("condition = %q, want a carve-out", g.Condition.Summary)
	}
	if set.Partial {
		t.Fatalf("a carve-out must not be a gap: %v", set.Gaps)
	}
}

// B2: '*' and '?' anywhere in a guardrail's action pattern.
func TestGuardrailMidStringWildcards(t *testing.T) {
	p := newSeedProvider(t)
	set := evaluate(t, p,
		identity("id", policy(`{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:ListBucket","s3:GetObjectAcl"],"Resource":"*"}`)),
		guardrail("scp", "", policy(`{"Effect":"Allow","Action":["s3:*Object","s3:Get?bjectAcl"],"Resource":"*"}`)),
	)
	allowed(t, set, key("s3:GetObject", "*"))
	allowed(t, set, key("s3:PutObject", "*"))
	allowed(t, set, key("s3:GetObjectAcl", "*"))
	notAllowed(t, set, key("s3:ListBucket", "*"))
}

// B3: actions are case-insensitive, resources are not.
func TestActionCaseFoldsButResourceCaseDoesNot(t *testing.T) {
	p := newSeedProvider(t)
	set := evaluate(t, p,
		identity("id", policy(
			`{"Effect":"Allow","Action":"S3:GETOBJECT","Resource":"*"}`,
			`{"Effect":"Allow","Action":"iam:GetRole","Resource":"arn:aws:iam::1:role/Deploy"}`,
		)),
		guardrail("scp", "", policy(
			`{"Effect":"Allow","Action":"s3:getobject","Resource":"*"}`,
			`{"Effect":"Allow","Action":"IAM:*","Resource":"arn:aws:iam::1:role/deploy"}`,
		)),
	)
	allowed(t, set, key("s3:GetObject", "*"))
	notAllowed(t, set, key("iam:GetRole", "arn:aws:iam::1:role/Deploy"))
}

// B4: guardrails intersect per target and union within one.
func TestGuardrailTargetsIntersectAndSameTargetUnions(t *testing.T) {
	p := newSeedProvider(t)
	id := identity("id", policy(`{"Effect":"Allow","Action":["s3:GetObject","ec2:DescribeInstances","iam:GetRole"],"Resource":"*"}`))

	set := evaluate(t, p, id,
		guardrail("FullAWSAccess", "r-root", policy(`{"Effect":"Allow","Action":"*","Resource":"*"}`)),
		guardrail("OnlyS3", "ou-prod", policy(`{"Effect":"Allow","Action":"s3:*","Resource":"*"}`)),
		guardrail("AlsoEC2", "ou-prod", policy(`{"Effect":"Allow","Action":"ec2:*","Resource":"*"}`)),
	)
	allowed(t, set, key("s3:GetObject", "*"))
	allowed(t, set, key("ec2:DescribeInstances", "*"))
	notAllowed(t, set, key("iam:GetRole", "*"))

	// With no target every guardrail document shares one layer.
	set = evaluate(t, p, id,
		guardrail("a", "", policy(`{"Effect":"Allow","Action":"s3:*","Resource":"*"}`)),
		guardrail("b", "", policy(`{"Effect":"Allow","Action":"ec2:*","Resource":"*"}`)),
	)
	allowed(t, set, key("s3:GetObject", "*"))
	allowed(t, set, key("ec2:DescribeInstances", "*"))
	notAllowed(t, set, key("iam:GetRole", "*"))
}

// B5: conditions on guardrail allows and on denies compose into the
// grant rather than being dropped or treated as unconditional.
func TestConditionalGuardrailAndDenyCompose(t *testing.T) {
	p := newSeedProvider(t)
	id := identity("id", policy(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`))

	set := evaluate(t, p, id, guardrail("scp", "", policy(`{"Effect":"Allow","Action":"s3:*","Resource":"*",`+mfa+`}`)))
	g := allowed(t, set, key("s3:GetObject", "*"))
	if g.Condition.Empty() {
		t.Fatal("conditional guardrail allow was dropped")
	}

	withDeny := evaluate(t, p, id, identity("deny", policy(`{"Effect":"Deny","Action":"s3:GetObject","Resource":"*",`+mfa+`}`)))
	d := allowed(t, withDeny, key("s3:GetObject", "*"))
	if d.Condition.Empty() {
		t.Fatal("conditional deny should compose, not be ignored")
	}
	plain := allowed(t, evaluate(t, p, id), key("s3:GetObject", "*"))
	if d.Condition.Fingerprint == plain.Condition.Fingerprint || d.Condition.Fingerprint == g.Condition.Fingerprint {
		t.Fatal("removing a conditional deny must change the fingerprint")
	}
}

// B6: NotAction is the catalogue's complement; NotResource is a carve-out.
func TestNotActionAndNotResource(t *testing.T) {
	p := newSeedProvider(t)
	set := evaluate(t, p, identity("id", policy(`{"Effect":"Allow","NotAction":"s3:*","Resource":"*"}`)))
	allowed(t, set, key("ec2:DescribeInstances", "*"))
	notAllowed(t, set, key("s3:GetObject", "*"))

	set = evaluate(t, p,
		identity("id", policy(`{"Effect":"Allow","Action":["s3:GetObject","iam:PassRole"],"Resource":"*"}`)),
		guardrail("scp", "", policy(`{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}`)),
	)
	allowed(t, set, key("s3:GetObject", "*"))
	notAllowed(t, set, key("iam:PassRole", "*"))

	set = evaluate(t, p, identity("id", policy(`{"Effect":"Allow","Action":"s3:GetObject","NotResource":"arn:aws:s3:::secret/*"}`)))
	g := allowed(t, set, key("s3:GetObject", "*"))
	if !strings.Contains(g.Condition.Summary, "except arn:aws:s3:::secret/*") {
		t.Fatalf("condition = %q", g.Condition.Summary)
	}

	deny := identity("deny", policy(`{"Effect":"Deny","Action":"s3:*","NotResource":"arn:aws:s3:::ok/*"}`))
	set = evaluate(t, p, deny, identity("id", policy(
		`{"Effect":"Allow","Action":"s3:GetObject","Resource":["arn:aws:s3:::ok/*","arn:aws:s3:::other/*","*"]}`,
	)))
	if g := allowed(t, set, key("s3:GetObject", "arn:aws:s3:::ok/*")); !g.Condition.Empty() {
		t.Fatalf("resource excluded from the deny should be unconditional, got %q", g.Condition.Summary)
	}
	notAllowed(t, set, key("s3:GetObject", "arn:aws:s3:::other/*"))
	if g := allowed(t, set, key("s3:GetObject", "*")); g.Condition.Empty() {
		t.Fatal("a deny with NotResource takes a bite out of *; expected a carve-out")
	}
}

// B7: statement order cannot hide an unconditional allow.
func TestUnconditionalAllowWinsInEitherOrder(t *testing.T) {
	p := newSeedProvider(t)
	cond := `{"Effect":"Allow","Action":"s3:GetObject","Resource":"*",` + mfa + `}`
	plain := `{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`
	for _, order := range [][]string{{cond, plain}, {plain, cond}} {
		g := allowed(t, evaluate(t, p, identity("id", policy(order...))), key("s3:GetObject", "*"))
		if !g.Condition.Empty() {
			t.Fatalf("order %v: condition %q survived", order, g.Condition.Summary)
		}
	}
}

// B8: a guardrail narrower than the grant narrows it to the intersection.
func TestGuardrailNarrowsResource(t *testing.T) {
	p := newSeedProvider(t)
	set := evaluate(t, p,
		identity("id", policy(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`)),
		guardrail("scp", "", policy(`{"Effect":"Allow","Action":"s3:*","Resource":["arn:aws:s3:::a/*","arn:aws:s3:::b/*"]}`)),
	)
	allowed(t, set, key("s3:GetObject", "arn:aws:s3:::a/*"))
	allowed(t, set, key("s3:GetObject", "arn:aws:s3:::b/*"))
	notAllowed(t, set, key("s3:GetObject", "*"))
	if set.Partial {
		t.Fatalf("narrowing is exact and must not be a gap: %v", set.Gaps)
	}
}

// ADR-0003: an overlap no pattern can express is a gap, and the grant is
// kept so that a widening is never hidden.
func TestPartialGuardrailOverlapIsAGap(t *testing.T) {
	p := newSeedProvider(t)
	set := evaluate(t, p,
		identity("id", policy(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`)),
		guardrail("scp", "", policy(`{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::*/logs/*"}`)),
	)
	allowed(t, set, key("s3:GetObject", "arn:aws:s3:::b/*"))
	if !set.Partial || len(set.Gaps) != 1 || !strings.Contains(set.Gaps[0], "cannot be expressed") {
		t.Fatalf("partial = %v gaps = %v", set.Partial, set.Gaps)
	}
}

// B9: a wildcard the catalogue cannot expand is a gap, not silence.
func TestUnknownWildcardIsAGap(t *testing.T) {
	p := newSeedProvider(t)
	set := evaluate(t, p, identity("id", policy(`{"Effect":"Allow","Action":["nosuchservice:*","s3:GetObject"],"Resource":"*"}`)))
	allowed(t, set, key("s3:GetObject", "*"))
	if !set.Partial || !strings.Contains(strings.Join(set.Gaps, "\n"), "nosuchservice:*") {
		t.Fatalf("partial = %v gaps = %v", set.Partial, set.Gaps)
	}
}

func TestBoundaryIntersectsIdentity(t *testing.T) {
	p := newSeedProvider(t)
	set := evaluate(t, p,
		identity("id", policy(`{"Effect":"Allow","Action":["s3:GetObject","iam:CreateUser"],"Resource":"*"}`)),
		boundary("b", policy(`{"Effect":"Allow","Action":"s3:*","Resource":"*"}`)),
	)
	allowed(t, set, key("s3:GetObject", "*"))
	notAllowed(t, set, key("iam:CreateUser", "*"))
}

func TestSingleStatementObjectAndBadEffect(t *testing.T) {
	p := newSeedProvider(t)
	set := evaluate(t, p, identity("id", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`))
	allowed(t, set, key("s3:GetObject", "*"))

	raw := &provider.RawSet{Principal: model.Principal{Ref: "t"}, Documents: []provider.Document{
		identity("id", policy(`{"Effect":"Maybe","Action":"s3:GetObject","Resource":"*"}`)),
	}}
	if _, err := p.Evaluate(context.Background(), raw); err == nil {
		t.Fatal("an unknown Effect must be an error, not an allow")
	}
}

// Guardrails are matched as patterns, never expanded: FullAWSAccess
// against an identity "*" must stay fast with the real catalogue.
func TestFullAWSAccessOnStarIdentityIsFast(t *testing.T) {
	p, err := New(provider.Config{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	set := evaluate(t, p.(*Provider),
		identity("admin", policy(`{"Effect":"Allow","Action":"*","Resource":"*"}`)),
		boundary("b", policy(`{"Effect":"Allow","Action":"*","Resource":"*"}`)),
		guardrail("FullAWSAccess", "r-root", policy(`{"Effect":"Allow","Action":"*","Resource":"*"}`)),
		guardrail("DenyIAM", "ou-prod", policy(
			`{"Effect":"Allow","Action":"*","Resource":"*"}`,
			`{"Effect":"Deny","Action":"iam:*","Resource":"*"}`,
		)),
	)
	elapsed := time.Since(start)
	t.Logf("evaluated %d grants in %s", len(set.Grants), elapsed)
	if elapsed > 3*time.Second {
		t.Fatalf("evaluation took %s; guardrails are probably being expanded", elapsed)
	}
	if len(set.Allowed()) < 20000 {
		t.Fatalf("only %d grants survived", len(set.Allowed()))
	}
	notAllowed(t, set, key("iam:PassRole", "*"))
	allowed(t, set, key("s3:GetObject", "*"))
}
