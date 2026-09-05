package aws

import (
	"context"
	"strings"
	"testing"

	"github.com/IbiliAze/iamdiff/internal/model"
	"github.com/IbiliAze/iamdiff/internal/provider"
)

func explain(t *testing.T, p *Provider, action, resource string, docs ...provider.Document) *model.Trace {
	t.Helper()
	raw := &provider.RawSet{Principal: model.Principal{Provider: Name, Kind: "role", Ref: "arn:aws:iam::1:role/t"}, Documents: docs}
	tr, err := p.Explain(context.Background(), raw, action, resource)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	return tr
}

func outcomes(tr *model.Trace) string {
	var parts []string
	for _, s := range tr.Steps {
		parts = append(parts, s.Layer+"/"+s.Name+":"+s.Outcome)
	}
	return strings.Join(parts, " ")
}

func TestExplainDeniedByGuardrail(t *testing.T) {
	p := newSeedProvider(t)
	tr := explain(t, p, "iam:PassRole", "",
		identity("deploy-policy", policy(`{"Effect":"Allow","Action":["s3:GetObject","iam:PassRole"],"Resource":"*"}`)),
		boundary("boundary", policy(`{"Effect":"Allow","Action":"*","Resource":"*"}`)),
		guardrail("FullAWSAccess", "r-root", policy(`{"Effect":"Allow","Action":"*","Resource":"*"}`)),
		guardrail("DenyIAM", "ou-prod", policy(`{"Effect":"Allow","Action":"*","Resource":"*"}`, `{"Effect":"Deny","Action":"iam:*","Resource":"*"}`)),
	)
	if tr.Permitted {
		t.Fatal("iam:PassRole should be denied by the OU guardrail")
	}
	want := "identity/deploy-policy:Allow boundary/boundary:Allow guardrail/ou-prod:Allow guardrail/r-root:Allow guardrail/DenyIAM:Deny"
	if got := outcomes(tr); got != want {
		t.Fatalf("steps = %s\nwant    %s", got, want)
	}
	if tr.Partial || tr.Conditional {
		t.Fatalf("unexpected flags: %+v", tr)
	}
}

func TestExplainPermittedAndNoMatch(t *testing.T) {
	p := newSeedProvider(t)
	docs := []provider.Document{
		identity("deploy-policy", policy(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::assets/*"}`)),
		guardrail("scp", "", policy(`{"Effect":"Allow","Action":"s3:*","Resource":"*"}`)),
	}
	tr := explain(t, p, "s3:GetObject", "arn:aws:s3:::assets/k", docs...)
	if !tr.Permitted || tr.Conditional || tr.Resource != "arn:aws:s3:::assets/k" {
		t.Fatalf("trace = %+v", tr)
	}
	if got := outcomes(tr); got != "identity/deploy-policy:Allow guardrail/guardrail:Allow" {
		t.Fatalf("steps = %s", got)
	}

	tr = explain(t, p, "s3:GetObject", "arn:aws:s3:::other/k", docs...)
	if tr.Permitted || !strings.Contains(outcomes(tr), "identity/-:NoMatch") {
		t.Fatalf("trace = %+v", tr)
	}

	tr = explain(t, p, "s3:GetObject", "arn:aws:s3:::*/k", docs...)
	if !strings.Contains(outcomes(tr), "Allow (partial)") {
		t.Fatalf("an identity grant that only overlaps the resource should say so: %s", outcomes(tr))
	}
}

func TestExplainConditionalAndPartial(t *testing.T) {
	p := newSeedProvider(t)
	tr := explain(t, p, "s3:GetObject", "",
		identity("id", policy(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`)),
		identity("mfa", policy(`{"Effect":"Deny","Action":"s3:GetObject","Resource":"*",`+mfa+`}`)),
	)
	if !tr.Permitted || !tr.Conditional || tr.Condition == "" {
		t.Fatalf("trace = %+v", tr)
	}
	if !strings.Contains(outcomes(tr), "identity/mfa:Deny (conditional)") {
		t.Fatalf("steps = %s", outcomes(tr))
	}

	raw := &provider.RawSet{
		Principal: model.Principal{Provider: Name, Kind: "role", Ref: "t"},
		Gaps:      []string{"organizations:ListParents denied"},
		Documents: []provider.Document{identity("id", policy(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`))},
	}
	tr, err := p.Explain(context.Background(), raw, "s3:GetObject", "")
	if err != nil {
		t.Fatal(err)
	}
	if !tr.Partial || len(tr.Gaps) != 1 || !tr.Permitted {
		t.Fatalf("trace = %+v", tr)
	}
}

func TestExplainRejectsPatterns(t *testing.T) {
	p := newSeedProvider(t)
	raw := &provider.RawSet{Principal: model.Principal{Ref: "t"}}
	for _, action := range []string{"", "s3:*", "s3:Get?bject"} {
		if _, err := p.Explain(context.Background(), raw, action, ""); err == nil {
			t.Errorf("action %q accepted", action)
		}
	}
}
