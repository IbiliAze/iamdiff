package plan

import (
	"os"
	"testing"
)

// The fixture is the real output of "terraform show -json" for
// testdata/tf, regenerated with:
//
//	cd testdata/tf && terraform init && terraform plan -out=tfplan && terraform show -json tfplan > ../create.json
func load(t *testing.T) *Plan {
	t.Helper()
	b, err := os.ReadFile("testdata/create.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func change(t *testing.T, p *Plan, address string) *ResourceChange {
	t.Helper()
	for i := range p.ResourceChanges {
		if p.ResourceChanges[i].Address == address {
			return &p.ResourceChanges[i]
		}
	}
	t.Fatalf("no resource change %q", address)
	return nil
}

func TestParseFixtureShapes(t *testing.T) {
	p := load(t)
	if p.FormatVersion != "1.2" || len(p.ResourceChanges) != 15 {
		t.Fatalf("format %s, %d changes", p.FormatVersion, len(p.ResourceChanges))
	}
	rc := change(t, p, `module.svc["a"].aws_iam_role_policy.svc`)
	if rc.ModuleAddress != `module.svc["a"]` || rc.Type != "aws_iam_role_policy" || !rc.Has("create") {
		t.Fatalf("module instance parsed as %+v", rc)
	}
	if before, after := rc.Exists(); before || !after {
		t.Fatalf("create should exist only after: %v %v", before, after)
	}
	if role, _ := String(rc.Change.After, "role"); role != "svc-a" {
		t.Fatalf("role = %q", role)
	}
}

func TestParseRejectsNonPlans(t *testing.T) {
	for name, body := range map[string]string{
		"policy document": `{"Version":"2012-10-17","Statement":[]}`,
		"not json":        `nope`,
		"future format":   `{"format_version":"2.0","resource_changes":[]}`,
	} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestUnknownLooksInsideNestedValues(t *testing.T) {
	p := load(t)
	if !change(t, p, "aws_iam_user_policy.ci").Unknown("policy") {
		t.Error("user policy computed from a role ARN should be unknown")
	}
	if !change(t, p, "aws_iam_role_policy.worker").Unknown("role") {
		t.Error("role created with name_prefix should leave the policy's role unknown")
	}
	role := change(t, p, "aws_iam_role.deploy")
	if role.Unknown("inline_policy") {
		t.Error("a fully specified inline_policy block must not count as unknown")
	}
	if !role.Unknown("arn") {
		t.Error("arn of a created role should be unknown")
	}
	if !containsTrue([]any{map[string]any{"policy": true}}) || containsTrue([]any{map[string]any{}}) {
		t.Error("containsTrue")
	}
}

func TestBlocksAndStrings(t *testing.T) {
	p := load(t)
	role := change(t, p, "aws_iam_role.deploy")
	blocks := Blocks(role.Change.After, "inline_policy")
	if len(blocks) != 1 {
		t.Fatalf("inline_policy blocks = %d", len(blocks))
	}
	if name, _ := String(blocks[0], "name"); name != "legacy" {
		t.Fatalf("inline policy name = %q", name)
	}
	if policy, ok := String(blocks[0], "policy"); !ok || policy == "" {
		t.Fatal("inline policy body missing")
	}
	if Strings(map[string]any{"x": []any{"a", "b"}}, "x")[1] != "b" {
		t.Fatal("Strings")
	}
	if String(nil, "x"); Blocks(nil, "x") != nil || Strings(nil, "x") != nil {
		t.Fatal("nil maps must be safe")
	}
}

func TestReferencesResolveThroughConfiguration(t *testing.T) {
	p := load(t)
	refs := p.References("aws_iam_role_policy_attachment.deploy", "policy_arn")
	if len(refs) != 1 || refs[0].Address != "aws_iam_policy.deploy" {
		t.Fatalf("attachment policy_arn refs = %v", addresses(refs))
	}
	refs = p.References("aws_iam_role_policy.worker", "role")
	if len(refs) != 1 || refs[0].Address != "aws_iam_role.worker" {
		t.Fatalf("worker role refs = %v", addresses(refs))
	}
	if refs := p.References("aws_iam_role_policy_attachment.readonly", "policy_arn"); len(refs) != 0 {
		t.Fatalf("a literal ARN has no references, got %v", addresses(refs))
	}
	if refs := p.References("aws_iam_role.deploy", "nope"); len(refs) != 0 {
		t.Fatalf("unknown attribute has no references, got %v", addresses(refs))
	}
}

func TestReferencesWalkModulesAndKeepInstanceKeys(t *testing.T) {
	p := load(t)
	refs := p.References(`module.svc["a"].aws_iam_role_policy.svc`, "role")
	if len(refs) != 1 || refs[0].Address != `module.svc["a"].aws_iam_role.svc` {
		t.Fatalf("module refs = %v", addresses(refs))
	}
	if len(p.Instances(`module.svc["b"].aws_iam_role.svc[0]`)) != 1 {
		t.Fatal("instance lookup should ignore the trailing index")
	}
}

func TestConfigured(t *testing.T) {
	p := load(t)
	if !p.Configured("aws_iam_role.deploy", "permissions_boundary") {
		t.Error("permissions_boundary is configured")
	}
	if p.Configured("aws_iam_role.deploy", "managed_policy_arns") {
		t.Error("managed_policy_arns is not configured; it is only computed")
	}
	if p.Configured("aws_iam_role.deploy", "arn") {
		t.Error("arn is not configured")
	}
}

func TestAddressHelpers(t *testing.T) {
	cases := map[string]string{
		`aws_iam_role.x`:                                 `aws_iam_role.x`,
		`aws_iam_role.x[0]`:                              `aws_iam_role.x`,
		`aws_iam_role.x["a.b"]`:                          `aws_iam_role.x`,
		`module.svc["a.b"].aws_iam_role.x[0]`:            `module.svc["a.b"].aws_iam_role.x`,
		`module.svc["a"].module.inner[1].aws_iam_role.x`: `module.svc["a"].module.inner[1].aws_iam_role.x`,
		`data.aws_iam_policy_document.d`:                 `data.aws_iam_policy_document.d`,
	}
	for in, want := range cases {
		if got := stripLastIndex(in); got != want {
			t.Errorf("stripLastIndex(%q) = %q, want %q", in, got, want)
		}
	}
	refs := map[string]string{
		"aws_iam_policy.x.arn":  "aws_iam_policy.x",
		"aws_iam_policy.x":      "aws_iam_policy.x",
		"aws_iam_policy.x[0]":   "aws_iam_policy.x",
		"var.policy_arn":        "",
		"module.svc.policy_arn": "",
		"data.aws_iam_policy.x": "",
		"each.key":              "",
		"local.x":               "",
	}
	for in, want := range refs {
		if got := resourceReference(in); got != want {
			t.Errorf("resourceReference(%q) = %q, want %q", in, got, want)
		}
	}
}

func addresses(rcs []*ResourceChange) []string {
	var out []string
	for _, rc := range rcs {
		out = append(out, rc.Address)
	}
	return out
}
