package aws

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IbiliAze/iamdiff/internal/diff"
	"github.com/IbiliAze/iamdiff/internal/model"
	"github.com/IbiliAze/iamdiff/internal/plan"
	"github.com/IbiliAze/iamdiff/internal/provider"
)

// create.json is real "terraform show -json" output for
// internal/plan/testdata/tf; update.json and delete.json are derived
// from it by settling every unknown value.
func loadPlan(t *testing.T, name string) []provider.PrincipalChange {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "plan", name))
	if err != nil {
		t.Fatal(err)
	}
	pl, err := plan.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := newSeedProvider(t).FromPlan(pl)
	if err != nil {
		t.Fatal(err)
	}
	return changes
}

func byRef(changes []provider.PrincipalChange) map[string]provider.PrincipalChange {
	out := map[string]provider.PrincipalChange{}
	for _, c := range changes {
		out[c.Principal.Kind+"/"+c.Principal.Ref] = c
	}
	return out
}

func docNames(raw *provider.RawSet) []string {
	var out []string
	for _, d := range raw.Documents {
		out = append(out, string(d.Kind)+":"+d.Name)
	}
	return out
}

func TestFromPlanCreateGroupsPrincipals(t *testing.T) {
	changes := byRef(loadPlan(t, "create.json"))
	want := []string{
		"policy/aws_iam_policy.orphan",
		"role/aws_iam_role.worker",
		"role/deploy",
		"role/svc-a",
		"role/svc-b",
		"scp/deny-iam",
		"user/ci",
	}
	for _, k := range want {
		if _, ok := changes[k]; !ok {
			t.Errorf("missing principal %s (have %v)", k, keys(changes))
		}
	}
	if len(changes) != len(want) {
		t.Fatalf("principals = %v", keys(changes))
	}
	if _, ok := changes["policy/aws_iam_policy.deploy"]; ok {
		t.Fatal("a policy attached to a role must not also stand alone")
	}

	deploy := changes["role/deploy"]
	if len(deploy.Before.Documents) != 0 || len(deploy.Before.Gaps) != 0 {
		t.Fatalf("created role has a before: %v %v", docNames(deploy.Before), deploy.Before.Gaps)
	}
	gotDocs := strings.Join(docNames(deploy.After), " ")
	for _, want := range []string{"identity:aws_iam_role.deploy/legacy", "identity:aws_iam_role_policy.extra", "identity:aws_iam_policy.deploy"} {
		if !strings.Contains(gotDocs, want) {
			t.Errorf("role/deploy after lacks %s: %s", want, gotDocs)
		}
	}
	for _, d := range deploy.After.Documents {
		if strings.Contains(string(d.Body), "ec2.amazonaws.com") {
			t.Fatal("trust policy leaked into the effective set")
		}
	}
	gaps := strings.Join(deploy.After.Gaps, "\n")
	if !strings.Contains(gaps, "permissions boundary arn:aws:iam::123456789012:policy/ci-boundary is not in the plan") {
		t.Errorf("boundary gap missing: %s", gaps)
	}
	if !strings.Contains(gaps, "attached policy arn:aws:iam::aws:policy/ReadOnlyAccess is not in the plan") {
		t.Errorf("managed policy gap missing: %s", gaps)
	}
	if strings.Contains(gaps, "managed_policy_arns") {
		t.Errorf("an unconfigured computed attribute must not be a gap: %s", gaps)
	}

	worker := changes["role/aws_iam_role.worker"]
	if got := docNames(worker.After); len(got) != 1 || got[0] != "identity:aws_iam_role_policy.worker" {
		t.Errorf("worker docs = %v", got)
	}

	ci := changes["user/ci"]
	if len(ci.After.Gaps) != 1 || !strings.Contains(ci.After.Gaps[0], "policy is not known until apply") {
		t.Errorf("user/ci gaps = %v", ci.After.Gaps)
	}

	for _, ref := range []string{"role/svc-a", "role/svc-b"} {
		if got := docNames(changes[ref].After); len(got) != 1 || !strings.HasPrefix(got[0], "identity:module.svc[") {
			t.Errorf("%s docs = %v", ref, got)
		}
	}

	if got := docNames(changes["scp/deny-iam"].After); len(got) != 1 {
		t.Errorf("scp docs = %v", got)
	}
}

func TestFromPlanUpdateDiffsThroughAttachments(t *testing.T) {
	p := newSeedProvider(t)
	changes := byRef(loadPlan(t, "update.json"))
	deploy := changes["role/deploy"]
	before, err := p.Evaluate(context.Background(), deploy.Before)
	if err != nil {
		t.Fatal(err)
	}
	after, err := p.Evaluate(context.Background(), deploy.After)
	if err != nil {
		t.Fatal(err)
	}
	res := diff.Compare(before, after)
	added := map[model.GrantKey]bool{}
	for _, d := range res.Added {
		added[d.Key] = true
	}
	if !added[model.GrantKey{Action: "iam:PassRole", Resource: "*"}] {
		t.Errorf("inline policy update not seen: %+v", res.Added)
	}
	if !added[model.GrantKey{Action: "s3:ListBucket", Resource: "arn:aws:s3:::assets"}] {
		t.Errorf("attached managed policy update not seen: %+v", res.Added)
	}
	if len(res.Removed) != 1 || res.Removed[0].Key != (model.GrantKey{Action: "s3:GetObject", Resource: "*"}) {
		t.Errorf("the rewritten inline policy dropped s3:GetObject on *; removals = %+v", res.Removed)
	}
	// Both sides carry the same out-of-plan gaps, so the diff is partial.
	if !res.Partial {
		t.Error("boundary and ReadOnlyAccess remain out of plan; the result must be partial")
	}

	svc := changes["role/svc-a"]
	if len(svc.Before.Documents) != 1 || len(svc.After.Documents) != 1 {
		t.Fatalf("no-op module role should carry its policy on both sides: %v / %v", docNames(svc.Before), docNames(svc.After))
	}
}

func TestFromPlanDeleteNarrows(t *testing.T) {
	p := newSeedProvider(t)
	changes := byRef(loadPlan(t, "delete.json"))
	svc := changes["role/svc-a"]
	if len(svc.After.Documents) != 0 || len(svc.After.Gaps) != 0 {
		t.Fatalf("destroyed role has an after: %v", docNames(svc.After))
	}
	before, _ := p.Evaluate(context.Background(), svc.Before)
	after, _ := p.Evaluate(context.Background(), svc.After)
	if v := diff.Compare(before, after).Verdict(); v != diff.VerdictNarrowed {
		t.Fatalf("verdict = %s, want narrowed", v)
	}
}

func keys(m map[string]provider.PrincipalChange) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
