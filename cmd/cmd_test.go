package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/IbiliAze/iamdiff/internal/provider/aws"
)

func run(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errw bytes.Buffer
	code = Execute(context.Background(), args, &out, &errw)
	return out.String(), errw.String(), code
}

func write(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// readmeSample is the output the README promises for examples/. The test
// below checks both that the tool prints it and that the README still
// contains it, so the two cannot drift apart silently.
const readmeSample = `Added (2):
  + MEDIUM dynamodb:DeleteItem                *
  + HIGH   iam:PassRole                       *

Condition changed - review manually (1):
  ~ HIGH   sts:AssumeRole                     *

VERDICT: widened
`

func TestPolicyExamplesWidenedExit2(t *testing.T) {
	out, errw, code := run(t, "policy", "../examples/before.json", "../examples/after.json")
	if code != 2 {
		t.Fatalf("exit = %d, want 2; stderr: %s", code, errw)
	}
	if out != readmeSample {
		t.Fatalf("output:\n%s\nwant:\n%s", out, readmeSample)
	}
	if errw != "" {
		t.Fatalf("unexpected stderr: %s", errw)
	}
}

func TestReadmeShowsRealOutput(t *testing.T) {
	readme, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), readmeSample) {
		t.Fatal("README sample output does not match what the tool prints")
	}
}

func TestPolicyIdenticalExit0(t *testing.T) {
	out, _, code := run(t, "policy", "../examples/before.json", "../examples/before.json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	want := "No effective permission change.\n\nVERDICT: unchanged\n"
	if out != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out, want)
	}
}

func TestPolicyRemovedGrantNarrowsExit1(t *testing.T) {
	before := write(t, "before.json", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","iam:PassRole"],"Resource":"*"}]}`)
	after := write(t, "after.json", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	out, _, code := run(t, "policy", before, after)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(out, "Removed (1):") || !strings.Contains(out, "- HIGH   iam:PassRole") {
		t.Fatalf("output:\n%s", out)
	}
}

// A guardrail composed with both sides removes access neither side can
// exercise, so a change the guardrail already blocks is not a widening.
func TestPolicyGuardrailRemovesWidening(t *testing.T) {
	before := write(t, "before.json", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	after := write(t, "after.json", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","iam:CreateUser"],"Resource":"*"}]}`)
	scp := write(t, "scp.json", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`)

	if _, _, code := run(t, "policy", before, after); code != 2 {
		t.Fatalf("without guardrail: exit = %d, want 2", code)
	}
	out, errw, code := run(t, "policy", before, after, "--guardrail", "root="+scp)
	if code != 0 {
		t.Fatalf("with guardrail: exit = %d, want 0; out: %s; err: %s", code, out, errw)
	}
}

func TestPolicyBoundaryDenyBlocksWidening(t *testing.T) {
	before := write(t, "before.json", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	after := write(t, "after.json", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","iam:CreateUser"],"Resource":"*"}]}`)
	boundary := write(t, "boundary.json", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:CreateUser","Resource":"*"}]}`)
	if _, _, code := run(t, "policy", before, after, "--boundary", boundary); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
}

func TestPolicyAcceptsRawSetSnapshot(t *testing.T) {
	snapshot := write(t, "raw.json", `{
	  "principal": {"provider": "aws", "kind": "role", "ref": "deploy"},
	  "gaps": ["organizations:ListPoliciesForTarget denied - SCPs not evaluated"],
	  "documents": [
	    {"kind": "identity", "name": "deploy-policy", "body": {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}}
	  ]}`)
	plain := write(t, "plain.json", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	out, _, code := run(t, "policy", snapshot, plain)
	if code != 4 {
		t.Fatalf("exit = %d, want 4 (partial)", code)
	}
	if !strings.Contains(out, "INCOMPLETE") || !strings.Contains(out, "SCPs not evaluated") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestOutputFormats(t *testing.T) {
	out, _, code := run(t, "policy", "../examples/before.json", "../examples/after.json", "--output", "json")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	var got struct {
		Verdict  string `json:"verdict"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json output: %v\n%s", err, out)
	}
	if got.Verdict != "widened" || got.ExitCode != 2 {
		t.Fatalf("json = %+v", got)
	}

	out, _, code = run(t, "policy", "../examples/before.json", "../examples/after.json", "--output", "markdown")
	if code != 2 || !strings.HasPrefix(out, "### iamdiff: **widened**") {
		t.Fatalf("markdown exit = %d, output:\n%s", code, out)
	}
}

func TestUsageErrorsExit64(t *testing.T) {
	cases := [][]string{
		{"policy", "../examples/before.json"},
		{"policy", "--bogus", "a", "b"},
		{"policy", "../examples/before.json", "../examples/after.json", "--output", "yaml"},
		{"policy", "../examples/before.json", "../examples/after.json", "--provider", "gcp"},
		{"explain", "role/x"},
		{"roles", "role/a"},
		{"collect"},
		{"nonsense"},
	}
	for _, args := range cases {
		_, errw, code := run(t, args...)
		if code != ExitUsage {
			t.Errorf("%v: exit = %d, want %d", args, code, ExitUsage)
		}
		if !strings.HasPrefix(errw, "iamdiff: ") {
			t.Errorf("%v: stderr = %q", args, errw)
		}
	}
}

func TestRuntimeErrorsExit70(t *testing.T) {
	_, errw, code := run(t, "policy", "does-not-exist.json", "../examples/after.json")
	if code != ExitRuntime {
		t.Fatalf("exit = %d, want %d", code, ExitRuntime)
	}
	if !strings.Contains(errw, "does-not-exist.json") {
		t.Fatalf("stderr = %q", errw)
	}
	bad := write(t, "bad.json", `{not json`)
	if _, errw, code := run(t, "policy", bad, bad); code != ExitRuntime || !strings.Contains(errw, "not valid JSON") {
		t.Fatalf("invalid json: exit = %d, stderr = %q", code, errw)
	}
}

func TestVersionAndProviders(t *testing.T) {
	out, _, code := run(t, "version")
	if code != 0 || out != "iamdiff dev (commit none, built unknown)\n" {
		t.Fatalf("version: exit = %d, out = %q", code, out)
	}
	out, _, code = run(t, "--version")
	if code != 0 || out != "iamdiff dev\n" {
		t.Fatalf("--version: exit = %d, out = %q", code, out)
	}
	out, _, code = run(t, "providers")
	if code != 0 || out != "aws\n" {
		t.Fatalf("providers: exit = %d, out = %q", code, out)
	}
}

func TestSplitLevel(t *testing.T) {
	cases := map[string][2]string{
		"scp.json":              {"", "scp.json"},
		"root=scp.json":         {"root", "scp.json"},
		"ou-prod=/tmp/a=b.json": {"ou-prod", "/tmp/a=b.json"},
		"/tmp/a=b.json":         {"", "/tmp/a=b.json"},
		"./x=y.json":            {"", "./x=y.json"},
		"=scp.json":             {"", "=scp.json"},
		"root=":                 {"", "root="},
		"r-abcd=ou/policy.json": {"r-abcd", "ou/policy.json"},
	}
	for in, want := range cases {
		level, path := splitLevel(in)
		if level != want[0] || path != want[1] {
			t.Errorf("splitLevel(%q) = (%q, %q), want (%q, %q)", in, level, path, want[0], want[1])
		}
	}
}

func TestPlanCommand(t *testing.T) {
	fixture := "../internal/provider/aws/testdata/plan/create.json"
	out, errw, code := run(t, "plan", fixture)
	if code != 4 {
		t.Fatalf("exit = %d, want 4 (unknown policy and out-of-plan attachments); stderr: %s", code, errw)
	}
	for _, want := range []string{
		"== role/svc-a: widened ==",
		"== user/ci: incomplete ==",
		"== policy/aws_iam_policy.orphan: widened ==",
		"+ HIGH   iam:PassRole",
		"VERDICT: incomplete",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	out, _, code = run(t, "plan", fixture, "--output", "json")
	var got struct {
		Verdict    string `json:"verdict"`
		Principals []struct {
			Principal struct{ Kind, Ref string } `json:"principal"`
			Verdict   string                     `json:"verdict"`
		} `json:"principals"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || code != 4 {
		t.Fatalf("json: exit %d, err %v", code, err)
	}
	if got.Verdict != "incomplete" || len(got.Principals) != 7 {
		t.Fatalf("json = %+v", got)
	}

	out, _, code = run(t, "plan", fixture, "--output", "markdown")
	if code != 4 || !strings.Contains(out, "#### `role/svc-a` — widened") || !strings.Contains(out, "> - aws_iam_user_policy.ci: policy is not known until apply") {
		t.Fatalf("markdown:\n%s", out)
	}
}

func TestPlanReadsStdin(t *testing.T) {
	body, err := os.ReadFile("../internal/provider/aws/testdata/plan/delete.json")
	if err != nil {
		t.Fatal(err)
	}
	root := NewRoot()
	var out, errw bytes.Buffer
	root.SetArgs([]string{"plan", "-"})
	root.SetIn(bytes.NewReader(body))
	root.SetOut(&out)
	root.SetErr(&errw)
	err = root.Execute()
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 4 {
		t.Fatalf("delete plan: err = %v, out:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "== role/svc-a: narrowed ==") {
		t.Fatalf("output:\n%s", out.String())
	}
}

func TestPlanRejectsPolicyDocument(t *testing.T) {
	_, errw, code := run(t, "plan", "../examples/before.json")
	if code != ExitRuntime || !strings.Contains(errw, "format_version") {
		t.Fatalf("exit = %d, stderr = %q", code, errw)
	}
}

func writeSnapshot(t *testing.T, gaps string) string {
	t.Helper()
	return write(t, "raw.json", `{
	  "principal": {"provider": "aws", "kind": "role", "ref": "arn:aws:iam::123456789012:role/deploy"},
	  `+gaps+`
	  "documents": [
	    {"kind": "identity", "name": "deploy-policy", "body": {"Version":"2012-10-17","Statement":[
	      {"Effect":"Allow","Action":["s3:GetObject","iam:PassRole","s3:DeleteObject"],"Resource":"*"},
	      {"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"false"}}}
	    ]}},
	    {"kind": "guardrail", "name": "DenyIAM", "target": "ou-prod", "body": {"Version":"2012-10-17","Statement":[
	      {"Effect":"Allow","Action":"*","Resource":"*"},
	      {"Effect":"Deny","Action":"iam:*","Resource":"*"}
	    ]}}
	  ]}`)
}

func TestExplainFromSnapshotExitCodes(t *testing.T) {
	snap := writeSnapshot(t, "")
	cases := []struct {
		action string
		code   int
		want   string
	}{
		{"s3:GetObject", 0, "PERMITTED"},
		{"iam:PassRole", 1, "DENIED"},
		{"s3:DeleteObject", 3, "PERMITTED (conditional"},
		{"ec2:DescribeInstances", 1, "NoMatch"},
	}
	for _, c := range cases {
		out, errw, code := run(t, "explain", "role/deploy", "--from", snap, "--action", c.action)
		if code != c.code || !strings.Contains(out, c.want) {
			t.Errorf("%s: exit = %d, want %d; out:\n%s%s", c.action, code, c.code, out, errw)
		}
	}

	partial := writeSnapshot(t, `"gaps": ["organizations:ListParents denied"],`)
	out, _, code := run(t, "explain", "arn:aws:iam::123456789012:role/deploy", "--from", partial, "--action", "s3:GetObject", "-v")
	if code != 4 || !strings.Contains(out, "INCOMPLETE") || !strings.Contains(out, "statement 0 allows") {
		t.Fatalf("partial: exit = %d, out:\n%s", code, out)
	}

	out, _, code = run(t, "explain", "role/deploy", "--from", snap, "--action", "iam:PassRole", "--output", "json")
	var got struct {
		Permitted bool `json:"permitted"`
		ExitCode  int  `json:"exit_code"`
		Steps     []struct{ Layer, Name, Outcome string }
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || code != 1 || got.Permitted || got.ExitCode != 1 || len(got.Steps) == 0 {
		t.Fatalf("json: exit %d err %v out %s", code, err, out)
	}

	if _, errw, code := run(t, "explain", "role/other", "--from", snap, "--action", "s3:GetObject"); code != ExitRuntime || !strings.Contains(errw, "holds arn:aws:iam::123456789012:role/deploy") {
		t.Fatalf("mismatched principal: exit %d, %s", code, errw)
	}
	if _, _, code := run(t, "explain", "role/deploy", "--from", snap, "--action", "s3:GetObject", "--output", "markdown"); code != ExitUsage {
		t.Fatalf("markdown should be a usage error, got %d", code)
	}
}
