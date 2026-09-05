package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/IbiliAze/iamdiff/internal/catalogue"
	"github.com/IbiliAze/iamdiff/internal/diff"
	"github.com/IbiliAze/iamdiff/internal/model"
)

// stubCatalogue classifies by a fixed table so the renderer's severity
// column is deterministic.
type stubCatalogue map[string]catalogue.Level

func (s stubCatalogue) Expand(p string) ([]string, error) { return []string{p}, nil }
func (s stubCatalogue) AccessLevel(a string) catalogue.Level {
	if l, ok := s[a]; ok {
		return l
	}
	return catalogue.LevelUnknown
}
func (s stubCatalogue) Version() string { return "stub" }

var cat = stubCatalogue{
	"s3:GetObject":        catalogue.LevelRead,
	"dynamodb:DeleteItem": catalogue.LevelWrite,
	"iam:PassRole":        catalogue.LevelPermissionsMgmt,
}

func grant(action, resource, source string, cond model.Condition) model.Grant {
	return model.Grant{Action: action, Resource: resource, Effect: model.Allow, Condition: cond,
		Origin: model.Origin{SourceKind: model.SourceIdentity, SourceName: source}}
}

func set(ref string, grants ...model.Grant) *model.EffectiveSet {
	s := model.NewEffectiveSet(model.Principal{Kind: "role", Ref: ref})
	for _, g := range grants {
		s.Add(g)
	}
	return s
}

func readmeReport() diff.Report {
	mfa := model.NewCondition(json.RawMessage(`{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`))
	before := set("deploy",
		grant("s3:GetObject", "arn:aws:s3:::assets/*", "before.json", model.Condition{}),
		grant("sts:AssumeRole", "*", "before.json", mfa))
	after := set("deploy",
		grant("s3:GetObject", "arn:aws:s3:::assets/*", "after.json", model.Condition{}),
		grant("iam:PassRole", "*", "after.json", model.Condition{}),
		grant("dynamodb:DeleteItem", "*", "after.json", model.Condition{}),
		grant("sts:AssumeRole", "*", "after.json", model.Condition{}))
	return diff.Single(after.Principal, diff.Compare(before, after))
}

func render(t *testing.T, format string, rep diff.Report) string {
	t.Helper()
	r, err := New(format, cat)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := r.Render(&buf, rep); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestTextSingleEntryMatchesReadme(t *testing.T) {
	want := `Added (2):
  + MEDIUM dynamodb:DeleteItem                *
  + HIGH   iam:PassRole                       *

Condition changed - review manually (1):
  ~ HIGH   sts:AssumeRole                     *

VERDICT: widened
`
	if got := render(t, "text", readmeReport()); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestTextShowsViaOnlyWhenSourcesDiffer(t *testing.T) {
	after := set("deploy",
		grant("s3:GetObject", "*", "managed", model.Condition{}),
		grant("iam:PassRole", "*", "inline", model.Condition{}))
	rep := diff.Single(after.Principal, diff.Compare(set("deploy"), after))
	got := render(t, "text", rep)
	if !strings.Contains(got, "*  via managed") || !strings.Contains(got, "*  via inline") {
		t.Fatalf("via column missing:\n%s", got)
	}
}

func TestTextPartialEmptyAndMulti(t *testing.T) {
	base := set("a", grant("s3:GetObject", "*", "p", model.Condition{}))
	partial := set("a", grant("s3:GetObject", "*", "p", model.Condition{}))
	partial.MarkGap("SCPs unreachable")
	rep := diff.Report{Entries: []diff.Entry{
		{Principal: base.Principal, Result: diff.Compare(base, base)},
		{Principal: model.Principal{Kind: "role", Ref: "b"}, Result: diff.Compare(base, partial)},
	}}
	want := `== role/a: unchanged ==

No effective permission change.

== role/b: incomplete ==

INCOMPLETE - some policy sources could not be read:
  ! SCPs unreachable

No effective permission change.

VERDICT: incomplete
`
	if got := render(t, "text", rep); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if got := render(t, "text", diff.Report{}); got != "No principals to compare.\n\nVERDICT: unchanged\n" {
		t.Fatalf("empty report:\n%s", got)
	}
}

func TestJSONShape(t *testing.T) {
	out := render(t, "json", readmeReport())
	var got struct {
		Verdict    string `json:"verdict"`
		ExitCode   int    `json:"exit_code"`
		Principals []struct {
			Principal model.Principal `json:"principal"`
			Added     []diff.Delta    `json:"added"`
			Changed   []diff.Delta    `json:"changed"`
			Verdict   string          `json:"verdict"`
		} `json:"principals"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Verdict != "widened" || got.ExitCode != 2 || len(got.Principals) != 1 {
		t.Fatalf("got %+v", got)
	}
	p := got.Principals[0]
	if p.Principal.Ref != "deploy" || len(p.Added) != 2 || len(p.Changed) != 1 || p.Verdict != "widened" {
		t.Fatalf("principal %+v", p)
	}
	if p.Changed[0].Before.Condition.Fingerprint == "" || p.Changed[0].Before.Condition.Summary == "" {
		t.Fatal("condition details must survive JSON output")
	}
}

func TestMarkdownSingleAndMulti(t *testing.T) {
	want := "### iamdiff: **widened**\n\n| | Severity | Action | Resource |\n|---|---|---|---|\n| `+` | MEDIUM | `dynamodb:DeleteItem` | `*` |\n| `+` | HIGH | `iam:PassRole` | `*` |\n| `~` | HIGH | `sts:AssumeRole` | `*` |\n"
	if got := render(t, "markdown", readmeReport()); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}

	partial := set("b", grant("s3:GetObject", "*", "p", model.Condition{}))
	partial.MarkGap("SCPs unreachable")
	rep := readmeReport()
	rep.Entries = append(rep.Entries, diff.Entry{Principal: partial.Principal, Result: diff.Compare(set("b"), partial)})
	got := render(t, "markdown", rep)
	for _, want := range []string{
		"### iamdiff: **incomplete**",
		"> **Incomplete evaluation.**",
		"> - SCPs unreachable",
		"#### `role/deploy` — widened",
		"#### `role/b` — incomplete",
		"| `+` | LOW | `s3:GetObject` | `*` |",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("markdown lacks %q:\n%s", want, got)
		}
	}
	if got := render(t, "markdown", diff.Single(model.Principal{Ref: "x"}, diff.Compare(set("x"), set("x")))); !strings.HasSuffix(got, "No effective permission change.\n") {
		t.Fatalf("empty markdown:\n%s", got)
	}
}

func TestUnknownFormat(t *testing.T) {
	if _, err := New("yaml", cat); err == nil {
		t.Fatal("yaml accepted")
	}
}

func TestTraceText(t *testing.T) {
	tr := &model.Trace{
		Principal: model.Principal{Ref: "arn:aws:iam::1:role/deploy"},
		Action:    "s3:DeleteObject",
		Resource:  "arn:aws:s3:::assets/*",
		Permitted: true, Conditional: true, Condition: "unless {...mfa...}",
		Steps: []model.Step{
			{Layer: "identity", Name: "deploy-policy", Outcome: "Allow", Detail: "statement 0 allows"},
			{Layer: "guardrail", Name: "ou-prod", Outcome: "Allow"},
			{Layer: "identity", Name: "mfa", Outcome: "Deny (conditional)", Detail: "statement 1 denies under a condition"},
		},
	}
	var buf bytes.Buffer
	if err := Trace(&buf, tr, false); err != nil {
		t.Fatal(err)
	}
	want := `s3:DeleteObject on arn:aws:iam::1:role/deploy
  resource arn:aws:s3:::assets/*

  identity   deploy-policy Allow
  guardrail  ou-prod       Allow
  identity   mfa           Deny (conditional)

PERMITTED (conditional: unless {...mfa...})
`
	if buf.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", buf.String(), want)
	}

	buf.Reset()
	tr.Permitted, tr.Conditional, tr.Partial, tr.Gaps = false, false, true, []string{"SCPs unreachable"}
	_ = Trace(&buf, tr, true)
	got := buf.String()
	for _, want := range []string{"INCOMPLETE", "! SCPs unreachable", "statement 0 allows", "DENIED\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("verbose trace lacks %q:\n%s", want, got)
		}
	}

	buf.Reset()
	if err := TraceJSON(&buf, tr, 4); err != nil {
		t.Fatal(err)
	}
	var js struct {
		Action   string `json:"action"`
		ExitCode int    `json:"exit_code"`
		Partial  bool   `json:"partial"`
	}
	if err := json.Unmarshal(buf.Bytes(), &js); err != nil || js.Action != "s3:DeleteObject" || js.ExitCode != 4 || !js.Partial {
		t.Fatalf("json trace: %v %+v", err, js)
	}
}
