package severity

import (
	"testing"

	"github.com/IbiliAze/iamdiff/internal/catalogue"
)

type stub map[string]catalogue.Level

func (s stub) Expand(p string) ([]string, error) { return []string{p}, nil }
func (s stub) AccessLevel(a string) catalogue.Level {
	if l, ok := s[a]; ok {
		return l
	}
	return catalogue.LevelUnknown
}
func (s stub) Version() string { return "stub" }

func TestClassify(t *testing.T) {
	cat := stub{
		"s3:GetObject":       catalogue.LevelRead,
		"s3:PutObject":       catalogue.LevelWrite,
		"s3:PutBucketPolicy": catalogue.LevelPermissionsMgmt,
		"ec2:CreateTags":     catalogue.LevelTagging,
	}
	cases := []struct {
		action string
		extra  []string
		want   Rank
	}{
		{"s3:GetObject", nil, Low},
		{"s3:PutObject", nil, Medium},
		{"s3:PutBucketPolicy", nil, High},
		{"ec2:CreateTags", nil, Low},
		{"iam:CreateUser", nil, High},               // curated iam:*
		{"IAM:createuser", nil, High},               // curated list is case-insensitive
		{"sts:AssumeRole", nil, High},               // curated
		{"nosuch:Action", nil, Low},                 // unknown level
		{"s3:GetObject", []string{"s3:Get*"}, High}, // caller's extra patterns
	}
	for _, c := range cases {
		if got := Classify(cat, c.action, c.extra); got != c.want {
			t.Errorf("Classify(%q, %v) = %s, want %s", c.action, c.extra, got, c.want)
		}
	}
}

func TestClassifyWithoutCatalogue(t *testing.T) {
	if got := Classify(nil, "s3:PutObject", nil); got != Low {
		t.Fatalf("nil catalogue should fall back to Low, got %s", got)
	}
	if got := Classify(nil, "iam:PassRole", nil); got != High {
		t.Fatalf("curated list must work without a catalogue, got %s", got)
	}
}

func TestRankString(t *testing.T) {
	for r, want := range map[Rank]string{Low: "LOW", Medium: "MEDIUM", High: "HIGH"} {
		if r.String() != want {
			t.Errorf("%d.String() = %s", r, r.String())
		}
	}
}
