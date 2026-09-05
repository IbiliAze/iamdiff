package catalogue

import (
	"reflect"
	"testing"
)

const seed = `{"version":"test","actions":[
  {"name":"s3:GetObject","level":"Read"},
  {"name":"s3:GetObjectAcl","level":"Read"},
  {"name":"s3:PutObject","level":"Write"},
  {"name":"iam:CreateAccessKey","level":"Write"},
  {"name":"iam:DeleteAccessKey","level":"Write"},
  {"name":"iam:ListAccessKeys","level":"List"},
  {"name":"iam:PassRole","level":"PermissionsManagement"},
  {"name":"verifiedpermissions:isauthorized","level":"Unknown"},
  {"name":"verifiedpermissions:IsAuthorized","level":"Read"},
  {"name":"odd:NoLevel"}
]}`

func load(t *testing.T) *Static {
	t.Helper()
	c, err := Load([]byte(seed))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoadDedupesCaseInsensitive(t *testing.T) {
	c := load(t)
	if c.Len() != 9 {
		t.Fatalf("len = %d, want 9 (one case-insensitive duplicate collapsed)", c.Len())
	}
	if got := c.AccessLevel("VerifiedPermissions:IsAuthorized"); got != LevelRead {
		t.Fatalf("duplicate resolved to %q, want the entry with a level", got)
	}
	got, _ := c.Expand("verifiedpermissions:*")
	if !reflect.DeepEqual(got, []string{"verifiedpermissions:IsAuthorized"}) {
		t.Fatalf("expand = %v", got)
	}
}

func TestMissingLevelIsUnknown(t *testing.T) {
	if got := load(t).AccessLevel("odd:NoLevel"); got != LevelUnknown {
		t.Fatalf("level = %q, want Unknown", got)
	}
}

func TestExpandStarReturnsAll(t *testing.T) {
	got, err := load(t).Expand("*")
	if err != nil || len(got) != 9 {
		t.Fatalf("expand(*) = %d actions, err %v", len(got), err)
	}
}

func TestExpandMidStringWildcard(t *testing.T) {
	got, err := load(t).Expand("iam:*AccessKey*")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:ListAccessKeys"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expand = %v, want %v", got, want)
	}
	got, _ = load(t).Expand("s3:GetObject???")
	if !reflect.DeepEqual(got, []string{"s3:GetObjectAcl"}) {
		t.Fatalf("expand(?) = %v", got)
	}
}

func TestExpandIsCaseInsensitive(t *testing.T) {
	got, _ := load(t).Expand("S3:get*")
	want := []string{"s3:GetObject", "s3:GetObjectAcl"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expand = %v, want %v", got, want)
	}
}

func TestExpandNoMatchIsEmptyNotError(t *testing.T) {
	got, err := load(t).Expand("foo:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expand = %v, want empty", got)
	}
}

func TestExpandUnknownConcreteActionPassesThrough(t *testing.T) {
	got, err := load(t).Expand("newservice:DoThing")
	if err != nil || !reflect.DeepEqual(got, []string{"newservice:DoThing"}) {
		t.Fatalf("expand = %v, err %v", got, err)
	}
}

func TestExpandRejectsEmpty(t *testing.T) {
	if _, err := load(t).Expand(""); err == nil {
		t.Fatal("empty pattern accepted")
	}
}

// Only '*' and '?' are wildcards in IAM; a bracket is an ordinary
// character, not a shell character class.
func TestExpandTreatsBracketsAsLiterals(t *testing.T) {
	got, err := load(t).Expand("s3:[G]et*")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expand = %v, want nothing (no action contains a bracket)", got)
	}
}

func TestAccessLevelCaseInsensitive(t *testing.T) {
	c := load(t)
	if got := c.AccessLevel("IAM:passrole"); got != LevelPermissionsMgmt {
		t.Fatalf("level = %q", got)
	}
	if got := c.AccessLevel("nope:Nothing"); got != LevelUnknown {
		t.Fatalf("level = %q, want Unknown", got)
	}
}

func TestExpandCanonicalisesKnownActionSpelling(t *testing.T) {
	got, err := load(t).Expand("S3:GETOBJECT")
	if err != nil || !reflect.DeepEqual(got, []string{"s3:GetObject"}) {
		t.Fatalf("expand = %v, err %v", got, err)
	}
}
