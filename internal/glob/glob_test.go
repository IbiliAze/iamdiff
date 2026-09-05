package glob

import (
	"regexp"
	"strings"
	"testing"
)

func TestMatchDocumentedARNExamples(t *testing.T) {
	// From the IAM Resource element documentation.
	pattern := "arn:aws:s3:::amzn-s3-demo-bucket/*/test/*"
	for _, obj := range []string{
		"amzn-s3-demo-bucket/1/test/object.jpg",
		"amzn-s3-demo-bucket/1/2/test/object.jpg",
		"amzn-s3-demo-bucket/1/2/test/3/object.jpg",
		"amzn-s3-demo-bucket/1/2/3/test/4/object.jpg",
		"amzn-s3-demo-bucket/1///test///object.jpg",
		"amzn-s3-demo-bucket/1/test/.jpg",
		"amzn-s3-demo-bucket//test/object.jpg",
		"amzn-s3-demo-bucket/1/test/",
	} {
		if !Match(pattern, "arn:aws:s3:::"+obj, false) {
			t.Errorf("%q should match %q", pattern, obj)
		}
	}
	if Match(pattern, "arn:aws:s3:::amzn-s3-demo-bucket/1/object.jpg", false) {
		t.Error("object without /test/ matched")
	}
}

func TestMatchStarStaysInsideSegmentUnlessItEndsOne(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"a*b", "a:b", false},
		{"a*b", "axxb", true},
		{"a*", "a:b", true},
		{"a*:c", "a:b:c", true},
		{"*", "arn:aws:s3:::b/k", true},
		{"arn:aws:ec2:us-*-1:123:instance/i-1", "arn:aws:ec2:us-east-1:123:instance/i-1", true},
		{"arn:aws:ec2:us-*-1:123:instance/i-1", "arn:aws:ec2:us-east-1:999:123:instance/i-1", false},
		{"arn:aws:iam::*:role/x", "arn:aws:iam::123:role/x", true},
		{"arn:aws:iam::*:role/x", "arn:aws:iam::123:extra:role/x", true},
		{"s3:Get?bject", "s3:GetObject", true},
		{"s3:Get?bject", "s3:Getbject", false},
		{"s3:[Get", "s3:[Get", true},
		{"", "", true},
		{"", "a", false},
		{"*", "", true},
		{"?", "", false},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.s, false); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestMatchFold(t *testing.T) {
	if !Match("IAM:*accesskey*", "iam:CreateAccessKey", true) {
		t.Error("fold did not apply")
	}
	if Match("IAM:*accesskey*", "iam:CreateAccessKey", false) {
		t.Error("case-sensitive match should fail")
	}
	if Match("arn:aws:iam::1:user/Bob", "arn:aws:iam::1:user/bob", false) {
		t.Error("resource names are case-sensitive")
	}
}

func TestCoversExamples(t *testing.T) {
	cases := []struct {
		outer, inner string
		want         bool
	}{
		{"*", "arn:aws:s3:::b/*", true},
		{"arn:aws:s3:::b/*", "*", false},
		{"arn:aws:s3:::b/*", "arn:aws:s3:::b/logs/*", true},
		{"arn:aws:s3:::b/*", "arn:aws:s3:::*/logs/*", false},
		{"arn:aws:s3:::*/logs/*", "arn:aws:s3:::b/*", false},
		{"arn:aws:s3:::b/*", "arn:aws:s3:::b/k", true},
		{"arn:aws:s3:::b/k", "arn:aws:s3:::b/k", true},
		{"arn:aws:s3:::b/k", "arn:aws:s3:::b/*", false},
		{"a?", "a*", false},
		{"?*", "*x", true},
		{"a*", "a?b", true},
		{"a", "a*", false},
		{"*", "*", true},
		{"a*b", "a*b", true},
		{"a*b", "a:b", false},
		{"a*", "a:b", true},
		{"a*b", "a*:*b", false},
		{"a*", "a*:*b", true},
		{"s3:*", "s3:GetObject", true},
		{"s3:Get*", "s3:*", false},
	}
	for _, c := range cases {
		if got := Covers(c.outer, c.inner, false); got != c.want {
			t.Errorf("Covers(%q, %q) = %v, want %v", c.outer, c.inner, got, c.want)
		}
	}
}

// Covers must agree with brute-force language inclusion, or the
// evaluator's narrowing lies. Enumerate every pattern up to length 3 over
// {a, b, :, *, ?} and every string up to length 5 over {a, b, :}.
func TestCoversAgreesWithBruteForce(t *testing.T) {
	patterns := enumerate("ab:*?", 3)
	strs := enumerate("ab:", 5)
	langs := make([]map[string]bool, len(patterns))
	for pi, p := range patterns {
		langs[pi] = map[string]bool{}
		for _, s := range strs {
			if Match(p, s, false) {
				langs[pi][s] = true
			}
		}
	}
	checked := 0
	for oi, o := range patterns {
		for ii, i := range patterns {
			want := true
			for s := range langs[ii] {
				if !langs[oi][s] {
					want = false
					break
				}
			}
			// Inclusion over bounded strings can only over-approximate
			// true inclusion, so a false positive here is a bug in
			// Covers, and a false negative means the bound is too small
			// to witness a difference. Strings of length 5 are enough to
			// separate every pair of length-3 patterns.
			if got := Covers(o, i, false); got != want {
				t.Errorf("Covers(%q, %q) = %v, brute force says %v", o, i, got, want)
			}
			checked++
		}
	}
	if checked < 20000 {
		t.Fatalf("only %d pairs checked", checked)
	}
}

func enumerate(alphabet string, maxLen int) []string {
	out := []string{""}
	frontier := []string{""}
	for l := 1; l <= maxLen; l++ {
		var next []string
		for _, s := range frontier {
			for _, c := range alphabet {
				next = append(next, s+string(c))
			}
		}
		out = append(out, next...)
		frontier = next
	}
	return out
}

// oracle translates a pattern into the regular expression the IAM
// documentation describes, so Match is checked against an independent
// implementation rather than against itself.
func oracle(p string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '*':
			if i+1 == len(p) || p[i+1] == ':' {
				b.WriteString("(?s:.*)")
			} else {
				b.WriteString("[^:]*")
			}
		case '?':
			b.WriteString("(?s:.)")
		default:
			b.WriteString(regexp.QuoteMeta(p[i : i+1]))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

func TestMatchAgreesWithRegexpOracle(t *testing.T) {
	patterns := enumerate("ab:*?", 4)
	strs := enumerate("ab:", 5)
	for _, p := range patterns {
		re := oracle(p)
		for _, s := range strs {
			if got, want := Match(p, s, false), re.MatchString(s); got != want {
				t.Fatalf("Match(%q, %q) = %v, oracle says %v", p, s, got, want)
			}
		}
	}
}

func TestOverlapsExamples(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"arn:aws:s3:::a/*", "arn:aws:s3:::b/*", false},
		{"arn:aws:s3:::a/*", "*", true},
		{"arn:aws:s3:::b/*", "arn:aws:s3:::*/logs/*", true},
		{"arn:aws:s3:::b/k", "arn:aws:s3:::b/k", true},
		{"arn:aws:s3:::b/k", "arn:aws:s3:::b/j", false},
		{"a*b", "a:b", false},
		{"a*", "a:b", true},
		{"s3:Get*", "s3:*Object", true},
		{"s3:Get*", "s3:Put*", false},
	}
	for _, c := range cases {
		if got := Overlaps(c.a, c.b, false); got != c.want {
			t.Errorf("Overlaps(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestOverlapsAgreesWithBruteForce(t *testing.T) {
	patterns := enumerate("ab:*?", 3)
	strs := enumerate("ab:", 6)
	langs := make([]map[string]bool, len(patterns))
	for pi, p := range patterns {
		langs[pi] = map[string]bool{}
		re := oracle(p)
		for _, s := range strs {
			if re.MatchString(s) {
				langs[pi][s] = true
			}
		}
	}
	for ai, a := range patterns {
		for bi, b := range patterns {
			want := false
			for s := range langs[ai] {
				if langs[bi][s] {
					want = true
					break
				}
			}
			if got := Overlaps(a, b, false); got != want {
				t.Errorf("Overlaps(%q, %q) = %v, brute force says %v", a, b, got, want)
			}
		}
	}
}
