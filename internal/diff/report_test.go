package diff

import (
	"testing"

	"github.com/IbiliAze/iamdiff/internal/model"
)

func entry(ref string, before, after *model.EffectiveSet) Entry {
	return Entry{Principal: model.Principal{Ref: ref}, Result: Compare(before, after)}
}

func TestReportVerdictIsWorstEntry(t *testing.T) {
	base := set(allow("s3:GetObject", "*"))
	wider := set(allow("s3:GetObject", "*"), allow("s3:DeleteObject", "*"))
	narrower := set()
	partial := set(allow("s3:GetObject", "*"))
	partial.MarkGap("scp unreachable")

	cases := []struct {
		name    string
		entries []Entry
		want    Verdict
		exit    int
	}{
		{"empty report", nil, VerdictUnchanged, ExitUnchanged},
		{"all unchanged", []Entry{entry("a", base, base)}, VerdictUnchanged, ExitUnchanged},
		{"narrowed beats unchanged", []Entry{entry("a", base, base), entry("b", base, narrower)}, VerdictNarrowed, ExitNarrowed},
		{"widened beats narrowed", []Entry{entry("a", base, narrower), entry("b", base, wider)}, VerdictWidened, ExitWidened},
		{"incomplete beats widened", []Entry{entry("a", base, wider), entry("b", base, partial)}, VerdictIncomplete, ExitIncomplete},
	}
	for _, c := range cases {
		r := Report{Entries: c.entries}
		if got := r.Verdict(); got != c.want {
			t.Errorf("%s: verdict = %s, want %s", c.name, got, c.want)
		}
		if got := r.ExitCode(); got != c.exit {
			t.Errorf("%s: exit = %d, want %d", c.name, got, c.exit)
		}
	}
}

func TestReportEmptyAndPartial(t *testing.T) {
	base := set(allow("s3:GetObject", "*"))
	r := Single(model.Principal{Ref: "a"}, Compare(base, base))
	if !r.Empty() || r.Partial() {
		t.Fatal("identical sets should be empty and complete")
	}
	partial := set(allow("s3:GetObject", "*"))
	partial.MarkGap("gap")
	r = Single(model.Principal{Ref: "a"}, Compare(base, partial))
	if !r.Partial() {
		t.Fatal("gap not reported")
	}
}
