package diff

import "github.com/IbiliAze/iamdiff/internal/model"

// Entry is one principal's comparison inside a Report.
type Entry struct {
	Principal model.Principal `json:"principal"`
	Result    Result          `json:"result"`
}

// Report is the comparison of one or more principals. A policy diff has
// one entry; an infrastructure plan has one per principal it touches.
type Report struct {
	Entries []Entry `json:"entries"`
}

// Single wraps one comparison as a report.
func Single(p model.Principal, r Result) Report {
	return Report{Entries: []Entry{{Principal: p, Result: r}}}
}

// rank orders verdicts by how much they demand of a reviewer, so a
// report's verdict is the worst of its entries. Incompleteness outranks
// widening for the same reason it does inside a single result: a partial
// evaluation cannot honestly claim access did not widen.
func rank(v Verdict) int {
	switch v {
	case VerdictIncomplete:
		return 4
	case VerdictWidened:
		return 3
	case VerdictIndeterminate:
		return 2
	case VerdictNarrowed:
		return 1
	default:
		return 0
	}
}

// Verdict collapses the report into a single judgement: the worst entry.
func (r Report) Verdict() Verdict {
	worst := VerdictUnchanged
	for _, e := range r.Entries {
		if v := e.Result.Verdict(); rank(v) > rank(worst) {
			worst = v
		}
	}
	return worst
}

func (r Report) ExitCode() int { return exitCode(r.Verdict()) }

// Empty reports whether no entry records any change.
func (r Report) Empty() bool {
	for _, e := range r.Entries {
		if !e.Result.Empty() {
			return false
		}
	}
	return true
}

// Partial reports whether any entry is incomplete.
func (r Report) Partial() bool {
	for _, e := range r.Entries {
		if e.Result.Partial {
			return true
		}
	}
	return false
}
