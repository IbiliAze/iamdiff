// Package render turns a diff report into output. Renderers are
// interchangeable and know nothing about any cloud.
package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/IbiliAze/iamdiff/internal/catalogue"
	"github.com/IbiliAze/iamdiff/internal/diff"
	"github.com/IbiliAze/iamdiff/internal/model"
	"github.com/IbiliAze/iamdiff/internal/severity"
)

type Renderer interface {
	Render(w io.Writer, r diff.Report) error
}

// New selects a renderer by name.
func New(format string, cat catalogue.Catalogue) (Renderer, error) {
	switch format {
	case "", "text":
		return &Text{cat: cat}, nil
	case "json":
		return &JSON{}, nil
	case "markdown":
		return &Markdown{cat: cat}, nil
	default:
		return nil, fmt.Errorf("unknown output format %q (text, json, markdown)", format)
	}
}

// label names a principal in a report with several.
func label(p model.Principal) string {
	if p.Kind == "" {
		return p.Ref
	}
	return p.Kind + "/" + p.Ref
}

type Text struct{ cat catalogue.Catalogue }

func (t *Text) Render(w io.Writer, rep diff.Report) error {
	var buf bytes.Buffer
	multi := len(rep.Entries) > 1
	if len(rep.Entries) == 0 {
		fmt.Fprintln(&buf, "No principals to compare.")
		fmt.Fprintln(&buf)
	}
	for _, e := range rep.Entries {
		if multi {
			fmt.Fprintf(&buf, "== %s: %s ==\n\n", label(e.Principal), e.Result.Verdict())
		}
		t.result(&buf, e.Result)
	}
	fmt.Fprintf(&buf, "VERDICT: %s\n", rep.Verdict())
	_, err := w.Write(buf.Bytes())
	return err
}

func (t *Text) result(w *bytes.Buffer, r diff.Result) {
	if r.Partial {
		fmt.Fprintln(w, "INCOMPLETE - some policy sources could not be read:")
		for _, g := range r.Gaps {
			fmt.Fprintf(w, "  ! %s\n", g)
		}
		fmt.Fprintln(w)
	}
	if r.Empty() {
		fmt.Fprintln(w, "No effective permission change.")
		fmt.Fprintln(w)
	}
	showVia := multipleSources(r)
	section(w, t.cat, "Added", r.Added, showVia)
	section(w, t.cat, "Removed", r.Removed, showVia)
	section(w, t.cat, "Condition changed - review manually", r.Changed, showVia)
}

// multipleSources reports whether either side of the comparison draws
// on more than one named source. The "via" column only earns its space
// when it tells a principal's documents apart; for a single document per
// side it would repeat the file name on every line.
func multipleSources(r diff.Result) bool {
	before, after := map[string]bool{}, map[string]bool{}
	for _, group := range [][]diff.Delta{r.Added, r.Removed, r.Changed} {
		for _, d := range group {
			if d.Before != nil && d.Before.Origin.SourceName != "" {
				before[d.Before.Origin.SourceName] = true
			}
			if d.After != nil && d.After.Origin.SourceName != "" {
				after[d.After.Origin.SourceName] = true
			}
		}
	}
	return len(before) > 1 || len(after) > 1
}

func sourceName(d diff.Delta) string {
	if d.After != nil && d.After.Origin.SourceName != "" {
		return d.After.Origin.SourceName
	}
	if d.Before != nil && d.Before.Origin.SourceName != "" {
		return d.Before.Origin.SourceName
	}
	return ""
}

func section(w *bytes.Buffer, cat catalogue.Catalogue, title string, deltas []diff.Delta, showVia bool) {
	if len(deltas) == 0 {
		return
	}
	fmt.Fprintf(w, "%s (%d):\n", title, len(deltas))
	for _, d := range deltas {
		rank := severity.Classify(cat, d.Key.Action, nil)
		via := ""
		if showVia {
			if n := sourceName(d); n != "" {
				via = "  via " + n
			}
		}
		fmt.Fprintf(w, "  %s %-6s %-34s %s%s\n", d.Kind.Symbol(), rank, d.Key.Action, d.Key.Resource, via)
	}
	fmt.Fprintln(w)
}

type JSON struct{}

type jsonEntry struct {
	Principal model.Principal `json:"principal"`
	diff.Result
	Verdict  string `json:"verdict"`
	ExitCode int    `json:"exit_code"`
}

func (j *JSON) Render(w io.Writer, rep diff.Report) error {
	entries := make([]jsonEntry, 0, len(rep.Entries))
	for _, e := range rep.Entries {
		entries = append(entries, jsonEntry{
			Principal: e.Principal,
			Result:    e.Result,
			Verdict:   string(e.Result.Verdict()),
			ExitCode:  e.Result.ExitCode(),
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Verdict    string      `json:"verdict"`
		ExitCode   int         `json:"exit_code"`
		Principals []jsonEntry `json:"principals"`
	}{Verdict: string(rep.Verdict()), ExitCode: rep.ExitCode(), Principals: entries})
}

// Markdown is shaped for a pull-request comment.
type Markdown struct{ cat catalogue.Catalogue }

func (m *Markdown) Render(w io.Writer, rep diff.Report) error {
	var buf bytes.Buffer
	b := &buf
	fmt.Fprintf(b, "### iamdiff: **%s**\n\n", rep.Verdict())
	if rep.Partial() {
		fmt.Fprint(b, "> **Incomplete evaluation.** Some policy sources could not be read; this result cannot rule out widened access.\n")
		for _, e := range rep.Entries {
			for _, g := range e.Result.Gaps {
				fmt.Fprintf(b, "> - %s\n", g)
			}
		}
		fmt.Fprintln(b)
	}
	if rep.Empty() {
		fmt.Fprintln(b, "No effective permission change.")
		_, err := w.Write(buf.Bytes())
		return err
	}
	multi := len(rep.Entries) > 1
	for _, e := range rep.Entries {
		if multi {
			fmt.Fprintf(b, "#### `%s` — %s\n\n", label(e.Principal), e.Result.Verdict())
		}
		if e.Result.Empty() {
			fmt.Fprintln(b, "No effective permission change.")
			fmt.Fprintln(b)
			continue
		}
		fmt.Fprintln(b, "| | Severity | Action | Resource |")
		fmt.Fprintln(b, "|---|---|---|---|")
		for _, group := range [][]diff.Delta{e.Result.Added, e.Result.Removed, e.Result.Changed} {
			for _, d := range group {
				fmt.Fprintf(b, "| `%s` | %s | `%s` | `%s` |\n",
					d.Kind.Symbol(), severity.Classify(m.cat, d.Key.Action, nil), d.Key.Action, d.Key.Resource)
			}
		}
		if multi {
			fmt.Fprintln(b)
		}
	}
	_, err := w.Write(buf.Bytes())
	return err
}
