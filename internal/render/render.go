// Package render turns a diff result into output. Renderers are
// interchangeable and know nothing about any cloud.
package render

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/IbiliAze/iamdiff/internal/catalogue"
	"github.com/IbiliAze/iamdiff/internal/diff"
	"github.com/IbiliAze/iamdiff/internal/severity"
)

type Renderer interface {
	Render(w io.Writer, r diff.Result) error
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

type Text struct{ cat catalogue.Catalogue }

func (t *Text) Render(w io.Writer, r diff.Result) error {
	if r.Partial {
		fmt.Fprintln(w, "INCOMPLETE - some policy sources could not be read:")
		for _, g := range r.Gaps {
			fmt.Fprintf(w, "  ! %s\n", g)
		}
		fmt.Fprintln(w)
	}
	if r.Empty() {
		fmt.Fprintln(w, "No effective permission change.")
	}
	section(w, t.cat, "Added", r.Added)
	section(w, t.cat, "Removed", r.Removed)
	section(w, t.cat, "Condition changed - review manually", r.Changed)

	fmt.Fprintf(w, "\nVERDICT: %s\n", r.Verdict())
	return nil
}

func section(w io.Writer, cat catalogue.Catalogue, title string, deltas []diff.Delta) {
	if len(deltas) == 0 {
		return
	}
	fmt.Fprintf(w, "%s (%d):\n", title, len(deltas))
	for _, d := range deltas {
		rank := severity.Classify(cat, d.Key.Action, nil)
		via := ""
		if d.After != nil && d.After.Origin.SourceName != "" {
			via = "  via " + d.After.Origin.SourceName
		} else if d.Before != nil && d.Before.Origin.SourceName != "" {
			via = "  via " + d.Before.Origin.SourceName
		}
		fmt.Fprintf(w, "  %s %-6s %-34s %s%s\n", d.Kind.Symbol(), rank, d.Key.Action, d.Key.Resource, via)
	}
	fmt.Fprintln(w)
}

type JSON struct{}

func (j *JSON) Render(w io.Writer, r diff.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		diff.Result
		Verdict  string `json:"verdict"`
		ExitCode int    `json:"exit_code"`
	}{Result: r, Verdict: string(r.Verdict()), ExitCode: r.ExitCode()})
}

// Markdown is shaped for a pull-request comment.
type Markdown struct{ cat catalogue.Catalogue }

func (m *Markdown) Render(w io.Writer, r diff.Result) error {
	fmt.Fprintf(w, "### iamdiff: **%s**\n\n", r.Verdict())
	if r.Partial {
		fmt.Fprint(w, "> **Incomplete evaluation.** Some policy sources could not be read; this result cannot rule out widened access.\n\n")
	}
	if r.Empty() {
		fmt.Fprintln(w, "No effective permission change.")
		return nil
	}
	fmt.Fprintln(w, "| | Severity | Action | Resource |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, group := range [][]diff.Delta{r.Added, r.Removed, r.Changed} {
		for _, d := range group {
			fmt.Fprintf(w, "| `%s` | %s | `%s` | `%s` |\n",
				d.Kind.Symbol(), severity.Classify(m.cat, d.Key.Action, nil), d.Key.Action, d.Key.Resource)
		}
	}
	return nil
}
