package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/IbiliAze/iamdiff/internal/model"
)

// Trace prints a decision trace produced by provider.Explainer.
// Verbose includes every step's detail; the default view shows only
// the outcome of each layer, matching the density of Text.Render.
func Trace(w io.Writer, t *model.Trace, verbose bool) error {
	var buf bytes.Buffer
	b := &buf
	fmt.Fprintf(b, "%s on %s\n", t.Action, t.Principal.Ref)
	if t.Resource != "" && t.Resource != "*" {
		fmt.Fprintf(b, "  resource %s\n", t.Resource)
	}
	fmt.Fprintln(b)
	if t.Partial {
		fmt.Fprintln(b, "  INCOMPLETE - some policy sources could not be read:")
		for _, g := range t.Gaps {
			fmt.Fprintf(b, "    ! %s\n", g)
		}
		fmt.Fprintln(b)
	}
	width := 10
	for _, s := range t.Steps {
		if len(s.Name) > width {
			width = len(s.Name)
		}
	}
	for _, s := range t.Steps {
		fmt.Fprintf(b, "  %-10s %-*s %s\n", s.Layer, width, s.Name, s.Outcome)
		if verbose && s.Detail != "" {
			fmt.Fprintf(b, "  %-10s %-*s   %s\n", "", width, "", s.Detail)
		}
	}
	fmt.Fprintln(b)
	switch {
	case t.Permitted && t.Conditional:
		fmt.Fprintf(b, "PERMITTED (conditional: %s)\n", t.Condition)
	case t.Permitted:
		fmt.Fprintln(b, "PERMITTED")
	default:
		fmt.Fprintln(b, "DENIED")
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// TraceJSON writes the trace as JSON, with the exit code the command
// will return alongside it.
func TraceJSON(w io.Writer, t *model.Trace, exitCode int) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		*model.Trace
		ExitCode int `json:"exit_code"`
	}{Trace: t, ExitCode: exitCode})
}
