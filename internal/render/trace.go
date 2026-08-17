package render

import (
	"fmt"
	"io"

	"github.com/IbiliAze/iamdiff/internal/model"
)

// Trace prints a decision trace produced by provider.Explainer.
// Verbose includes every step's detail; the default view shows only
// the outcome of each layer, matching the density of Text.Render.
func Trace(w io.Writer, t *model.Trace, verbose bool) error {
	fmt.Fprintf(w, "%s on %s\n\n", t.Action, t.Principal.Ref)
	for _, s := range t.Steps {
		fmt.Fprintf(w, "  %-10s %-10s %s\n", s.Layer, s.Name, s.Outcome)
		if verbose && s.Detail != "" {
			fmt.Fprintf(w, "             %s\n", s.Detail)
		}
	}
	fmt.Fprintln(w)
	if t.Permitted {
		fmt.Fprintln(w, "PERMITTED")
	} else {
		fmt.Fprintln(w, "DENIED")
	}
	return nil
}
