package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/IbiliAze/iamdiff/internal/diff"
	"github.com/IbiliAze/iamdiff/internal/model"
	"github.com/IbiliAze/iamdiff/internal/provider"
	"github.com/IbiliAze/iamdiff/internal/render"
)

// Exit codes for explain. They share meaning with the diff codes where
// they can: 3 is "review a condition", 4 is "a source was unreachable".
const (
	ExitPermitted   = 0
	ExitDenied      = 1
	ExitConditional = diff.ExitIndeterminate
)

func newExplainCmd() *cobra.Command {
	var action, resource, from string
	var verbose bool
	c := &cobra.Command{
		Use:   "explain <principal>",
		Short: "Show why a principal can or can't take one action",
		Long: `Explain resolves whether a single principal can perform one action by
composing its identity policies, permissions boundaries and organisation
guardrails, then prints the layer that decided the outcome.

Unlike "iamdiff policy", which diffs two policy documents offline, "explain"
answers a standing question about one principal: as it exists today, or as
captured in a snapshot from "iamdiff collect" with --from.

  $ iamdiff explain role/deploy --action s3:DeleteObject --resource arn:aws:s3:::assets/*

  s3:DeleteObject on arn:aws:iam::123456789012:role/deploy
    resource arn:aws:s3:::assets/*

    identity   deploy-policy   Allow
    boundary   boundary        Allow
    guardrail  ou-prod         Deny

  DENIED

Exit codes: 0 permitted, 1 denied, 3 permitted only under a condition,
4 incomplete because a policy source could not be read. Pass --verbose to
also print the detail behind each layer's outcome; --output json prints
the whole trace.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExplain(cmd, args[0], action, resource, from, verbose)
		},
	}
	c.Flags().StringVar(&action, "action", "", "the action to explain, e.g. s3:DeleteObject (required)")
	_ = c.MarkFlagRequired("action")
	c.Flags().StringVar(&resource, "resource", "*", "the resource the action is taken on")
	c.Flags().StringVar(&from, "from", "", "explain a snapshot written by \"iamdiff collect\" instead of the live principal")
	c.Flags().BoolVarP(&verbose, "verbose", "v", false, "show the detail behind each layer's outcome")
	return c
}

func runExplain(cmd *cobra.Command, principal, action, resource, from string, verbose bool) error {
	format, _ := cmd.Flags().GetString("output")
	if format != "" && format != "text" && format != "json" {
		return usageErr("explain prints text or json, not %q", format)
	}
	p, err := openProvider(cmd, from != "")
	if err != nil {
		return err
	}
	explainer, ok := p.(provider.Explainer)
	if !ok {
		return runtimeErr(fmt.Errorf("provider %q does not support explain: %w", p.Name(), provider.ErrUnsupported))
	}

	var raw *provider.RawSet
	if from != "" {
		raw, err = loadSnapshot(p, from, principal)
	} else {
		raw, err = p.Collect(cmd.Context(), provider.Selector{Refs: []string{principal}})
	}
	if err != nil {
		return runtimeErr(err)
	}

	trace, err := explainer.Explain(cmd.Context(), raw, action, resource)
	if err != nil {
		return runtimeErr(err)
	}

	code := ExitPermitted
	switch {
	case trace.Partial:
		code = diff.ExitIncomplete
	case !trace.Permitted:
		code = ExitDenied
	case trace.Conditional:
		code = ExitConditional
	}
	if format == "json" {
		err = render.TraceJSON(cmd.OutOrStdout(), trace, code)
	} else {
		err = render.Trace(cmd.OutOrStdout(), trace, verbose)
	}
	if err != nil {
		return runtimeErr(err)
	}
	return verdictExit(code)
}

// loadSnapshot reads a RawSet written by "iamdiff collect". The
// principal argument must agree with the snapshot, or be the snapshot's
// own reference, so a trace is never attributed to the wrong identity.
func loadSnapshot(p provider.Provider, path, principal string) (*provider.RawSet, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw provider.RawSet
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("%s: parse snapshot: %w", path, err)
	}
	if raw.Documents == nil && raw.Principal.Ref == "" {
		return nil, fmt.Errorf("%s: not a snapshot written by \"iamdiff collect\"", path)
	}
	if raw.Principal.Provider == "" {
		raw.Principal.Provider = p.Name()
	}
	if raw.Principal.Ref == "" {
		raw.Principal = model.Principal{Provider: p.Name(), Ref: principal}
	} else if principal != raw.Principal.Ref && principal != raw.Principal.Kind+"/"+lastSegment(raw.Principal.Ref) {
		return nil, fmt.Errorf("%s holds %s, not %s", path, raw.Principal.Ref, principal)
	}
	return &raw, nil
}

func lastSegment(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return s[i+1:]
		}
	}
	return s
}
