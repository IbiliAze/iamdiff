package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/IbiliAze/iamdiff/internal/diff"
	"github.com/IbiliAze/iamdiff/internal/plan"
	"github.com/IbiliAze/iamdiff/internal/provider"
)

func newPlanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "plan <plan.json>",
		Short: "Diff the effective permissions an infrastructure plan would change",
		Long: `Plan reads the machine-readable form of a Terraform plan and diffs the
effective permissions of every principal it touches, before and after.
Pass "-" to read the plan from standard input.

  terraform plan -out=tfplan
  terraform show -json tfplan | iamdiff plan -

A policy computed at apply time, or attached by an ARN whose content the
plan does not carry, cannot be evaluated; the result says so and exits 4.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlan(cmd, args[0])
		},
	}
}

func runPlan(cmd *cobra.Command, path string) error {
	p, err := openProvider(cmd, true)
	if err != nil {
		return err
	}
	adapter, ok := p.(provider.PlanAdapter)
	if !ok {
		return runtimeErr(fmt.Errorf("provider %q cannot read plans: %w", p.Name(), provider.ErrUnsupported))
	}
	r, err := newRenderer(cmd, p)
	if err != nil {
		return err
	}

	body, err := readPlan(cmd.InOrStdin(), path)
	if err != nil {
		return runtimeErr(err)
	}
	pl, err := plan.Parse(body)
	if err != nil {
		return runtimeErr(err)
	}
	changes, err := adapter.FromPlan(pl)
	if err != nil {
		return runtimeErr(err)
	}

	var report diff.Report
	for _, c := range changes {
		before, err := p.Evaluate(cmd.Context(), c.Before)
		if err != nil {
			return runtimeErr(fmt.Errorf("%s (before): %w", c.Principal.Ref, err))
		}
		after, err := p.Evaluate(cmd.Context(), c.After)
		if err != nil {
			return runtimeErr(fmt.Errorf("%s (after): %w", c.Principal.Ref, err))
		}
		report.Entries = append(report.Entries, diff.Entry{Principal: c.Principal, Result: diff.Compare(before, after)})
	}

	if err := r.Render(cmd.OutOrStdout(), report); err != nil {
		return runtimeErr(err)
	}
	return verdictExit(report.ExitCode())
}

func readPlan(stdin io.Reader, path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path)
}
