package cmd

import (
	"github.com/spf13/cobra"

	"github.com/IbiliAze/iamdiff/internal/diff"
	"github.com/IbiliAze/iamdiff/internal/provider"
)

func newRolesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "roles <a> <b>",
		Short: "Diff the effective permissions of two live principals",
		Long: `Roles collects two principals through the cloud API, resolves what each
can actually do, and diffs the two. Use it to compare a role against its
counterpart in another environment, or a user against the role meant to
replace it.

  iamdiff roles role/deploy-staging role/deploy-prod

Each principal is an ARN, role/NAME or user/NAME in the credentials'
account. To compare one principal with itself across a change, snapshot it
with "iamdiff collect" before and after and diff the snapshots offline.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRoles(cmd, args[0], args[1])
		},
	}
}

func runRoles(cmd *cobra.Command, a, b string) error {
	p, err := openProvider(cmd, false)
	if err != nil {
		return err
	}
	r, err := newRenderer(cmd, p)
	if err != nil {
		return err
	}

	rawA, err := p.Collect(cmd.Context(), provider.Selector{Refs: []string{a}})
	if err != nil {
		return runtimeErr(err)
	}
	rawB, err := p.Collect(cmd.Context(), provider.Selector{Refs: []string{b}})
	if err != nil {
		return runtimeErr(err)
	}
	before, err := p.Evaluate(cmd.Context(), rawA)
	if err != nil {
		return runtimeErr(err)
	}
	after, err := p.Evaluate(cmd.Context(), rawB)
	if err != nil {
		return runtimeErr(err)
	}

	report := diff.Single(after.Principal, diff.Compare(before, after))
	if err := r.Render(cmd.OutOrStdout(), report); err != nil {
		return runtimeErr(err)
	}
	return verdictExit(report.ExitCode())
}
