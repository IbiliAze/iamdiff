package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/IbiliAze/iamdiff/internal/provider"
)

func newCollectCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "collect <principal>",
		Short: "Snapshot everything that decides a principal's permissions",
		Long: `Collect reads a principal's identity policies, permissions boundary and
service control policies through the cloud API and writes them as one
JSON snapshot. The snapshot needs no credentials to evaluate: pass it to
"iamdiff policy" as either side of a comparison, or to "iamdiff explain
--from".

  iamdiff collect role/deploy --out before.json
  ... apply the change ...
  iamdiff collect role/deploy --out after.json
  iamdiff policy before.json after.json

A principal is an ARN, role/NAME or user/NAME in the credentials' account.
Sources the credentials cannot read are recorded as gaps in the snapshot,
and any evaluation of it will say so.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCollect(cmd, args[0], out)
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "", "write the snapshot to this file instead of standard output")
	return c
}

func runCollect(cmd *cobra.Command, principal, out string) error {
	p, err := openProvider(cmd, false)
	if err != nil {
		return err
	}
	raw, err := p.Collect(cmd.Context(), provider.Selector{Refs: []string{principal}})
	if err != nil {
		return runtimeErr(err)
	}

	w := cmd.OutOrStdout()
	var file *os.File
	if out != "" {
		file, err = os.Create(out)
		if err != nil {
			return runtimeErr(err)
		}
		w = file
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(raw); err != nil {
		return runtimeErr(err)
	}
	if file != nil {
		// A snapshot that did not reach the disk is worse than none.
		if err := file.Close(); err != nil {
			return runtimeErr(err)
		}
	}
	if len(raw.Gaps) > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "iamdiff: snapshot is partial - %d source(s) could not be read:\n", len(raw.Gaps))
		for _, g := range raw.Gaps {
			fmt.Fprintf(cmd.ErrOrStderr(), "  ! %s\n", g)
		}
	}
	return nil
}
