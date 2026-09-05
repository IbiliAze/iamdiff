package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/IbiliAze/iamdiff/internal/provider"
)

func newProvidersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "providers",
		Short: "List the cloud providers compiled into this binary",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, name := range provider.Available() {
				fmt.Fprintln(cmd.OutOrStdout(), name)
			}
			return nil
		},
	}
}
