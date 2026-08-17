/*
Copyright © 2026 Ibi Hasanli <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/IbiliAze/iamdiff/internal/diff"
	"github.com/IbiliAze/iamdiff/internal/provider"
	"github.com/IbiliAze/iamdiff/internal/render"
)

// explainCmd represents the explain command
var explainCmd = &cobra.Command{
	Use:   "explain <principal>",
	Short: "Show why a principal can or can't take one action",
	Long: `Explain resolves whether a single principal can perform one action by
composing its identity policies, permissions boundaries and organisation
guardrails, then prints the layer that decided the outcome.

Unlike "iamdiff policy", which diffs two policy documents offline, "explain"
answers a standing question about one principal as it exists today.

For example:

  $ iamdiff explain arn:aws:iam::123456789012:role/deploy --action s3:DeleteObject

  s3:DeleteObject on arn:aws:iam::123456789012:role/deploy

    identity   deploy-policy   Allow
    boundary   ci-boundary     Allow
    guardrail  org-scp         Deny

  DENIED

Pass --verbose to also print the detail behind each layer's outcome.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		principal := args[0]
		action, _ := cmd.Flags().GetString("action")
		providerName, _ := cmd.Flags().GetString("provider")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if action == "" {
			fmt.Fprintln(os.Stderr, "iamdiff: explain requires --action")
			os.Exit(2)
		}

		p, err := provider.Open(providerName, provider.Config{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "iamdiff: %v\n", err)
			os.Exit(2)
		}

		raw, err := p.Collect(cmd.Context(), provider.Selector{Refs: []string{principal}})
		if err != nil {
			fmt.Fprintf(os.Stderr, "iamdiff: %v\n", err)
			os.Exit(2)
		}

		explainer, ok := p.(provider.Explainer)
		if !ok {
			fmt.Fprintf(os.Stderr, "iamdiff: provider %q does not support explain yet\n", providerName)
			os.Exit(diff.ExitIncomplete)
		}

		trace, err := explainer.Explain(cmd.Context(), raw, action)
		if err != nil {
			fmt.Fprintf(os.Stderr, "iamdiff: %v\n", err)
			os.Exit(2)
		}

		if err := render.Trace(os.Stdout, trace, verbose); err != nil {
			fmt.Fprintf(os.Stderr, "iamdiff: %v\n", err)
			os.Exit(2)
		}

		if !trace.Permitted {
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(explainCmd)

	explainCmd.Flags().String("action", "", "the action to explain, e.g. s3:DeleteObject (required)")
	explainCmd.Flags().String("provider", "aws", "cloud provider")
	explainCmd.Flags().BoolP("verbose", "v", false, "show the detail behind each layer's outcome")
}
