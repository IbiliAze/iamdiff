// Package cli is the command surface.
//
// Phase 1 uses stdlib flag with a hand-rolled dispatch so the tool
// builds with zero external dependencies. The shape mirrors Cobra's
// command tree exactly, so swapping it in at phase 2 is mechanical:
// each run* function becomes a *cobra.Command RunE.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/IbiliAze/iamdiff/internal/core/diff"
	"github.com/IbiliAze/iamdiff/internal/provider"
)

const Version = "0.1.0-dev"

type Env struct {
	Out io.Writer
	Err io.Writer
}

func Default() Env { return Env{Out: os.Stdout, Err: os.Stderr} }

const usage = `iamdiff - effective cloud IAM permissions diff

Usage:
  iamdiff policy <before.json> <after.json>   Diff two policy documents offline
  iamdiff roles <a> <b>                       Diff two live principals      (phase 3)
  iamdiff plan <plan.json>                    Diff a Terraform plan         (phase 4)
  iamdiff explain <principal> --action <a>    Explain one decision          (phase 5)
  iamdiff providers                           List registered providers
  iamdiff version

Flags:
  --provider string   cloud provider (default "aws")
  --output   string   text | json | markdown (default "text")

Exit codes:
  0 unchanged   1 narrowed   2 widened   3 indeterminate   4 incomplete
`

// Run dispatches a command and returns the process exit code.
func Run(ctx context.Context, env Env, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(env.Out, usage)
		return 0
	}

	switch args[0] {
	case "policy":
		return runPolicy(ctx, env, args[1:])
	case "providers":
		fmt.Fprintf(env.Out, "%v\n", provider.Available())
		return 0
	case "version":
		fmt.Fprintf(env.Out, "iamdiff %s\n", Version)
		return 0
	case "roles", "plan", "explain":
		fmt.Fprintf(env.Err, "iamdiff: %q is not implemented yet - see the roadmap in README.md\n", args[0])
		return diff.ExitIncomplete
	case "-h", "--help", "help":
		fmt.Fprint(env.Out, usage)
		return 0
	default:
		fmt.Fprintf(env.Err, "iamdiff: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
