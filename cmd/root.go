/*
Copyright © 2026 Ibi Hasanli

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

// Package cmd is the command surface. Each command is a cobra.Command
// built by a constructor; nothing lives in package-level state, so a
// test can execute the tree as many times as it likes.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/IbiliAze/iamdiff/internal/catalogue"
	"github.com/IbiliAze/iamdiff/internal/provider"
	"github.com/IbiliAze/iamdiff/internal/render"
)

var (
	buildVersion = "dev"
	buildCommit  = "none"
	buildDate    = "unknown"
)

// SetVersion records the build metadata the linker injects into main.
func SetVersion(version, commit, date string) {
	buildVersion, buildCommit, buildDate = version, commit, date
}

// NewRoot builds a fresh command tree.
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "iamdiff",
		Short: "Effective cloud IAM permissions diff and explanation",
		Long: `iamdiff resolves what a principal can actually do by composing identity
policies, permissions boundaries and organisation guardrails, then diffs
two resolved sets. It answers one question inside a pull request review:
did this change widen access, and why?

Exit codes are the contract:

  0  unchanged
  1  narrowed only
  2  widened
  3  indeterminate - a condition changed; review manually
  4  incomplete - a policy source could not be read
  64 bad command line
  70 failure at run time`,
		Version:       buildVersion,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetVersionTemplate("iamdiff {{.Version}}\n")
	root.PersistentFlags().String("provider", "aws", "cloud provider")
	root.PersistentFlags().String("output", "text", "output format: text, json, markdown")
	root.PersistentFlags().String("profile", "", "credentials profile for commands that talk to the cloud")

	root.AddCommand(
		newPolicyCmd(),
		newPlanCmd(),
		newRolesCmd(),
		newCollectCmd(),
		newExplainCmd(),
		newProvidersCmd(),
		newVersionCmd(),
	)
	return root
}

// Execute runs the CLI with the given arguments and returns the process
// exit code. Verdict codes pass through untouched; anything cobra rejects
// before a command runs is a usage error.
func Execute(ctx context.Context, args []string, out, errw io.Writer) int {
	root := NewRoot()
	root.SetArgs(args)
	root.SetOut(out)
	root.SetErr(errw)

	cmd, err := root.ExecuteContextC(ctx)
	if err == nil {
		return 0
	}

	var ee *exitError
	if errors.As(err, &ee) {
		if ee.err != nil {
			fmt.Fprintf(errw, "iamdiff: %v\n", ee.err)
		}
		return ee.code
	}

	fmt.Fprintf(errw, "iamdiff: %v\n", err)
	if cmd != nil {
		fmt.Fprintf(errw, "Run '%s --help' for usage.\n", cmd.CommandPath())
	}
	return ExitUsage
}

// openProvider constructs the provider named by the persistent flags.
func openProvider(cmd *cobra.Command, offline bool) (provider.Provider, error) {
	name, _ := cmd.Flags().GetString("provider")
	profile, _ := cmd.Flags().GetString("profile")
	p, err := provider.Open(name, provider.Config{Profile: profile, Offline: offline})
	if err != nil {
		return nil, usageErr("%v", err)
	}
	return p, nil
}

// newRenderer selects the renderer named by --output, feeding it the
// provider's catalogue when it has one.
func newRenderer(cmd *cobra.Command, p provider.Provider) (render.Renderer, error) {
	format, _ := cmd.Flags().GetString("output")
	var cat catalogue.Catalogue
	if c, ok := p.(provider.Cataloguer); ok {
		cat = c.Catalogue()
	}
	r, err := render.New(format, cat)
	if err != nil {
		return nil, usageErr("%v", err)
	}
	return r, nil
}
