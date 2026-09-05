package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/IbiliAze/iamdiff/internal/diff"
	"github.com/IbiliAze/iamdiff/internal/model"
	"github.com/IbiliAze/iamdiff/internal/provider"
)

func newPolicyCmd() *cobra.Command {
	var boundaries, guardrails []string
	c := &cobra.Command{
		Use:   "policy <before> <after>",
		Short: "Diff two policy documents offline, with no credentials",
		Long: `Policy evaluates two documents and diffs the effective permissions each
one grants. It needs no credentials and is the fastest way to gate a
pull request that edits a policy.

Each argument is either a policy document or a snapshot written by
"iamdiff collect". Documents named with --boundary and --guardrail are
composed with both sides, so the diff shows what changed inside the
environment the principal actually runs in. Guardrails at different
levels of an organisation intersect; name the level as LEVEL=FILE and
files that share a level union together.

Example:

  iamdiff policy before.json after.json --guardrail root=scp.json`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicy(cmd, args[0], args[1], boundaries, guardrails)
		},
	}
	c.Flags().StringArrayVar(&boundaries, "boundary", nil, "permissions boundary document composed with both sides (repeatable)")
	c.Flags().StringArrayVar(&guardrails, "guardrail", nil, "organisation guardrail document composed with both sides, optionally LEVEL=FILE (repeatable)")
	return c
}

func runPolicy(cmd *cobra.Command, beforePath, afterPath string, boundaries, guardrails []string) error {
	p, err := openProvider(cmd, true)
	if err != nil {
		return err
	}
	loader, ok := p.(provider.OfflineLoader)
	if !ok {
		return runtimeErr(fmt.Errorf("provider %q cannot evaluate offline", p.Name()))
	}
	r, err := newRenderer(cmd, p)
	if err != nil {
		return err
	}

	env, err := environmentDocuments(boundaries, guardrails)
	if err != nil {
		return runtimeErr(err)
	}

	before, err := evaluateSide(cmd.Context(), p, loader, beforePath, env)
	if err != nil {
		return runtimeErr(err)
	}
	after, err := evaluateSide(cmd.Context(), p, loader, afterPath, env)
	if err != nil {
		return runtimeErr(err)
	}

	report := diff.Single(after.Principal, diff.Compare(before, after))
	if err := r.Render(cmd.OutOrStdout(), report); err != nil {
		return runtimeErr(err)
	}
	return verdictExit(report.ExitCode())
}

// evaluateSide loads one side of the comparison. A file whose top level
// carries a "documents" key is a provider.RawSet snapshot; anything else
// is a single identity policy document.
func evaluateSide(ctx context.Context, p provider.Provider, l provider.OfflineLoader, path string, env []provider.Document) (*model.EffectiveSet, error) {
	raw, err := loadRawSet(p, l, path)
	if err != nil {
		return nil, err
	}
	raw.Documents = append(raw.Documents, env...)
	return p.Evaluate(ctx, raw)
}

func loadRawSet(p provider.Provider, l provider.OfflineLoader, path string) (*provider.RawSet, error) {
	body, err := readJSON(path)
	if err != nil {
		return nil, err
	}

	var probe struct {
		Documents json.RawMessage `json:"documents"`
	}
	if json.Unmarshal(body, &probe) == nil && len(probe.Documents) > 0 && string(probe.Documents) != "null" {
		var raw provider.RawSet
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, fmt.Errorf("%s: parse snapshot: %w", path, err)
		}
		if raw.Principal.Provider == "" {
			raw.Principal.Provider = p.Name()
		}
		return &raw, nil
	}

	return l.FromDocuments(
		model.Principal{Kind: "document", Ref: path},
		[]provider.Document{{Kind: model.SourceIdentity, Name: filepath.Base(path), Body: body}},
	)
}

// environmentDocuments turns --boundary and --guardrail flags into the
// documents composed with both sides.
func environmentDocuments(boundaries, guardrails []string) ([]provider.Document, error) {
	var out []provider.Document
	for _, path := range boundaries {
		body, err := readJSON(path)
		if err != nil {
			return nil, err
		}
		out = append(out, provider.Document{Kind: model.SourceBoundary, Name: filepath.Base(path), Body: body})
	}
	for _, spec := range guardrails {
		level, path := splitLevel(spec)
		body, err := readJSON(path)
		if err != nil {
			return nil, err
		}
		out = append(out, provider.Document{Kind: model.SourceGuardrail, Name: filepath.Base(path), Body: body, Target: level})
	}
	return out, nil
}

// splitLevel parses the optional LEVEL= prefix of a --guardrail value. A
// path containing '=' is still a path as long as the part before it looks
// like a path segment rather than a bare label.
func splitLevel(spec string) (level, path string) {
	i := strings.IndexByte(spec, '=')
	if i <= 0 || i == len(spec)-1 {
		return "", spec
	}
	label := spec[:i]
	if strings.ContainsAny(label, `/\.`) {
		return "", spec
	}
	return label, spec[i+1:]
}

func readJSON(path string) ([]byte, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("%s: not valid JSON", path)
	}
	return body, nil
}
