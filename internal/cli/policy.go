package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/IbiliAze/iamdiff/internal/catalogue"
	"github.com/IbiliAze/iamdiff/internal/core/diff"
	"github.com/IbiliAze/iamdiff/internal/core/model"
	"github.com/IbiliAze/iamdiff/internal/core/render"
	"github.com/IbiliAze/iamdiff/internal/provider"
)

// runPolicy diffs two policy documents with no credentials at all.
// Deliberately the first command implemented: it exercises the whole
// pipeline end to end and is demonstrable by anyone in ten seconds.
func runPolicy(ctx context.Context, env Env, args []string) int {
	fs := flag.NewFlagSet("policy", flag.ContinueOnError)
	fs.SetOutput(env.Err)
	name := fs.String("provider", "aws", "cloud provider")
	format := fs.String("output", "text", "output format: text, json, markdown")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(env.Err, "usage: iamdiff policy <before.json> <after.json>")
		return 2
	}

	p, err := provider.Open(*name, provider.Config{Offline: true})
	if err != nil {
		fmt.Fprintf(env.Err, "iamdiff: %v\n", err)
		return 2
	}
	loader, ok := p.(provider.OfflineLoader)
	if !ok {
		fmt.Fprintf(env.Err, "iamdiff: provider %q cannot evaluate offline\n", *name)
		return 2
	}

	before, err := evaluateFile(ctx, p, loader, fs.Arg(0))
	if err != nil {
		fmt.Fprintf(env.Err, "iamdiff: %v\n", err)
		return 2
	}
	after, err := evaluateFile(ctx, p, loader, fs.Arg(1))
	if err != nil {
		fmt.Fprintf(env.Err, "iamdiff: %v\n", err)
		return 2
	}

	result := diff.Compare(before, after)

	var cat catalogue.Catalogue
	if c, ok := p.(provider.Cataloguer); ok {
		cat = c.Catalogue()
	}
	r, err := render.New(*format, cat)
	if err != nil {
		fmt.Fprintf(env.Err, "iamdiff: %v\n", err)
		return 2
	}
	if err := r.Render(env.Out, result); err != nil {
		fmt.Fprintf(env.Err, "iamdiff: %v\n", err)
		return 2
	}
	return result.ExitCode()
}

func evaluateFile(ctx context.Context, p provider.Provider, l provider.OfflineLoader, path string) (*model.EffectiveSet, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("%s: not valid JSON", path)
	}
	raw, err := l.FromDocuments(
		model.Principal{Kind: "document", Ref: path},
		[]provider.Document{{Kind: model.SourceIdentity, Name: path, Body: body}},
	)
	if err != nil {
		return nil, err
	}
	return p.Evaluate(ctx, raw)
}
