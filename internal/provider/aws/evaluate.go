package aws

import (
	"context"

	"github.com/IbiliAze/iamdiff/internal/model"
	"github.com/IbiliAze/iamdiff/internal/provider"
)

// Evaluate applies AWS's own precedence rules and returns a flat,
// provider-neutral effective set.
//
// AWS composition, in order:
//  1. identity allows are unioned
//  2. the permissions boundary intersects -- it never adds access
//  3. guardrails intersect, one layer per organisation level, because
//     an action must be allowed at every level from the root down
//  4. any explicit deny anywhere wins outright
//
// Steps 2 to 4 are what distinguish this from a policy linter, and are
// the reason the answer cannot be derived from one document alone.
//
// Conditions stay opaque throughout. A conditional allow in a layer, a
// conditional deny, or a deny that removes only part of a grant's
// resources all become clauses of the grant's condition rather than a
// guess about whether access exists: the diff then reports a change to
// any of them as "condition changed", never as silence.
func (p *Provider) Evaluate(ctx context.Context, raw *provider.RawSet) (*model.EffectiveSet, error) {
	return p.evaluate(raw, nil)
}

func (p *Provider) evaluate(raw *provider.RawSet, obs observer) (*model.EffectiveSet, error) {
	out := model.NewEffectiveSet(raw.Principal)
	out.Catalogue = p.cat.Version()
	for _, g := range raw.Gaps {
		out.MarkGap(g)
	}

	set, err := p.compile(raw)
	if err != nil {
		return nil, err
	}
	for _, g := range set.gaps {
		out.MarkGap(g)
	}

	seen := map[string]bool{}
	for _, g := range set.identity {
		grants, gaps := set.resolve(g, obs)
		for _, gap := range gaps {
			if !seen[gap] {
				seen[gap] = true
				out.MarkGap(gap)
			}
		}
		for _, final := range grants {
			out.Add(final)
		}
	}
	return out, nil
}
