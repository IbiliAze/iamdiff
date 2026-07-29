package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/IbiliAze/iamdiff/internal/core/model"
	"github.com/IbiliAze/iamdiff/internal/provider"
)

// Evaluate applies AWS's own precedence rules and returns a flat,
// provider-neutral effective set.
//
// AWS composition, in order:
//  1. identity allows are unioned
//  2. guardrails (boundary, SCP) intersect -- they never add access
//  3. any explicit deny anywhere wins outright
//
// Steps 2 and 3 are what distinguish this from a policy linter, and are
// the reason the answer cannot be derived from one document alone.
func (p *Provider) Evaluate(ctx context.Context, raw *provider.RawSet) (*model.EffectiveSet, error) {
	out := model.NewEffectiveSet(raw.Principal)
	out.Catalogue = p.cat.Version()
	for _, g := range raw.Gaps {
		out.MarkGap(g)
	}

	var identity []model.Grant
	var denies []model.Grant
	guardrails := map[model.SourceKind][]model.Grant{}

	for _, doc := range raw.Documents {
		parsed, err := parseDocument(doc.Body)
		if err != nil {
			return nil, fmt.Errorf("document %q: %w", doc.Name, err)
		}
		grants, err := p.expand(parsed, doc)
		if err != nil {
			return nil, fmt.Errorf("document %q: %w", doc.Name, err)
		}
		for _, g := range grants {
			if g.Effect == model.Deny {
				denies = append(denies, g)
				continue
			}
			switch doc.Kind {
			case model.SourceBoundary, model.SourceGuardrail:
				guardrails[doc.Kind] = append(guardrails[doc.Kind], g)
			default:
				identity = append(identity, g)
			}
		}
	}

	for _, g := range identity {
		if permittedBy(guardrails, g) {
			out.Add(g)
		}
	}

	// Explicit deny is applied last and unconditionally.
	for _, d := range denies {
		out.Grants[d.Key()] = d
	}

	return out, nil
}

// permittedBy intersects an identity grant with each guardrail layer
// that is present. A layer that was never collected does not silently
// permit -- the caller records a gap instead.
func permittedBy(layers map[model.SourceKind][]model.Grant, g model.Grant) bool {
	for _, grants := range layers {
		ok := false
		for _, l := range grants {
			if wildcardMatch(l.Action, g.Action) && resourceMatch(l.Resource, g.Resource) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// expand turns one policy document into concrete grants.
func (p *Provider) expand(d *Document, doc provider.Document) ([]model.Grant, error) {
	var out []model.Grant
	for i, st := range d.Statement {
		effect := model.Allow
		if strings.EqualFold(st.Effect, "Deny") {
			effect = model.Deny
		}
		if len(st.NotAction) > 0 {
			// NotAction inverts the action set. Deferred deliberately:
			// getting it subtly wrong is worse than declining it.
			return nil, fmt.Errorf("statement %d: NotAction is not yet supported", i)
		}
		resources := st.Resource
		if len(resources) == 0 {
			resources = []string{"*"}
		}
		cond := model.NewCondition(st.Condition)
		for _, pattern := range st.Action {
			actions, err := p.cat.Expand(pattern)
			if err != nil {
				return nil, fmt.Errorf("statement %d: %w", i, err)
			}
			for _, a := range actions {
				for _, r := range resources {
					out = append(out, model.Grant{
						Action:    a,
						Resource:  r,
						Effect:    effect,
						Condition: cond,
						Origin: model.Origin{
							SourceKind: doc.Kind,
							SourceName: doc.Name,
							Statement:  i,
							Inherited:  doc.Inherited,
						},
					})
				}
			}
		}
	}
	return out, nil
}

func wildcardMatch(pattern, s string) bool {
	if pattern == "*" || pattern == s {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(strings.ToLower(s), strings.ToLower(strings.TrimSuffix(pattern, "*")))
	}
	return strings.EqualFold(pattern, s)
}

// resourceMatch is intentionally simple for phase 1. Full ARN
// segment-aware matching lands with live collection in phase 3.
func resourceMatch(pattern, s string) bool { return wildcardMatch(pattern, s) }
