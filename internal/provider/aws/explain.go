package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/IbiliAze/iamdiff/internal/model"
	"github.com/IbiliAze/iamdiff/internal/provider"
)

// Explain answers whether the principal may take one action on one
// resource, and which layer decided. It runs the same pipeline as
// Evaluate over just the identity grants that name the action, with an
// observer recording each layer's verdict.
func (p *Provider) Explain(ctx context.Context, raw *provider.RawSet, action, resource string) (*model.Trace, error) {
	if action == "" {
		return nil, fmt.Errorf("aws: explain needs an action")
	}
	if strings.ContainsAny(action, "*?") {
		return nil, fmt.Errorf("aws: explain takes one concrete action, not the pattern %q", action)
	}
	if resource == "" {
		resource = "*"
	}

	set, err := p.compile(raw)
	if err != nil {
		return nil, err
	}
	tr := &model.Trace{Principal: raw.Principal, Action: action, Resource: resource}
	tr.Gaps = append(tr.Gaps, raw.Gaps...)
	tr.Gaps = append(tr.Gaps, set.gaps...)
	obs := &tracer{trace: tr}

	// Which identity statements grant the action on this resource? A
	// grant broader than the resource is narrowed to it, so the layers
	// judge the resource the caller asked about; one that only overlaps
	// it is judged as it stands and flagged.
	lower := strings.ToLower(action)
	var candidates []model.Grant
	for _, g := range set.identity {
		if strings.ToLower(g.Action) != lower {
			continue
		}
		switch {
		case covers(g.Resource, resource):
			obs.step(g.Origin.SourceKind, g.Origin.SourceName, "Allow", fmt.Sprintf("statement %d allows %s on %s", g.Origin.Statement, action, g.Resource))
			narrowed := g
			narrowed.Resource = resource
			candidates = append(candidates, narrowed)
		case overlaps(g.Resource, resource):
			obs.step(g.Origin.SourceKind, g.Origin.SourceName, "Allow (partial)", fmt.Sprintf("statement %d allows %s on %s, which covers only part of %s", g.Origin.Statement, action, g.Resource, resource))
			candidates = append(candidates, g)
		}
	}
	if len(candidates) == 0 {
		obs.step(model.SourceIdentity, "-", "NoMatch", fmt.Sprintf("no identity statement allows %s on %s", action, resource))
	}

	var survivors []model.Grant
	for _, g := range candidates {
		grants, gaps := set.resolve(g, obs)
		tr.Gaps = append(tr.Gaps, gaps...)
		survivors = append(survivors, grants...)
	}

	tr.Partial = len(tr.Gaps) > 0
	if len(survivors) == 0 {
		return tr, nil
	}
	tr.Permitted = true
	tr.Conditional = true
	for _, g := range survivors {
		if g.Condition.Empty() {
			tr.Conditional = false
			tr.Condition = ""
			break
		}
		if tr.Condition == "" {
			tr.Condition = g.Condition.Summary
		}
	}
	return tr, nil
}

// tracer records the decision path into a Trace.
type tracer struct {
	trace *model.Trace
}

func (t *tracer) step(kind model.SourceKind, name, outcome, detail string) {
	t.trace.Steps = append(t.trace.Steps, model.Step{Layer: string(kind), Name: name, Outcome: outcome, Detail: detail})
}
