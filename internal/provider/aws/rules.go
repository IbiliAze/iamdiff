package aws

import (
	"fmt"
	"sort"
	"strings"

	"github.com/IbiliAze/iamdiff/internal/glob"
	"github.com/IbiliAze/iamdiff/internal/model"
	"github.com/IbiliAze/iamdiff/internal/provider"
)

// A policy statement is kept as a rule: patterns, not expansions. Only
// identity allows are expanded into concrete grants, because those are
// what the diff compares. Everything that restricts them -- boundaries,
// guardrails, explicit denies -- stays a pattern and is matched against
// each grant. Expanding a guardrail's "*" through a catalogue of twenty
// thousand actions would be both slow and pointless.
type rule struct {
	effect       model.Effect
	actions      []string // lower-cased patterns; empty when notActions is set
	notActions   []string // lower-cased patterns
	resources    []string // patterns; ["*"] when the statement names none
	notResources []string
	cond         model.Condition
	origin       model.Origin
	service      string // literal service prefix shared by every action pattern, or "" for any
}

func (r *rule) matchesAction(lowerAction string) bool {
	if len(r.notActions) > 0 {
		for _, p := range r.notActions {
			if glob.Match(p, lowerAction, false) {
				return false
			}
		}
		return true
	}
	for _, p := range r.actions {
		if glob.Match(p, lowerAction, false) {
			return true
		}
	}
	return false
}

// resourceSummary names the rule's resource clause for messages.
func (r *rule) resourceSummary() string {
	s := strings.Join(r.resources, ",")
	if len(r.notResources) > 0 {
		s += " except " + strings.Join(r.notResources, ",")
	}
	return s
}

// relation classifies how a rule's resource clause applies to one grant's
// resource pattern.
type relation struct {
	full    bool     // the clause covers every resource the grant names
	narrow  []string // clause patterns inside the grant's pattern: the intersection, exactly
	partial bool     // some overlap that no pattern can express
}

func covers(pattern, res string) bool {
	if pattern == "*" || pattern == res {
		return true
	}
	if glob.IsLiteral(pattern) {
		return glob.IsLiteral(res) && pattern == res
	}
	return glob.Covers(pattern, res, false)
}

func overlaps(pattern, res string) bool {
	if pattern == "*" || res == "*" || pattern == res {
		return true
	}
	if glob.IsLiteral(pattern) && glob.IsLiteral(res) {
		return false
	}
	return glob.Overlaps(pattern, res, false)
}

// relate works out how the rule's resource clause meets the grant's
// resource pattern. Resource matching is case-sensitive, as ARNs are.
func (r *rule) relate(res string) relation {
	var rel relation
	for _, n := range r.notResources {
		if covers(n, res) {
			return rel // excluded outright
		}
	}
	excludedInPart := false
	for _, n := range r.notResources {
		if overlaps(n, res) {
			excludedInPart = true
		}
	}
	for _, p := range r.resources {
		switch {
		case covers(p, res):
			rel.full = true
		case covers(res, p):
			rel.narrow = append(rel.narrow, p)
		case overlaps(p, res):
			rel.partial = true
		}
	}
	if excludedInPart && (rel.full || len(rel.narrow) > 0) {
		// The clause reaches the grant but a NotResource takes an
		// inexpressible bite out of it.
		rel.full, rel.narrow, rel.partial = false, nil, true
	}
	return rel
}

// index finds the rules that could name an action without scanning
// every rule for every one of twenty thousand grants.
type index struct {
	byService map[string][]*rule
	any       []*rule
}

func newIndex() *index { return &index{byService: map[string][]*rule{}} }

func (ix *index) add(r *rule) {
	if r.service == "" {
		ix.any = append(ix.any, r)
		return
	}
	ix.byService[r.service] = append(ix.byService[r.service], r)
}

// for_ returns every rule whose action clause matches.
func (ix *index) for_(lowerAction string) []*rule {
	service, _, _ := strings.Cut(lowerAction, ":")
	var out []*rule
	for _, r := range ix.byService[service] {
		if r.matchesAction(lowerAction) {
			out = append(out, r)
		}
	}
	for _, r := range ix.any {
		if r.matchesAction(lowerAction) {
			out = append(out, r)
		}
	}
	return out
}

// layer is a set of allow rules that must, between them, permit a grant
// for it to survive. A boundary is one layer; each guardrail target is
// its own layer, because an organisation requires an allow at every
// level between the root and the account.
type layer struct {
	kind   model.SourceKind
	name   string
	depth  int // distance from the organisation root, when known
	allows *index
}

// ruleset is a RawSet compiled for evaluation.
type ruleset struct {
	identity []model.Grant
	layers   []*layer
	denies   *index
	gaps     []string
}

// compile parses every document into identity grants, allow layers and
// deny rules.
func (p *Provider) compile(raw *provider.RawSet) (*ruleset, error) {
	set := &ruleset{denies: newIndex()}
	guardrails := map[string]*layer{}
	var boundary *layer

	for _, doc := range raw.Documents {
		parsed, err := parseDocument(doc.Body)
		if err != nil {
			return nil, fmt.Errorf("document %q: %w", doc.Name, err)
		}
		for i, st := range parsed.Statement {
			r, err := compileStatement(st, doc, i)
			if err != nil {
				return nil, fmt.Errorf("document %q: %w", doc.Name, err)
			}
			if r == nil {
				continue
			}
			if r.effect == model.Deny {
				set.denies.add(r)
				continue
			}
			switch doc.Kind {
			case model.SourceBoundary:
				if boundary == nil {
					boundary = &layer{kind: doc.Kind, name: doc.Name, allows: newIndex()}
				}
				boundary.allows.add(r)
			case model.SourceGuardrail:
				target := doc.Target
				if target == "" {
					target = "guardrail"
				}
				l, ok := guardrails[target]
				if !ok {
					l = &layer{kind: doc.Kind, name: target, depth: len(doc.Inherited), allows: newIndex()}
					guardrails[target] = l
				}
				l.allows.add(r)
			default:
				grants, gaps, err := p.expandAllow(r, st, doc, i)
				if err != nil {
					return nil, fmt.Errorf("document %q: %w", doc.Name, err)
				}
				set.identity = append(set.identity, grants...)
				set.gaps = append(set.gaps, gaps...)
			}
		}
	}

	if boundary != nil {
		set.layers = append(set.layers, boundary)
	}
	// Root first when the chain is known, so a trace reads top-down;
	// by name otherwise, so the order is at least stable.
	levels := make([]*layer, 0, len(guardrails))
	for _, l := range guardrails {
		levels = append(levels, l)
	}
	sort.Slice(levels, func(i, j int) bool {
		if levels[i].depth != levels[j].depth {
			return levels[i].depth < levels[j].depth
		}
		return levels[i].name < levels[j].name
	})
	set.layers = append(set.layers, levels...)
	return set, nil
}

// compileStatement turns one statement into a rule, or nil for a
// statement that grants nothing this tool models (a resource policy's
// Principal-only statement, say).
func compileStatement(st Statement, doc provider.Document, i int) (*rule, error) {
	if len(st.Action) == 0 && len(st.NotAction) == 0 {
		return nil, nil
	}
	r := &rule{
		effect:       model.Allow,
		resources:    st.Resource,
		notResources: st.NotResource,
		cond:         model.NewCondition(st.Condition),
		origin: model.Origin{
			SourceKind: doc.Kind,
			SourceName: doc.Name,
			SourceRef:  doc.Target,
			Statement:  i,
			Inherited:  doc.Inherited,
		},
	}
	if strings.EqualFold(st.Effect, "Deny") {
		r.effect = model.Deny
	} else if !strings.EqualFold(st.Effect, "Allow") {
		return nil, fmt.Errorf("statement %d: effect %q is neither Allow nor Deny", i, st.Effect)
	}
	if len(r.resources) == 0 {
		r.resources = []string{"*"}
	}
	for _, a := range st.Action {
		if a == "" {
			return nil, fmt.Errorf("statement %d: empty action", i)
		}
		r.actions = append(r.actions, strings.ToLower(a))
	}
	for _, a := range st.NotAction {
		r.notActions = append(r.notActions, strings.ToLower(a))
	}
	r.service = commonService(r.actions)
	return r, nil
}

// commonService returns the literal service prefix every pattern shares,
// or "" when any pattern could reach other services.
func commonService(patterns []string) string {
	service := ""
	for _, p := range patterns {
		prefix, _, ok := strings.Cut(p, ":")
		if !ok || !glob.IsLiteral(prefix) {
			return ""
		}
		if service == "" {
			service = prefix
		} else if service != prefix {
			return ""
		}
	}
	return service
}

// expandAllow turns an identity allow into concrete grants, one per
// action and resource. A wildcard the catalogue cannot expand is a gap:
// the tool cannot see what it grants, and pretending otherwise is the
// one unacceptable failure. NotAction is the catalogue's complement.
// NotResource becomes a grant on everything with a carve-out clause, so
// the exclusion is visible and any change to it is a condition change.
func (p *Provider) expandAllow(r *rule, st Statement, doc provider.Document, i int) (grants []model.Grant, gaps []string, err error) {
	var actions []string
	if len(r.notActions) > 0 {
		all, err := p.cat.Expand("*")
		if err != nil {
			return nil, nil, fmt.Errorf("statement %d: %w", i, err)
		}
		for _, a := range all {
			if r.matchesAction(strings.ToLower(a)) {
				actions = append(actions, a)
			}
		}
	} else {
		for _, pattern := range st.Action {
			expanded, err := p.cat.Expand(pattern)
			if err != nil {
				return nil, nil, fmt.Errorf("statement %d: %w", i, err)
			}
			if len(expanded) == 0 {
				gaps = append(gaps, fmt.Sprintf("document %q statement %d: action pattern %q matches nothing in catalogue %s", doc.Name, i, pattern, p.cat.Version()))
				continue
			}
			actions = append(actions, expanded...)
		}
	}

	resources := r.resources
	cond := r.cond
	if len(r.notResources) > 0 {
		resources = []string{"*"}
		cond = model.ComposeCondition(
			model.Part(model.RoleRequire, r.cond, ""),
			model.Part(model.RoleUnless, model.Condition{}, "except "+strings.Join(r.notResources, ",")),
		)
	}

	for _, a := range actions {
		for _, res := range resources {
			grants = append(grants, model.Grant{
				Action:    a,
				Resource:  res,
				Effect:    model.Allow,
				Condition: cond,
				Origin:    r.origin,
			})
		}
	}
	return grants, gaps, nil
}

// observer receives the decision path for one grant. Evaluate passes
// nil; Explain uses it to build a trace.
type observer interface {
	step(kind model.SourceKind, name, outcome, detail string)
}

// resolve pushes one identity grant through every layer and then the
// denies, returning what survives. A layer may narrow the grant to the
// resources it actually permits, so one grant in can be several out.
func (set *ruleset) resolve(g model.Grant, obs observer) (out []model.Grant, gaps []string) {
	lower := strings.ToLower(g.Action)
	type candidate struct {
		resource string
		parts    []model.ConditionPart
	}
	current := []candidate{{resource: g.Resource, parts: []model.ConditionPart{model.Part(model.RoleRequire, g.Condition, "")}}}

	for _, l := range set.layers {
		rules := l.allows.for_(lower)
		var next []candidate
		for _, c := range current {
			var full []*rule
			narrowed := map[string]*rule{}
			var partialRule *rule
			for _, r := range rules {
				rel := r.relate(c.resource)
				switch {
				case rel.full:
					full = append(full, r)
				case len(rel.narrow) > 0:
					for _, res := range rel.narrow {
						if prev, ok := narrowed[res]; !ok || (!prev.cond.Empty() && r.cond.Empty()) {
							narrowed[res] = r
						}
					}
				case rel.partial:
					partialRule = r
				}
			}

			switch {
			case len(full) > 0:
				var conds []model.Condition
				unconditional := false
				for _, r := range full {
					if r.cond.Empty() {
						unconditional = true
						break
					}
					conds = append(conds, r.cond)
				}
				if unconditional {
					observe(obs, l, "Allow", fmt.Sprintf("%s permits %s", describe(full[0]), c.resource))
					next = append(next, c)
					continue
				}
				anyOf := conds[0]
				for _, extra := range conds[1:] {
					anyOf = model.Any(anyOf, extra)
				}
				observe(obs, l, "Allow (conditional)", fmt.Sprintf("%s permits %s only under a condition", describe(full[0]), c.resource))
				next = append(next, candidate{resource: c.resource, parts: append(clone(c.parts), model.Part(model.RoleRequire, anyOf, ""))})
			case len(narrowed) > 0:
				keys := make([]string, 0, len(narrowed))
				for res := range narrowed {
					keys = append(keys, res)
				}
				sort.Strings(keys)
				for _, res := range keys {
					r := narrowed[res]
					parts := clone(c.parts)
					if !r.cond.Empty() {
						parts = append(parts, model.Part(model.RoleRequire, r.cond, ""))
					}
					observe(obs, l, "Narrow", fmt.Sprintf("%s permits only %s of %s", describe(r), res, c.resource))
					next = append(next, candidate{resource: res, parts: parts})
				}
				if partialRule != nil {
					gaps = append(gaps, partialGap(l, partialRule, g.Action, c.resource))
				}
			case partialRule != nil:
				// The layer reaches part of the grant in a way no pattern
				// can express. Keep the grant so a widening is never
				// hidden, and say so.
				observe(obs, l, "Partial", fmt.Sprintf("%s overlaps %s; intersection cannot be expressed", describe(partialRule), c.resource))
				gaps = append(gaps, partialGap(l, partialRule, g.Action, c.resource))
				next = append(next, c)
			default:
				observe(obs, l, "NoMatch", fmt.Sprintf("no statement permits %s on %s", g.Action, c.resource))
			}
		}
		current = next
		if len(current) == 0 {
			return nil, gaps
		}
	}

	denies := set.denies.for_(lower)
	for _, c := range current {
		parts := c.parts
		denied := false
		for _, r := range denies {
			rel := r.relate(c.resource)
			switch {
			case rel.full && r.cond.Empty():
				observe(obs, &layer{kind: r.origin.SourceKind, name: r.origin.SourceName}, "Deny", fmt.Sprintf("%s denies %s", describe(r), c.resource))
				denied = true
			case rel.full:
				observe(obs, &layer{kind: r.origin.SourceKind, name: r.origin.SourceName}, "Deny (conditional)", fmt.Sprintf("%s denies %s under a condition", describe(r), c.resource))
				parts = append(clone(parts), model.Part(model.RoleUnless, r.cond, ""))
			case len(rel.narrow) > 0 || rel.partial:
				observe(obs, &layer{kind: r.origin.SourceKind, name: r.origin.SourceName}, "Deny (partial)", fmt.Sprintf("%s denies part of %s", describe(r), c.resource))
				parts = append(clone(parts), model.Part(model.RoleUnless, r.cond, "except "+r.resourceSummary()))
			}
			if denied {
				break
			}
		}
		if denied {
			continue
		}
		out = append(out, model.Grant{
			Action:    g.Action,
			Resource:  c.resource,
			Effect:    model.Allow,
			Condition: model.ComposeCondition(parts...),
			Origin:    g.Origin,
		})
	}
	return out, gaps
}

func partialGap(l *layer, r *rule, action, resource string) string {
	return fmt.Sprintf("%s %q statement %d: %s on %s overlaps %s without covering it; the intersection cannot be expressed and the grant is kept as is",
		l.kind, r.origin.SourceName, r.origin.Statement, action, r.resourceSummary(), resource)
}

func describe(r *rule) string {
	return fmt.Sprintf("%s %q statement %d", r.origin.SourceKind, r.origin.SourceName, r.origin.Statement)
}

func observe(obs observer, l *layer, outcome, detail string) {
	if obs != nil {
		obs.step(l.kind, l.name, outcome, detail)
	}
}

func clone(parts []model.ConditionPart) []model.ConditionPart {
	return append([]model.ConditionPart(nil), parts...)
}
