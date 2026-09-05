// Package provider defines the plug-in seam.
//
// A provider is anything that can turn cloud state into a
// model.EffectiveSet. Everything cloud-shaped -- wildcard expansion,
// role-bundle expansion, hierarchy inheritance, guardrail composition --
// happens inside Evaluate. The core never sees it.
package provider

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/IbiliAze/iamdiff/internal/catalogue"
	"github.com/IbiliAze/iamdiff/internal/model"
	"github.com/IbiliAze/iamdiff/internal/plan"
)

// ErrUnsupported is returned by capabilities a provider has not
// implemented yet. Callers must degrade visibly, never silently.
var ErrUnsupported = errors.New("provider: capability not supported")

// Selector describes which principals to operate on, in neutral terms.
// Providers interpret Refs and Scope themselves.
type Selector struct {
	Refs    []string
	Scope   string // account, subscription or project
	Profile string
}

// Document is an opaque policy payload. Only the owning provider knows
// how to parse Body; the envelope exists so collection and evaluation
// can be tested independently of each other.
//
// Target names the point a guardrail is attached to (an organisation
// root, unit or account). Guardrails attached to different targets
// intersect, because every level must permit an action; guardrails that
// share a target union. Inherited is provenance only: the path of
// targets between the organisation root and the principal.
type Document struct {
	Kind      model.SourceKind `json:"kind"`
	Name      string           `json:"name"`
	Body      json.RawMessage  `json:"body"`
	Target    string           `json:"target,omitempty"`
	Inherited []string         `json:"inherited,omitempty"`
}

// RawSet is everything collected for one principal, before evaluation.
type RawSet struct {
	Principal model.Principal `json:"principal"`
	Documents []Document      `json:"documents"`
	Gaps      []string        `json:"gaps,omitempty"`
}

// Provider is the contract every cloud plug-in implements.
type Provider interface {
	Name() string
	Collect(ctx context.Context, sel Selector) (*RawSet, error)
	Evaluate(ctx context.Context, raw *RawSet) (*model.EffectiveSet, error)
}

// ---- optional capability interfaces, detected by type assertion ----

// PrincipalChange is one principal's raw state before and after a plan.
// A principal the plan creates has an empty Before; one it destroys has
// an empty After.
type PrincipalChange struct {
	Principal model.Principal
	Before    *RawSet
	After     *RawSet
}

// PlanAdapter is implemented by providers that can read a proposed
// change out of an infrastructure-as-code plan. The adapter decides
// which resource types carry policy and how they group into principals;
// anything it cannot see (a policy computed at apply time, an attached
// policy whose content is not in the plan) must become a gap.
type PlanAdapter interface {
	FromPlan(p *plan.Plan) ([]PrincipalChange, error)
}

// Cataloguer exposes the provider's action catalogue.
type Cataloguer interface {
	Catalogue() catalogue.Catalogue
}

// Explainer produces a decision trace for a single action on a resource.
// An empty resource means "*".
type Explainer interface {
	Explain(ctx context.Context, raw *RawSet, action, resource string) (*model.Trace, error)
}

// OfflineLoader is implemented by providers that can build a RawSet from
// local documents with no credentials. This powers `iamdiff policy`,
// which is the fastest path to a useful first release.
type OfflineLoader interface {
	FromDocuments(p model.Principal, docs []Document) (*RawSet, error)
}
