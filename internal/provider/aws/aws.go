// Package aws implements the AWS provider.
//
// Phase 1 supports offline evaluation from policy documents on disk.
// Live collection via GetAccountAuthorizationDetails is stubbed and
// returns provider.ErrUnsupported rather than a partial answer.
package aws

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/IbiliAze/iamdiff/internal/catalogue"
	"github.com/IbiliAze/iamdiff/internal/model"
	"github.com/IbiliAze/iamdiff/internal/provider"
)

//go:embed data/catalogue.json
var catalogueData []byte

const Name = "aws"

func init() {
	provider.Register(Name, New)
}

type Provider struct {
	cfg provider.Config
	cat catalogue.Catalogue
}

func New(cfg provider.Config) (provider.Provider, error) {
	cat, err := catalogue.Load(catalogueData)
	if err != nil {
		return nil, fmt.Errorf("aws: load catalogue: %w", err)
	}
	return &Provider{cfg: cfg, cat: cat}, nil
}

func (p *Provider) Name() string                   { return Name }
func (p *Provider) Catalogue() catalogue.Catalogue { return p.cat }
func (p *Provider) Explain(ctx context.Context, raw *provider.RawSet, action string) (*model.Trace, error) {
	return &model.Trace{}, nil
}

// FromDocuments builds a RawSet with no credentials. This is what powers
// `iamdiff policy a.json b.json`.
func (p *Provider) FromDocuments(pr model.Principal, docs []provider.Document) (*provider.RawSet, error) {
	pr.Provider = Name
	return &provider.RawSet{Principal: pr, Documents: docs}, nil
}

// Collect is phase 3. It must gather identity policies via
// GetAccountAuthorizationDetails, the permissions boundary, and SCPs via
// the Organizations API -- recording a gap for any source it cannot reach.
func (p *Provider) Collect(ctx context.Context, sel provider.Selector) (*provider.RawSet, error) {
	return nil, fmt.Errorf("aws: live collection: %w (planned, phase 3)", provider.ErrUnsupported)
}

var (
	_ provider.Provider      = (*Provider)(nil)
	_ provider.Cataloguer    = (*Provider)(nil)
	_ provider.Explainer     = (*Provider)(nil)
	_ provider.OfflineLoader = (*Provider)(nil)
)
