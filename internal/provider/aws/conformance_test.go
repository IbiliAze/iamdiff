package aws

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/IbiliAze/iamdiff/internal/catalogue"
	"github.com/IbiliAze/iamdiff/internal/provider"
	"github.com/IbiliAze/iamdiff/internal/provider/conformance"
)

// newSeedProvider builds the provider over the 22-action seed catalogue so
// that assertions do not float with the weekly snapshot refresh.
func newSeedProvider(t *testing.T) *Provider {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "catalogue_seed.json"))
	if err != nil {
		t.Fatal(err)
	}
	cat, err := catalogue.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	return newWithCatalogue(provider.Config{Offline: true}, cat)
}

// The embedded snapshot must load and carry the actions the README and
// severity model lean on, whatever the refresh has done to the rest.
func TestEmbeddedCatalogueLoadsAndClassifies(t *testing.T) {
	p, err := New(provider.Config{Offline: true})
	if err != nil {
		t.Fatalf("construct provider: %v", err)
	}
	cat := p.(*Provider).cat
	want := map[string]catalogue.Level{
		"s3:GetObject":          catalogue.LevelRead,
		"s3:PutBucketPolicy":    catalogue.LevelPermissionsMgmt,
		"iam:PassRole":          catalogue.LevelPermissionsMgmt,
		"dynamodb:DeleteItem":   catalogue.LevelWrite,
		"ec2:DescribeInstances": catalogue.LevelList,
	}
	for action, level := range want {
		if got := cat.AccessLevel(action); got != level {
			t.Errorf("%s: level = %q, want %q", action, got, level)
		}
	}
	got, err := cat.Expand("s3:Get*")
	if err != nil || len(got) < 20 {
		t.Fatalf("s3:Get* expanded to %d actions (err %v); the snapshot looks like a seed", len(got), err)
	}
	if cat.Version() == "" || cat.Version() == "seed-2026-07" {
		t.Fatalf("embedded catalogue version = %q; the real snapshot has not been generated", cat.Version())
	}
}

// TestConformance runs the shared provider contract against AWS.
// Azure and GCP will run this identical loop with their own fixtures.
func TestConformance(t *testing.T) {
	p := newSeedProvider(t)

	for _, c := range conformance.Cases() {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			raw := loadFixture(t, c.Name)
			got, err := p.Evaluate(context.Background(), raw)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			conformance.Check(t, c, got)
		})
	}
}

func loadFixture(t *testing.T, name string) *provider.RawSet {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "conformance", name+".json"))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	var raw provider.RawSet
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return &raw
}
