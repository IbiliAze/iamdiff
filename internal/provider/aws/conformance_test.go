package aws

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/IbiliAze/iamdiff/internal/provider"
	"github.com/IbiliAze/iamdiff/internal/provider/conformance"
)

// TestConformance runs the shared provider contract against AWS.
// Azure and GCP will run this identical loop with their own fixtures.
func TestConformance(t *testing.T) {
	p, err := New(provider.Config{Offline: true})
	if err != nil {
		t.Fatalf("construct provider: %v", err)
	}

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
