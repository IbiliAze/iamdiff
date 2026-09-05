package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/IbiliAze/iamdiff/internal/model"
)

type stubProvider struct{ name string }

func (s stubProvider) Name() string { return s.name }
func (s stubProvider) Collect(context.Context, Selector) (*RawSet, error) {
	return nil, ErrUnsupported
}
func (s stubProvider) Evaluate(context.Context, *RawSet) (*model.EffectiveSet, error) {
	return model.NewEffectiveSet(model.Principal{Provider: s.name}), nil
}

func TestRegisterOpenAvailable(t *testing.T) {
	Register("zeta-test", func(cfg Config) (Provider, error) { return stubProvider{"zeta-test"}, nil })
	Register("alpha-test", func(cfg Config) (Provider, error) { return stubProvider{"alpha-test"}, nil })

	p, err := Open("zeta-test", Config{})
	if err != nil || p.Name() != "zeta-test" {
		t.Fatalf("Open = %v, %v", p, err)
	}
	names := strings.Join(Available(), ",")
	if !strings.Contains(names, "alpha-test,") || strings.Index(names, "alpha-test") > strings.Index(names, "zeta-test") {
		t.Fatalf("Available() = %s, want sorted names", names)
	}
	if _, err := Open("nope", Config{}); err == nil || !strings.Contains(err.Error(), "available:") {
		t.Fatalf("unknown provider error = %v", err)
	}
}

func TestDuplicateRegistrationPanics(t *testing.T) {
	Register("dup-test", func(cfg Config) (Provider, error) { return stubProvider{"dup-test"}, nil })
	defer func() {
		if recover() == nil {
			t.Fatal("second registration did not panic")
		}
	}()
	Register("dup-test", func(cfg Config) (Provider, error) { return stubProvider{"dup-test"}, nil })
}
