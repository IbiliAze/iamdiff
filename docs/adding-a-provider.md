# Adding a provider

Write this document *before* you need it. Articulating the abstraction in prose
is the cheapest way to find out where it leaks.

## The contract

A provider turns cloud state into a `model.EffectiveSet`. Three required
methods:

```go
Name() string
Collect(ctx, Selector) (*RawSet, error)
Evaluate(ctx, *RawSet) (*model.EffectiveSet, error)
```

Everything cloud-shaped happens inside `Evaluate`. By the time a set reaches
the core it must be flat: concrete actions, concrete resources, denies already
resolved.

## The rule

No core package (every `internal/*` package outside `internal/provider`) may
import `internal/provider/*`. CI enforces this with a `go list -deps` check that
defines "core" by subtraction, so a package added later is covered
automatically. If a field named `arn`, `scp`, `subscription` or `binding`
appears in a core struct, the abstraction has failed - fix it rather than
working around it.

## Steps

1. Create `internal/provider/<cloud>/`.
2. Implement the three required methods. Register in `init()`.
3. Add a catalogue snapshot under `data/` and a generator in `scripts/`.
4. Add fixtures under `testdata/conformance/` - one per case in
   `conformance.Cases()`.
5. Copy `aws/conformance_test.go`; it is provider-agnostic apart from the
   constructor.
6. Add the blank import to `main.go`.

## Capability interfaces

Implement only what the cloud supports. Everything else is detected by type
assertion and degrades visibly:

- `Cataloguer` - action metadata
- `OfflineLoader` - evaluate documents without credentials
- `PlanAdapter` - read a proposed change from an IaC plan
- `Explainer` - decision trace for one action

## Guardrail layering

A `provider.Document` carries a `Target`: the point in the organisation it is
attached to. Documents attached to different targets intersect, because every
level between the root and the principal must permit an action; documents that
share a target union. A provider that has no hierarchy leaves `Target` empty
and gets a single layer.

## What differs between clouds

| | AWS | Azure | GCP |
|---|---|---|---|
| Grant unit | policy statement | role assignment -> role definition | binding at a hierarchy node |
| Composition | intersect across policy types | union down a scope tree | union down a resource tree |
| Explicit deny | Deny statement | deny assignments; `NotActions` is **subtractive, not a deny** | deny policies, evaluated first |
| Wildcards | `s3:Get*` | `Microsoft.Compute/*/read` | effectively none; expand role bundles |
| Conditions | condition blocks | ABAC conditions | CEL |

Conflating Azure's `NotActions` with an AWS `Deny` produces wrong answers. Each
provider resolves this internally and emits only final allows plus genuine
overriding denies.
