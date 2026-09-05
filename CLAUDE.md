# iamdiff

Go CLI that resolves a principal's effective AWS IAM permissions (identity
policies ∩ permissions boundary ∩ SCPs per organisation level, explicit deny
wins), diffs two resolved sets and exits with a verdict code.

## Commands

    make test       # go test -race, all packages
    make lint       # golangci-lint (config in .golangci.yml, v2 format)
    make layering   # the CI guard: no core package may import a provider
    make catalogue  # regenerate the embedded AWS action catalogue
    make demo       # iamdiff policy examples/before.json examples/after.json

## Layout

- `main.go` — entry point; blank-imports each provider.
- `cmd/` — cobra commands. `NewRoot()` builds a fresh tree; `Execute()` maps
  errors to exit codes. Commands return `*exitError`, never call `os.Exit`.
- `internal/model` — provider-neutral types. No ARNs, no cloud words.
- `internal/diff` — `Compare`, `Result`, `Report`, verdicts, exit codes.
- `internal/render` — text / json / markdown renderers and the explain trace.
- `internal/severity` — LOW/MEDIUM/HIGH from a curated list + catalogue level.
- `internal/catalogue` — action names and access levels; `Expand` wildcards.
- `internal/glob` — the IAM wildcard language (`*`, `?`), with exact `Covers`
  and `Overlaps` checks used to intersect resource patterns.
- `internal/plan` — cloud-neutral reader for `terraform show -json`.
- `internal/provider` — the plug-in seam (`Provider`, `RawSet`, `Document`,
  optional capability interfaces) and the registry.
- `internal/provider/aws` — the AWS provider: `rules.go`/`evaluate.go`
  (evaluation), `collect.go`/`org.go` (live collection), `plan.go`
  (Terraform adapter), `explain.go`.
- `internal/provider/conformance` — the behavioural contract every provider
  must pass; fixtures live under each provider's `testdata/conformance/`.
- `docs/adr/` — decisions. Read 0002 (conditions are opaque), 0003 (partial
  fails loudly), 0004 (guardrails intersect per level), 0005 (conditional
  and partial restrictions compose) before touching evaluation.

## Rules

- Exit codes are a public contract: 0 unchanged, 1 narrowed, 2 widened,
  3 indeterminate, 4 incomplete, 64 usage error, 70 runtime error. Explain
  uses 0 permitted, 1 denied, 3 conditional, 4 incomplete.
- Core packages (everything under `internal/` except `internal/provider`)
  must not import `internal/provider`. CI enforces it.
- Anything the tool cannot see must become a gap (Partial), never silence.
- Only identity allows are expanded through the catalogue; boundaries,
  guardrails and denies stay pattern rules.
- Tests that count expansions use the 22-action seed
  (`internal/provider/aws/testdata/catalogue_seed.json` via
  `newSeedProvider`); the embedded snapshot floats with the weekly refresh.
- Plan fixtures: `internal/plan/testdata/create.json` is real Terraform output
  for `internal/plan/testdata/tf`; `update.json`/`delete.json` under
  `internal/provider/aws/testdata/plan` are derived from it.

## Releasing

Tag `vX.Y.Z`; `.github/workflows/release.yml` runs goreleaser. Needs the
`HOMEBREW_TAP_TOKEN` secret (write access to `IbiliAze/homebrew-tap`).
