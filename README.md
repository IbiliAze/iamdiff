# iamdiff

Effective cloud IAM permissions diff and explanation.

`iamdiff` resolves what a principal **can actually do** by composing identity
policies, permissions boundaries and organisation guardrails, then diffs two
resolved sets. It answers one question inside a pull request review: _did this
change widen access, and why?_

```
$ iamdiff policy before.json after.json

Added (2):
  + MEDIUM dynamodb:DeleteItem                *
  + HIGH   iam:PassRole                       *

Condition changed - review manually (1):
  ~ HIGH   sts:AssumeRole                     *

VERDICT: widened
```

Exit code `2`. Drop it into CI and fail the build unless a human approves.

## Why not a text diff

Reordering statements or replacing `s3:Get*` with an explicit list produces a
huge text diff and zero permission change. A one-character condition edit
produces a trivial diff and opens production. `iamdiff` compares **sets of
effective permissions**, not JSON.

## Why not Access Analyzer

`CheckNoNewAccess` is an excellent CI gate and a useless explanation: pass/fail
on a single policy pair, with no boundary or SCP composition and no readable
diff. `iamdiff` aggregates across sources and produces output a reviewer can
read in ten seconds.

## Install

```bash
brew install ibiliaze/tap/iamdiff
go install github.com/IbiliAze/iamdiff/cmd/iamdiff@latest
```

## Commands

| Command                            | Status                            |
| ---------------------------------- | --------------------------------- |
| `iamdiff policy <a.json> <b.json>` | working — offline, no credentials |
| `iamdiff providers`                | working                           |
| `iamdiff roles <a> <b>`            | phase 3                           |
| `iamdiff plan <plan.json>`         | phase 4                           |
| `iamdiff explain <principal>`      | phase 5                           |

## Exit codes

| Code | Meaning                                      |
| ---- | -------------------------------------------- |
| 0    | unchanged                                    |
| 1    | narrowed only                                |
| 2    | **widened**                                  |
| 3    | indeterminate — conditions changed           |
| 4    | incomplete — a policy source was unreachable |

Exit code 4 matters. If credentials cannot reach the Organizations API,
`iamdiff` says so loudly and refuses to imply a complete answer.

## Non-goals

Not a CSPM. Not runtime analysis. Not a policy linter. Not a condition solver —
condition equivalence is a constraint-satisfaction problem and is deliberately
left to human review (see [ADR-0002](docs/adr/0002-conditions-are-opaque.md)).

## Multi-cloud

`Collect` and `Evaluate` are provider-owned; everything after them is
cloud-neutral. Wildcard expansion, GCP role-bundle expansion, Azure's
subtractive `NotActions` and hierarchy inheritance all resolve inside the
provider, which emits flat `Grant` records. See
[docs/adding-a-provider.md](docs/adding-a-provider.md).

AWS ships first. Azure and GCP sit behind the same interface and must pass the
same [conformance suite](internal/provider/conformance/conformance.go).

## Development

```bash
make test    # race detector, all packages
make demo    # run against examples/
make deps    # add Cobra and the AWS SDK (phase 2)
```

## Licence

Apache 2.0.
