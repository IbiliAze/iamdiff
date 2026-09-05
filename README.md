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
go install github.com/IbiliAze/iamdiff@latest
```

## Commands

| Command                                     | Needs credentials |
| ------------------------------------------- | ----------------- |
| `iamdiff policy <before.json> <after.json>` | no                |
| `iamdiff plan <plan.json>`                  | no                |
| `iamdiff roles <a> <b>`                     | yes               |
| `iamdiff collect <principal>`               | yes               |
| `iamdiff explain <principal> --action <a>`  | yes, or `--from`  |
| `iamdiff providers`, `iamdiff version`      | no                |

Every diffing command takes `--output text|json|markdown`; markdown is shaped
for a pull-request comment. Live commands take `--profile`.

### policy — diff two documents offline

`policy` composes the environment around a change too. Pass the permissions
boundary and organisation guardrails the principal runs under, and the diff
shows only what can actually be exercised:

```bash
iamdiff policy before.json after.json --boundary ci-boundary.json \
  --guardrail root=full-access.json --guardrail ou-prod=deny-compute.json
```

Guardrails at different levels intersect, as they do in AWS Organizations;
files that share a level union. Either side may also be a snapshot written by
`iamdiff collect` instead of a bare policy document, which is how to diff one
principal across a change:

```bash
iamdiff collect role/deploy --out before.json
# apply the change
iamdiff collect role/deploy --out after.json
iamdiff policy before.json after.json
```

### plan — diff what a Terraform plan would change

```bash
terraform plan -out=tfplan
terraform show -json tfplan | iamdiff plan - --output markdown
```

The plan is grouped by principal: every role, user and group whose policies
change gets its own section, attached policies created in the same plan are
followed by reference, and policies attached to nothing are diffed on their
own. A policy computed at apply time, or attached by an ARN whose content the
plan does not carry, cannot be evaluated; the result says so and exits 4.

### roles — diff two live principals

```bash
iamdiff roles role/deploy-staging role/deploy-prod
```

A principal is an ARN, `role/NAME` or `user/NAME` in the credentials'
account. Collection reads attached and inline policies (and, for users, group
policies), the permissions boundary, and the service control policies at every
level of the organisation above the account. See
[docs/iam-permissions.md](docs/iam-permissions.md) for the read-only
permissions this needs and why a member account sees exit code 4.

### explain — why can this principal do that?

```
$ iamdiff explain role/deploy --action s3:DeleteObject --from snapshot.json

s3:DeleteObject on arn:aws:iam::123456789012:role/deploy

  identity   deploy-policy Allow
  boundary   ci-boundary   Allow
  guardrail  r-root        Allow
  guardrail  ou-prod       Allow
  identity   deploy-policy Deny (conditional)

PERMITTED (conditional: unless {"Bool":{"aws:MultiFactorAuthPresent":"false"}})
```

Exit codes: 0 permitted, 1 denied, 3 permitted only under a condition,
4 incomplete. `--resource` narrows the question to one ARN; `--verbose` prints
the statement behind each step; `--output json` prints the whole trace.

## Exit codes

| Code | Meaning                                      |
| ---- | -------------------------------------------- |
| 0    | unchanged                                    |
| 1    | narrowed only                                |
| 2    | **widened**                                  |
| 3    | indeterminate — conditions changed           |
| 4    | incomplete — a policy source was unreachable |
| 64   | bad command line                             |
| 70   | failure at run time                          |

Exit code 4 matters. If credentials cannot reach the Organizations API,
`iamdiff` says so loudly and refuses to imply a complete answer.

Errors never share a code with a verdict, so a pipeline that fails on any exit
code above 1 cannot mistake a crash for a widening, or a typo for "narrowed".

## In CI

```yaml
- run: |
    terraform plan -out=tfplan
    terraform show -json tfplan > plan.json
- id: iamdiff
  run: |
    set +e
    iamdiff plan plan.json --output markdown > iamdiff.md
    echo "code=$?" >> "$GITHUB_OUTPUT"
- uses: marocchino/sticky-pull-request-comment@v3
  with:
    header: iamdiff
    path: iamdiff.md
- run: |
    case "${{ steps.iamdiff.outputs.code }}" in
      0|1) ;;
      *) echo "iamdiff: review required (exit ${{ steps.iamdiff.outputs.code }})"; exit 1 ;;
    esac
```

## How it decides

- Identity allows are unioned and expanded through a catalogue of every AWS
  action (regenerated weekly from the Service Authorization Reference).
- The permissions boundary intersects. Each organisation level intersects
  separately: an action must be allowed at the root, at every OU on the path,
  and at the account, exactly as AWS evaluates SCPs
  ([ADR-0004](docs/adr/0004-guardrails-intersect-per-level.md)).
- An explicit deny that covers a grant removes it. A guardrail narrower than a
  grant narrows it to the intersection.
- Conditions are compared by fingerprint, never interpreted
  ([ADR-0002](docs/adr/0002-conditions-are-opaque.md)). A conditional deny, a
  conditional guardrail allow, or a deny that removes only part of a grant
  becomes a clause of the grant's condition, so a change to any of them is
  reported as "condition changed" rather than hidden
  ([ADR-0005](docs/adr/0005-conditional-and-partial-denies-compose.md)).
- Anything the tool cannot see — an unreachable source, a wildcard the
  catalogue cannot expand, an overlap no pattern can express — marks the
  result partial ([ADR-0003](docs/adr/0003-incomplete-evaluation-fails-loudly.md)).

## Non-goals

Not a CSPM. Not runtime analysis. Not a policy linter. Not a condition solver —
condition equivalence is a constraint-satisfaction problem and is deliberately
left to human review. Resource-based policies, session policies and resource
control policies are outside the model: "complete" means complete with respect
to identity policies, the permissions boundary and service control policies.

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
make test       # race detector, all packages
make lint       # golangci-lint
make layering   # the CI guard: no core package may import a provider
make catalogue  # regenerate the embedded AWS action catalogue
make demo       # run against examples/
```

Design decisions live in [docs/adr](docs/adr).

## Licence

MIT.
