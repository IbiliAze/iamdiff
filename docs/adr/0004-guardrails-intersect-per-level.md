# ADR-0004: Guardrails intersect per level and are never expanded

**Status:** accepted

## Context

AWS Organizations requires an explicit `Allow` at every level between the
root and the account for an action to be permitted; a `Deny` at any level
wins. The first evaluator unioned every guardrail document into one layer,
so a permissive root policy silently restored access an OU policy removed.

Separately, the first evaluator expanded every document through the action
catalogue. With the real catalogue of some twenty thousand actions, the
default `FullAWSAccess` policy alone became twenty thousand grants, and
intersecting an administrator identity against it was quadratic.

## Decision

A `provider.Document` carries a `Target`: the point it is attached to.
Guardrail documents that share a target union into one layer; each distinct
target is its own layer, and a grant must be permitted by every layer.
Documents with no target share a single layer, which is the right reading
for a provider with no hierarchy and for a hand-assembled offline set.

Only identity allows are expanded into concrete grants, because those are
what the diff compares. Boundaries, guardrails and explicit denies stay as
pattern rules, indexed by service prefix, and are matched against each
grant with an exact glob matcher that implements the IAM wildcard rules,
including the one that keeps a `*` inside its ARN segment unless it ends
the segment.

## Consequences

Live collection must record the target of each SCP it reads, and the
offline `policy` command accepts `--guardrail LEVEL=FILE` so an operator can
reproduce the hierarchy without credentials.

A guardrail narrower than a grant narrows it: an identity allow on `*`
under an SCP that permits `arn:aws:s3:::bucket/*` becomes a grant on the
bucket. Where two patterns overlap without either covering the other, the
intersection has no pattern that expresses it; the grant is kept whole and
the result is marked partial, because hiding a possible widening is the one
failure this tool must never commit (ADR-0003).
