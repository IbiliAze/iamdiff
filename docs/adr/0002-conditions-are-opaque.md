# ADR-0002: Conditions are compared by fingerprint, never semantically

**Status:** accepted

## Context

Two statements can grant the same action on the same resource but differ by a
condition. Deciding whether one condition block is strictly narrower than
another is a constraint-satisfaction problem. AWS solves it internally with an
SMT solver (Zelkova) and exposes only thin slices of it.

## Decision

Canonicalise the condition document, hash it, and compare fingerprints. Any
difference is classified `indeterminate — review manually` and both blocks are
displayed side by side.

## Rationale

Attempting semantic equivalence is the single most reliable way never to ship
this tool. Open-source attempts hit this wall and retreat into linting, which
is where Parliament and policy_sentry stop.

A reviewer shown two condition blocks side by side is far better served than
one reading a raw JSON diff. The honest answer is useful; the perfect answer is
unreachable.

## Consequences

`iamdiff` cannot say whether a condition change widened or narrowed access. Exit
code 3 exists for exactly this, and the limitation is stated in the README so
users do not request it as a feature.
