# ADR-0005: Conditional and partial restrictions compose into the grant

**Status:** accepted

## Context

ADR-0002 keeps conditions opaque: the tool compares fingerprints and never
decides whether a condition holds. The first evaluator nevertheless treated
a conditional `Deny` as an unconditional one, dropped the condition on a
conditional guardrail `Allow`, and ignored `NotResource` entirely. Each of
those is a silent guess in one direction or the other.

A related problem has no condition at all: a `Deny` on
`arn:aws:s3:::bucket/secret/*` against an allow on `arn:aws:s3:::bucket/*`
removes part of the grant, and no single pattern expresses what remains.

## Decision

Anything that restricts a grant without unconditionally covering it becomes
a clause of the grant's condition:

- a conditional guardrail or boundary allow adds a `require` clause;
- a conditional deny that covers the grant adds an `unless` clause;
- a deny, conditional or not, that covers only part of the grant's
  resources adds an `unless` clause that names the excluded pattern;
- an identity allow with `NotResource` becomes a grant on `*` with the same
  kind of clause;
- two allows on one key under different conditions merge as `any`.

Clauses are canonicalised and fingerprinted together, so the same set of
clauses in any order agrees and a change to any clause changes the
fingerprint. An unconditional deny that covers the grant still removes it
outright, and an unconditional allow still beats a conditional one on the
same key.

## Rationale

The diff already has a category for "access exists but something about it
changed that a human must read": exit code 3. Routing every partial or
conditional restriction there is honest in both directions. Adding a
conditional deny shows as a condition change rather than as narrowing;
removing one shows as a condition change rather than as nothing.

## Consequences

Some sets carry composed conditions whose summaries are long. That is the
price of never guessing. A grant with a carve-out clause names the excluded
pattern in its summary, so a reviewer can see what was taken away.
