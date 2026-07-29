# ADR-0003: An incomplete evaluation must fail loudly

**Status:** accepted

## Context

SCPs live in a management account and often require delegated admin. Resource
policies live in each service. Credentials frequently cannot reach all of them.

## Decision

`EffectiveSet.Partial` is set whenever any source was unreachable, the gap is
recorded in human-readable form, and `Partial` outranks every other verdict —
including `unchanged`. Exit code 4.

## Rationale

A partial evaluation cannot honestly claim that access did not widen. Silently
degrading to identity-only would produce a confident, wrong "no change" in
exactly the situation where the guardrail was the interesting part.

Stating this caveat prominently is what makes the rest of the output
trustworthy.

## Consequences

Some users will see exit code 4 on first run and must widen their read-only
permissions. That friction is intentional.
