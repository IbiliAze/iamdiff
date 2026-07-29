# ADR-0001: In-process provider registry

**Status:** accepted

## Context

Providers must be pluggable so Azure and GCP can be added without touching the
core. Two options: compile-time registration (`database/sql` style) or
out-of-process plug-ins over gRPC (`hashicorp/go-plugin`, as Terraform uses).

## Decision

Compile-time registration via blank import.

## Rationale

`go-plugin` is the right answer when third parties ship providers independently
on their own release cycles. That is not this project. In-process registration
keeps the binary single-file, debugging trivial and the build simple, and it is
immediately familiar to any Go reviewer.

## Consequences

Adding a provider requires a rebuild. Revisit only if an external contributor
genuinely needs to ship a provider out of tree.
