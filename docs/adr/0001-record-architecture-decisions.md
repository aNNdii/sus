# 0001. Record architecture decisions

Status: Accepted
Date: 2026-11-18

## Context

`sus` decides what runs as root and why. Most of its design choices trade security against
convenience or against sudo compatibility. A later reader, including the maintainer a year
from now, needs to know the reason and the options that lost, not only the result.

`docs/architecture.md` follows arc42. Its chapter 9 used to be one table with one row per
decision: chosen, rejected, why. One row has no room for the context or for what a decision
costs, and decisions made later had no place at all.

## Decision

- Every architecture decision gets its own file under `docs/adr/`, in Michael Nygard's
  format: `# NNNN. Title`, `Status`, `Date`, `## Context`, `## Decision`,
  `## Consequences`, and optionally `## Alternatives considered`.
- Numbers are four digits, given in order, and never reused or changed.
- Status is one of `Proposed`, `Accepted`, `Deferred` or `Superseded by NNNN`. A changed
  decision gets a new ADR; the old one stays and points to it.
- Chapter 9 of `docs/architecture.md` and `docs/adr/README.md` list every ADR. Other
  chapters link to an ADR instead of repeating its reasoning.
- An ADR says only what the code does or what is planned. Claims are checked against
  `src/` and `tests/` before they are written.

## Consequences

- A change that reverses or extends a decision updates the ADRs in the same change as the
  code.
- Two indexes (chapter 9 and `docs/adr/README.md`) must be kept in step.
- The README and `docs/comparison.md` stay user-facing; the reasons live here.

## Alternatives considered

- **Keep the decision table in chapter 9.** Short, but it loses context and consequences.
