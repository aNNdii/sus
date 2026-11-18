# 0006. Audit at decision time

Status: Accepted
Date: 2026-11-18

## Context

Every request should leave a trace in the unified log: who asked, what for, and what the
service decided. A command may run for hours. In that time launchd may stop the service
with `SIGTERM`, the service may panic, or the machine may lose power.

## Decision

- The audit entry is written when the service decides: `allowed` right after the command
  started, `denied` before the refusal is sent, `abandoned` when the client left before
  sending a request.
- The exit code of the command is not part of the audit.
- Entries go to the unified log (`os_log`) under the subsystem `io.github.anndii.sus`,
  all fields public. In test mode they go to the subsystem `io.github.anndii.sus.test` and
  to stderr.

## Consequences

- The entry exists even if the service is stopped or crashes while the command runs.
- The audit says what was allowed to run, not how it ended.
- One entry per request; `tests/audit.rs` checks this for each result.

## Alternatives considered

- **Write at exit, with the exit code.** Lost whenever the service stops before the
  command does.
