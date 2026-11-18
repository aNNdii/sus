# 0017. No fallback to an Admin dialog or a password

Status: Accepted
Date: 2026-11-18

## Context

A call can fail before anything runs: the service is not installed or not running, the agent
is unreachable, the agent holds none of the caller's keys, or the user declines. A tool could
then fall back to something that still works, such as the macOS Admin dialog or a password
prompt.

The point of `sus` is that root needs a signature from the user's agent and that the
password stays home. A fallback would give every caller, including unwanted ones, a second
path that skips the agent. An attacker could force that path by making the first one fail.

## Decision

- No fallback. Every failure prints one line on stderr, starting with `sus:`, and the client
  exits 1.
- The client never shows a dialog and never asks for a password. It contains no code for
  either.
- The service refuses with a reason (`Refused`), which the client prints as that line.

## Consequences

- One way to root through `sus`, with one audit trail.
- When the agent is locked or gone, `sus` cannot be used. The user falls back to `sudo` by
  hand, which is a conscious step.
- Scripts can rely on exit 1 and one line, for example `SSH agent did not sign: approval
  denied or not given` or `service not installed (/var/run/sus.sock does not exist)`.
- Tested in `tests/run.rs` (`no_service_fails_in_one_line`, `no_agent_fails_in_one_line`)
  and `tests/signals.rs` (`rejected_approval_fails_in_one_line`).

## Alternatives considered

- **Fall back to the Admin dialog or a password.** Convenient, but it adds a weaker path
  that an attacker can choose by breaking the strong one.
