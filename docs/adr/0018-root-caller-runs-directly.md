# 0018. A root caller runs the command directly

Status: Accepted
Date: 2026-11-18

## Context

Scripts often prefix commands with `sudo` and are sometimes already run as root. sudo, called
as root, runs the command without asking for a password. If `sus` refused root callers, or
asked root for a signature, such scripts would break or wait for an agent that root does not
have.

## Decision

- When the client's effective uid is 0, it `exec`s the command in place: no connection to
  the service, no signature, no environment reset, no audit entry.
- An empty argument list prints usage and exits 1, as for any caller.
- If `exec` fails, the client prints one line (`sus: <command>: <error>`) and exits 1.

## Consequences

- `sus` in a script that already runs as root behaves like a prefix that does nothing.
- This differs from sudo, which still resets the environment and logs the call when the
  caller is root. Calls by root leave no `sus` audit entry. Resetting the environment and
  logging for root callers too, as sudo does, is open for a later version.
- Root gains nothing from this: it can run anything anyway.
- Tested in `src/client.rs` (`root_runs_the_command_in_place`,
  `root_with_unknown_command_fails`).

## Alternatives considered

- **Refuse root callers.** Breaks scripts that work with sudo.
- **Send root's calls through the service.** Needs an agent and a key for root, and a
  `[users]` entry that `install` refuses (`root` is not allowed as `--user`).
