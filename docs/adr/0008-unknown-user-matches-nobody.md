# 0008. Unknown user in the config matches nobody

Status: Accepted
Date: 2026-11-18

## Context

`[users]` in `config.toml` maps account names to keys. A name may match no account: a typo,
a deleted account, or a config copied from another Mac. The service looks the names up with
`getpwnam_r` on every request.

Treating that as an invalid config would lock out every other user because of one stale
line. Ignoring it silently would hide a typo that leaves the intended user without access.
sudoers accepts rules for names that match no account; they simply never apply.

## Decision

- A name without an account matches nobody. `config::load` leaves it out of the users and
  returns it in `unknown_users`.
- The service logs `warning: unknown user "<name>" in <path> matches nobody` for each such
  name, on every request, to the unified log (and to stderr in test mode). launchd drops
  the service's stderr, so the log is the only place it can be seen.
- The config is still checked as a whole: the key lines of an unknown name must parse and
  be `ssh-ed25519`, or the config is invalid.

## Consequences

- One stale line never blocks the other users.
- A typo shows up in the log, not as an error at the terminal. The user only sees
  `uid N is not allowed`.
- Tested in `src/config.rs` (`custom_secure_path_and_unknown_user`) and `tests/audit.rs`
  (`unknown_user_in_config_is_logged_by_the_service`).

## Alternatives considered

- **Config invalid.** Safe, but one bad line stops everybody.
