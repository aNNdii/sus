# 0005. Filter the environment, don't sign it

Status: Accepted
Date: 2026-11-18

## Context

The signed message covers what decides which command runs: version, nonce, uid, cwd and
argv. The caller's environment can also change what a root command does (`DYLD_*`, `PATH`,
`TZ`, editor variables). It is large, differs between terminals and apps, and the user
cannot read it in an agent prompt anyway.

sudo solves this with `env_reset` (start from a minimal environment) and `env_check` (drop
kept variables with suspicious values).

## Decision

- The environment is not part of the signed message.
- One rule, `proto::filter_env`, filters it on both sides: only `TERM`, `COLORTERM`, `LANG`
  and `LC_*` pass, never `DYLD_*`. A value with `/` or `%` or a leading `()` is dropped, a
  name containing `=` never passes, and for a repeated name only the first value counts.
- The service sets the rest itself: `PATH` = `secure_path`, `HOME=/var/root`, `USER` and
  `LOGNAME` = `root`, `SHELL=/bin/sh`, `SUDO_USER`, `SUDO_UID`, `SUDO_GID` and
  `SUDO_COMMAND` (arguments cut after 4096 bytes, as in sudo).
- The caller's umask travels unsigned too; the command gets `022 | (umask & 0777)`, so it
  can only tighten.

## Consequences

- Another process of the same user could change `TERM` or `LANG` of a call the user
  approved. After the filter those values cannot name a path, a format string or a shell
  function. Malware as the same user is out of scope anyway.
- The signed message stays fixed and small.
- Tools that need the user's `HOME` or `PATH` behave differently than under macOS's sudo,
  which keeps them. `docs/comparison.md` lists this.
- Tested in `tests/run.rs` (`env_is_reset_like_sudo`), `src/command.rs`
  (`env_is_exactly_the_documented_set`) and `src/proto.rs`
  (`drops_allowed_names_with_bad_values`).

## Alternatives considered

- **Sign the environment.** Adds a large, noisy field to every message and still needs the
  same filter, because a signed `DYLD_INSERT_LIBRARIES` is no safer than an unsigned one.
