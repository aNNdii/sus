# 0002. One crate with small private modules

Status: Accepted
Date: 2026-11-18

## Context

`sus` is two programs, a client and a root service, that share a wire format, a signature
scheme and a list of names. Code that runs as root should be easy to read in full. The
project has one maintainer and no library users.

Richer shapes were on the table: a typestate machine that encodes each step of a request in
the type system, a domain-driven layout with many small types, or a public library API that
other tools could call.

## Decision

- One crate, `sus-cli`, with one library (`sus`) and two one-line binaries:
  `src/bin/sus.rs` calls `client_main`, `src/bin/susd.rs` calls `daemon_main`.
- Eight modules: `client`, `command`, `config`, `daemon`, `install`, `macos`, `names`,
  `proto`. Only `names` is public, plus the two entry points.
- Shared contracts (frames, the signed message, limits, the environment rule) live in
  `proto`, so client and service cannot drift apart.
- Test seams are plain values: `Limits` shortens timers, `Layout::under(tmp)` installs into
  a temporary directory, and the service has a test mode when not run as root.

## Consequences

- The surface is small: no public API to keep stable, no semver promise for the library.
- Internals are tested by unit tests inside each module; `tests/` drives the real binaries
  and uses only `sus::names`.
- Nobody can reuse the protocol or the verifier as a library. That is fine for v1.
- Some functions are long, and some state checks are runtime checks rather than types.
  Reviewers read them in place instead of following many small types.

## Alternatives considered

- **Typestate machine / domain-driven design.** More types than the problem needs; harder
  to review in one sitting.
- **Public library API.** Commits the project to an interface nobody asked for.
