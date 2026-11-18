# Architecture decision records

One file per decision, in Michael Nygard's format (see [0001](0001-record-architecture-decisions.md)).
[`../architecture.md`](../architecture.md) chapter 9 links the same list.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-one-crate-small-private-modules.md) | One crate with small private modules | Accepted |
| [0003](0003-reap-safe-waiting.md) | Wait with `waitid(WNOWAIT)`, then reap | Accepted |
| [0004](0004-config-check-open-fstat.md) | Check the config file with `open` + `fstat` | Accepted |
| [0005](0005-environment-filtered-not-signed.md) | Filter the environment, don't sign it | Accepted |
| [0006](0006-audit-at-decision-time.md) | Audit at decision time | Accepted |
| [0007](0007-ssh-agent-client-crate.md) | Use `ssh-agent-client-rs`, pinned | Accepted |
| [0008](0008-unknown-user-matches-nobody.md) | Unknown user in the config matches nobody | Accepted |
| [0009](0009-key-from-pub-file.md) | `--key` takes a path to a `.pub` file | Accepted |
| [0010](0010-label-and-namespace.md) | Label and namespace tied to the repo | Accepted |
| [0011](0011-releases-with-cargo-dist.md) | Releases with cargo-dist, archives only | Accepted |
| [0012](0012-keys-per-user.md) | Keys belong to users | Accepted |
| [0013](0013-job-control-without-pty.md) | Job control like sudo without a pty | Accepted |
| [0014](0014-audit-names-key-cwd-command.md) | Audit names key, cwd and command | Accepted |
| [0015](0015-no-pty-in-v1.md) | No pty in v1 | Accepted |
| [0016](0016-hardware-keys-and-dialog-deferred.md) | Hardware-bound keys and a confirmation dialog | Deferred |
| [0017](0017-no-fallback.md) | No fallback to an Admin dialog or a password | Accepted |
| [0018](0018-root-caller-runs-directly.md) | A root caller runs the command directly | Accepted |

New decision: copy the shape of an existing record, take the next number, add a row here and
in chapter 9.
