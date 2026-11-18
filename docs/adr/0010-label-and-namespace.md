# 0010. Label and namespace tied to the repo

Status: Accepted
Date: 2026-11-18

## Context

Two identifiers need a globally unique prefix:

- The launchd label, which also names the plist and serves as the unified log subsystem.
- The SSHSIG namespace, which is part of the signed data. A signature made in one namespace
  does not verify in another, so it keeps signatures for `sus` apart from signatures for
  git, SSH logins or other tools that use the same key.

Reverse-DNS names usually come from a domain the author owns. A personal domain ties the
project to one person and breaks when the project moves or the domain lapses.

## Decision

- Label: `io.github.anndii.sus`. Plist: `/Library/LaunchDaemons/io.github.anndii.sus.plist`.
  Log subsystem: the label; in test mode `io.github.anndii.sus.test`.
- SSHSIG namespace: `sus@github.com/aNNdii`.
- All of them are built in `src/names.rs` from the `name!` macro.

## Consequences

- The identifiers follow the GitHub repository, not a person's domain.
- Renaming the tool changes label, plist path, log subsystem and namespace together. A
  renamed `susd` has a new label and new paths, so the old `susd uninstall` must run first.
- Changing the namespace makes old clients and new services reject each other's
  signatures. Signatures are never stored, so nothing else breaks.

## Alternatives considered

- **A personal domain as prefix.** Ties the project to one person's domain.
