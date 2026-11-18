# 0004. Check the config file with `open` + `fstat`

Status: Accepted
Date: 2026-11-18

## Context

`/usr/local/etc/sus/config.toml` decides who may run anything as root and with which keys.
Anyone who can write it can add a key and become root. The service reads it for every
request, so a bad file must stop requests without stopping the service.

sudo checks its sudoers file the same way: it opens the file and checks owner and mode on
the open descriptor. It does not walk the parent directories on every run.

## Decision

- `config::load` runs on every request: `open`, then `fstat` on the descriptor, then read
  from the same descriptor.
- The file must be a regular file owned by root, not writable by everyone, and writable by
  its group only if the group is gid 0.
- The content must parse, list at least one user with at least one plain `ssh-ed25519` key,
  and every `secure_path` entry must be an absolute path.
- Any failure refuses the request with `service config invalid: <reason>`, audits it as
  `denied`, and the service keeps running.
- The whole directory chain up to `/` is checked only by `susd install` (`check_chain`).

## Consequences

- No race between check and read: both use one descriptor.
- An edit applies to the next request; no restart, no cache.
- A later `chmod g+w` with a group such as `staff` stops every call until it is fixed.
- A parent directory made writable after the install is not noticed by the service.
- Tested in `src/config.rs` (`rejects_bad_files`, `secure_path_entries_must_be_absolute`)
  and end to end in `tests/audit.rs`
  (`invalid_config_is_refused_audited_and_the_service_lives_on`).

## Alternatives considered

- **Check the whole directory chain on every request.** More system calls per request and
  still path-based. sudo does not do it either.
