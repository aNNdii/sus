# 0014. Audit names key, cwd and command

Status: Accepted
Date: 2026-11-18

## Context

The first audit format had uid, pid, result, reason and the argv. That leaves open:

- Which key approved the call. With several keys per user (laptop, desktop agent), that is
  the only hint which device or agent approved.
- Where the command ran. `rm -rf build` means different things in different directories.
- What actually ran. `sus echo` runs whatever `secure_path` resolves `echo` to.

sudo logs `PWD=` and `COMMAND=/full/path args`.

## Decision

- The head entry of each request carries, once known:
  - `key=SHA256:…`: the fingerprint of the key that verified, as `ssh-keygen -l` prints it.
  - `cwd="…"`: the working directory from the request.
  - `command="…"`: the program `argv[0]` resolved to.
- "Once known" is literal. A refusal before the request has none of them. A bad signature
  has `cwd` but no `key`. A command that is not found has `key` and `cwd` but no `command`.
- A path longer than 160 masked bytes keeps its end after `...`, the most specific part.
- Everything is masked like the argv: non-printable bytes as `\xNN`, `"` and `\` escaped.
  The signature is never logged.

## Consequences

- An entry answers who, where, what and with which key without other sources.
- The head entry stays below the unified log's limit of about 1 KiB with every field at its
  longest; a unit test in `src/daemon.rs` checks it
  (`first_entry_fits_with_every_field_at_its_longest`).
- The fingerprint identifies the key, not the device. A key synced to several devices looks
  the same from each.
- Tested end to end in `tests/audit.rs`: `entry_says_which_key_where_and_what_ran`,
  `denied_after_the_signature_keeps_key_and_cwd`.

## Alternatives considered

- **Keep uid, pid and argv only.** Shorter, but it cannot tell which key approved or what
  program ran.
