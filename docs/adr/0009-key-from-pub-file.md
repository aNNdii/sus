# 0009. `--key` takes a path to a `.pub` file

Status: Accepted
Date: 2026-11-18

## Context

`susd install` has to learn which public key may sign for a user. An OpenSSH public key line
has spaces (`ssh-ed25519 AAAA… comment`), so passing it as an argument needs quoting.
Users also confuse private and public key files, and some agents export certificates or
other key types.

## Decision

- `--key` takes the path to a file, as `ssh-keygen -f` does.
- `install::read_key` accepts the file only if it holds exactly one non-empty key line that
  parses as a plain OpenSSH `ssh-ed25519` public key.
- It refuses a private key (a file starting with `-----BEGIN`) with
  `is a private key; pass the .pub file`, a certificate (`-cert-` in the type), any other
  algorithm, and files with more than one key line.
- `--key` and `--user` can be repeated; every named user gets every given key. `--user`
  defaults to `$SUDO_USER`; an empty name or `root` is refused, and so is `--user` without
  `--key`.

## Consequences

- The file can be checked before anything is written; a wrong file fails the install with
  one clear line.
- The user has to save the public key from the agent as a file first.
- Tested in `src/install.rs` (`read_key_accepts_only_plain_ed25519`, `user_rules`).

## Alternatives considered

- **Key as a string argument.** Needs shell quoting for a line with spaces, and is less
  familiar than a file path for SSH users.
