# 0012. Keys belong to users

Status: Accepted
Date: 2026-11-18

## Context

An earlier config format had two independent lists: `users` (who may call) and `keys`
(which keys may sign). Any listed key could then sign for any listed user. On a Mac with two
allowed users, one user's key could approve the other user's calls. A passkey relying party
binds each credential to one account; `authorized_keys` does the same per account.

The config also accepted any key type the `ssh-key` crate could parse, while `install`
accepted only ed25519. The two disagreed.

## Decision

- The config maps each account to its keys:

  ```toml
  [users]
  alice = ["ssh-ed25519 AAAA… laptop-sudo-sign-2026"]
  ```

- `Hello` lists only the caller's keys, in config order, and only those verify its
  signature. Another user's key signs nothing for the caller.
- `config::load` accepts only plain `ssh-ed25519` keys, like `install`: no RSA, ECDSA,
  `sk-*` or certificates. Any other key fails the whole config.
- The old two-list format is refused, not converted. `load` fails with
  `cannot parse …`, so the service refuses every request; `install` refuses to merge into
  it (`users` … `is not a table`).

## Consequences

- One user's key cannot approve another user's call.
- A config from a development build in the old format must be replaced: `susd uninstall`, then
  `susd install --key …` again, or rewrite the file by hand.
- Hardware-bound key types need a new decision
  ([ADR 0016](0016-hardware-keys-and-dialog-deferred.md)).
- Tested in `src/config.rs` (`keys_belong_to_their_user`, `only_plain_ed25519_keys_load`,
  `rejects_bad_files`, `merge_rules`), `src/daemon.rs`
  (`another_users_key_does_not_sign_for_the_caller`) and `tests/run.rs`
  (`another_users_key_in_the_agent_runs_nothing`).

## Alternatives considered

- **Keep the two lists.** Simpler, but every key is a key for every user.
- **Convert the old format automatically.** It cannot know which key belongs to whom.
