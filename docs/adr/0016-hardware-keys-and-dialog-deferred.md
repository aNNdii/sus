# 0016. Hardware-bound keys and a confirmation dialog

Status: Deferred (until after v0.1.0)
Date: 2026-11-18

## Context

`sus` verifies that a listed key signed exactly this call. It cannot verify more:

- **No proof that a person approved.** An `ssh-ed25519` signature carries no flags. Whether
  a human was asked depends on the agent's settings. Bitwarden asks for every signature only
  with "Ask for authorization: Always"; the OpenSSH agent asks only for keys added with
  `ssh-add -c`.
- **The key can be copied.** A Bitwarden SSH key is a vault item, synced to every device of
  the account and exportable.
- **The prompt does not show what is signed.** The agent shows "sign request", not the
  command.

FIDO-style keys (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`) sign
flags for user presence (UP) and user verification (UV) and a counter. Security keys and
the Secure Enclave, through macOS's SSH keychain provider, offer such keys, and their
private part cannot be exported.

## Decision

Deferred until after v0.1.0, as one piece of work:

- Accept `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com` keys.
  Require UP, optionally UV, and reject a counter that does not go up.
- Add a confirmation dialog shown by `susd` with the user, the directory and the command,
  before the agent is asked.

v1 accepts only plain `ssh-ed25519` ([ADR 0012](0012-keys-per-user.md)) and has no dialog.

## Consequences

- Until then, per-call approval is a property of the agent's settings, not something `susd`
  can check. The README says so and tells users to deny unexpected prompts.
- Today `config::check_key` and `install::read_key` allow only `ssh-ed25519`, and
  `proto::verify` checks the signature alone. New key types touch all three: the first two
  to accept them, `verify` to check flags and counter.
- Open question for the dialog: how to draw it so that code running as the same user can
  neither fake nor click it.

## Alternatives considered

- **Ship both in v1.** Delays the first release for features that need their own design.
- **Neither, ever.** Leaves the gaps above open for good.
