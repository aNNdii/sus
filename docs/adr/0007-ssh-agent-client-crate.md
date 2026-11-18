# 0007. Use `ssh-agent-client-rs`, pinned

Status: Accepted
Date: 2026-11-18

## Context

The client needs two things from the SSH agent: the list of keys it holds, and one
signature over the SSHSIG signed data of the call. The agent protocol is small and
documented. The service verifies with the `ssh-key` crate, so the client's signature type
must fit `ssh-key`'s SSHSIG code.

## Decision

- The client uses the crate `ssh-agent-client-rs` (`Client::connect`,
  `list_all_identities`, `sign`).
- It is pinned with `=` in `Cargo.toml` (`=1.1.4`), as is `ssh-key` (`=0.6.7`); CI builds
  with `--locked`.
- The signing step goes through `proto::sign`, which takes the agent call as a closure and
  builds the SSHSIG blob itself. Only `client.rs` touches the crate's types.
- A bare agent failure (`RemoteFailure`) is reported as
  `SSH agent did not sign: approval denied or not given`.

## Consequences

- Less own code in the client; no hand-written agent protocol to test.
- One more dependency in the supply chain. `cargo audit` in CI checks `Cargo.lock`.
- The crate turns on `ssh-key`'s `crypto` feature, which brings in RSA and the NIST curves
  that sus does not use. Their advisories RUSTSEC-2023-0071 (`rsa`) and RUSTSEC-2026-0387
  (`crypto-bigint`) concern operations on private keys, which sus never does. They are
  ignored in `.cargo/audit.toml`, each with its reason. An own client would remove them.
- An update of either crate is a deliberate change of the pin, because their APIs must keep
  fitting together.
- If the crate becomes unmaintained or its API drifts, an own client for the two messages
  is the fallback. Only `client.rs` would change.

## Alternatives considered

- **Own agent protocol code.** Small, but more code to write and test now, for no gain in
  v1. Kept as plan B.
