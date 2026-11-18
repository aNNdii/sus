# How sus compares to sudo, sudo-rs and passkeys

sus was reviewed against three references:

- sudo's documented behaviour: sudo(8) and sudoers(5), plus the sudo that ships with macOS.
- The test suites of sudo and sudo-rs.
- The passkey standards: W3C WebAuthn Level 3 and FIDO CTAP 2.2, with OpenSSH
  PROTOCOL.sshsig as the signature format sus actually uses.

The verdict: on process hygiene (environment, fds, signals, umask, core dumps, config
checks, logging) sus matches sudo or is stricter. On the verifier side it matches a
WebAuthn relying party. The weak spot is the authenticator. A plain `ssh-ed25519`
signature cannot prove that a human approved this call, so that depends on how your SSH
agent is set up.

## sudo

Compared with sudo 1.9.18 (upstream docs) and sudo 1.9.17p2 as shipped with macOS 26.

| Area | sudo | sus | |
|---|---|---|---|
| Authentication | Your password through PAM (or Touch ID via `pam_tid`) | Signature from your SSH agent over this exact call | differs |
| Caching | Timestamp, 5 min, per terminal by default | None in sus. The agent may cache (see below) | differs |
| Who may sign for whom | sudoers rules per user, host and command | `[users] name = ["ssh-ed25519 …"]`: only that user's keys verify | differs (no command rules) |
| Env reset | `env_reset`: minimal env, `SUDO_*` set | Same: fixed `PATH`, `HOME=/var/root`, `USER`, `LOGNAME`, `SHELL`, `SUDO_*` | match |
| Env check | Drops kept values with `/`, `%` or a leading `()` | Same, for `TERM`, `COLORTERM`, `LANG`, `LC_*`; first value of a name wins | match |
| Kept variables | macOS sudoers keeps `HOME`, `MAIL`, `SSH_AUTH_SOCK`, `TZ`, `EDITOR` and more | Only `TERM`, `COLORTERM`, `LANG`, `LC_*` | stricter |
| `SUDO_COMMAND` | Resolved path plus args, args cut at 4096 bytes | Same | match |
| PATH | `secure_path` if set. macOS sets none, so your PATH is searched | Always `secure_path`, every entry absolute | stricter |
| Command lookup | Bare name in PATH, a name with `/` from the cwd; argv[0] as typed | Same | match |
| Script without shebang | Falls back to `/bin/sh` on `ENOEXEC` | Fails with "Exec format error" | differs |
| cwd | Inherited | Signed absolute path; the command `chdir`s to it | match (stricter on errors) |
| umask | Yours, but never looser than `022` | Same | match |
| Core dumps | Limit 0 | Limit 0, hard limit too | match |
| Other rlimits | Yours (on macOS) | launchd's | differs |
| fds | `closefrom(3)` | Every fd from 3 up closed at exec | match |
| Signal state at exec | Default dispositions, empty mask | Same | match |
| Signal relay | INT, QUIT, TSTP, TERM, HUP, ALRM, PIPE, USR1, USR2, CONT, INFO, WINCH | INT, TERM, HUP, QUIT, WINCH, plus stop and continue for job control | differs |
| Exit status | Command's code; on a signal sudo kills itself with the same signal | Command's code; 128+N for signal N | differs |
| Job control | Ctrl-Z stops the command with sudo; `fg` continues both | Same, with one gap on macOS: the first input after Ctrl-Z still goes to the stopped command. A background `sus` with the terminal on stdin waits stopped until `fg` | differs (gap after Ctrl-Z, stricter in the background) |
| pty | `use_pty` on by default since 1.9.14 | No pty, no controlling terminal, no `/dev/tty` | differs |
| Process context | Your login session | launchd system context; TCC applies to `susd` | differs |
| Config file | Owned by root, not world-writable, group-writable only for its gid | Same check, on every request | match |
| Config errors | sudo refuses to run | Request refused and logged; the service keeps running | match |
| Logging | `user : TTY= ; PWD= ; USER= ; COMMAND=/full/path args`, control characters escaped | uid, pid, result, reason, `key=SHA256:…`, `cwd`, `command=/full/path`, argv; bytes escaped | match (no tty field) |
| Denials | Logged with the attempted command | Logged, also `abandoned` when the client leaves | match |
| Called as root | Still resets env and logs | Runs the command in place, no reset, no log entry | differs |
| Target user, options | `-u`, `-E`, `-i`, `-s`, `-k`, `-n`, … | Root only; no options at all | not applicable |

**CVE classes.** These do not apply to sus, for the reasons given:

- **Argument escaping and parser overflows** (CVE-2021-3156, Baron Samedit): the client is
  not setuid, and argv travels as length-prefixed raw bytes that are never escaped. The
  frame decoder is the one parser of untrusted input, and only allowed uids reach it.
- **Run-as uid tricks** (CVE-2019-14287): there is no `-u`. The caller's uid comes from the
  kernel.
- **sudoedit** (CVE-2023-22809 and others): there is no sudoedit, and `EDITOR`/`VISUAL`
  are never passed on.
- **chroot and host options** (CVE-2025-32463, CVE-2025-32462): there is no `-R` and no
  `-h`. Before the decision the service reads only root-owned paths.
- **Terminal injection** (CVE-2005-4890, TIOCSTI): the target is always root, so there is
  nothing to escalate to. It becomes relevant once `-u` exists.
- **Log injection** (CVE-2023-28486/28487): handled, because non-printable bytes are
  escaped.
- **PATH and TZ tricks** (CVE-2010-1646, CVE-2014-9680): handled. `PATH` is fixed and `TZ`
  is never passed on.

### Differences you may notice

- `sus env` shows `HOME=/var/root`, not your home. macOS sudo keeps your `HOME`.
- `sus htop` fails where `sudo htop` works on a Homebrew Mac. The default `secure_path` has
  no `/opt/homebrew/bin`, so use the full path or extend `secure_path`.
- `sus -u bob id` and `sus -- id` are not options. They ask for a signature, then fail with
  `command not found`.
- A script without a `#!` line fails. Under sudo it runs through `/bin/sh`.
- A command killed by a signal gives exit code 128+N. sudo dies of the signal itself, so
  shell loops react differently to Ctrl-C.
- `USR1`, `USR2`, `ALRM` and `INFO` (Ctrl-T) are not relayed.
- Programs that need `/dev/tty` complain, because there is no pty.
- The command runs in launchd's system context. Folders protected by TCC need Full Disk
  Access for `susd`, and resource limits such as open files come from launchd, not from
  your shell.
- After Ctrl-Z, the first thing you type still goes to the stopped command if it was
  waiting for terminal input; it gets it after `fg`. macOS completes a read that was
  already waiting, and sudo's guard (the terminal's background check) does not apply
  because the command runs in its own session. Type `fg` before anything else. A pty for
  the command, as sudo uses by default, is planned after v0.1.0 and closes this.
- `sus cmd &` with the terminal on stdin waits stopped until you `fg` it. sudo lets a
  background job run until it reads the terminal. `sus cmd </dev/null &` runs normally.
- There is no `sudo -k`. sus keeps no timestamp. If your agent remembers approvals,
  locking the agent (the Bitwarden vault) is the equivalent.

## sudo-rs

sudo-rs is a Rust rewrite of sudo. Its compliance tests run each case against original
sudo and against sudo-rs in fresh containers, so every test documents real sudo behaviour.
sus did not take code from sudo-rs. It took two things:

- **Behaviour references.** The relevant sudo-rs cases (env reset and env check, path
  search, `secure_path`, umask, core limit, closed fds, signal forwarding, exit codes,
  sudoers file permissions, syslog) were mapped to sus tests. Where sus had a gap, it was
  fixed and a test was added. Examples: the umask cases (stricter, looser, overlapping), env values with `/`, `%` or
  `()`, empty stderr when the command dies of a signal, arguments arriving byte for byte,
  and a hostile client sending signals outside the allowed set.
- **The compliance idea.** Before a release, run the same probes through `/usr/bin/sudo`
  and through `sus` on a Mac and diff the output: `env`, `umask`, `ulimit -a`, `id`,
  `ls /dev/fd`, exit codes and signal traps. Every difference must be one of those listed
  above. This is a manual release step for now, not an automated suite.

Tests that need root or a real agent are not part of `cargo test`. They belong to that
manual step.

## Passkeys (WebAuthn / CTAP)

sus is not a passkey system, but its call follows the same pattern as a WebAuthn
assertion: the server sends a fresh challenge, the authenticator signs, and the server
verifies. Here the server is `susd` and the authenticator is your SSH agent.

| Concept | WebAuthn / CTAP | sus | Status |
|---|---|---|---|
| Challenge | Random, at least 16 bytes, single use, with a timeout | 32-byte nonce from the OS RNG, one per connection, valid 30 s | equivalent |
| Channel binding | Challenge kept in the server session | Nonce bound to one Unix socket connection; the uid comes from the kernel and is signed | stronger |
| RP ID | `rpIdHash` checked by the RP | SSHSIG namespace `sus@github.com/aNNdii`, checked on verify | equivalent |
| Origin | Checked by the RP; the browser vouches for it | No origin: any process of the uid counts as the caller | weaker (as with sudo) |
| Server check by client | Browser checks TLS and origin | Client checks the socket is root-owned and the peer is uid 0 | equivalent |
| Credential scoped to RP | The authenticator signs only for its RP ID | The agent signs any namespace for any process of the user | weaker |
| What is signed | `clientDataJSON` (type, challenge, origin) plus authenticator data | `CALL`, version, nonce, uid, cwd, every argument | equivalent |
| Parsing what is signed | RP parses `clientDataJSON` | `susd` rebuilds the message from its own state; it parses nothing signed | stronger |
| User presence (UP) | Flag in signed authenticator data; RP must check it | `ssh-ed25519` has no flags | weaker |
| User verification (UV) | Flag; required where the RP asks for it | No flags; Touch ID in the agent is invisible to `susd` | weaker |
| Signature counter | Optional clone detection | None | weaker |
| Backup state (BE/BS) | Flags tell the RP if the key is synced | Not visible. Bitwarden keys are synced vault items | weaker |
| Attestation | `none` is the default | None; the key comes from a `.pub` file at install | equivalent (to `none`) |
| allowCredentials | RP lists acceptable credentials | `Hello` lists only the caller's keys; only they verify | equivalent |
| Credential belongs to user | RP checks it | Keys are listed per user in `[users]` | equivalent |
| Algorithms | EdDSA, ES256, RS256 and more | `ssh-ed25519` only, at install and at load | weaker (no hardware keys yet) |
| Transaction confirmation | Not in WebAuthn; Secure Payment Confirmation shows details | The agent prompt shows "sign request", not the command | weaker |
| Revocation | RP deletes the credential record | Remove the key from `config.toml`; applies on the next request | equivalent |
| Errors | One user-visible failure | One line, exit 1; every outcome logged, the signature never | equivalent |

**WebAuthn §7.2 (verifying an assertion), step by step.**

- **Steps the verifier controls are met:** challenge (11), type (10), RP ID (15), allowed
  credential (5), user binding (6) and signature (20–21). `susd` rebuilds the signed
  message itself, so the parsing steps (8–9) have nothing to go wrong.
- **Steps that need evidence from the authenticator cannot be met with `ssh-ed25519`:**
  UP (16), UV (17), backup state (18–19) and the counter (22).
- **Origin (12) has no equivalent beyond the kernel uid,** the same model as sudo.

### What is weaker and why

- **Per-call approval is not provable.** The signature proves only that the key signed this
  exact call. Whether a human approved it depends on the agent. Bitwarden needs "Ask for
  authorization: Always". Its "Remember until lock" applies to every application until the
  vault locks. The OpenSSH agent asks only for keys added with `ssh-add -c`. With an agent
  that never asks, sus is passwordless root for every process of your user.
- **The prompt does not show what is signed.** You approve "sign request", not
  `rm -rf /`. Deny any prompt you did not just cause. Don't let scripts or AI agents call
  `sus` unattended.
- **The key is not scoped to sus.** The agent signs for any namespace. Use a dedicated key
  for sus. Don't use it for SSH logins or git signing, and don't forward an agent that
  holds it.
- **The key is synced and exportable.** A Bitwarden SSH key lives in the vault on every
  device you are logged in to. That does not meet NIST SP 800-63B-4 AAL3, which requires a
  non-exportable key. Root on your Mac is as safe as your Bitwarden account.
- **No counter, no backup flags.** A copied key cannot be detected.

### What comes next

Planned after v0.1.0:

- **Hardware-bound keys.** Support `sk-ssh-ed25519@openssh.com` and
  `sk-ecdsa-sha2-nistp256@openssh.com` keys (FIDO security keys and the Secure Enclave via
  macOS's SSH keychain provider). Their signatures carry signed UP/UV flags and a counter.
  `susd` will require UP, optionally UV, and reject a counter that does not go up. That
  closes the gap in §7.2 steps 16, 17 and 22, and these keys cannot be exported.
- **A confirmation dialog in `susd`.** It shows the user, the directory and the command
  before the agent is asked, so you see what you approve.

## Sources

- sudo 1.9.18 source tree, pinned at commit `d58e85d`:
  <https://github.com/sudo-project/sudo/tree/d58e85d868c79ab92860e22fc2d76756cf8f0e2c>
  - sudo(8): [`docs/sudo.mdoc.in`](https://github.com/sudo-project/sudo/blob/d58e85d868c79ab92860e22fc2d76756cf8f0e2c/docs/sudo.mdoc.in)
  - sudoers(5): [`docs/sudoers.mdoc.in`](https://github.com/sudo-project/sudo/blob/d58e85d868c79ab92860e22fc2d76756cf8f0e2c/docs/sudoers.mdoc.in)
  - Rendered man pages: <https://www.sudo.ws/docs/man/sudo.man/>,
    <https://www.sudo.ws/docs/man/sudoers.man/>
  - Security advisories: <https://www.sudo.ws/security/advisories/>
- macOS: `sudo -V` reports 1.9.17p2 on macOS 26. For the default sudoers we used a
  published copy from macOS 14.2.1, because the shipped file is not world-readable:
  <https://gist.github.com/myxiaoao/39f10edd0ffeca56625bbb0aec7c07fd>
- sudo-rs, pinned at commit `81dff9a` (after 0.2.15):
  <https://github.com/trifectatechfoundation/sudo-rs/tree/81dff9a1ccb350f90155ec0a84b4a206a2f5f2c4>
  - Compliance tests:
    [`test-framework/sudo-compliance-tests`](https://github.com/trifectatechfoundation/sudo-rs/tree/81dff9a1ccb350f90155ec0a84b4a206a2f5f2c4/test-framework/sudo-compliance-tests/src)
  - CVE classification:
    [`docs/sudo-cve.md`](https://github.com/trifectatechfoundation/sudo-rs/blob/81dff9a1ccb350f90155ec0a84b4a206a2f5f2c4/docs/sudo-cve.md)
- W3C Web Authentication Level 3, Recommendation of 25 August 2026:
  <https://www.w3.org/TR/webauthn-3/>
- FIDO Client to Authenticator Protocol v2.2, Proposed Standard, 14 July 2025:
  <https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html>
- W3C Secure Payment Confirmation: <https://www.w3.org/TR/secure-payment-confirmation/>
- OpenSSH PROTOCOL.sshsig:
  <https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig>
- NIST SP 800-63B-4, final, July 2025: <https://pages.nist.gov/800-63-4/sp800-63b.html>
- Bitwarden "Ask for authorization" setting: <https://github.com/bitwarden/clients/pull/13995>
