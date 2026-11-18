# Security

What `sus` protects, what it does not, and what it does to keep a root command clean.
Setup: [configuration.md](configuration.md). Design: [architecture.md](architecture.md).
Comparison with sudo and passkeys: [comparison.md](comparison.md).
Reporting a vulnerability: [SECURITY.md](../SECURITY.md).

## Threat model

Same as `sudo`: `sus` protects root from other users and from anything that cannot talk to
your SSH agent. It does **not** protect you from malware running as you. Anything that runs
as your user can run `sus` and ask for a signature.

| Attacker | Result |
|---|---|
| Another local user | Refused: their uid is not in the config, or their keys are not yours. |
| A process of yours, while you deny the prompt | Nothing runs. Logged as `abandoned`. |
| A process of yours, while you approve the wrong prompt | Runs as root. See below. |
| Someone replaying a captured signature | Refused: the nonce is new per connection. |
| A fake service on the socket path | The client refuses a socket not owned by root. |
| Someone who can write the config | `install` writes it `0600`, so only root can. A file others can write fails the check on every request and nothing runs. A parent folder made writable after install is not noticed. |

## Approval

An `ssh-ed25519` signature says which key signed, not whether a person was asked. `susd`
cannot tell the difference. So:

- Set the agent to ask every time (Bitwarden "Ask for authorization: Always",
  `ssh-add -c` for OpenSSH). See [configuration.md](configuration.md#the-agent).
- Bitwarden does not show what is being signed. You see "sign request", not "run
  `rm -rf /`". If a prompt appears and you did not just run `sus`, deny it.
- Use a key only for `sus`, and never forward it.

Keys bound to hardware (FIDO security keys, the Secure Enclave) sign flags that prove a
person touched the device. `sus` does not support them yet; they are planned after v0.1.0.

## What a signature covers

One call: the protocol version, a nonce chosen by the service for this connection, your
uid, the working directory and every argument as raw bytes. The message is wrapped in
SSHSIG with the namespace `sus@github.com/aNNdii`, so a signature made for git or another
tool does not fit. Replays, signatures for another call, another namespace or another key
are refused. You have 30 seconds from connect to a valid signature.

Your uid comes from the socket (`getpeereid`), never from the client.

## What is not signed

- **The environment.** `susd` resets it like sudo's `env_reset`: `PATH` is `secure_path`,
  `HOME=/var/root`, `USER=root`, `LOGNAME=root`, `SHELL=/bin/sh`, and `SUDO_USER`, `SUDO_UID`,
  `SUDO_GID` and `SUDO_COMMAND` describe the call. Only `TERM`, `COLORTERM`, `LANG` and
  `LC_*` come through from you, never `DYLD_*`. Like sudo's `env_check`, those are dropped
  too when the value has a `/` or `%` or starts with `()`, and only the first value of a
  name counts. `SUDO_COMMAND` keeps only the first 4096 bytes of the arguments, as in sudo.
- **Your umask.** The command gets `022` or yours if it is stricter. It can only tighten:
  `umask 077` gives `0077`, `umask 002` still gives `0022`.

## The command's process

The command starts with a clean slate, like under sudo:

- In its own session, so the terminal's signals reach it only through `sus`.
- Only your stdin, stdout and stderr. Every other descriptor the service holds is closed at
  exec.
- Default signal handling, nothing blocked or ignored.
- No core dumps: `ulimit -c` is 0, the hard limit too.
- The working directory you signed.

## The service

- `susd` re-reads `config.toml` on every request and checks it with `open` and `fstat`: a
  regular file, owned by root, not writable by others (group write only for `wheel`), every
  `secure_path` entry absolute. If anything is wrong, nothing runs.
- `install` also checks every directory from the config up to `/`.
- The client checks that the socket is owned by root and that the process behind it runs
  as root before it asks the agent for anything.
- At most 4 requests wait for a signature at once.
- Called as root already, `sus` runs the command directly, like `sudo` as root: no
  signature, no environment reset and no log entry.

## Audit log

Every request the service handles leaves entries in the Unified Log under the subsystem
`io.github.anndii.sus`. Two cases leave none: a caller that is already root (it never asks
the service), and a connection whose peer credentials cannot be read (there is no uid to
name).

```sh
log show --last 1h --predicate 'subsystem == "io.github.anndii.sus"' --style compact
```

The first entry of a request:

```
req=1 uid=501 pid=4242 result=allowed reason="" key=SHA256:… cwd="/private/tmp" command="/bin/echo" argc=2 argv_bytes=7 argv_sha256=… parts=1
```

| Field | Meaning |
|---|---|
| `req` | Counter that ties the entries of one request together. |
| `uid`, `pid` | The caller, from the socket. |
| `result` | `allowed`, `denied`, or `abandoned` when the client left before sending a request. |
| `reason` | Why it was denied, empty when allowed. |
| `key` | Fingerprint of the key that signed, as `ssh-keygen -l` shows it. Once verified. |
| `cwd` | The working directory. Once known. |
| `command` | The program that ran, after the `secure_path` lookup (`sus echo` gives `/bin/echo`). |
| `argc`, `argv_bytes`, `argv_sha256` | Count, size and SHA-256 of the arguments. |
| `parts` | How many entries with the arguments follow. |

Then `req=N part=I/K argv=[…]` entries with the arguments themselves, because the Unified
Log cuts long lines. Non-printable bytes appear as `\xNN`. The signature is never logged.
Entries are written when the decision is made, so they survive a crash.

## Known gaps

- **No proof that a person approved.** That is the agent's job (see [Approval](#approval)).
- **After Ctrl-Z, the next input can reach the command.** On macOS a command stopped while it
  waits for terminal input still gets the next input after `fg`. Type `fg` before anything
  else. A pseudo-terminal for the command will close this after v0.1.0.
- **Release binaries are not notarized** by Apple. Build from source if you want to check
  what you run.
