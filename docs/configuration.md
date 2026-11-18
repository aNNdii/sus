# Configuration

How to install `sus`, set up the agent and the key, and edit the config.
Why it is built this way: [architecture.md](architecture.md). What it protects against:
[security.md](security.md).

## The key

`sus` accepts plain `ssh-ed25519` keys. RSA keys, ECDSA keys and certificates are refused.

Create one key only for `sus`, per machine. Don't use it for SSH logins or git signing, and
never forward it (`ssh -A`): every place that can ask the agent for that key can then ask
for root. Name it after the machine, e.g. `laptop-sudo-sign-2026`.

Save the public half as a `.pub` file with one `ssh-ed25519` line. `susd install` reads it.

## The agent

An `ssh-ed25519` signature says which key signed, not whether someone was asked. The
agent's settings decide what "approve" means.

- **Bitwarden:** set the key to **"Ask for authorization: Always"**. With the default,
  Bitwarden remembers an approval for a while and every process of yours can use it. In a
  test, six calls in 180 ms got one prompt. Bitwarden keys are synced to your other devices
  and can be exported.
- **OpenSSH `ssh-agent`:** it signs without asking unless the key was added with
  `ssh-add -c`. A key loaded without `-c` turns `sus` into passwordless sudo.

`sus` finds the agent through `SSH_AUTH_SOCK`. Without it (GUI apps have none), it falls back
to `~/.bitwarden-ssh-agent.sock`. It uses the first key from the service's list that the
agent also holds.

## Install

```sh
sudo $(mise which susd) install --key ~/.ssh/laptop-sudo-sign-2026.pub
```

This copies `susd` to `/usr/local/libexec/sus/`, writes `/usr/local/etc/sus/config.toml`,
adds the LaunchDaemon `/Library/LaunchDaemons/io.github.anndii.sus.plist` and loads it.
launchd creates the socket `/var/run/sus.sock` and starts `susd` on the first call.

| Option | Meaning |
|---|---|
| `--key <file.pub>` | A key that may sign. Repeatable. |
| `--user <name>` | Who may use the keys. Default: whoever ran `sudo`. Repeatable. Root is refused. |

Every user named gets every key given. `--user` without `--key` is refused, and so is a
first install without `--key`.

### Install again or upgrade

Running `install` again replaces the binary and the plist.

- With `--key`, it merges the new keys into the existing config. Everything else stays,
  including `secure_path` and other users' keys. The file is rewritten: its content is kept,
  but comments and the order of entries are not.
- Without `--key`, the config is not touched.

You can upgrade through the service itself: `sus $(mise which susd) install`. `install`
ignores the hangup that stopping the old service sends to its commands. `sus` then prints
`connection to service lost, command state unknown`, because the service it talked to just
went away. That's expected: the install finishes and the new service is up a moment later.

## The config file

`/usr/local/etc/sus/config.toml` is plain TOML. Each user lists the keys that may sign for
it, like `authorized_keys`. A key listed for one user does nothing for another.

```toml
secure_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

[users]
alice = ["ssh-ed25519 AAAA… laptop-sudo-sign-2026"]
```

- `secure_path` is optional and defaults to the line above. It is the command's `PATH`.
  It has to come before `[users]`, as in any TOML file.
- Every `secure_path` entry has to be an absolute path. `.`, `bin` or an empty entry
  (`/usr/bin::/bin`) gets the config refused with
  `service config invalid: secure_path entry "." is not absolute`, and `install` refuses to
  merge into such a config. A relative entry would be looked up from the service's directory
  but run from yours.
- A user that does not exist matches nobody. `susd` logs a warning and goes on.
- Only plain `ssh-ed25519` keys load. The config needs at least one user, and every user at
  least one key.

`susd` reads the file on every request, so changes apply at once. If you edit it by hand,
keep it a regular file owned by root that nobody else can write (group write only for group
`wheel`). Otherwise `susd` refuses to run anything and says `service config invalid`.
`install` writes it as `root:wheel` `0600`, which is the safe choice.

To revoke a key, delete it from the file.

## Full Disk Access (TCC)

macOS keeps `~/Desktop`, `~/Documents`, `~/Downloads` and removable volumes behind TCC. A
root process started by launchd has no access there unless you grant it. If a command fails
there with "Operation not permitted", add `/usr/local/libexec/sus/susd` to System Settings →
Privacy & Security → Full Disk Access. `install` never touches TCC.

## Limits

- At most 4 requests wait for a signature at once. The 5th gets
  `busy: too many pending requests`, as does any request when macOS won't give the service
  another thread. Running commands do not count.
- You have 30 seconds from connect to a valid signature.
- A request (arguments plus working directory) is at most 1 MiB and 65536 arguments.

## Uninstall

```sh
sudo $(mise which susd) uninstall
```

Unloads the service and removes the plist, the binary, the config and the socket. Safe to
run twice.
