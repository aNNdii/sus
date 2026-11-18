# Security policy

`sus` runs commands as root, so security reports are welcome.

## Reporting a vulnerability

Report it privately through GitHub: the repository's **Security** tab → **Report a
vulnerability**. Please don't open a public issue.

Include what you did, what happened and the version (`susd` binary from a release, or a
commit). `sus` has one maintainer, so expect an answer within days, not hours. Once a fix
is released, the advisory is published and you are credited unless you ask not to be.

## Supported versions

Only the latest release gets fixes.

## Scope

In scope: anything that lets a call run as root without a valid signature from a key listed
for the caller, runs something other than what was signed, leaks file descriptors or
environment into the command, or hides a call from the audit log.

Out of scope, by design: malware running as the same user that asks for a signature, an SSH
agent that signs without asking, and access to TCC-protected folders. See
[docs/security.md](docs/security.md).
