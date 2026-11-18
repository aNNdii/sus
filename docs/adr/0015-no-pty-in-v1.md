# 0015. No pty in v1

Status: Accepted
Date: 2026-11-18

## Context

sudo runs commands on a pseudo-terminal by default since 1.9.14 (`use_pty`). The pty sits
between the user's terminal and the command: the command gets a terminal of its own, and
sudo relays input, output and job control.

`sus` passes the caller's stdin, stdout and stderr to the command with `SCM_RIGHTS`. The
command runs in its own session (`setsid`) and has no controlling terminal.

## Decision

- v1 has no pty. The command gets the caller's fds 0, 1 and 2 as they are.
- Job control is done as sudo does it without a pty
  ([ADR 0013](0013-job-control-without-pty.md)).
- A pty for the command is planned after v0.1.0.

## Consequences

- Pipes and redirections work as with any command: `echo hi | sus cat`.
- The command has no `/dev/tty`. Programs that open it, or insist on a controlling
  terminal, fail or complain.
- The Ctrl-Z gap of ADR 0013 stays until the pty exists: the first input after Ctrl-Z can
  reach a stopped command.
- The target user is always root, so the terminal injection that `use_pty` guards against
  (TIOCSTI, CVE-2005-4890) gains nothing in v1. It becomes relevant once a `-u` option
  exists; then the command must not get the user's terminal fds.
- A pty means relaying input and output for the whole life of the command. That is new
  code on the path of every call, which is why it gets its own design.

## Alternatives considered

- **A pty in v1.** Closes the Ctrl-Z gap and gives `/dev/tty`, but is the largest single
  piece of new code and was not needed for the first release.
