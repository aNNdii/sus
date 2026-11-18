# 0013. Job control like sudo without a pty

Status: Accepted
Date: 2026-11-18

## Context

The command runs in its own session (`setsid`), started by the service, not by the client.
The terminal's job control therefore reaches only the client:

- Ctrl-Z stopped the client, the shell took the terminal back, and the root command went on
  reading the same terminal, competing with the shell for keystrokes.
- `sus cmd &` gave a root command that read the terminal in the background and never got
  `SIGTTIN`, because the terminal is not its controlling terminal.

sudo without a pty shares the process group with the command, so Ctrl-Z stops both. With a
pty it relays the stop and suspends itself.

## Decision

- The client takes `SIGTSTP` itself. On Ctrl-Z it sends `Signal(SIGSTOP)` for the command's
  group, then stops itself with `SIGSTOP`, which cannot be ignored.
- When the shell continues the client in the foreground (`fg`), it sends `Signal(SIGCONT)`.
- A client whose stdin is a terminal with another foreground group stays stopped until it
  is in the foreground. It checks this before it even asks the agent. Without a terminal on
  stdin (`sus cmd </dev/null &`) it runs in the background as usual.
- The service relays `SIGSTOP` and `SIGCONT` in addition to the forwarded signals, and
  nothing else (`proto::relayed`).
- A hang-up is `SIGHUP` followed by `SIGCONT`, so a stopped group sees it.
- Stop reports from macOS's `waitid(WEXITED)` are consumed with `WSTOPPED`
  ([ADR 0003](0003-reap-safe-waiting.md)).

## Consequences

- Ctrl-Z and `fg` work as with sudo without a pty.
- A background `sus` with the terminal on stdin waits for `fg`, where sudo would run until
  it reads. This is stricter on purpose: a root command must not read the shell's input.
- Known gap on macOS: a command stopped while blocked in `read()` on the terminal still
  takes the next input when it arrives and gets it after `SIGCONT`. Under sudo the
  terminal's background check (`SIGTTIN`) stops that read first; here the terminal is not
  the command's controlling terminal, so the check does not apply. The first input after
  Ctrl-Z, usually one line, goes to the command. With `sus tee /etc/foo`, it would end up in
  the file. The README tells users to type `fg` before anything else.
- A pty for the command closes the gap ([ADR 0015](0015-no-pty-in-v1.md)).
- Tested in `tests/signals.rs`: `ctrl_z_stops_the_command_and_continue_resumes_it`,
  `lost_connection_hangs_up_a_stopped_command`, `background_job_on_a_terminal_waits_for_fg`.

## Alternatives considered

- **Ignore `SIGTSTP`, `SIGTTIN` and `SIGTTOU` in the client.** No job control at all; Ctrl-Z
  would do nothing.
- **A pty now.** Closes the gap, but is a larger change ([ADR 0015](0015-no-pty-in-v1.md)).
