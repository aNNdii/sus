# 0003. Wait with `waitid(WNOWAIT)`, then reap

Status: Accepted
Date: 2026-11-18

## Context

The service runs as root and sends signals to the command's process group with `killpg`:
forwarded signals from the client, `SIGHUP` when the client is gone, and `SIGHUP` to every
group on `SIGTERM`. These come from other threads than the one that waits for the command.

With a plain `wait()`, the leader is reaped first and the group is marked dead afterwards.
In between, the kernel may give the same pid to a new process. A `killpg` in that window
would hit a group that is not ours, as root.

## Decision

- The waiting thread calls `waitid(P_PID, pid, WEXITED | WNOWAIT)`. The leader stays a
  zombie, so its pid cannot be reused.
- It then marks the group dead under the `Running` lock, and only then reaps it.
- Every signal to a group is sent under the same lock, and only while the group is marked
  alive.
- Running calls are keyed by a call id, not by the pgid, so a signal for a finished call
  never reaches a later command with the same pid.
- macOS also reports a stopped child to `WEXITED` (`CLD_STOPPED`). Such a report is taken
  with `WSTOPPED`, which never reaps, and the wait goes on.

## Consequences

- No signal from the service can reach a recycled process group.
- Once the leader is reaped, other members of its group get no more forwarded signals or
  hang-ups from the service. A background child that outlives the command is on its own.
- Unit tests in `src/daemon.rs` cover it: `leader_is_alive_until_waited_for_and_dead_after`
  and `signals_reach_the_group_only_until_the_leader_is_reaped`.

## Alternatives considered

- **`wait()`, then stop signalling.** Leaves the window between reap and mark, in which a
  `killpg` as root can hit a stranger's group.
