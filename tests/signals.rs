//! Signals, lost connections and the SIGTERM fan-out (AC3); approvals that
//! are rejected or never finish (AC9). The service runs in test mode.

mod common;

use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use common::{Agent, Service, client, keygen, run, stderr, stdout, tmpdir};
use sus::names;

/// Longest wait for anything a test expects to happen.
const PATIENCE: Duration = Duration::from_secs(15);
const LOST: &str = "connection to service lost, command state unknown";

struct World {
    dir: tempfile::TempDir,
    agent: Agent,
    service: Service,
}

/// A service that allows me with one key, and an agent holding that key.
/// With `askpass`, the agent asks that script to confirm every use (`ssh-add -c`).
fn world_with(askpass: Option<&str>) -> World {
    let dir = tmpdir();
    let key = keygen(dir.path(), "a");
    let socket = dir.path().join("agent.sock");
    let agent = match askpass {
        None => {
            let agent = Agent::start(socket);
            agent.add(&key);
            agent
        }
        Some(script) => {
            let path = dir.path().join("askpass");
            std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            let env: [(&str, &OsStr); 3] = [
                ("SSH_ASKPASS", path.as_os_str()),
                ("SSH_ASKPASS_REQUIRE", OsStr::new("force")),
                ("DISPLAY", OsStr::new(":0")),
            ];
            let agent = Agent::start_with(socket, &env);
            agent.add_with(&key, &["-c"]);
            agent
        }
    };
    let me = common::me();
    let service = Service::start(dir.path(), &[&me], &[&key], "/usr/bin:/bin:/usr/sbin:/sbin");
    World {
        dir,
        agent,
        service,
    }
}

fn world() -> World {
    world_with(None)
}

impl World {
    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn sus(&self, args: &[&str]) -> Command {
        let mut cmd = client(self.path(), args);
        cmd.env(names::ENV_SOCKET, &self.service.socket)
            .env("SSH_AUTH_SOCK", &self.agent.socket);
        cmd
    }

    /// Sends `sig` to the service and waits until it has exited.
    fn stop_service(&mut self, sig: i32) -> (ExitStatus, Duration) {
        let started = Instant::now();
        signal(self.service.child.id(), sig);
        let status = wait_child(&mut self.service.child);
        (status, started.elapsed())
    }
}

fn signal(pid: u32, sig: i32) {
    // SAFETY: plain syscall on a child of this test that is not reaped yet.
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, sig) }, 0);
}

fn wait_child(child: &mut Child) -> ExitStatus {
    let end = Instant::now() + PATIENCE;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() > end {
            let _ = child.kill();
            panic!("process {} did not exit", child.id());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for(path: &Path) {
    let end = Instant::now() + PATIENCE;
    while !path.exists() {
        assert!(Instant::now() < end, "{} did not appear", path.display());
        thread::sleep(Duration::from_millis(10));
    }
}

/// A client started in the background, its stdout readable line by line.
struct Started {
    child: Child,
    lines: Receiver<String>,
    err: Option<JoinHandle<Vec<u8>>>,
}

fn start(mut cmd: Command) -> Started {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let out = child.stdout.take().unwrap();
    let (tx, lines) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(out).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut err = child.stderr.take().unwrap();
    let err = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err.read_to_end(&mut buf);
        buf
    });
    Started {
        child,
        lines,
        err: Some(err),
    }
}

impl Started {
    fn line(&self) -> String {
        self.lines
            .recv_timeout(PATIENCE)
            .expect("no line from the command")
    }

    fn signal(&self, sig: i32) {
        signal(self.child.id(), sig);
    }

    fn wait(&mut self) -> ExitStatus {
        wait_child(&mut self.child)
    }

    /// Exit status, the rest of stdout and all of stderr. Returns once every
    /// holder of the pipes, the command included, has closed them.
    fn finish(&mut self) -> Output {
        let status = self.wait();
        let mut stdout = Vec::new();
        loop {
            match self.lines.recv_timeout(PATIENCE) {
                Ok(line) => stdout.extend_from_slice(format!("{line}\n").as_bytes()),
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(e) => panic!("stdout still open: {e}"),
            }
        }
        let stderr = self.err.take().unwrap().join().unwrap();
        Output {
            status,
            stdout,
            stderr,
        }
    }
}

impl Drop for Started {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Prints its pid (= its process group), loops until `sig`, then says so and exits 7.
fn trapping(sig: &str) -> String {
    format!("trap 'echo got {sig}; exit 7' {sig}; echo $$; while :; do sleep 0.1; done")
}

fn kill_group(pgid: &str) {
    let pgid: libc::pid_t = pgid.parse().unwrap();
    // SAFETY: plain syscall; the group is the test's own command.
    unsafe { libc::killpg(pgid, libc::SIGKILL) };
}

fn assert_one_line_failure(o: &Output, want: &str) {
    let err = stderr(o);
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    assert_eq!(err.lines().count(), 1, "{err:?}");
    assert!(err.contains(want), "{err:?} should contain {want:?}");
}

#[test]
fn forwarded_signals_reach_the_command() {
    let w = world();
    for (sig, name) in [
        (libc::SIGINT, "INT"),
        (libc::SIGTERM, "TERM"),
        (libc::SIGHUP, "HUP"),
        (libc::SIGQUIT, "QUIT"),
        (libc::SIGWINCH, "WINCH"),
    ] {
        let mut s = start(w.sus(&["sh", "-c", &trapping(name)]));
        s.line();
        s.signal(sig);
        let o = s.finish();
        assert_eq!(o.status.code(), Some(7), "{name}: {o:?}");
        assert_eq!(stdout(&o), format!("got {name}\n"));
    }
}

#[test]
fn ctrl_c_kills_the_command_with_exit_130() {
    let w = world();
    let mut s = start(w.sus(&["sh", "-c", "echo ready; exec sleep 30"]));
    assert_eq!(s.line(), "ready");
    s.signal(libc::SIGINT);
    let o = s.finish();
    assert_eq!(o.status.code(), Some(130), "{o:?}");
}

#[test]
fn signals_reach_the_whole_group() {
    // The leader dies of SIGTERM; its child traps it and still gets it.
    let inner = "trap 'echo inner got TERM; exit 0' TERM; echo ready; while :; do sleep 0.1; done";
    let w = world();
    let mut s = start(w.sus(&["sh", "-c", &format!("sh -c \"{inner}\" & wait")]));
    assert_eq!(s.line(), "ready");
    s.signal(libc::SIGTERM);
    let o = s.finish();
    assert_eq!(o.status.code(), Some(128 + libc::SIGTERM), "{o:?}");
    assert_eq!(stdout(&o), "inner got TERM\n");
}

/// `ps` state of `pid`, e.g. `S`, `T` (stopped), `Ss+`.
fn state(pid: &str) -> String {
    let out = Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", pid])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn wait_until_state(pid: &str, stopped: bool) {
    let end = Instant::now() + PATIENCE;
    while state(pid).starts_with('T') != stopped {
        assert!(
            Instant::now() < end,
            "{pid} is {:?}, want stopped={stopped}",
            state(pid)
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn ctrl_z_stops_the_command_and_continue_resumes_it() {
    let w = world();
    let mut s = start(w.sus(&["sh", "-c", &trapping("TERM")]));
    let pgid = s.line();
    let client = s.child.id().to_string();
    s.signal(libc::SIGTSTP);
    wait_until_state(&client, true);
    wait_until_state(&pgid, true);
    // No terminal on stdin counts as foreground: SIGCONT continues the command.
    s.signal(libc::SIGCONT);
    wait_until_state(&pgid, false);
    wait_until_state(&client, false);
    s.signal(libc::SIGTERM);
    let o = s.finish();
    assert_eq!(o.status.code(), Some(7), "{o:?}");
    assert_eq!(stdout(&o), "got TERM\n");
}

#[test]
fn lost_connection_hangs_up_a_stopped_command() {
    let w = world();
    let mut s = start(w.sus(&["sh", "-c", &trapping("HUP")]));
    let pgid = s.line();
    s.signal(libc::SIGTSTP);
    wait_until_state(&pgid, true);
    s.signal(libc::SIGKILL);
    let o = s.finish();
    assert_eq!(o.status.signal(), Some(libc::SIGKILL));
    // Continued after the hang-up, so the trap ran.
    assert_eq!(stdout(&o), "got HUP\n");
}

/// `sus touch marker &` under a job-control shell on a pty: the client waits,
/// stopped, before it even asks the agent, and runs the command after `fg`.
#[test]
fn background_job_on_a_terminal_waits_for_fg() {
    use std::fs::File;
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt;

    let w = world();
    let (mut master, mut slave) = (0, 0);
    // SAFETY: out pointers are live; the other arguments may be null.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);
    // SAFETY: openpty returned two fresh fds that nothing else owns.
    let (mut master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
    let script = r#""$SUS" touch marker & pid=$!
sleep 1
[ -e marker ] && echo ran-in-background
echo "state=$(ps -o stat= -p $pid)"
fg %1 >/dev/null
echo "fg=$?"
[ -e marker ] && echo ran-after-fg
"#;
    // An interactive zsh, as at a prompt: zsh hands the terminal to a job only
    // when interactive, and bash in a script misses a job that stops itself.
    let mut cmd = Command::new("/bin/zsh");
    cmd.args(["-f", "-i", "-o", "monitor", "-c", script])
        .env_clear()
        .env("SUS", env!("CARGO_BIN_EXE_sus"))
        .env(names::ENV_SOCKET, &w.service.socket)
        .env("SSH_AUTH_SOCK", &w.agent.socket)
        .env("HOME", w.path())
        .env("PATH", "/usr/bin:/bin")
        .current_dir(w.path())
        .stdin(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .stderr(slave);
    // SAFETY: setsid and ioctl are async-signal-safe; stdin is the pty already.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY.into(), 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut shell = cmd.spawn().unwrap();
    drop(cmd);
    let reader = thread::spawn(move || {
        let mut out = Vec::new();
        // Ends with EIO once the last slave fd closes.
        let _ = master.read_to_end(&mut out);
        String::from_utf8_lossy(&out).replace('\r', "")
    });
    let status = wait_child(&mut shell);
    let out = reader.join().unwrap();
    assert!(status.success(), "{status:?}\n{out}");
    assert!(!out.contains("ran-in-background"), "{out}");
    assert!(out.contains("state=T"), "{out}");
    assert!(out.contains("fg=0"), "{out}");
    assert!(out.contains("ran-after-fg"), "{out}");
}

#[test]
fn lost_connection_hangs_up_the_command() {
    let w = world();
    let mut s = start(w.sus(&["sh", "-c", &trapping("HUP")]));
    s.line();
    s.signal(libc::SIGKILL);
    let o = s.finish();
    assert_eq!(o.status.signal(), Some(libc::SIGKILL));
    // The command still writes to the caller's stdout.
    assert_eq!(stdout(&o), "got HUP\n");
}

#[test]
fn service_gone_leaves_the_command_state_unknown() {
    let mut w = world();
    let mut s = start(w.sus(&["sh", "-c", "echo $$; while :; do sleep 0.1; done"]));
    let pgid = s.line();
    w.stop_service(libc::SIGKILL);
    let status = s.wait();
    kill_group(&pgid);
    let o = s.finish();
    assert_eq!(status.code(), Some(1));
    assert_one_line_failure(&o, LOST);
}

#[test]
fn sigterm_hangs_up_running_commands() {
    let mut w = world();
    let mut s = start(w.sus(&["sh", "-c", &trapping("HUP")]));
    s.line();
    let (status, took) = w.stop_service(libc::SIGTERM);
    assert_eq!(status.code(), Some(0), "{status:?}");
    assert!(
        took < Duration::from_secs(4),
        "waited {took:?} for a finished group"
    );
    // The exit code still reached the caller.
    let o = s.finish();
    assert_eq!(o.status.code(), Some(7), "{o:?}");
    assert_eq!(stdout(&o), "got HUP\n");
}

#[test]
fn sigterm_waits_out_the_grace_and_kills_nothing() {
    let mut w = world();
    let mut s = start(w.sus(&[
        "sh",
        "-c",
        "trap '' HUP; echo $$; while :; do sleep 0.1; done",
    ]));
    let pgid = s.line();
    let (status, took) = w.stop_service(libc::SIGTERM);
    assert_eq!(status.code(), Some(0), "{status:?}");
    assert!(
        took >= Duration::from_millis(4500) && took < Duration::from_secs(8),
        "grace is 5 s, took {took:?}"
    );
    // No SIGKILL: the command outlives the service.
    let leader: libc::pid_t = pgid.parse().unwrap();
    // SAFETY: signal 0 only checks that the process exists.
    assert_eq!(unsafe { libc::kill(leader, 0) }, 0, "command was killed");
    let client = s.wait();
    kill_group(&pgid);
    let o = s.finish();
    assert_eq!(client.code(), Some(1));
    assert_one_line_failure(&o, LOST);
}

#[test]
fn approval_landing_after_sigterm_runs_nothing() {
    let dir = tmpdir();
    let (first, asked, release) = (
        dir.path().join("first"),
        dir.path().join("asked"),
        dir.path().join("release"),
    );
    // Approves the first use at once; holds later ones until the test releases them.
    let script = format!(
        "if [ ! -e '{}' ]; then touch '{0}'; exit 0; fi; touch '{}'; i=0; while [ ! -e '{}' ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done; exit 0",
        first.display(),
        asked.display(),
        release.display()
    );
    let mut w = world_with(Some(&script));
    // Ignores the hang-up (but says so), so the grace stays open.
    let mut held = start(w.sus(&[
        "sh",
        "-c",
        "trap 'echo got HUP' HUP; echo $$; while :; do sleep 0.1; done",
    ]));
    let pgid = held.line();
    let marker = w.path().join("marker");
    let mut late = start(w.sus(&["touch", marker.to_str().unwrap()]));
    wait_for(&asked);
    signal(w.service.child.id(), libc::SIGTERM);
    // The fan-out has happened; the service is now stopping.
    assert_eq!(held.line(), "got HUP");
    std::fs::write(&release, "").unwrap();
    let o = late.finish();
    assert_one_line_failure(&o, "service is stopping");
    assert!(!marker.exists(), "a command started after SIGTERM");
    let status = wait_child(&mut w.service.child);
    assert_eq!(status.code(), Some(0), "{status:?}");
    let log = std::fs::read_to_string(w.path().join("service.log")).unwrap();
    // The audit's first entry has the result, a later `part` of the same `req` the argv.
    let req = log
        .lines()
        .filter_map(|l| l.split_once(" audit "))
        .map(|(_, text)| text)
        .find(|t| t.contains("result=denied") && t.contains("service is stopping"))
        .and_then(|t| t.split_once(' '))
        .map(|(req, _)| req)
        .unwrap_or_else(|| panic!("{log}"));
    assert!(
        log.lines()
            .any(|l| l.contains(&format!(" audit {req} part=")) && l.contains("touch")),
        "{log}"
    );
    kill_group(&pgid);
    held.finish();
}

#[test]
fn client_dying_during_approval_runs_nothing() {
    let dir = tmpdir();
    let (asked, release) = (dir.path().join("asked"), dir.path().join("release"));
    // Holds the approval open until the test releases it (at most 30 s), then rejects.
    let script = format!(
        "touch '{}'; i=0; while [ ! -e '{}' ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done; exit 1",
        asked.display(),
        release.display()
    );
    let w = world_with(Some(&script));
    let marker = w.path().join("marker");
    let mut s = start(w.sus(&["touch", marker.to_str().unwrap()]));
    wait_for(&asked);
    // Ctrl-C at the approval prompt ends the client as usual.
    s.signal(libc::SIGINT);
    let o = s.finish();
    assert_eq!(o.status.signal(), Some(libc::SIGINT), "{o:?}");
    std::fs::write(&release, "").unwrap();
    thread::sleep(Duration::from_millis(300));
    assert!(!marker.exists());
}

#[test]
fn rejected_approval_fails_in_one_line() {
    let w = world_with(Some("exit 1"));
    let marker = w.path().join("marker");
    let o = run(w.sus(&["touch", marker.to_str().unwrap()]), b"");
    assert_one_line_failure(&o, "SSH agent did not sign: approval denied or not given");
    assert!(!marker.exists());
}
