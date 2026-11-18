//! Preparing and starting the command: lookup, environment, spawn, exit code.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};

use crate::proto::{Call, filter_env};

const TCC_HINT: &str = "operation not permitted; the service needs Full Disk Access \
     to reach ~/Desktop, ~/Documents, ~/Downloads and removable volumes";

/// The caller as seen by the service (uid, gid and pid come from the socket, never from the client).
pub(crate) struct Peer {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
    pub user: String,
}

fn is_eperm(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::EPERM)
}

fn is_executable(path: &Path) -> Result<bool, io::Error> {
    let meta = std::fs::metadata(path)?;
    Ok(meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// A name without `/` is searched in `secure_path`, one with `/` is taken relative to `cwd`.
pub(crate) fn resolve(cmd: &OsStr, cwd: &Path, secure_path: &str) -> Result<PathBuf, String> {
    let shown = String::from_utf8_lossy(cmd.as_bytes()).into_owned();
    if cmd.is_empty() {
        return Err("empty command".into());
    }
    let mut eperm = false;
    let candidates: Vec<PathBuf> = if cmd.as_bytes().contains(&b'/') {
        vec![cwd.join(cmd)]
    } else {
        secure_path
            .split(':')
            .filter(|d| !d.is_empty())
            .map(|d| Path::new(d).join(cmd))
            .collect()
    };
    for path in candidates {
        match is_executable(&path) {
            Ok(true) => return Ok(path),
            Ok(false) => {}
            Err(e) => eperm |= is_eperm(&e),
        }
    }
    if eperm {
        Err(format!("{shown}: {TCC_HINT}"))
    } else {
        Err(format!("{shown}: command not found"))
    }
}

/// Longest arguments part of `SUDO_COMMAND`, in bytes, as in sudo.
const SUDO_COMMAND_ARGS_MAX: usize = 4096;

/// The environment of the command, like sudo with `env_reset`.
/// `SUDO_COMMAND` is the resolved `program`, a space and `argv[1..]` joined by spaces, as with
/// sudo. Like sudo, the arguments part is cut after `SUDO_COMMAND_ARGS_MAX` bytes (raw bytes,
/// so possibly inside a UTF-8 sequence): argv and environment share `ARG_MAX`, and a full
/// copy of a large argv would make `execve` fail with `E2BIG`.
pub(crate) fn env(
    peer: &Peer,
    passed: &[(OsString, OsString)],
    secure_path: &str,
    program: &Path,
    argv: &[OsString],
) -> Vec<(OsString, OsString)> {
    let mut out = filter_env(passed.iter().cloned());
    let mut command = program.as_os_str().as_bytes().to_vec();
    if argv.len() > 1 {
        let mut args = argv[1..]
            .iter()
            .map(|a| a.as_bytes())
            .collect::<Vec<_>>()
            .join(&b' ');
        args.truncate(SUDO_COMMAND_ARGS_MAX);
        command.push(b' ');
        command.extend_from_slice(&args);
    }
    let fixed: [(&str, OsString); 9] = [
        ("PATH", secure_path.into()),
        ("HOME", "/var/root".into()),
        ("USER", "root".into()),
        ("LOGNAME", "root".into()),
        ("SHELL", "/bin/sh".into()),
        ("SUDO_USER", peer.user.clone().into()),
        ("SUDO_UID", peer.uid.to_string().into()),
        ("SUDO_GID", peer.gid.to_string().into()),
        ("SUDO_COMMAND", OsString::from_vec(command)),
    ];
    out.extend(fixed.into_iter().map(|(k, v)| (OsString::from(k), v)));
    out
}

/// The caller's cwd must be a directory root can reach, or the chdir in `spawn` fails
/// and the error would blame the program instead. A relative one would name a directory
/// under the service's cwd, not the caller's.
fn check_cwd(cwd: &Path) -> Result<(), String> {
    if !cwd.is_absolute() {
        return Err(format!(
            "{}: working directory is not an absolute path",
            cwd.display()
        ));
    }
    let err = match std::fs::metadata(cwd) {
        Ok(m) if m.is_dir() => return Ok(()),
        Ok(_) => io::Error::from_raw_os_error(libc::ENOTDIR),
        Err(e) => e,
    };
    if is_eperm(&err) {
        Err(format!("{}: {TCC_HINT}", cwd.display()))
    } else {
        Err(format!(
            "{}: working directory not available: {err}",
            cwd.display()
        ))
    }
}

/// Highest fd the command's `pre_exec` marks close-on-exec, for huge or unlimited fd limits.
const MAX_FD: libc::c_int = 65_536;
/// Signals are 1..NSIG (`<sys/signal.h>`); libc does not export NSIG for macOS.
const NSIG: libc::c_int = 32;

/// The command's umask: the caller's, but never looser than 022 (sudo never lowers it).
fn umask_for(caller: u32) -> libc::mode_t {
    // At most 0o777, so it fits mode_t.
    (0o022 | (caller & 0o777)) as libc::mode_t
}

/// One past the highest fd the service may hold: the NOFILE soft limit, capped at MAX_FD.
fn fd_end() -> libc::c_int {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit only writes into `lim`, which we own.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return MAX_FD;
    }
    // At most MAX_FD, so it fits c_int.
    lim.rlim_cur.min(MAX_FD as libc::rlim_t) as libc::c_int
}

fn check(ret: libc::c_int) -> io::Result<()> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Gives the command a clean process state, like sudo before exec: only fds 0-2,
/// default dispositions, an empty signal mask, no core dumps and `umask`.
/// Runs between fork and exec, so it only makes async-signal-safe calls or
/// plain system calls (`setrlimit`) and does not allocate (`last_os_error` does not).
fn reset_inherited(fd_end: libc::c_int, umask: libc::mode_t) -> io::Result<()> {
    // fcntl rather than close: std's exec-error pipe must stay open until exec
    // (it is close-on-exec already).
    for fd in 3..fd_end {
        // SAFETY: fcntl on any fd number is harmless; a closed one gives EBADF.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags >= 0 && flags & libc::FD_CLOEXEC == 0 {
            // SAFETY: as above, and only adds FD_CLOEXEC to an open fd.
            check(unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) })?;
        }
    }
    // Handlers end at exec, but SIG_IGN and the mask survive it. Dispositions
    // first, so a pending signal that the empty mask lets through acts by default.
    for sig in (1..NSIG).filter(|&s| s != libc::SIGKILL && s != libc::SIGSTOP) {
        // SAFETY: signal is async-signal-safe; SIG_DFL runs no code of ours.
        if unsafe { libc::signal(sig, libc::SIG_DFL) } == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: sigset_t is plain data; sigemptyset fills the local `empty` and
    // sigprocmask only reads it. Both are async-signal-safe.
    check(unsafe {
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut())
    })?;
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit is a plain system call and only reads `no_core`.
    check(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) })?;
    // SAFETY: umask only sets this process's file mode mask.
    unsafe { libc::umask(umask) };
    Ok(())
}

/// A command ready to start: cwd checked, program resolved, environment built.
pub(crate) struct Prepared {
    cmd: Command,
    program: PathBuf,
    cwd: PathBuf,
}

/// Everything before the fork: checks the cwd, resolves the program and builds the
/// command with the caller's stdin, stdout and stderr. These `stat` calls can block
/// (a dead network mount), so they run before the caller takes any lock.
/// `caller_umask` only tightens the command's umask, see `umask_for`.
pub(crate) fn prepare(
    call: &Call,
    peer: &Peer,
    secure_path: &str,
    passed: &[(OsString, OsString)],
    caller_umask: u32,
    fds: [OwnedFd; 3],
) -> Result<Prepared, String> {
    let first = call.argv.first().ok_or("empty command")?;
    check_cwd(&call.cwd)?;
    let program = resolve(first, &call.cwd, secure_path)?;
    let [stdin, stdout, stderr] = fds;
    let mut cmd = Command::new(&program);
    cmd.arg0(first)
        .args(&call.argv[1..])
        .env_clear()
        .envs(env(peer, passed, secure_path, &program, &call.argv))
        .current_dir(&call.cwd)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    let (fd_end, umask) = (fd_end(), umask_for(caller_umask));
    // SAFETY: setsid and the calls in reset_inherited are safe between fork and
    // exec (see there), and the closure only copies two integers it owns.
    unsafe {
        cmd.pre_exec(move || {
            check(libc::setsid())?;
            reset_inherited(fd_end, umask)
        });
    }
    Ok(Prepared {
        cmd,
        program,
        cwd: call.cwd.clone(),
    })
}

impl Prepared {
    /// The program `argv[0]` resolved to, as it will be executed.
    pub(crate) fn program(&self) -> &Path {
        &self.program
    }

    /// Starts the command in its own session.
    pub(crate) fn spawn(mut self) -> Result<Child, String> {
        crate::macos::before_fork();
        self.cmd.spawn().map_err(|e| {
            if is_eperm(&e) {
                format!("{}: {TCC_HINT}", self.cwd.display())
            } else {
                format!("{}: {e}", self.program.display())
            }
        })
    }
}

/// Exit code, or 128 + N for a command killed by signal N.
pub(crate) fn exit_code(s: ExitStatus) -> i32 {
    match (s.code(), s.signal()) {
        (Some(c), _) => c,
        (None, Some(n)) => 128 + n,
        (None, None) => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    fn peer() -> Peer {
        Peer {
            uid: 501,
            gid: 20,
            pid: 7,
            user: "alice".into(),
        }
    }

    fn os(s: &str) -> OsString {
        s.into()
    }

    #[test]
    fn env_is_exactly_the_documented_set() {
        let passed = vec![
            (os("TERM"), os("xterm")),
            (os("LC_ALL"), os("C")),
            (os("PATH"), os("/evil")),
            (os("DYLD_INSERT_LIBRARIES"), os("/x.dylib")),
            (os("HOME"), os("/Users/alice")),
            (os("SUDO_UID"), os("0")),
        ];
        let argv = vec![os("ls"), os("-l")];
        let got: HashMap<_, _> = env(&peer(), &passed, "/a:/b", Path::new("/b/ls"), &argv)
            .into_iter()
            .collect();
        let want: HashMap<OsString, OsString> = [
            ("TERM", "xterm"),
            ("LC_ALL", "C"),
            ("PATH", "/a:/b"),
            ("HOME", "/var/root"),
            ("USER", "root"),
            ("LOGNAME", "root"),
            ("SHELL", "/bin/sh"),
            ("SUDO_USER", "alice"),
            ("SUDO_UID", "501"),
            ("SUDO_GID", "20"),
            ("SUDO_COMMAND", "/b/ls -l"),
        ]
        .into_iter()
        .map(|(k, v)| (os(k), os(v)))
        .collect();
        assert_eq!(got, want);
    }

    /// The daemon does not trust the client's filter: bad values and repeated names from a
    /// raw request are dropped here too, so `execve` gets at most one value per name.
    #[test]
    fn env_checks_values_and_keeps_the_first_of_repeated_names() {
        let passed = vec![
            (os("TERM"), os("() { :;}; echo x")),
            (os("COLORTERM"), os("%n")),
            (os("LANG"), os("/tmp/locale")),
            (os("LC_ALL"), os("C")),
            (os("LC_ALL"), os("en_US.UTF-8")),
            (os("TERM"), os("xterm")),
        ];
        let got = env(&peer(), &passed, "/a", Path::new("/a/x"), &[os("x")]);
        let names: Vec<_> = got.iter().map(|(k, _)| k.clone()).collect();
        for name in &names {
            assert_eq!(names.iter().filter(|n| *n == name).count(), 1, "{name:?}");
        }
        for name in ["TERM", "COLORTERM", "LANG"] {
            assert!(!names.contains(&os(name)), "{name}");
        }
        assert!(got.contains(&(os("LC_ALL"), os("C"))));
    }

    fn sudo_command(argv: &[OsString]) -> Vec<u8> {
        env(&peer(), &[], "/a", Path::new("/a/x"), argv)
            .into_iter()
            .find(|(k, _)| k == "SUDO_COMMAND")
            .unwrap()
            .1
            .into_vec()
    }

    #[test]
    fn sudo_command_cuts_the_arguments_after_4096_bytes() {
        let max = SUDO_COMMAND_ARGS_MAX;
        assert_eq!(sudo_command(&[os("x")]), b"/a/x");
        assert_eq!(sudo_command(&[os("x"), os("")]), b"/a/x ");
        // exactly at the limit: kept whole
        let full = "y".repeat(max);
        assert_eq!(
            sudo_command(&[os("x"), os(&full)]),
            format!("/a/x {full}").into_bytes()
        );
        // one huge argument and many small ones: the arguments part is cut at max bytes
        let huge = sudo_command(&[os("x"), os(&"z".repeat(600_000))]);
        assert_eq!(huge, format!("/a/x {}", "z".repeat(max)).into_bytes());
        let many: Vec<OsString> = std::iter::once(os("x"))
            .chain(std::iter::repeat_n(os("ab"), 5000))
            .collect();
        let got = sudo_command(&many);
        assert_eq!(got.len(), "/a/x ".len() + max);
        assert!(got.starts_with(b"/a/x ab ab "));
        // raw bytes: a cut inside a UTF-8 sequence is fine
        let mut long = vec![b'a'; max - 1];
        long.extend_from_slice("ä".as_bytes());
        let got = sudo_command(&[os("x"), OsString::from_vec(long.clone())]);
        assert_eq!(&got[5..], &long[..max]);
    }

    fn exe(path: &Path) {
        std::fs::write(path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn resolve_uses_secure_path_for_bare_names() {
        let t = tempfile::tempdir().unwrap();
        let bin = t.path().join("bin");
        let cwd = t.path().join("cwd");
        std::fs::create_dir(&bin).unwrap();
        std::fs::create_dir(&cwd).unwrap();
        exe(&bin.join("tool"));
        exe(&cwd.join("tool")); // must not win over secure_path
        let sp = format!("/nonexistent::{}", bin.display());
        assert_eq!(
            resolve(OsStr::new("tool"), &cwd, &sp).unwrap(),
            bin.join("tool")
        );
        let err = resolve(OsStr::new("nothere"), &cwd, &sp).unwrap_err();
        assert!(
            err.contains("nothere") && err.contains("not found"),
            "{err}"
        );
    }

    #[test]
    fn resolve_with_slash_is_relative_to_cwd() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir(t.path().join("sub")).unwrap();
        exe(&t.path().join("sub/tool"));
        assert_eq!(
            resolve(OsStr::new("./sub/tool"), t.path(), "/usr/bin").unwrap(),
            t.path().join("./sub/tool")
        );
        assert!(resolve(OsStr::new("./sub/none"), t.path(), "/usr/bin").is_err());
        // a directory or a non-executable file is not a command
        std::fs::write(t.path().join("plain"), "x").unwrap();
        assert!(resolve(OsStr::new("./plain"), t.path(), "/usr/bin").is_err());
        assert!(resolve(OsStr::new("./sub"), t.path(), "/usr/bin").is_err());
    }

    #[test]
    fn exit_code_maps_code_and_signal() {
        let st = Command::new("/bin/sh")
            .args(["-c", "exit 3"])
            .status()
            .unwrap();
        assert_eq!(exit_code(st), 3);
        let st = Command::new("/bin/sh")
            .args(["-c", "kill -TERM $$"])
            .status()
            .unwrap();
        assert_eq!(exit_code(st), 128 + libc::SIGTERM);
    }

    fn fd_of(f: File) -> OwnedFd {
        f.into()
    }

    #[test]
    fn spawn_passes_fds_and_starts_new_session() {
        let t = tempfile::tempdir().unwrap();
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        let null = || fd_of(File::open("/dev/null").unwrap());
        let call = Call {
            uid: 501,
            cwd: t.path().to_path_buf(),
            argv: vec![
                os("sh"),
                os("-c"),
                os("echo $SUDO_USER; echo $$; ps -o pgid= -p $$; pwd; echo err >&2; exit 4"),
            ],
        };
        let out: OwnedFd = theirs.try_clone().unwrap().into();
        let err: OwnedFd = theirs.into();
        let mut child = prepare(
            &call,
            &peer(),
            "/bin/:/usr/bin",
            &[],
            0o022,
            [null(), out, err],
        )
        .unwrap()
        .spawn()
        .unwrap();
        let status = child.wait().unwrap();
        drop(child);
        assert_eq!(exit_code(status), 4);
        let mut got = String::new();
        ours.read_to_string(&mut got).unwrap();
        let lines: Vec<&str> = got.lines().collect();
        assert_eq!(lines[0], "alice");
        // setsid makes the child a group leader: pgid == pid, and not our group
        let pid: i32 = lines[1].trim().parse().unwrap();
        let pgid: i32 = lines[2].trim().parse().unwrap();
        assert_eq!(pid, pgid);
        // SAFETY: getpgid(0) asks for our own group; no pointers involved.
        let my_group = unsafe { libc::getpgid(0) };
        assert_ne!(pgid, my_group);
        assert_eq!(
            std::fs::canonicalize(lines[3]).unwrap(),
            std::fs::canonicalize(t.path()).unwrap()
        );
        assert_eq!(lines[4], "err");
    }

    #[test]
    fn spawn_unknown_command_runs_nothing() {
        let t = tempfile::tempdir().unwrap();
        let null = || fd_of(File::open("/dev/null").unwrap());
        let call = Call {
            uid: 1,
            cwd: t.path().to_path_buf(),
            argv: vec![os("no-such-cmd")],
        };
        let err = prepare(
            &call,
            &peer(),
            "/usr/bin",
            &[],
            0o022,
            [null(), null(), null()],
        )
        .err()
        .unwrap();
        assert!(err.contains("not found"), "{err}");
    }

    #[test]
    fn spawn_with_unusable_cwd_blames_the_cwd() {
        let t = tempfile::tempdir().unwrap();
        let file = t.path().join("plain");
        std::fs::write(&file, "x").unwrap();
        let marker = t.path().join("ran");
        for cwd in [t.path().join("gone"), file] {
            let null = || fd_of(File::open("/dev/null").unwrap());
            let call = Call {
                uid: 1,
                cwd: cwd.clone(),
                argv: vec![os("touch"), marker.clone().into_os_string()],
            };
            let err = prepare(
                &call,
                &peer(),
                "/usr/bin",
                &[],
                0o022,
                [null(), null(), null()],
            )
            .err()
            .unwrap();
            assert!(
                err.starts_with(&format!(
                    "{}: working directory not available: ",
                    cwd.display()
                )),
                "{err}"
            );
            assert!(!marker.exists(), "command ran despite unusable cwd");
        }
    }

    /// Runs `sh -c script` through prepare and spawn: its exit code and output.
    fn sh(script: &str, caller_umask: u32) -> (i32, String) {
        let t = tempfile::tempdir().unwrap();
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        let call = Call {
            uid: 501,
            cwd: t.path().to_path_buf(),
            argv: vec![os("sh"), os("-c"), os(script)],
        };
        let null = fd_of(File::open("/dev/null").unwrap());
        let out: OwnedFd = theirs.try_clone().unwrap().into();
        let err: OwnedFd = theirs.into();
        let fds = [null, out, err];
        let mut child = prepare(&call, &peer(), "/bin:/usr/bin", &[], caller_umask, fds)
            .unwrap()
            .spawn()
            .unwrap();
        let status = child.wait().unwrap();
        drop(child);
        let mut got = String::new();
        ours.read_to_string(&mut got).unwrap();
        (exit_code(status), got)
    }

    #[test]
    fn command_inherits_only_stdin_stdout_and_stderr() {
        let leak = File::open("/dev/null").unwrap();
        // SAFETY: fcntl on an fd we own; clears its close-on-exec flag.
        let rc = unsafe { libc::fcntl(leak.as_raw_fd(), libc::F_SETFD, 0) };
        assert_eq!(rc, 0);
        // A glob rather than ls, which opens two fds of its own.
        let (code, out) = sh("echo /dev/fd/*", 0o022);
        drop(leak);
        assert_eq!(code, 0, "{out}");
        // 3 is the directory the glob itself reads.
        assert_eq!(out, "/dev/fd/0 /dev/fd/1 /dev/fd/2 /dev/fd/3\n");
    }

    #[test]
    fn command_gets_the_callers_umask_but_at_least_022() {
        for (caller, want) in [
            (0o022, "0022"),
            (0o002, "0022"),
            (0o000, "0022"),
            (0o077, "0077"),
            (0o027, "0027"),
            (0o7777, "0777"),
        ] {
            assert_eq!(sh("umask", caller), (0, format!("{want}\n")), "{caller:o}");
        }
    }

    #[test]
    fn command_cannot_dump_core() {
        let mut old = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit only writes into `old`.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut old) }, 0);
        // A small soft limit of our own, so the command has one to inherit.
        let ours = libc::rlimit {
            rlim_cur: old.rlim_max.min(1 << 20),
            rlim_max: old.rlim_max,
        };
        // SAFETY: setrlimit only reads `ours`.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &ours) }, 0);
        let got = sh("ulimit -c; ulimit -H -c", 0o022);
        // SAFETY: setrlimit only reads `old`, the limit read above.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &old) }, 0);
        assert_eq!(got, (0, "0\n0\n".to_string()));
    }

    #[test]
    fn command_starts_with_default_signals_and_an_empty_mask() {
        // A shell cannot undo a signal ignored on entry, and a blocked one never arrives.
        let script = "trap - INT; kill -INT $$; echo survived";
        // SAFETY: sigset_t is plain data, filled by sigemptyset/sigaddset;
        // pthread_sigmask changes only this thread's mask.
        let (mut int, mut before) = unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
        // SAFETY: as above.
        unsafe {
            libc::sigemptyset(&mut int);
            libc::sigaddset(&mut int, libc::SIGINT);
            libc::pthread_sigmask(libc::SIG_BLOCK, &int, &mut before);
        }
        let blocked = sh(script, 0o022);
        // SAFETY: restores this thread's mask from above.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &before, std::ptr::null_mut()) };
        assert_eq!(blocked, (128 + libc::SIGINT, String::new()));

        // SAFETY: SIG_IGN runs no code; the old disposition is put back below.
        let old = unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
        let ignored = sh(script, 0o022);
        // SAFETY: restores the disposition read above.
        unsafe { libc::signal(libc::SIGINT, old) };
        assert_eq!(ignored, (128 + libc::SIGINT, String::new()));
    }
}
