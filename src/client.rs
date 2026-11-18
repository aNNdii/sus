//! The client: asks the service to run one command and returns its exit code.

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, stderr, stdin, stdout};
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

use ssh_agent_client_rs::{Client, Identity};
use ssh_key::PublicKey;
use ssh_key::public::KeyData;

use crate::macos;
use crate::names;
use crate::proto::{
    self, Call, Conn, FORWARDED, MAX_FRAME, ProtoError, ToClient, ToService, VERSION,
};

const LOST: &str = "connection to service lost, command state unknown";

pub fn client_main(argv: Vec<OsString>) -> i32 {
    // SAFETY: geteuid has no preconditions.
    run(argv, unsafe { libc::geteuid() })
}

fn run(argv: Vec<OsString>, euid: u32) -> i32 {
    if argv.is_empty() {
        eprintln!("usage: {} <command> [args...]", names::CLIENT);
        return 1;
    }
    if euid == 0 {
        return direct(&argv);
    }
    match request(argv) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{}: {e}", names::CLIENT);
            1
        }
    }
}

/// Already root: nothing to approve, run the command in place.
fn direct(argv: &[OsString]) -> i32 {
    let e = Command::new(&argv[0]).args(&argv[1..]).exec();
    eprintln!("{}: {}: {e}", names::CLIENT, argv[0].to_string_lossy());
    1
}

fn request(argv: Vec<OsString>) -> Result<i32, String> {
    let cwd = env::current_dir().map_err(|e| format!("cannot read the working directory: {e}"))?;
    // SAFETY: geteuid has no preconditions. The service sees the effective uid too.
    let uid = unsafe { libc::geteuid() };
    let call = Call { uid, cwd, argv };
    call.check_size()?;
    // A background job must not get the terminal's keystrokes to a root command.
    stop_while_in_background();

    let socket = socket_path();
    let mut conn = connect(&socket, expected_owner(&socket, uid))?;
    let (nonce, keys) = match conn.recv::<ToClient>(MAX_FRAME) {
        Ok((ToClient::Hello { nonce, keys, .. }, _)) => (nonce, keys),
        Ok((ToClient::Refused(why), _)) => return Err(why),
        Ok((ToClient::Exit(_), _)) => return Err(ProtoError::Malformed.to_string()),
        Err(e) => return Err(format!("service: {e}")),
    };

    let agent_path = agent_socket()?;
    let mut agent = Client::connect(&agent_path).map_err(|e| {
        format!(
            "SSH agent not reachable at {}: {}",
            agent_path.display(),
            describe(&e)
        )
    })?;
    let have = agent
        .list_all_identities()
        .map_err(|e| format!("SSH agent: {}", describe(&e)))?;
    let key = first_shared_key(&keys, &have).ok_or("no allowed key in the SSH agent")?;
    let signature = proto::sign(key, &call.message(&nonce), |k, d| agent.sign(k, d))
        .map_err(|e| sign_failure(&e))?;

    let request = ToService::Request {
        version: VERSION,
        cwd: call.cwd,
        argv: call.argv,
        env: proto::passed_env_now(),
        umask: current_umask(),
        signature,
    };
    let signals = conn
        .try_clone()
        .map_err(|e| format!("cannot watch signals: {e}"))?;
    // From here on the command may run: signals go to it, not to us. Until
    // the forwarder starts they wait, blocked.
    let set = take_forwarded_signals();
    let (i, o, e) = (stdin(), stdout(), stderr());
    conn.send(&request, &[i.as_fd(), o.as_fd(), e.as_fd()])
        .map_err(|_| LOST)?;
    thread::spawn(move || forward_signals(signals, set));
    match conn.recv::<ToClient>(MAX_FRAME) {
        Ok((ToClient::Exit(code), _)) => Ok(code),
        Ok((ToClient::Refused(why), _)) => Err(why),
        Ok((ToClient::Hello { .. }, _)) => Err(ProtoError::Malformed.to_string()),
        Err(_) => Err(LOST.into()),
    }
}

/// This process's umask. Reading it means setting it, so it is set to the
/// strictest mask and put back at once. Call before any other thread exists.
fn current_umask() -> u32 {
    // SAFETY: umask only swaps the process's file mode mask; no other thread
    // exists yet that could create a file while the strict mask is in place.
    let old = unsafe { libc::umask(0o777) };
    // SAFETY: as above, restores the mask read in the first call.
    unsafe { libc::umask(old) };
    u32::from(old)
}

extern "C" fn ignore(_: libc::c_int) {}

/// Blocks the FORWARDED signals and SIGTSTP (Ctrl-Z) this process does not
/// ignore (`nohup`, `&` in a script keep theirs) and returns them for
/// `sigwait`. Each also gets a no-op handler: macOS drops a blocked signal
/// whose default is to ignore it (SIGWINCH) instead of queueing it. Call
/// before any other thread exists.
fn take_forwarded_signals() -> libc::sigset_t {
    // SAFETY: sigset_t is plain data, filled by sigemptyset/sigaddset.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is a live sigset_t.
    unsafe { libc::sigemptyset(&mut set) };
    for sig in FORWARDED.into_iter().chain([libc::SIGTSTP]) {
        // SAFETY: sigaction and sigset_t are plain data. Reads the current
        // action, blocks the signal (this thread and all later ones), then
        // installs a handler that does nothing.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(sig, std::ptr::null(), &mut old) != 0
                || old.sa_sigaction == libc::SIG_IGN
            {
                continue;
            }
            let mut one: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut one);
            libc::sigaddset(&mut one, sig);
            libc::pthread_sigmask(libc::SIG_BLOCK, &one, std::ptr::null_mut());
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = ignore as *const () as libc::sighandler_t;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(sig, &action, std::ptr::null_mut());
            libc::sigaddset(&mut set, sig);
        }
    }
    set
}

/// Sends every blocked FORWARDED signal to the service, which passes it to
/// the command's group (AC3), and turns Ctrl-Z into `suspend`. Runs until the
/// process ends or the service is gone.
fn forward_signals(mut conn: Conn, set: libc::sigset_t) {
    loop {
        let mut sig = 0;
        // SAFETY: `set` and `sig` are live for the call; the signals in `set`
        // are blocked in every thread, so only `sigwait` takes them.
        if unsafe { libc::sigwait(&set, &mut sig) } != 0 {
            continue;
        }
        let sent = if sig == libc::SIGTSTP {
            suspend(&mut conn)
        } else {
            conn.send(&ToService::Signal(sig), &[])
        };
        if sent.is_err() {
            return;
        }
    }
}

/// Ctrl-Z, as sudo does it without a pty: stop the command, then this process,
/// so the shell takes the job back. The command runs in a session of its own,
/// so the terminal stops only us; a running command would go on reading the
/// keystrokes meant for the shell. Once we are continued in the foreground
/// (`fg`), the command is continued too.
fn suspend(conn: &mut Conn) -> Result<(), ProtoError> {
    conn.send(&ToService::Signal(libc::SIGSTOP), &[])?;
    stop_self();
    stop_while_in_background();
    conn.send(&ToService::Signal(libc::SIGCONT), &[])
}

/// Stops this process until the shell continues it. SIGSTOP, not SIGTSTP:
/// it cannot be ignored or dropped, so this never spins.
fn stop_self() {
    // SAFETY: plain syscalls on this process.
    unsafe { libc::kill(libc::getpid(), libc::SIGSTOP) };
}

/// Waits, stopped, while this process is a background job of the terminal on
/// its stdin (`sus cmd &`, `bg`): the command would read that terminal like a
/// foreground job but get no SIGTTIN, being in another session. Like a
/// background job reading the terminal, it waits for `fg`. `sus cmd </dev/null &`
/// runs in the background as usual.
fn stop_while_in_background() {
    while in_background() {
        stop_self();
    }
}

/// Whether stdin is a terminal whose foreground group is not ours. No terminal,
/// or one that is not our controlling terminal, counts as foreground.
fn in_background() -> bool {
    // SAFETY: plain syscalls; tcgetpgrp only reads.
    let (fg, ours) = unsafe { (libc::tcgetpgrp(libc::STDIN_FILENO), libc::getpgrp()) };
    fg > 0 && fg != ours
}

/// `SUS_SOCKET` or the standard socket.
fn socket_path() -> PathBuf {
    env::var_os(names::ENV_SOCKET)
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| names::SOCKET.into())
}

/// The uid that must own the socket at `path` and run the service behind it:
/// root (strict), except for another socket used without root, which may
/// belong to the caller `euid` (test mode).
fn expected_owner(path: &Path, euid: u32) -> u32 {
    if path == Path::new(names::SOCKET) || euid == 0 {
        0
    } else {
        euid
    }
}

/// Trusts the socket only if it is a socket owned by `want` and the process
/// behind it runs as `want`.
fn connect(path: &Path, want: u32) -> Result<Conn, String> {
    let shown = path.display();
    let meta = fs::symlink_metadata(path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => format!("service not installed ({shown} does not exist)"),
        _ => format!("cannot check {shown}: {e}"),
    })?;
    if !meta.file_type().is_socket() {
        return Err(format!("{shown} is not a socket"));
    }
    if meta.uid() != want {
        return Err(format!(
            "{shown} is owned by uid {}, expected {want}",
            meta.uid()
        ));
    }
    let stream =
        UnixStream::connect(path).map_err(|e| format!("service not running ({shown}: {e})"))?;
    let (uid, _, _) = macos::peer(&stream).map_err(|e| format!("cannot check the service: {e}"))?;
    if uid != want {
        return Err(format!(
            "service at {shown} runs as uid {uid}, expected {want}"
        ));
    }
    Ok(Conn::new(stream))
}

/// `SSH_AUTH_SOCK`, else the Bitwarden agent in `$HOME` (apps have no `SSH_AUTH_SOCK`).
fn agent_socket() -> Result<PathBuf, String> {
    let set = |name| env::var_os(name).filter(|v: &OsString| !v.is_empty());
    if let Some(path) = set("SSH_AUTH_SOCK") {
        return Ok(path.into());
    }
    let home = set("HOME").ok_or("no SSH agent: neither SSH_AUTH_SOCK nor HOME is set")?;
    Ok(Path::new(&home).join(names::BITWARDEN_AGENT))
}

/// The first key the service offers (config order) that the agent also has.
fn first_shared_key<'a>(offered: &'a [PublicKey], agent: &[Identity]) -> Option<&'a PublicKey> {
    offered
        .iter()
        .find(|k| agent.iter().any(|i| <&KeyData>::from(i) == k.key_data()))
}

/// The agent answers a denied or timed-out approval with a bare SSH_AGENT_FAILURE.
fn sign_failure(e: &ssh_agent_client_rs::Error) -> String {
    match e {
        ssh_agent_client_rs::Error::RemoteFailure => {
            "SSH agent did not sign: approval denied or not given".into()
        }
        other => format!("SSH agent did not sign: {}", describe(other)),
    }
}

/// `e` with its source: the agent crate hides the io error behind it.
fn describe(e: &dyn Error) -> String {
    match e.source() {
        Some(s) => format!("{e}: {s}"),
        None => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey};

    fn key() -> PublicKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone()
    }

    #[test]
    fn refused_signature_reads_as_a_denied_approval() {
        let msg = sign_failure(&ssh_agent_client_rs::Error::RemoteFailure);
        assert_eq!(msg, "SSH agent did not sign: approval denied or not given");
    }

    #[test]
    fn first_shared_key_follows_the_service_order() {
        let (a, b, c) = (key(), key(), key());
        let offered = [a.clone(), b.clone()];
        let ids = |ks: &[&PublicKey]| -> Vec<Identity> {
            ks.iter().map(|k| Identity::from((*k).clone())).collect()
        };
        assert_eq!(first_shared_key(&offered, &ids(&[&b, &a])), Some(&a));
        assert_eq!(first_shared_key(&offered, &ids(&[&c, &b])), Some(&b));
        assert_eq!(first_shared_key(&offered, &ids(&[&c])), None);
        // the agent's comment does not matter
        let mut commented = b.clone();
        commented.set_comment("laptop");
        assert_eq!(first_shared_key(&offered, &ids(&[&commented])), Some(&b));
    }

    /// Set in the child process of `root_runs_the_command_in_place`.
    const AS_ROOT_CHILD: &str = "DIRECT_EXEC_CHILD";

    #[test]
    fn root_runs_the_command_in_place() {
        if env::var_os(AS_ROOT_CHILD).is_some() {
            // Replaces this test process; only reached if exec failed.
            run(vec!["sh".into(), "-c".into(), "exit 7".into()], 0);
            unreachable!("exec failed");
        }
        let status = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "client::tests::root_runs_the_command_in_place",
                "--quiet",
            ])
            .env(AS_ROOT_CHILD, "1")
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(7));
    }

    #[test]
    fn root_with_unknown_command_fails() {
        assert_eq!(run(vec!["no-such-command-xyz".into()], 0), 1);
    }

    #[test]
    fn empty_arguments_fail() {
        assert_eq!(run(vec![], 501), 1);
    }

    #[test]
    fn only_another_socket_without_root_may_belong_to_the_caller() {
        let standard = Path::new(names::SOCKET);
        let other = Path::new("other.sock");
        assert_eq!(expected_owner(standard, 501), 0);
        assert_eq!(expected_owner(other, 501), 501);
        assert_eq!(expected_owner(standard, 0), 0);
        assert_eq!(expected_owner(other, 0), 0);
    }

    /// A root-owned socket whose service runs as another uid (mDNSResponder
    /// runs as _mdnsresponder) passes the owner check but not the peer check.
    #[test]
    fn service_not_running_as_the_owner_is_refused() {
        let socket = Path::new(names::SOCKET).with_file_name("mDNSResponder");
        match fs::symlink_metadata(&socket) {
            Ok(m) if m.file_type().is_socket() && m.uid() == 0 => {}
            _ => return eprintln!("skipped: no root-owned {}", socket.display()),
        }
        let err = connect(&socket, 0).err().expect("connect must fail");
        assert!(err.contains("runs as uid"), "{err}");
        assert!(err.ends_with("expected 0"), "{err}");
    }
}
