//! The service: checks caller, config and signature, then runs the command.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::Read;
use std::os::fd::IntoRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixListener;
use std::os::unix::process::ExitStatusExt;
use std::panic::Location;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use ssh_key::{HashAlg, PublicKey};

use crate::command::{self, Peer};
use crate::config::{self, Config, Layout, Owner};
use crate::install;
use crate::macos;
use crate::names;
use crate::proto::{
    self, Call, Conn, Limits, MAX_FRAME, Nonce, ProtoError, ToClient, ToService, VERSION,
};

const BUSY: &str = "busy: too many pending requests";
/// Longest frame accepted while the command runs: a `Signal` is 5 bytes.
const MAX_SIGNAL_FRAME: usize = 16;

pub fn daemon_main(args: Vec<OsString>) -> i32 {
    match args.as_slice() {
        [cmd] if cmd == "serve" => match Mode::from_env() {
            Ok(mode) => {
                let limits = Limits::default();
                // Lives as long as the process; `serve` never returns.
                let running: &'static Running = Box::leak(Box::default());
                if let Err(e) = watch_sigterm(running, limits.sigterm_grace) {
                    eprintln!("{}: cannot watch SIGTERM: {e}", names::DAEMON);
                    return 1;
                }
                stop_on_panic(mode.test);
                serve(mode, limits, running)
            }
            Err(e) => {
                eprintln!("{}: {e}", names::DAEMON);
                1
            }
        },
        [cmd, rest @ ..] if cmd == "install" || cmd == "uninstall" => {
            // SAFETY: geteuid has no preconditions.
            if unsafe { libc::geteuid() } != 0 {
                eprintln!(
                    "{}: {} must run as root (use sudo)",
                    names::DAEMON,
                    cmd.to_string_lossy()
                );
                return 1;
            }
            let layout = Layout::system();
            let done = if cmd == "install" {
                install::install(rest, &layout)
            } else {
                install::uninstall(&layout)
            };
            match done {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("{}: {e}", names::DAEMON);
                    1
                }
            }
        }
        _ => {
            eprintln!(
                "usage: {0} serve | {0} install --key <file.pub> [--user <name>] | {0} uninstall",
                names::DAEMON
            );
            1
        }
    }
}

struct Mode {
    config: PathBuf,
    owner: Owner,
    listener: UnixListener,
    /// Test mode: audit entries are also written to stderr.
    test: bool,
}

impl Mode {
    /// Without root (test mode): `SUS_SOCKET` and `SUS_CONFIG`, a socket of its
    /// own, files owned by the caller, commands run as the caller.
    fn from_env() -> Result<Mode, String> {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            let listener = macos::launchd_listener(macos::LISTENER)
                .map_err(|e| format!("cannot get the launchd socket: {e}"))?;
            return Ok(Mode {
                config: Layout::system().config(),
                owner: Owner::Root,
                listener,
                test: false,
            });
        }
        let var = |name: &str| {
            std::env::var_os(name)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .ok_or_else(|| format!("{name} must be set when not running as root"))
        };
        let socket = var(names::ENV_SOCKET)?;
        let config = var(names::ENV_CONFIG)?;
        // Bound under a temporary name and linked into place once it listens:
        // the path never exists without a listener behind it (`bind` and
        // `listen` are two steps, and a connect in between is refused).
        let mut tmp = socket.clone().into_os_string();
        tmp.push(".new");
        let tmp = PathBuf::from(tmp);
        let listener = UnixListener::bind(&tmp)
            .and_then(|l| {
                let linked = std::fs::hard_link(&tmp, &socket);
                let _ = std::fs::remove_file(&tmp);
                linked.map(|()| l)
            })
            .map_err(|e| format!("cannot listen on {}: {e}", socket.display()))?;
        Ok(Mode {
            config,
            owner: Owner::Me,
            listener,
            test: true,
        })
    }
}

fn serve(mode: Mode, limits: Limits, running: &'static Running) -> ! {
    // Lives as long as the process; `serve` never returns.
    let slots: &'static Slots = Box::leak(Box::new(Slots::new(limits.pending)));
    loop {
        let stream = match mode.listener.accept() {
            Ok((s, _)) => s,
            Err(_) => {
                // Out of fds or similar: do not spin.
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        let accepted = Instant::now();
        // Not audited: without the uid there is nobody to name, and no reply can reach the client.
        let Ok((uid, gid, pid)) = macos::peer(&stream) else {
            continue;
        };
        let mut conn = Conn::new(stream);
        let config = match config::load(&mode.config, mode.owner) {
            Ok(c) => {
                for name in &c.unknown_users {
                    warn(
                        &format!(
                            "unknown user {name:?} in {} matches nobody",
                            mode.config.display()
                        ),
                        mode.test,
                    );
                }
                c
            }
            Err(e) => {
                deny(
                    &mut conn,
                    mode.test,
                    uid,
                    pid,
                    &[],
                    &format!("service config invalid: {e}"),
                );
                continue;
            }
        };
        let Some(user) = config.user(uid).map(|u| u.name.clone()) else {
            deny(
                &mut conn,
                mode.test,
                uid,
                pid,
                &[],
                &format!("uid {uid} is not allowed"),
            );
            continue;
        };
        let Some(slot) = slots.take() else {
            deny(&mut conn, mode.test, uid, pid, &[], BUSY);
            continue;
        };
        let peer = Peer {
            uid,
            gid,
            pid,
            user,
        };
        let test = mode.test;
        let deadline = accepted + limits.approval_window;
        dispatch(thread::Builder::new(), conn, test, uid, pid, move |conn| {
            handle(conn, peer, config, slot, deadline, running, test)
        });
    }
}

/// Runs `handler(conn)` on a thread from `builder`. When the OS refuses a
/// thread, the client is refused as busy (audited), like a full queue.
fn dispatch(
    builder: thread::Builder,
    conn: Conn,
    test: bool,
    uid: u32,
    pid: i32,
    handler: impl FnOnce(Conn) + Send + 'static,
) {
    // The connection waits here until the thread takes it, so it is still at
    // hand when no thread starts.
    let mine = Arc::new(Mutex::new(Some(conn)));
    let theirs = Arc::clone(&mine);
    let spawned = builder.spawn(move || {
        let conn = theirs.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(conn) = conn {
            handler(conn);
        }
    });
    if let Err(e) = spawned {
        warn(&format!("cannot start a thread for a request: {e}"), test);
        let conn = mine.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(mut conn) = conn {
            deny(&mut conn, test, uid, pid, &[], BUSY);
        }
    }
}

/// Places for requests that wait for their signature (AC8).
struct Slots {
    taken: AtomicUsize,
    max: usize,
}

/// One taken place; dropping it gives the place back.
struct Slot<'a>(&'a Slots);

impl Slots {
    fn new(max: usize) -> Slots {
        Slots {
            taken: AtomicUsize::new(0),
            max,
        }
    }

    fn take(&self) -> Option<Slot<'_>> {
        self.taken
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < self.max).then_some(n + 1)
            })
            .ok()
            .map(|_| Slot(self))
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.taken.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The started commands by call: process group and whether its leader still
/// lives. Keyed by call, not by pgid, so a signal for a finished call can never
/// reach a later command that got the same pid.
#[derive(Default)]
struct Running {
    calls: Mutex<Calls>,
    next: AtomicU64,
}

#[derive(Default)]
struct Calls {
    groups: HashMap<u64, (i32, bool)>,
    /// Set by the SIGTERM fan-out; from then on nothing starts.
    stopping: bool,
}

impl Running {
    fn lock(&self) -> std::sync::MutexGuard<'_, Calls> {
        // A panicking handler leaves the map consistent: every change is one insert or update.
        self.calls.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Starts the command and registers its group in one step, so a SIGTERM
    /// fan-out sees every group that exists. After the fan-out it refuses.
    /// `spawn` runs under the lock of every call: it should only fork and exec
    /// (see `command::prepare`).
    fn start(
        &self,
        spawn: impl FnOnce() -> Result<Child, String>,
    ) -> Result<RunningCall<'_>, String> {
        let mut calls = self.lock();
        if calls.stopping {
            return Err("service is stopping".into());
        }
        let child = spawn()?;
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        // With setsid the leader's pid is the group id.
        calls.groups.insert(id, (child.id() as i32, true));
        Ok(RunningCall {
            running: self,
            id,
            child,
        })
    }

    /// SIGHUP to every running group, and no new ones from now on.
    fn hang_up_all(&self) {
        let mut calls = self.lock();
        calls.stopping = true;
        for &(pgid, alive) in calls.groups.values() {
            if alive {
                hang_up(pgid);
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.lock().groups.is_empty()
    }
}

/// One started command, registered in `Running` until dropped. It keeps the
/// invariant that `killpg` reaches the group only while its leader is not
/// reaped: afterwards the pgid may belong to someone else.
struct RunningCall<'a> {
    running: &'a Running,
    id: u64,
    child: Child,
}

/// Signals one call's group from any thread; once its leader is reaped they
/// go nowhere.
#[derive(Clone, Copy)]
struct CallSignals<'a> {
    running: &'a Running,
    id: u64,
}

impl<'a> RunningCall<'a> {
    fn signals(&self) -> CallSignals<'a> {
        CallSignals {
            running: self.running,
            id: self.id,
        }
    }

    /// Waits for the leader without reaping it (`waitid` with `WNOWAIT`), marks
    /// it dead, then reaps. Until the mark its pid cannot be reused, so `killpg`
    /// never hits a group that is not ours. The call stays registered until the
    /// guard is dropped.
    ///
    /// macOS also reports a stopped child to `WEXITED` (`CLD_STOPPED`), again and
    /// again under `WNOWAIT`. Such a report is taken with `WSTOPPED`, which never
    /// reaps, and the wait goes on: a stopped command (Ctrl-Z) is not a finished one.
    fn wait(&mut self) -> ExitStatus {
        loop {
            // SAFETY: siginfo_t is plain data; all-zero is valid.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: waits for our own child; `info` is a live out pointer.
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id(),
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            if rc == 0
                && !matches!(
                    info.si_code,
                    libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
                )
            {
                // SAFETY: as above; WSTOPPED and WCONTINUED only take reports, never reap.
                unsafe {
                    libc::waitid(
                        libc::P_PID,
                        self.child.id(),
                        &mut info,
                        libc::WSTOPPED | libc::WCONTINUED | libc::WNOHANG,
                    )
                };
                continue;
            }
            if rc == 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                break;
            }
        }
        if let Some(entry) = self.running.lock().groups.get_mut(&self.id) {
            entry.1 = false;
        }
        self.child
            .wait()
            .unwrap_or_else(|_| ExitStatus::from_raw(1 << 8))
    }
}

impl Drop for RunningCall<'_> {
    fn drop(&mut self) {
        self.running.lock().groups.remove(&self.id);
    }
}

impl CallSignals<'_> {
    fn send(self, sig: i32) {
        if let Some(&(pgid, true)) = self.running.lock().groups.get(&self.id) {
            // SAFETY: plain syscall; the group exists while its leader is unreaped.
            unsafe { libc::killpg(pgid, sig) };
        }
    }

    fn hang_up(self) {
        if let Some(&(pgid, true)) = self.running.lock().groups.get(&self.id) {
            hang_up(pgid);
        }
    }
}

/// SIGHUP, then SIGCONT: a group the user stopped with Ctrl-Z would not see the
/// hang-up until continued (the kernel does the same for orphaned stopped groups).
/// Call under the `Running` lock, with the group's leader not yet reaped.
fn hang_up(pgid: i32) {
    // SAFETY: plain syscalls; the caller holds the lock that keeps the group ours.
    unsafe {
        libc::killpg(pgid, libc::SIGHUP);
        libc::killpg(pgid, libc::SIGCONT);
    }
}

/// Write end of the pipe the SIGTERM handler wakes the watcher with.
static SIGTERM_PIPE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn sigterm_handler(_: libc::c_int) {
    wake_sigterm_watcher();
}

/// Starts the SIGTERM shutdown. Async-signal-safe.
fn wake_sigterm_watcher() {
    let byte = 1u8;
    // SAFETY: write is async-signal-safe; the fd stays open for the process
    // lifetime (before `watch_sigterm` it is -1 and the write fails harmlessly).
    unsafe {
        libc::write(
            SIGTERM_PIPE.load(Ordering::Relaxed),
            (&byte as *const u8).cast(),
            1,
        )
    };
}

/// A panic is a bug, and the thread it ends may have been watching a command.
/// It is logged (launchd discards stderr), then the service stops as on
/// SIGTERM: groups hung up, exit, a clean service on the next call.
fn stop_on_panic(test: bool) {
    std::panic::set_hook(Box::new(move |info| {
        let line = panic_line(info.location(), info.payload_as_str());
        macos::log(subsystem(test), &line);
        if test {
            eprintln!("{}: {line}", names::DAEMON);
        }
        wake_sigterm_watcher();
    }));
}

/// One log entry for a panic: where, and the message masked and cut like an
/// audit reason.
fn panic_line(location: Option<&Location<'_>>, payload: Option<&str>) -> String {
    let at = location.map_or_else(|| "unknown location".into(), |l| l.to_string());
    let what = payload.unwrap_or("(no message)");
    format!(
        "panic at {}: \"{}\", stopping",
        masked_cut(&at),
        masked_cut(what)
    )
}

/// SIGTERM (from launchd) wakes a thread of its own: SIGHUP to every running
/// group, wait up to `grace` for them, exit 0. No SIGKILL, like sudo.
///
/// A handler rather than a blocked mask: commands inherit the mask, but a
/// caught signal is back to its default after exec.
fn watch_sigterm(running: &'static Running, grace: Duration) -> std::io::Result<()> {
    // Close-on-exec, so commands never hold it.
    let (mut wake, write) = std::io::pipe()?;
    SIGTERM_PIPE.store(write.into_raw_fd(), Ordering::Relaxed);
    // SAFETY: sigaction is plain data; the handler only calls write.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = sigterm_handler as *const () as libc::sighandler_t;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    thread::Builder::new().spawn(move || {
        let mut byte = [0u8];
        loop {
            match wake.read(&mut byte) {
                Ok(1) => on_sigterm(running, grace),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                _ => return,
            }
        }
    })?;
    Ok(())
}

fn on_sigterm(running: &Running, grace: Duration) -> ! {
    running.hang_up_all();
    let end = Instant::now() + grace;
    while !running.is_empty() && Instant::now() < end {
        thread::sleep(Duration::from_millis(20));
    }
    std::process::exit(0)
}

fn refuse(conn: &mut Conn, why: &str) {
    let _ = conn.send(&ToClient::Refused(why.into()), &[]);
}

/// One audit entry (AC13). Public fields only, never the signature.
struct Audit<'a> {
    uid: u32,
    pid: i32,
    argv: &'a [OsString],
    result: &'static str,
    reason: &'a str,
    /// The key that signed, once verified: which device or agent approved.
    key: Option<&'a PublicKey>,
    /// The working directory from the request, once there is one.
    cwd: Option<&'a Path>,
    /// The program `argv[0]` resolved to: what ran (or would have).
    command: Option<&'a Path>,
}

impl<'a> Audit<'a> {
    fn new(
        uid: u32,
        pid: i32,
        argv: &'a [OsString],
        result: &'static str,
        reason: &'a str,
    ) -> Self {
        Audit {
            uid,
            pid,
            argv,
            result,
            reason,
            key: None,
            cwd: None,
            command: None,
        }
    }
}

/// Bytes that are not printable ASCII become `\xNN`; `"` and `\` are escaped.
fn mask(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        match b {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(b as char);
            }
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

/// Cuts masked text into pieces of at most `max` (>= 4) bytes, never inside
/// an escape. Every `\` in masked text starts one: `\\`, `\"` or `\xNN`.
fn split_masked(s: &str, max: usize) -> Vec<&str> {
    let b = s.as_bytes();
    let mut pieces = Vec::new();
    let (mut start, mut i) = (0, 0);
    while i < b.len() {
        let len = match (b[i], b.get(i + 1)) {
            (b'\\', Some(b'x')) => 4,
            (b'\\', _) => 2,
            _ => 1,
        }
        .min(b.len() - i);
        if i + len - start > max {
            pieces.push(&s[start..i]);
            start = i;
        }
        i += len;
    }
    pieces.push(&s[start..]);
    pieces
}

/// The unified log silently cuts a message after about 1 KiB, so every entry
/// stays below this many bytes.
const MAX_ENTRY: usize = 1000;
/// Masked argv bytes per part, leaving room for `req=N part=I/K argv=`.
const ARGV_PART: usize = MAX_ENTRY - 100;
/// Masked reason bytes kept in the first entry; the rest becomes `...`.
/// The fixed fields and the key take about 260 bytes, cwd and command
/// `PATH_MAX_LOG` each: the entry stays below `MAX_ENTRY`.
const REASON_MAX: usize = 300;
/// Masked bytes kept of the cwd and of the command; a longer path keeps its
/// end, the most specific part, after `...`.
const PATH_MAX_LOG: usize = 160;

/// `text` masked and cut after `REASON_MAX` bytes, the rest becoming `...`.
fn masked_cut(text: &str) -> String {
    match split_masked(&mask(text.as_bytes()), REASON_MAX).as_slice() {
        [whole] => whole.to_string(),
        [head, ..] => format!("{head}..."),
        [] => String::new(),
    }
}

/// `path` masked; when longer than `PATH_MAX_LOG`, only its end after `...`,
/// never cut inside an escape.
fn masked_tail(path: &Path) -> String {
    let masked = mask(path.as_os_str().as_bytes());
    if masked.len() <= PATH_MAX_LOG {
        return masked;
    }
    // Escapes are at most 4 bytes, so pieces of 4 hold whole escapes.
    let pieces = split_masked(&masked, 4);
    let (mut start, mut len) = (pieces.len(), 0);
    while start > 0 && len + pieces[start - 1].len() <= PATH_MAX_LOG - 3 {
        start -= 1;
        len += pieces[start].len();
    }
    format!("...{}", pieces[start..].concat())
}

/// The entries of one request (AC13): first the fixed fields with argc, the
/// length and SHA-256 of the argv joined with NUL, then the masked argv in
/// `parts` numbered entries, each tagged with `req`.
fn audit_lines(a: &Audit, req: u64) -> Vec<String> {
    let raw = a
        .argv
        .iter()
        .map(|arg| arg.as_bytes())
        .collect::<Vec<_>>()
        .join(&0u8);
    let hash: String = Sha256::digest(&raw)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let argv: Vec<String> = a
        .argv
        .iter()
        .map(|arg| format!("\"{}\"", mask(arg.as_bytes())))
        .collect();
    let argv = format!("[{}]", argv.join(" "));
    let parts = split_masked(&argv, ARGV_PART);
    let reason = masked_cut(a.reason);
    let mut known = String::new();
    if let Some(k) = a.key {
        known.push_str(&format!(" key={}", k.fingerprint(HashAlg::Sha256)));
    }
    if let Some(cwd) = a.cwd {
        known.push_str(&format!(" cwd=\"{}\"", masked_tail(cwd)));
    }
    if let Some(command) = a.command {
        known.push_str(&format!(" command=\"{}\"", masked_tail(command)));
    }
    let mut lines = vec![format!(
        "req={req} uid={} pid={} result={} reason=\"{reason}\"{known} argc={} argv_bytes={} \
         argv_sha256={hash} parts={}",
        a.uid,
        a.pid,
        a.result,
        a.argv.len(),
        raw.len(),
        parts.len()
    )];
    let k = parts.len();
    for (i, part) in parts.iter().enumerate() {
        lines.push(format!("req={req} part={}/{k} argv={part}", i + 1));
    }
    lines
}

/// Numbers the requests of this process, so a request's entries can be found.
static REQUESTS: AtomicU64 = AtomicU64::new(0);

/// The installed service logs under its label; the test mode under its own
/// subsystem, so `cargo test` never shows up in the real audit.
fn subsystem(test: bool) -> &'static str {
    if test { names::LOG_TEST } else { names::LABEL }
}

/// Every audit entry of this test binary, for the unit tests to read.
#[cfg(test)]
static AUDITED: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Unified log; in test mode also stderr, which the tests can read.
fn audit(a: &Audit, test: bool) {
    let req = REQUESTS.fetch_add(1, Ordering::Relaxed) + 1;
    for line in audit_lines(a, req) {
        macos::log(subsystem(test), &line);
        if test {
            eprintln!("{}: audit {line}", names::DAEMON);
        }
        #[cfg(test)]
        AUDITED.lock().unwrap_or_else(|e| e.into_inner()).push(line);
    }
}

/// A problem worth seeing that refuses nothing: unified log, and stderr in test mode.
fn warn(text: &str, test: bool) {
    let line = format!("warning: {text}");
    macos::log(subsystem(test), &line);
    if test {
        eprintln!("{}: {line}", names::DAEMON);
    }
}

/// Audits the refusal, then tells the client.
fn deny(conn: &mut Conn, test: bool, uid: u32, pid: i32, argv: &[OsString], why: &str) {
    audit(&Audit::new(uid, pid, argv, "denied", why), test);
    refuse(conn, why);
}

/// One approved caller: nonce and keys out, signed request in, command run, exit code out.
fn handle(
    mut conn: Conn,
    peer: Peer,
    config: Config,
    slot: Slot<'static>,
    deadline: Instant,
    running: &'static Running,
    test: bool,
) {
    let deny = |conn: &mut Conn, argv: &[OsString], why: &str| {
        deny(conn, test, peer.uid, peer.pid, argv, why)
    };
    // The client is gone, so there is nobody to refuse; only the entry is left.
    let abandon = |why: &str| audit(&Audit::new(peer.uid, peer.pid, &[], "abandoned", why), test);
    let mut nonce: Nonce = [0; 32];
    if let Err(e) = getrandom::fill(&mut nonce) {
        deny(&mut conn, &[], &format!("no randomness: {e}"));
        return;
    }
    // `serve` let only a listed uid through; its keys alone may sign, and only they
    // are shown to it.
    let keys = config
        .user(peer.uid)
        .map(|u| u.keys.clone())
        .unwrap_or_default();
    let hello = ToClient::Hello {
        version: VERSION,
        nonce,
        keys: keys.clone(),
    };
    if conn.send(&hello, &[]).is_err() {
        abandon("client left before the nonce");
        return;
    }
    let (request, fds) = match conn.recv_deadline::<ToService>(MAX_FRAME, deadline) {
        Ok(r) => r,
        // No request arrived and nobody is left to answer. A peer that is
        // already gone can also fail `set_read_timeout` (EINVAL).
        Err(ProtoError::Closed | ProtoError::Io(_)) => {
            abandon("client left before the request");
            return;
        }
        Err(e) => {
            deny(&mut conn, &[], &e.to_string());
            return;
        }
    };
    let ToService::Request {
        cwd,
        argv,
        env,
        umask,
        signature,
        ..
    } = request
    else {
        deny(&mut conn, &[], &ProtoError::Malformed.to_string());
        return;
    };
    let Ok(fds) = <[OwnedFd; 3]>::try_from(fds) else {
        deny(&mut conn, &argv, "expected stdin, stdout and stderr");
        return;
    };
    // The uid comes from the socket, never from the client.
    let call = Call {
        uid: peer.uid,
        cwd,
        argv,
    };
    let argv = &call.argv;
    // From here on every entry says where, and, once known, with which key and what.
    let audit_at = |result, reason: &str, key: Option<&PublicKey>, command: Option<&Path>| {
        let entry = Audit {
            key,
            cwd: Some(&call.cwd),
            command,
            ..Audit::new(peer.uid, peer.pid, argv, result, reason)
        };
        audit(&entry, test);
    };
    let deny_at = |conn: &mut Conn, key, command, why: &str| {
        audit_at("denied", why, key, command);
        refuse(conn, why);
    };
    let verified = proto::verify(&keys, &call.message(&nonce), &signature);
    // The place is free once the signature is checked, whatever the outcome.
    drop(slot);
    let key = match verified {
        Ok(k) => k,
        Err(e) => {
            deny_at(&mut conn, None, None, e);
            return;
        }
    };
    let signals = match conn.try_clone() {
        Ok(c) => c,
        Err(e) => {
            deny_at(&mut conn, Some(key), None, &e.to_string());
            return;
        }
    };
    // Lookups first: they can block, and `running.start` holds the lock of every call.
    let prepared = match command::prepare(&call, &peer, &config.secure_path, &env, umask, fds) {
        Ok(p) => p,
        Err(e) => {
            deny_at(&mut conn, Some(key), None, &e);
            return;
        }
    };
    let program = prepared.program().to_path_buf();
    let mut running_call = match running.start(|| prepared.spawn()) {
        Ok(c) => c,
        Err(e) => {
            deny_at(&mut conn, Some(key), Some(&program), &e);
            return;
        }
    };
    audit_at("allowed", "", Some(key), Some(&program));
    supervise(
        thread::Builder::new(),
        signals,
        running_call.signals(),
        test,
    );
    let status = running_call.wait();
    // Sent before the call is dropped: a SIGTERM fan-out waits for it.
    let _ = conn.send(&ToClient::Exit(command::exit_code(status)), &[]);
}

/// Forwards the client's signals on a thread from `builder`. Without a
/// thread nobody would notice the client leave (AC3), so when the OS refuses
/// one the command is hung up at once.
fn supervise(builder: thread::Builder, conn: Conn, group: CallSignals<'static>, test: bool) {
    if let Err(e) = builder.spawn(move || forward_signals(conn, group)) {
        group.hang_up();
        warn(
            &format!("cannot start a thread to forward signals, command hung up: {e}"),
            test,
        );
    }
}

/// Signals from the client go to the command's group; a lost connection
/// hangs it up (AC3). Ends when the client closes, after or before the exit.
fn forward_signals(mut conn: Conn, group: CallSignals) {
    loop {
        match conn.recv::<ToService>(MAX_SIGNAL_FRAME) {
            Ok((ToService::Signal(n), _)) if proto::relayed(n) => group.send(n),
            Ok(_) => {}
            Err(_) => {
                group.hang_up();
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_logs_apart_from_the_service() {
        assert_eq!(subsystem(false), names::LABEL);
        assert_eq!(subsystem(true), names::LOG_TEST);
        assert_ne!(names::LOG_TEST, names::LABEL);
    }
    use std::ffi::{CStr, OsStr};
    use std::fs::File;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::Command;

    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey, SigningKey};

    /// The service in a thread of this test, on a temp socket, with `limits`.
    struct TestService {
        dir: tempfile::TempDir,
        key: PrivateKey,
    }

    fn me() -> String {
        // SAFETY: getpwuid returns static data or null; read at once.
        unsafe {
            let pw = libc::getpwuid(libc::geteuid());
            assert!(!pw.is_null());
            CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned()
        }
    }

    impl TestService {
        fn start(limits: Limits) -> TestService {
            TestService::start_for(&me(), limits)
        }

        /// Allows only `user`.
        fn start_for(user: &str, limits: Limits) -> TestService {
            TestService::start_with(user, limits, Box::leak(Box::default()))
        }

        /// Allows only `user`; the started commands go to `running`.
        fn start_with(user: &str, limits: Limits, running: &'static Running) -> TestService {
            let dir = tempfile::tempdir().unwrap();
            let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
            let config = dir.path().join("config.toml");
            let line = key.public_key().to_openssh().unwrap();
            std::fs::write(&config, format!("[users]\n{user:?} = [{line:?}]\n")).unwrap();
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
            let listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
            let mode = Mode {
                config,
                owner: Owner::Me,
                listener,
                test: true,
            };
            thread::spawn(move || serve(mode, limits, running));
            TestService { dir, key }
        }

        fn connect(&self) -> Conn {
            Conn::new(UnixStream::connect(self.dir.path().join("s.sock")).unwrap())
        }

        /// Connects and expects the nonce.
        fn hello(&self) -> (Conn, Nonce) {
            let mut conn = self.connect();
            match conn.recv::<ToClient>(MAX_FRAME).unwrap().0 {
                ToClient::Hello { nonce, .. } => (conn, nonce),
                other => panic!("expected hello, got {other:?}"),
            }
        }

        fn request(&self, conn: &mut Conn, nonce: &Nonce, argv: &[&str], stdin: OwnedFd) {
            self.request_in(conn, nonce, self.dir.path(), argv, stdin);
        }

        fn request_in(
            &self,
            conn: &mut Conn,
            nonce: &Nonce,
            cwd: &Path,
            argv: &[&str],
            stdin: OwnedFd,
        ) {
            let null = File::create("/dev/null").unwrap();
            let argv = argv.iter().map(OsString::from).collect();
            let fds = [stdin.as_fd(), null.as_fd(), null.as_fd()];
            self.send_signed(conn, nonce, cwd, argv, vec![], &fds);
        }

        /// Sends `argv` in `cwd` with `env`, signed for `nonce` as the client
        /// signs it, with `fds`: any number, as a hostile client could.
        fn send_signed(
            &self,
            conn: &mut Conn,
            nonce: &Nonce,
            cwd: &Path,
            argv: Vec<OsString>,
            env: Vec<(OsString, OsString)>,
            fds: &[BorrowedFd<'_>],
        ) {
            let call = Call {
                // SAFETY: geteuid has no preconditions.
                uid: unsafe { libc::geteuid() },
                cwd: cwd.to_path_buf(),
                argv,
            };
            let signature = sign(&self.key, &call.message(nonce));
            let request = ToService::Request {
                version: VERSION,
                cwd: call.cwd,
                argv: call.argv,
                env,
                umask: 0o022,
                signature,
            };
            if fds.len() <= 3 {
                conn.send(&request, fds).unwrap();
            } else {
                let raw: Vec<_> = fds.iter().map(|fd| fd.as_raw_fd()).collect();
                conn.send_raw(&request, &raw);
            }
        }
    }

    fn sign(key: &PrivateKey, msg: &[u8]) -> Vec<u8> {
        fn agent<S: SigningKey>(key: &S, data: &[u8]) -> ssh_key::Result<ssh_key::Signature> {
            key.try_sign(data).map_err(|_| ssh_key::Error::Crypto)
        }
        proto::sign(key.public_key(), msg, |_, d| agent(key, d)).unwrap()
    }

    fn limits(pending: usize, approval_window: Duration) -> Limits {
        Limits {
            pending,
            approval_window,
            ..Limits::default()
        }
    }

    fn reply(conn: &mut Conn) -> ToClient {
        conn.recv::<ToClient>(MAX_FRAME).unwrap().0
    }

    /// The service notices a closed client asynchronously; retry until a place is free.
    fn hello_soon(s: &TestService) -> (Conn, Nonce) {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let mut conn = s.connect();
            match conn.recv::<ToClient>(MAX_FRAME).unwrap().0 {
                ToClient::Hello { nonce, .. } => return (conn, nonce),
                ToClient::Refused(why) if why == BUSY && Instant::now() < end => {
                    thread::sleep(Duration::from_millis(20))
                }
                other => panic!("expected hello, got {other:?}"),
            }
        }
    }

    fn entry<'a>(argv: &'a [OsString], reason: &'a str) -> Audit<'a> {
        Audit::new(501, 42, argv, "denied", reason)
    }

    #[test]
    fn long_argv_is_split_into_entries_under_the_log_limit() {
        // /bin/sh -c "true <1100 x>\xff; echo HIDDENTAIL"
        let mut script = b"true ".to_vec();
        script.extend(std::iter::repeat_n(b'x', 1100));
        script.extend(b"\xff\"; echo HIDDENTAIL");
        let argv: Vec<OsString> = [&b"/bin/sh"[..], b"-c", &script]
            .iter()
            .map(|a| OsStr::from_bytes(a).to_os_string())
            .collect();
        let lines = audit_lines(&entry(&argv, "r"), 7);
        assert!(lines.len() >= 3, "{lines:?}");
        for line in &lines {
            assert!(line.len() < MAX_ENTRY, "{} bytes: {line}", line.len());
            assert!(line.bytes().all(|b| (0x20..0x7f).contains(&b)), "{line}");
        }
        let raw_len = 7 + 1 + 2 + 1 + script.len();
        let k = lines.len() - 1;
        let head = &lines[0];
        assert!(
            head.starts_with(&format!(
                "req=7 uid=501 pid=42 result=denied reason=\"r\" argc=3 argv_bytes={raw_len} \
                 argv_sha256="
            )),
            "{head}"
        );
        assert!(head.ends_with(&format!(" parts={k}")), "{head}");
        assert!(!head.contains("/bin/sh"), "{head}");
        let mut joined = String::new();
        for (i, line) in lines[1..].iter().enumerate() {
            let prefix = format!("req=7 part={}/{k} argv=", i + 1);
            joined.push_str(line.strip_prefix(&prefix).expect(line));
        }
        let masked = format!(
            "[\"/bin/sh\" \"-c\" \"true {}\\xff\\\"; echo HIDDENTAIL\"]",
            "x".repeat(1100)
        );
        assert_eq!(joined, masked);
        assert!(lines.last().unwrap().contains("HIDDENTAIL"));
    }

    #[test]
    fn hash_covers_the_raw_argv_joined_with_nul() {
        let argv = [OsString::from("a"), OsString::from("b")];
        let lines = audit_lines(&entry(&argv, ""), 1);
        assert_eq!(
            lines,
            [
                "req=1 uid=501 pid=42 result=denied reason=\"\" argc=2 argv_bytes=3 \
                 argv_sha256=59b271ae1bbcb1d31d41929817f4b16fb439eb4f31520b5ad1d5ce98920a7138 \
                 parts=1",
                r#"req=1 part=1/1 argv=["a" "b"]"#,
            ]
        );
    }

    #[test]
    fn no_argv_still_has_one_part() {
        let lines = audit_lines(&entry(&[], "timed out"), 2);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("argc=0 argv_bytes=0 "), "{}", lines[0]);
        assert_eq!(lines[1], "req=2 part=1/1 argv=[]");
    }

    #[test]
    fn split_never_cuts_an_escape() {
        let masked = mask(&[0xff; 300]);
        for max in 4..=12 {
            let pieces = split_masked(&masked, max);
            assert_eq!(pieces.concat(), masked);
            for p in &pieces {
                assert!(p.len() <= max && p.len() % 4 == 0 && !p.is_empty(), "{p}");
            }
        }
        let masked = mask(b"\\x\"");
        assert_eq!(split_masked(&masked, 4), [r"\\x", r#"\""#]);
    }

    #[test]
    fn first_entry_fits_with_every_field_at_its_longest() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let reason = "\u{1}".repeat(2000);
        // MAXPATHLEN bytes that each mask to 4, ending in a readable name.
        let mut long = vec![0x01u8; 1000];
        long.extend(b"/the-end");
        let long = PathBuf::from(OsString::from_vec(long));
        let argv = vec![OsString::from("x"); 65_536];
        let entry = Audit {
            key: Some(key.public_key()),
            cwd: Some(&long),
            command: Some(&long),
            ..Audit::new(u32::MAX, i32::MIN, &argv, "abandoned", &reason)
        };
        let head = &audit_lines(&entry, u64::MAX)[0];
        assert!(head.len() < MAX_ENTRY, "{} bytes: {head}", head.len());
        // The end of a long path stays, the start goes.
        assert!(head.contains(r#" cwd="...\x01\x01"#), "{head}");
        assert!(head.contains(r#"/the-end" command="..."#), "{head}");
        assert!(head.bytes().all(|b| (0x20..0x7f).contains(&b)), "{head}");
    }

    #[test]
    fn short_paths_are_logged_whole() {
        let cwd = Path::new("/Users/a b/\"q\"");
        let entry = Audit {
            cwd: Some(cwd),
            command: Some(Path::new("/bin/echo")),
            ..Audit::new(501, 42, &[], "allowed", "")
        };
        let head = &audit_lines(&entry, 1)[0];
        assert!(
            head.contains(r#"reason="" cwd="/Users/a b/\"q\"" command="/bin/echo" argc=0 "#),
            "{head}"
        );
    }

    #[test]
    fn long_reason_is_cut_to_fit_the_first_entry() {
        let reason = format!("{}: command not found", "\u{1}".repeat(2000));
        let lines = audit_lines(&entry(&[], &reason), 3);
        assert!(lines[0].len() < MAX_ENTRY, "{}", lines[0].len());
        assert!(lines[0].contains(r#"\x01..." argc=0"#), "{}", lines[0]);
    }

    #[test]
    fn fifth_pending_request_is_busy() {
        let s = TestService::start(Limits::default());
        let _pending: Vec<_> = (0..4).map(|_| s.hello()).collect();
        let mut fifth = s.connect();
        assert_eq!(reply(&mut fifth), ToClient::Refused(BUSY.into()));
    }

    #[test]
    fn caller_not_in_users_is_refused_even_when_no_place_is_free() {
        let s = TestService::start_for("nobody", limits(0, Duration::from_secs(30)));
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        assert_eq!(
            reply(&mut s.connect()),
            ToClient::Refused(format!("uid {uid} is not allowed"))
        );
    }

    #[test]
    fn approval_window_frees_the_place() {
        let s = TestService::start(limits(1, Duration::from_millis(300)));
        let (mut slow, _) = s.hello();
        assert_eq!(reply(&mut s.connect()), ToClient::Refused(BUSY.into()));
        assert_eq!(reply(&mut slow), ToClient::Refused("timed out".into()));
        hello_soon(&s);
    }

    #[test]
    fn bad_signature_or_closing_frees_the_place() {
        let s = TestService::start(limits(1, Duration::from_secs(30)));
        let (mut conn, _) = s.hello();
        // Signed for another nonce.
        let (r, _w) = std::io::pipe().unwrap();
        s.request(&mut conn, &[7; 32], &["true"], r.into());
        assert_eq!(
            reply(&mut conn),
            ToClient::Refused("signature not accepted".into())
        );
        let (conn, _) = hello_soon(&s);
        drop(conn);
        hello_soon(&s);
    }

    /// Keys belong to their user: the caller is shown only its own, and another
    /// user's key in the config does not sign for it.
    #[test]
    fn another_users_key_does_not_sign_for_the_caller() {
        let mut s = TestService::start(Limits::default());
        let mut roots = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mine = s.key.public_key().to_openssh().unwrap();
        let root_line = roots.public_key().to_openssh().unwrap();
        // Read again for every connection.
        std::fs::write(
            s.dir.path().join("config.toml"),
            format!("[users]\n{:?} = [{mine:?}]\nroot = [{root_line:?}]\n", me()),
        )
        .unwrap();
        let mut conn = s.connect();
        let nonce = match reply(&mut conn) {
            ToClient::Hello { nonce, keys, .. } => {
                assert_eq!(keys.len(), 1);
                assert!(keys[0].key_data() == s.key.public_key().key_data());
                nonce
            }
            other => panic!("expected hello, got {other:?}"),
        };
        // Sign with root's key, as a client holding it could.
        std::mem::swap(&mut s.key, &mut roots);
        let marker = s.dir.path().join("as-root");
        let marker = marker.to_str().unwrap();
        let (r, _w) = std::io::pipe().unwrap();
        s.request(&mut conn, &nonce, &["/usr/bin/touch", marker], r.into());
        assert_eq!(
            reply(&mut conn),
            ToClient::Refused("signature not accepted".into())
        );
        assert!(!Path::new(marker).exists());
    }

    #[test]
    fn each_connection_gets_a_fresh_nonce_and_a_replay_is_denied() {
        let s = TestService::start(Limits::default());
        let (_first, nonce1) = s.hello();
        let (mut second, nonce2) = s.hello();
        assert_ne!(nonce1, [0; 32]);
        assert_ne!(nonce2, [0; 32]);
        assert_ne!(nonce1, nonce2);

        // Signed for the first connection, sent on the second.
        let marker = s.dir.path().join("replayed");
        let marker = marker.to_str().unwrap();
        let (r, _w) = std::io::pipe().unwrap();
        s.request(&mut second, &nonce1, &["/usr/bin/touch", marker], r.into());
        assert_eq!(
            reply(&mut second),
            ToClient::Refused("signature not accepted".into())
        );
        assert!(!Path::new(marker).exists(), "the replayed command ran");

        // Audited before the refusal is sent (A2).
        let audited = AUDITED.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let argv = format!("argv=[\"/usr/bin/touch\" \"{marker}\"]");
        let parts: Vec<_> = audited.iter().filter(|l| l.ends_with(&argv)).collect();
        assert_eq!(parts.len(), 1, "{audited:?}");
        let req = parts[0].split_once(' ').unwrap().0;
        let head = audited
            .iter()
            .find(|l| l.starts_with(&format!("{req} uid=")))
            .expect(req);
        assert!(
            head.contains("result=denied reason=\"signature not accepted\""),
            "{head}"
        );
    }

    #[test]
    fn running_commands_hold_no_place() {
        let s = TestService::start(limits(1, Duration::from_secs(30)));
        let (mut conn, nonce) = s.hello();
        // `cat` runs until its stdin closes.
        let (r, w) = std::io::pipe().unwrap();
        s.request(&mut conn, &nonce, &["cat"], r.into());
        let (other, _) = hello_soon(&s);
        drop(other);
        drop(w);
        assert_eq!(reply(&mut conn), ToClient::Exit(0));
    }

    #[test]
    fn lookup_errors_are_denied_without_waiting_for_running_calls() {
        let running: &'static Running = Box::leak(Box::default());
        let s = TestService::start_with(&me(), Limits::default(), running);
        // Held as by another call that is starting: the cwd check and the
        // command lookup must not wait for it.
        let held = running.lock();
        let gone = s.dir.path().join("gone");
        let cases = [
            (
                s.dir.path(),
                "no-such-cmd",
                "no-such-cmd: command not found".into(),
            ),
            (
                gone.as_path(),
                "true",
                format!("{}: working directory not available: ", gone.display()),
            ),
        ];
        for (cwd, cmd, want) in cases {
            let (mut conn, nonce) = s.hello();
            let (r, _w) = std::io::pipe().unwrap();
            s.request_in(&mut conn, &nonce, cwd, &[cmd], r.into());
            // Read in a thread: a read timeout on a socket the service already
            // closed fails with EINVAL.
            let (tx, rx) = std::sync::mpsc::channel();
            thread::spawn(move || tx.send(reply(&mut conn)));
            match rx.recv_timeout(Duration::from_secs(5)) {
                Ok(ToClient::Refused(why)) => assert!(why.starts_with(&want), "{why}"),
                Ok(other) => panic!("expected a refusal, got {other:?}"),
                Err(e) => panic!("no refusal while a call held the lock: {e}"),
            }
        }
        assert!(held.groups.is_empty() && !held.stopping);
        drop(held);
        assert!(running.is_empty());
    }

    #[test]
    fn leader_is_alive_until_waited_for_and_dead_after() {
        let running = Running::default();
        let mut call = running
            .start(|| {
                Command::new("sh")
                    .args(["-c", "exit 3"])
                    .spawn()
                    .map_err(|e| e.to_string())
            })
            .unwrap();
        let id = call.id;
        assert!(running.lock().groups[&id].1, "alive before the wait");
        let status = call.wait();
        assert_eq!(status.code(), Some(3));
        assert!(!running.lock().groups[&id].1, "dead once reaped");
        drop(call);
        assert!(running.is_empty());
    }

    #[test]
    fn signals_reach_the_group_only_until_the_leader_is_reaped() {
        let running = Running::default();
        let mut call = running
            .start(|| {
                // A group of its own, as `setsid` gives the real commands.
                Command::new("sleep")
                    .arg("30")
                    .process_group(0)
                    .spawn()
                    .map_err(|e| e.to_string())
            })
            .unwrap();
        // Kept like the forwarding thread keeps it, beyond the call.
        let group = call.signals();
        group.send(libc::SIGTERM);
        let status = call.wait();
        assert_eq!(status.signal(), Some(libc::SIGTERM));
        drop(call);
        // The call is gone: no entry, so nothing is sent anywhere.
        group.send(libc::SIGTERM);
        assert!(running.is_empty());
    }

    /// A builder whose threads never start: no stack that large fits.
    fn no_thread() -> thread::Builder {
        thread::Builder::new().stack_size(1 << 60)
    }

    #[test]
    fn no_thread_for_a_request_is_busy_and_audited() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut client = Conn::new(a);
        dispatch(no_thread(), Conn::new(b), true, 501, 424242, |_| {
            panic!("handler ran without a thread")
        });
        assert_eq!(reply(&mut client), ToClient::Refused(BUSY.into()));
        let audited = AUDITED.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let want = format!("uid=501 pid=424242 result=denied reason=\"{BUSY}\" argc=0 ");
        assert!(audited.iter().any(|l| l.contains(&want)), "{audited:?}");
    }

    #[test]
    fn no_thread_to_forward_signals_hangs_the_command_up() {
        let running: &'static Running = Box::leak(Box::default());
        let mut call = running
            .start(|| {
                Command::new("sleep")
                    .arg("30")
                    .process_group(0)
                    .spawn()
                    .map_err(|e| e.to_string())
            })
            .unwrap();
        let (a, _b) = UnixStream::pair().unwrap();
        supervise(no_thread(), Conn::new(a), call.signals(), true);
        assert_eq!(call.wait().signal(), Some(libc::SIGHUP));
    }

    #[test]
    fn panic_line_names_the_place_and_the_masked_message() {
        let here = Location::caller();
        assert_eq!(
            panic_line(Some(here), Some("bad\nframe \"x\"")),
            format!("panic at {here}: \"bad\\x0aframe \\\"x\\\"\", stopping")
        );
        assert_eq!(
            panic_line(None, None),
            "panic at unknown location: \"(no message)\", stopping"
        );
        let long = panic_line(None, Some(&"\u{1}".repeat(2000)));
        assert!(long.len() < MAX_ENTRY, "{}", long.len());
        assert!(long.ends_with("\\x01...\", stopping"), "{long}");
    }

    /// The reply, or a test failure after 5 s.
    fn reply_soon(mut conn: Conn) -> ToClient {
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || tx.send(reply(&mut conn)));
        rx.recv_timeout(Duration::from_secs(5))
            .expect("no reply within 5 s")
    }

    /// The first audit line of every request so far whose argv is `argv`.
    fn audited_heads(argv: &[OsString]) -> Vec<String> {
        let all = AUDITED.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let masked: Vec<_> = argv
            .iter()
            .map(|a| format!("\"{}\"", mask(a.as_bytes())))
            .collect();
        let part = format!(" part=1/1 argv=[{}]", masked.join(" "));
        all.iter()
            .filter_map(|l| l.strip_suffix(&part))
            .filter_map(|req| all.iter().find(|l| l.starts_with(&format!("{req} uid="))))
            .cloned()
            .collect()
    }

    /// The service still runs the next client's command.
    fn still_serves(s: &TestService) {
        let (mut conn, nonce) = hello_soon(s);
        let null = File::open("/dev/null").unwrap();
        s.request(&mut conn, &nonce, &["true"], null.into());
        assert_eq!(reply_soon(conn), ToClient::Exit(0));
    }

    /// Lets `send` play a hostile client on a fresh connection. Expects a
    /// refusal, exactly one new audit entry for it (denied, `argv` as the
    /// service read it, nothing allowed), and a service that still serves.
    /// Returns the reason.
    fn refused_once(
        s: &TestService,
        argv: &[OsString],
        send: impl FnOnce(&mut Conn, &Nonce),
    ) -> String {
        let before = audited_heads(argv);
        let (mut conn, nonce) = hello_soon(s);
        send(&mut conn, &nonce);
        let why = match reply_soon(conn) {
            ToClient::Refused(why) => why,
            other => panic!("expected a refusal for {argv:?}, got {other:?}"),
        };
        let new: Vec<_> = audited_heads(argv)
            .into_iter()
            .filter(|h| !before.contains(h))
            .collect();
        let reason = format!(" result=denied reason=\"{}\" ", masked_cut(&why));
        assert_eq!(
            new.iter().filter(|h| h.contains(&reason)).count(),
            1,
            "{new:?}"
        );
        assert!(!new.iter().any(|h| h.contains("result=allowed")), "{new:?}");
        still_serves(s);
        why
    }

    /// sudo-tests F2: stdin, stdout and stderr or nothing. A Signal before
    /// the Request is no request either.
    #[test]
    fn wrong_fd_count_or_early_signal_is_refused_and_runs_nothing() {
        let s = TestService::start(Limits::default());
        let marker = s.dir.path().join("ran");
        let argv = vec![OsString::from("/usr/bin/touch"), marker.clone().into()];
        let null = File::open("/dev/null").unwrap();
        for n in [0, 2, 4] {
            let fds = vec![null.as_fd(); n];
            // Four fds fail at the first byte, before the argv is read.
            let (read, want) = if n > 3 {
                (&[][..], "malformed message")
            } else {
                (&argv[..], "expected stdin, stdout and stderr")
            };
            let why = refused_once(&s, read, |conn, nonce| {
                s.send_signed(conn, nonce, s.dir.path(), argv.clone(), vec![], &fds)
            });
            assert_eq!(why, want, "{n} fds");
            assert!(!marker.exists(), "ran with {n} fds");
        }
        let why = refused_once(&s, &[], |conn, _| {
            conn.send(&ToService::Signal(libc::SIGTERM), &[]).unwrap()
        });
        assert_eq!(why, "malformed message");
    }

    /// sudo-tests M2, X5: what was signed either runs exactly or not at all.
    /// std refuses NUL bytes instead of cutting at them, and a relative cwd
    /// would name the service's directory, not the caller's.
    #[test]
    fn nul_bytes_empty_commands_and_relative_cwd_run_nothing() {
        let s = TestService::start(Limits::default());
        let dir = s.dir.path();
        let marker = dir.join("ran");
        let os = |b: &[u8]| OsString::from_vec(b.to_vec());
        let touch = || vec![os(b"/usr/bin/touch"), marker.clone().into()];
        let mut nul_marker = marker.clone().into_os_string();
        nul_marker.push("\0x");
        let mut nul_cwd = dir.as_os_str().to_owned();
        nul_cwd.push("\0x");
        let none: Vec<(OsString, OsString)> = vec![];
        let cases = [
            (
                dir.into(),
                vec![os(b"touch\0x"), marker.clone().into()],
                none.clone(),
                "command not found",
            ),
            (
                dir.into(),
                vec![os(b"/usr/bin/touch"), nul_marker],
                none.clone(),
                "nul byte",
            ),
            (
                PathBuf::from(nul_cwd),
                touch(),
                none.clone(),
                "working directory not available",
            ),
            (
                dir.into(),
                touch(),
                vec![(os(b"LANG"), os(b"C\0x"))],
                "nul byte",
            ),
            (
                dir.into(),
                touch(),
                vec![(os(b"LC_\0X"), os(b"C"))],
                "nul byte",
            ),
            (
                PathBuf::from("."),
                touch(),
                none.clone(),
                "not an absolute path",
            ),
            (
                PathBuf::from("tmp"),
                touch(),
                none.clone(),
                "not an absolute path",
            ),
            (
                dir.into(),
                vec![os(b""), marker.clone().into()],
                none.clone(),
                "empty command",
            ),
            (dir.into(), vec![], none, "empty command"),
        ];
        let null = File::open("/dev/null").unwrap();
        let fds = [null.as_fd(), null.as_fd(), null.as_fd()];
        for (cwd, argv, env, want) in cases {
            let why = refused_once(&s, &argv, |conn, nonce| {
                s.send_signed(conn, nonce, &cwd, argv.clone(), env.clone(), &fds)
            });
            assert!(
                why.contains(want),
                "{argv:?} in {cwd:?} with {env:?}: {why}"
            );
            assert!(!marker.exists(), "{argv:?} in {cwd:?} with {env:?} ran");
        }
    }

    /// sudo-tests E6: whatever the client sends, the command sees each name
    /// once, and PATH is secure_path.
    #[test]
    fn odd_env_reaches_the_command_once_per_name() {
        let s = TestService::start(Limits::default());
        let env: Vec<_> = [
            ("PATH", "/evil"),
            ("PATH", "/evil2"),
            ("LANG", "C"),
            ("LANG", "D"),
            ("LC_X=PATH", "/evil"),
            ("LC_ALL=x", "C"),
            ("LC_ALL", "C"),
            ("TERM=PATH", "x"),
        ]
        .into_iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect();
        let (mut conn, nonce) = s.hello();
        let null = File::open("/dev/null").unwrap();
        let (mut out, w) = std::io::pipe().unwrap();
        let fds = [null.as_fd(), w.as_fd(), null.as_fd()];
        let argv = vec![OsString::from("/usr/bin/env")];
        s.send_signed(&mut conn, &nonce, s.dir.path(), argv, env, &fds);
        drop(w);
        assert_eq!(reply_soon(conn), ToClient::Exit(0));
        let mut got = String::new();
        out.read_to_string(&mut got).unwrap();
        let names: Vec<_> = got.lines().map(|l| l.split('=').next().unwrap()).collect();
        for name in &names {
            assert_eq!(names.iter().filter(|n| *n == name).count(), 1, "{got}");
        }
        let lines: Vec<_> = got.lines().collect();
        let path = format!("PATH={}", config::DEFAULT_SECURE_PATH);
        for want in [path.as_str(), "LANG=C", "LC_ALL=C"] {
            assert!(lines.contains(&want), "{want} missing: {got}");
        }
    }

    /// sudo-tests S6: signal numbers outside the forwarded and job-control
    /// ones go nowhere.
    #[test]
    fn signals_outside_forwarded_are_ignored() {
        for n in proto::FORWARDED.into_iter().chain(proto::JOB_CONTROL) {
            assert!(proto::relayed(n), "{n}");
        }
        let s = TestService::start(Limits::default());
        let (mut conn, nonce) = s.hello();
        let null = File::open("/dev/null").unwrap();
        s.request(&mut conn, &nonce, &["sleep", "30"], null.into());
        for n in [libc::SIGKILL, libc::SIGUSR1, libc::SIGTSTP, 0, -1, 9999] {
            assert!(!proto::relayed(n), "{n}");
            conn.send(&ToService::Signal(n), &[]).unwrap();
        }
        // Frames are handled in order: the command is still unharmed when this one comes.
        conn.send(&ToService::Signal(libc::SIGTERM), &[]).unwrap();
        assert_eq!(reply_soon(conn), ToClient::Exit(128 + libc::SIGTERM));
    }

    #[test]
    fn nothing_starts_after_the_hang_up() {
        let running = Running::default();
        running.hang_up_all();
        let started = running.start(|| panic!("spawned while stopping"));
        assert_eq!(started.err().as_deref(), Some("service is stopping"));
        assert!(running.is_empty());
    }
}
