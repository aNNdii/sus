//! The wire contract and the signature scheme, shared by client and daemon.
//!
//! Everything both sides must agree on lives here: the protocol version, the
//! signed message, the SSHSIG namespace and hash, the size limits, the frames,
//! fd passing, the forwarded signals and the env filter.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ssh_key::{HashAlg, LineEnding, PublicKey, Signature, SshSig};

use crate::names;

pub(crate) const VERSION: u32 = 1;
/// argv + cwd bytes (macOS ARG_MAX).
pub(crate) const MAX_REQUEST: usize = 1 << 20;
pub(crate) const MAX_ARGS: usize = 65_536;
pub(crate) const MAX_SIG: usize = 8 * 1024;
/// Request plus signature plus room for env and framing.
pub(crate) const MAX_FRAME: usize = MAX_REQUEST + MAX_SIG + 64 * 1024;
pub(crate) const FORWARDED: [i32; 5] = [
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGWINCH,
];
/// Job control: the client stops the command when the user suspends it (Ctrl-Z)
/// and continues it when the job is back in the foreground, like sudo without a pty.
/// The command runs in a session of its own, so the terminal cannot do this itself.
pub(crate) const JOB_CONTROL: [i32; 2] = [libc::SIGSTOP, libc::SIGCONT];
pub(crate) type Nonce = [u8; 32];

/// Whether the service passes signal `n` from the client to the command.
pub(crate) fn relayed(n: i32) -> bool {
    FORWARDED.contains(&n) || JOB_CONTROL.contains(&n)
}

/// Hash inside SSHSIG; the agent only ever sees this digest wrapped in SSHSIG.
const HASH: HashAlg = HashAlg::Sha512;
/// Leading bytes of every signed message, so it cannot be mistaken for anything else.
const MAGIC: &[u8] = b"CALL";
/// Stdin, stdout, stderr.
const MAX_FDS: usize = 3;
const TOO_LONG: &str = "argument list too long";

pub(crate) struct Limits {
    pub pending: usize,
    pub approval_window: Duration,
    pub sigterm_grace: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            pending: 4,
            approval_window: Duration::from_secs(30),
            sigterm_grace: Duration::from_secs(5),
        }
    }
}

/// Whether the command may inherit this variable from the caller: only terminal and locale
/// names (sudo `env_reset`), and only with a value that is no path, no format string and no
/// bash function (sudo `env_check`). A name with `=` never passes: `LC_ALL=x` with value `C`
/// would reach the command as a second `LC_ALL`.
fn passes_env(name: &OsStr, value: &OsStr) -> bool {
    let name = name.as_bytes();
    let value = value.as_bytes();
    (matches!(name, b"TERM" | b"COLORTERM" | b"LANG") || name.starts_with(b"LC_"))
        && !name.contains(&b'=')
        && !value.iter().any(|b| matches!(b, b'/' | b'%'))
        && !value.starts_with(b"()")
}

/// The caller's variables the command inherits, by `passes_env`. For a name given more
/// than once only the first value counts, as `getenv` sees it; if that one fails the check
/// the name is dropped. Client and daemon both filter with this.
pub(crate) fn filter_env(
    vars: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    let mut seen = std::collections::HashSet::new();
    vars.into_iter()
        .filter(|(k, v)| seen.insert(k.clone()) && passes_env(k, v))
        .collect()
}

pub(crate) fn passed_env_now() -> Vec<(OsString, OsString)> {
    filter_env(std::env::vars_os())
}

/// One invocation: exactly what gets signed besides version and nonce.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Call {
    pub uid: u32,
    pub cwd: PathBuf,
    pub argv: Vec<OsString>,
}

impl Call {
    pub fn check_size(&self) -> Result<(), &'static str> {
        check_size(&self.cwd, &self.argv)
    }

    /// magic | VERSION | nonce | uid | lp(cwd) | argc | lp(arg)*, all u32 big endian, raw bytes.
    pub fn message(&self, nonce: &Nonce) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        put_u32(&mut out, VERSION);
        out.extend_from_slice(nonce);
        put_u32(&mut out, self.uid);
        put_bytes(&mut out, self.cwd.as_os_str().as_bytes());
        put_len(&mut out, self.argv.len());
        for arg in &self.argv {
            put_bytes(&mut out, arg.as_bytes());
        }
        out
    }
}

fn check_size(cwd: &Path, argv: &[OsString]) -> Result<(), &'static str> {
    if argv.len() > MAX_ARGS {
        return Err(TOO_LONG);
    }
    let bytes = argv
        .iter()
        .map(|a| a.len())
        .fold(cwd.as_os_str().len(), usize::saturating_add);
    if bytes > MAX_REQUEST {
        return Err(TOO_LONG);
    }
    Ok(())
}

#[derive(Debug, PartialEq)]
pub(crate) enum ToClient {
    Hello {
        version: u32,
        nonce: Nonce,
        keys: Vec<PublicKey>,
    },
    Refused(String),
    Exit(i32),
}

#[derive(Debug, PartialEq)]
pub(crate) enum ToService {
    Request {
        version: u32,
        cwd: PathBuf,
        argv: Vec<OsString>,
        env: Vec<(OsString, OsString)>,
        /// The caller's umask. Not signed: the service only ever tightens with it.
        umask: u32,
        signature: Vec<u8>,
    },
    Signal(i32),
}

#[derive(Debug)]
pub(crate) enum ProtoError {
    Mismatch,
    TooLarge,
    Closed,
    Timeout,
    Malformed,
    Io(io::Error),
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtoError::Mismatch => f.write_str("client and service don't match"),
            ProtoError::TooLarge => f.write_str("message too large"),
            ProtoError::Closed => f.write_str("connection closed"),
            ProtoError::Timeout => f.write_str("timed out"),
            ProtoError::Malformed => f.write_str("malformed message"),
            ProtoError::Io(e) => e.fmt(f),
        }
    }
}

/// A message on the wire: `[u32 length][tag][fields]`.
pub(crate) trait Frame: Sized {
    fn encode(&self) -> Vec<u8>;
    fn decode(b: &[u8]) -> Result<Self, ProtoError>;
}

const HELLO: u8 = 1;
const REFUSED: u8 = 2;
const EXIT: u8 = 3;
const REQUEST: u8 = 1;
const SIGNAL: u8 = 2;

impl Frame for ToClient {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            ToClient::Hello {
                version,
                nonce,
                keys,
            } => {
                out.push(HELLO);
                put_u32(&mut out, *version);
                out.extend_from_slice(nonce);
                put_len(&mut out, keys.len());
                for key in keys {
                    // Encoding a parsed key cannot fail.
                    put_bytes(&mut out, &key.to_bytes().expect("public key encodes"));
                }
            }
            ToClient::Refused(text) => {
                out.push(REFUSED);
                put_bytes(&mut out, text.as_bytes());
            }
            ToClient::Exit(code) => {
                out.push(EXIT);
                put_u32(&mut out, *code as u32);
            }
        }
        out
    }

    fn decode(b: &[u8]) -> Result<Self, ProtoError> {
        let mut r = Reader(b);
        let frame = match r.u8()? {
            HELLO => {
                let version = r.version()?;
                let nonce = r.take(32)?.try_into().map_err(|_| ProtoError::Malformed)?;
                let mut keys = Vec::new();
                for _ in 0..r.u32()? {
                    let key =
                        PublicKey::from_bytes(r.bytes()?).map_err(|_| ProtoError::Malformed)?;
                    keys.push(key);
                }
                ToClient::Hello {
                    version,
                    nonce,
                    keys,
                }
            }
            REFUSED => {
                let text =
                    String::from_utf8(r.bytes()?.to_vec()).map_err(|_| ProtoError::Malformed)?;
                ToClient::Refused(text)
            }
            EXIT => ToClient::Exit(r.u32()? as i32),
            _ => return Err(ProtoError::Malformed),
        };
        r.finish(frame)
    }
}

impl Frame for ToService {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            ToService::Request {
                version,
                cwd,
                argv,
                env,
                umask,
                signature,
            } => {
                out.push(REQUEST);
                put_u32(&mut out, *version);
                put_bytes(&mut out, cwd.as_os_str().as_bytes());
                put_len(&mut out, argv.len());
                for arg in argv {
                    put_bytes(&mut out, arg.as_bytes());
                }
                put_len(&mut out, env.len());
                for (k, v) in env {
                    put_bytes(&mut out, k.as_bytes());
                    put_bytes(&mut out, v.as_bytes());
                }
                put_u32(&mut out, *umask);
                put_bytes(&mut out, signature);
            }
            ToService::Signal(n) => {
                out.push(SIGNAL);
                put_u32(&mut out, *n as u32);
            }
        }
        out
    }

    fn decode(b: &[u8]) -> Result<Self, ProtoError> {
        let mut r = Reader(b);
        let frame = match r.u8()? {
            REQUEST => {
                let version = r.version()?;
                let cwd = PathBuf::from(r.os_string()?);
                let argc = r.u32()? as usize;
                if argc > MAX_ARGS {
                    return Err(ProtoError::TooLarge);
                }
                let mut argv = Vec::new();
                for _ in 0..argc {
                    argv.push(r.os_string()?);
                }
                check_size(&cwd, &argv).map_err(|_| ProtoError::TooLarge)?;
                let mut env = Vec::new();
                for _ in 0..r.u32()? {
                    env.push((r.os_string()?, r.os_string()?));
                }
                let umask = r.u32()?;
                let signature = r.bytes()?;
                if signature.len() > MAX_SIG {
                    return Err(ProtoError::TooLarge);
                }
                ToService::Request {
                    version,
                    cwd,
                    argv,
                    env,
                    umask,
                    signature: signature.to_vec(),
                }
            }
            SIGNAL => ToService::Signal(r.u32()? as i32),
            _ => return Err(ProtoError::Malformed),
        };
        r.finish(frame)
    }
}

fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_be_bytes());
}

/// Lengths beyond u32 never pass the size checks; saturate instead of wrapping.
fn put_len(out: &mut Vec<u8>, n: usize) {
    put_u32(out, u32::try_from(n).unwrap_or(u32::MAX));
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_len(out, b.len());
    out.extend_from_slice(b);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        if n > self.0.len() {
            return Err(ProtoError::Malformed);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, ProtoError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, ProtoError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// The version comes first, so another version is reported before its fields are parsed.
    fn version(&mut self) -> Result<u32, ProtoError> {
        match self.u32()? {
            VERSION => Ok(VERSION),
            _ => Err(ProtoError::Mismatch),
        }
    }

    fn bytes(&mut self) -> Result<&'a [u8], ProtoError> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    fn os_string(&mut self) -> Result<OsString, ProtoError> {
        Ok(OsString::from_vec(self.bytes()?.to_vec()))
    }

    fn finish<T>(self, value: T) -> Result<T, ProtoError> {
        if self.0.is_empty() {
            Ok(value)
        } else {
            Err(ProtoError::Malformed)
        }
    }
}

/// A connection between client and daemon. `recv` is the only reader, so
/// fds sent with a frame always arrive with that frame.
pub(crate) struct Conn(UnixStream);

impl Conn {
    pub fn new(s: UnixStream) -> Self {
        // A closed peer must give EPIPE, not kill the process.
        let on: libc::c_int = 1;
        // SAFETY: valid socket fd and a c_int option value of the right size.
        unsafe {
            libc::setsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&on as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        Conn(s)
    }

    pub fn try_clone(&self) -> io::Result<Conn> {
        Ok(Conn(self.0.try_clone()?))
    }

    /// Sends one frame; `fds` travel with its first byte (SCM_RIGHTS).
    pub fn send<F: Frame>(&mut self, f: &F, fds: &[BorrowedFd<'_>]) -> Result<(), ProtoError> {
        if fds.len() > MAX_FDS {
            return Err(ProtoError::TooLarge);
        }
        let payload = f.encode();
        let mut buf = Vec::with_capacity(4 + payload.len());
        put_len(&mut buf, payload.len());
        buf.extend_from_slice(&payload);
        send_all(self.0.as_raw_fd(), &buf, fds)
    }

    pub fn recv<F: Frame>(&mut self, max: usize) -> Result<(F, Vec<OwnedFd>), ProtoError> {
        self.recv_until(max, None)
    }

    pub fn recv_deadline<F: Frame>(
        &mut self,
        max: usize,
        deadline: Instant,
    ) -> Result<(F, Vec<OwnedFd>), ProtoError> {
        let result = self.recv_until(max, Some(deadline));
        self.0.set_read_timeout(None).map_err(ProtoError::Io)?;
        result
    }

    fn recv_until<F: Frame>(
        &mut self,
        max: usize,
        deadline: Option<Instant>,
    ) -> Result<(F, Vec<OwnedFd>), ProtoError> {
        let mut fds = Vec::new();
        let mut header = [0u8; 4];
        self.read_exact(&mut header, &mut fds, deadline)?;
        let len = u32::from_be_bytes(header) as usize;
        if len > max {
            return Err(ProtoError::TooLarge);
        }
        let mut payload = vec![0u8; len];
        self.read_exact(&mut payload, &mut fds, deadline)?;
        Ok((F::decode(&payload)?, fds))
    }

    fn read_exact(
        &self,
        mut buf: &mut [u8],
        fds: &mut Vec<OwnedFd>,
        deadline: Option<Instant>,
    ) -> Result<(), ProtoError> {
        while !buf.is_empty() {
            if let Some(deadline) = deadline {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(ProtoError::Timeout);
                }
                self.0
                    .set_read_timeout(Some(left))
                    .map_err(ProtoError::Io)?;
            }
            let n = recv_some(self.0.as_raw_fd(), buf, fds)?;
            buf = &mut buf[n..];
        }
        Ok(())
    }
}

#[cfg(test)]
impl Conn {
    /// Sends one frame with `fds` in a single `SCM_RIGHTS` message, past the
    /// `MAX_FDS` check in `send`, as a hostile peer could.
    pub(crate) fn send_raw(&self, f: &impl Frame, fds: &[RawFd]) {
        // macOS refuses more than 254 fds per message.
        assert!(fds.len() <= 254);
        let payload = f.encode();
        let mut bytes = Vec::new();
        put_len(&mut bytes, payload.len());
        bytes.extend_from_slice(&payload);
        let data_len = std::mem::size_of_val(fds) as u32;
        let mut control = [0u64; 256];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        // SAFETY: msghdr is plain data; all-zero is a valid empty value.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        // SAFETY: `control` (2 KiB) is larger than CMSG_SPACE of 254 fds
        // (1028 bytes), so the header and fd writes stay inside it.
        unsafe {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(data_len);
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(data_len);
            let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
            for (i, fd) in fds.iter().enumerate() {
                data.add(i).write_unaligned(*fd);
            }
        }
        // SAFETY: msg points to live buffers for the duration of the call.
        let n = unsafe { libc::sendmsg(self.0.as_raw_fd(), &msg, 0) };
        assert_eq!(n, bytes.len() as isize, "{}", io::Error::last_os_error());
    }
}

/// Room for MAX_FDS descriptors, aligned for `cmsghdr`.
type ControlBuf = [u64; 8];

/// Control buffer for `recvmsg`, aligned for `cmsghdr`. macOS accepts one
/// `SCM_RIGHTS` message of at most 254 fds per `sendmsg` (`CMSG_SPACE` 1028
/// bytes), and one `recvmsg` returns the control data of one `sendmsg` only.
/// The kernel installs every fd sent even when it truncates the control
/// data, so the buffer must hold them all for `take_fds` to close the excess.
#[repr(C, align(8))]
struct RecvControl([u8; 2048]);

fn send_all(sock: RawFd, mut buf: &[u8], fds: &[BorrowedFd<'_>]) -> Result<(), ProtoError> {
    let mut control: ControlBuf = [0; 8];
    let mut fds_pending = !fds.is_empty();
    while !buf.is_empty() {
        let mut iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        // SAFETY: msghdr is plain data; all-zero is a valid empty value.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if fds_pending {
            let data_len = (fds.len() * std::mem::size_of::<RawFd>()) as u32;
            // SAFETY: `fds.len() <= MAX_FDS` (checked in `Conn::send`), so
            // CMSG_SPACE fits `control`; CMSG_FIRSTHDR and CMSG_DATA point
            // inside it, and the header and fd writes (unaligned for the
            // fds) stay within those CMSG_SPACE bytes.
            unsafe {
                msg.msg_control = control.as_mut_ptr().cast();
                msg.msg_controllen = libc::CMSG_SPACE(data_len);
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(data_len);
                let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
                for (i, fd) in fds.iter().enumerate() {
                    data.add(i).write_unaligned(fd.as_raw_fd());
                }
            }
        }
        // SAFETY: msg points to live buffers for the duration of the call.
        let n = unsafe { libc::sendmsg(sock, &msg, 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::BrokenPipe => return Err(ProtoError::Closed),
                _ => return Err(ProtoError::Io(e)),
            }
        }
        fds_pending = false;
        buf = &buf[n as usize..];
    }
    Ok(())
}

/// One `recvmsg`. Received fds are owned (and close-on-exec) at once, so
/// they close on every error path.
fn recv_some(sock: RawFd, buf: &mut [u8], fds: &mut Vec<OwnedFd>) -> Result<usize, ProtoError> {
    loop {
        let mut control = RecvControl([0; 2048]);
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: msghdr is plain data; all-zero is a valid empty value.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.0.as_mut_ptr().cast();
        msg.msg_controllen = control.0.len() as _;
        // SAFETY: msg points to live buffers for the duration of the call.
        let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                    return Err(ProtoError::Timeout);
                }
                io::ErrorKind::ConnectionReset => return Err(ProtoError::Closed),
                _ => return Err(ProtoError::Io(e)),
            }
        }
        let filled = (msg.msg_controllen as usize).min(control.0.len());
        // Own every fd first so the excess closes on the error below.
        let well_formed = take_fds(&control.0[..filled], fds);
        if !well_formed || msg.msg_flags & libc::MSG_CTRUNC != 0 || fds.len() > MAX_FDS {
            return Err(ProtoError::Malformed);
        }
        if n == 0 {
            return Err(ProtoError::Closed);
        }
        return Ok(n as usize);
    }
}

/// Takes ownership of every fd in the `SCM_RIGHTS` messages of `control`,
/// the bytes `recvmsg` filled in, and marks them close-on-exec. Never reads
/// past `control`, whatever a `cmsg_len` claims. Returns false if the control
/// data is malformed or cut short; the fds found up to there are still taken.
fn take_fds(control: &[u8], fds: &mut Vec<OwnedFd>) -> bool {
    // SAFETY: CMSG_LEN only computes a size.
    let header = unsafe { libc::CMSG_LEN(0) } as usize;
    let mut rest = control;
    let mut ok = true;
    while !rest.is_empty() {
        if rest.len() < header {
            return false;
        }
        // SAFETY: `rest` holds at least CMSG_LEN(0) >= size_of::<cmsghdr>()
        // bytes, and read_unaligned needs no alignment.
        let cmsg = unsafe { rest.as_ptr().cast::<libc::cmsghdr>().read_unaligned() };
        let len = cmsg.cmsg_len as usize;
        if len < header {
            return false;
        }
        if cmsg.cmsg_level == libc::SOL_SOCKET && cmsg.cmsg_type == libc::SCM_RIGHTS {
            let data = &rest[header..len.min(rest.len())];
            for raw in data.as_chunks::<{ std::mem::size_of::<RawFd>() }>().0 {
                let fd = RawFd::from_ne_bytes(*raw);
                if fd < 0 {
                    ok = false;
                    continue;
                }
                // SAFETY: `fd` lies within the control data, so the kernel
                // just installed it in this process for us; nothing else owns it.
                let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                // Tiny window: macOS has no MSG_CMSG_CLOEXEC, so a concurrent
                // fork+exec between recvmsg and here inherits fd.
                // SAFETY: fcntl on an fd we own.
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
                fds.push(fd);
            }
        }
        if len > rest.len() {
            return false;
        }
        // SAFETY: CMSG_SPACE only computes a size.
        let space = unsafe { libc::CMSG_SPACE((len - header) as u32) } as usize;
        // The last message may lack its trailing padding.
        rest = rest.get(space..).unwrap_or_default();
    }
    ok
}

/// Signs `msg` as SSHSIG in the tool's namespace. `agent` signs the SSHSIG
/// blob with `key`; the result is the SSHSIG in PEM form.
pub(crate) fn sign<E>(
    key: &PublicKey,
    msg: &[u8],
    agent: impl FnOnce(&PublicKey, &[u8]) -> Result<Signature, E>,
) -> Result<Vec<u8>, E> {
    // Only fail on an empty namespace or an unencodable signature; neither can happen here.
    let data = SshSig::signed_data(names::NAMESPACE, HASH, msg).expect("namespace is set");
    let signature = agent(key, &data)?;
    let sshsig = SshSig::new(key.key_data().clone(), names::NAMESPACE, HASH, signature)
        .expect("namespace is set");
    Ok(sshsig
        .to_pem(LineEnding::LF)
        .expect("signature encodes")
        .into_bytes())
}

/// Accepts `sshsig` only if one of `allowed` made it over `msg` in the tool's namespace.
/// The allowed key that made `sshsig` over `msg`, or why not.
pub(crate) fn verify<'a>(
    allowed: &'a [PublicKey],
    msg: &[u8],
    sshsig: &[u8],
) -> Result<&'a PublicKey, &'static str> {
    const REJECTED: &str = "signature not accepted";
    if sshsig.len() > MAX_SIG {
        return Err(REJECTED);
    }
    let sig = SshSig::from_pem(sshsig).map_err(|_| REJECTED)?;
    let key = allowed
        .iter()
        .find(|k| k.key_data() == sig.public_key())
        .ok_or(REJECTED)?;
    key.verify(names::NAMESPACE, msg, &sig)
        .map(|()| key)
        .map_err(|_| REJECTED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey, SigningKey};
    use std::io::{Read, Write};
    use std::os::fd::AsFd;

    fn throwaway_key() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
    }

    /// Plays the agent: signs the blob it is given, nothing else.
    fn agent<S: SigningKey>(
        key: &S,
    ) -> impl FnOnce(&PublicKey, &[u8]) -> Result<Signature, ()> + '_ {
        move |_, data| key.try_sign(data).map_err(|_| ())
    }

    fn call() -> Call {
        Call {
            uid: 501,
            cwd: PathBuf::from("/Users/me/work"),
            argv: vec!["id".into(), OsString::from_vec(vec![b'-', 0xff, b'u'])],
        }
    }

    fn signed(key: &PrivateKey, call: &Call, nonce: &Nonce) -> Vec<u8> {
        sign(key.public_key(), &call.message(nonce), agent(key)).unwrap()
    }

    #[test]
    fn message_is_length_prefixed_raw_bytes() {
        let call = Call {
            uid: 7,
            cwd: PathBuf::from("/d"),
            argv: vec!["a".into(), OsString::from_vec(vec![0xff, 0])],
        };
        let mut want = b"CALL".to_vec();
        want.extend_from_slice(&[0, 0, 0, 1]);
        want.extend_from_slice(&[9; 32]);
        want.extend_from_slice(&[0, 0, 0, 7]);
        want.extend_from_slice(&[0, 0, 0, 2, b'/', b'd']);
        want.extend_from_slice(&[0, 0, 0, 2]);
        want.extend_from_slice(&[0, 0, 0, 1, b'a']);
        want.extend_from_slice(&[0, 0, 0, 2, 0xff, 0]);
        assert_eq!(call.message(&[9; 32]), want);
    }

    #[test]
    fn argument_boundaries_are_part_of_the_message() {
        let mut a = call();
        let mut b = call();
        a.argv = vec!["ab".into(), "c".into()];
        b.argv = vec!["a".into(), "bc".into()];
        assert_ne!(a.message(&[0; 32]), b.message(&[0; 32]));
    }

    #[test]
    fn signature_for_the_call_is_accepted() {
        let key = throwaway_key();
        let nonce = [1; 32];
        let sig = signed(&key, &call(), &nonce);
        let allowed = [
            throwaway_key().public_key().clone(),
            key.public_key().clone(),
        ];
        // Returns the key that signed, not the first allowed one.
        assert_eq!(
            verify(&allowed, &call().message(&nonce), &sig),
            Ok(&allowed[1])
        );
    }

    #[test]
    fn signature_with_another_nonce_is_rejected() {
        let key = throwaway_key();
        let sig = signed(&key, &call(), &[1; 32]);
        let msg = call().message(&[2; 32]);
        assert!(verify(&[key.public_key().clone()], &msg, &sig).is_err());
    }

    #[test]
    fn signature_for_another_call_is_rejected() {
        let key = throwaway_key();
        let nonce = [1; 32];
        let sig = signed(&key, &call(), &nonce);
        let allowed = [key.public_key().clone()];
        let mut other = call();
        other.uid = 0;
        assert!(verify(&allowed, &other.message(&nonce), &sig).is_err());
        let mut other = call();
        other.cwd = PathBuf::from("/");
        assert!(verify(&allowed, &other.message(&nonce), &sig).is_err());
        let mut other = call();
        other.argv.push("-g".into());
        assert!(verify(&allowed, &other.message(&nonce), &sig).is_err());
    }

    #[test]
    fn signature_in_a_foreign_namespace_is_rejected() {
        let key = throwaway_key();
        let msg = call().message(&[1; 32]);
        let foreign = key.sign("git", HashAlg::Sha512, &msg).unwrap();
        let pem = foreign.to_pem(LineEnding::LF).unwrap();
        assert!(verify(&[key.public_key().clone()], &msg, pem.as_bytes()).is_err());
    }

    #[test]
    fn signature_by_a_foreign_key_is_rejected() {
        let key = throwaway_key();
        let msg = call().message(&[1; 32]);
        let sig = signed(&key, &call(), &[1; 32]);
        assert!(verify(&[throwaway_key().public_key().clone()], &msg, &sig).is_err());
    }

    #[test]
    fn signature_claiming_an_allowed_key_but_made_by_another_is_rejected() {
        let allowed = throwaway_key();
        let thief = throwaway_key();
        let msg = call().message(&[1; 32]);
        let sig = sign(allowed.public_key(), &msg, agent(&thief)).unwrap();
        assert!(verify(&[allowed.public_key().clone()], &msg, &sig).is_err());
    }

    #[test]
    fn oversized_or_garbage_signature_is_rejected() {
        let key = throwaway_key();
        let msg = call().message(&[1; 32]);
        let mut sig = signed(&key, &call(), &[1; 32]);
        assert!(verify(&[key.public_key().clone()], &msg, b"nonsense").is_err());
        sig.resize(MAX_SIG + 1, b'\n');
        assert!(verify(&[key.public_key().clone()], &msg, &sig).is_err());
    }

    #[test]
    fn size_limits() {
        let mut c = call();
        c.cwd = PathBuf::from("/");
        c.argv = vec![OsString::from_vec(vec![b'x'; MAX_REQUEST - 1])];
        assert_eq!(c.check_size(), Ok(()));
        c.argv[0].push("x");
        assert_eq!(c.check_size(), Err("argument list too long"));

        c.argv = vec![OsString::new(); MAX_ARGS];
        assert_eq!(c.check_size(), Ok(()));
        c.argv.push(OsString::new());
        assert_eq!(c.check_size(), Err("argument list too long"));
    }

    fn request(argv: Vec<OsString>, signature: Vec<u8>) -> ToService {
        ToService::Request {
            version: VERSION,
            cwd: PathBuf::from("/tmp/x"),
            argv,
            env: vec![("LANG".into(), OsString::from_vec(vec![0xfe]))],
            umask: 0o027,
            signature,
        }
    }

    #[test]
    fn frames_round_trip() {
        let key = throwaway_key();
        let hello = ToClient::Hello {
            version: VERSION,
            nonce: [5; 32],
            keys: vec![key.public_key().clone()],
        };
        let back = ToClient::decode(&hello.encode()).unwrap();
        let ToClient::Hello { keys, nonce, .. } = back else {
            panic!()
        };
        assert_eq!(nonce, [5; 32]);
        assert_eq!(keys[0].key_data(), key.public_key().key_data());
        for f in [
            ToClient::Refused("busy".into()),
            ToClient::Exit(-1),
            ToClient::Exit(143),
        ] {
            assert_eq!(ToClient::decode(&f.encode()).unwrap(), f);
        }
        let req = request(vec!["a".into(), OsString::from_vec(vec![0xff])], vec![1, 2]);
        assert_eq!(ToService::decode(&req.encode()).unwrap(), req);
        let sig = ToService::Signal(libc::SIGINT);
        assert_eq!(ToService::decode(&sig.encode()).unwrap(), sig);
    }

    #[test]
    fn trailing_or_truncated_frames_are_malformed() {
        let mut b = ToClient::Exit(1).encode();
        b.push(0);
        assert!(matches!(ToClient::decode(&b), Err(ProtoError::Malformed)));
        let b = request(vec!["a".into()], vec![]).encode();
        assert!(matches!(
            ToService::decode(&b[..b.len() - 1]),
            Err(ProtoError::Malformed)
        ));
        assert!(matches!(
            ToService::decode(&[9]),
            Err(ProtoError::Malformed)
        ));
    }

    #[test]
    fn other_version_reports_mismatch() {
        let mut b = request(vec!["a".into()], vec![]).encode();
        b[1..5].copy_from_slice(&2u32.to_be_bytes());
        let err = ToService::decode(&b).unwrap_err();
        assert!(matches!(err, ProtoError::Mismatch));
        assert_eq!(err.to_string(), "client and service don't match");
        let mut b = ToClient::Hello {
            version: VERSION,
            nonce: [0; 32],
            keys: vec![],
        }
        .encode();
        b[1..5].copy_from_slice(&0u32.to_be_bytes());
        assert!(matches!(ToClient::decode(&b), Err(ProtoError::Mismatch)));
    }

    #[test]
    fn oversized_request_fields_are_rejected_on_decode() {
        let big_sig = request(vec!["a".into()], vec![0; MAX_SIG + 1]).encode();
        assert!(matches!(
            ToService::decode(&big_sig),
            Err(ProtoError::TooLarge)
        ));
        let big_argv = request(vec![OsString::from_vec(vec![b'x'; MAX_REQUEST])], vec![]).encode();
        assert!(matches!(
            ToService::decode(&big_argv),
            Err(ProtoError::TooLarge)
        ));
        let many = request(vec![OsString::new(); MAX_ARGS + 1], vec![]).encode();
        assert!(matches!(
            ToService::decode(&many),
            Err(ProtoError::TooLarge)
        ));
    }

    fn pair() -> (Conn, Conn) {
        let (a, b) = UnixStream::pair().unwrap();
        (Conn::new(a), Conn::new(b))
    }

    #[test]
    fn fds_arrive_with_their_frame() {
        let (mut client, mut service) = pair();
        let (mut r0, w0) = std::io::pipe().unwrap();
        let (mut r1, w1) = std::io::pipe().unwrap();
        let (mut r2, w2) = std::io::pipe().unwrap();
        // A frame without fds first: the fds must not arrive with it.
        client.send(&ToService::Signal(1), &[]).unwrap();
        let req = request(vec!["cat".into()], vec![7; 100]);
        client
            .send(&req, &[w0.as_fd(), w1.as_fd(), w2.as_fd()])
            .unwrap();
        drop((w0, w1, w2));

        let (first, fds) = service.recv::<ToService>(MAX_FRAME).unwrap();
        assert_eq!(first, ToService::Signal(1));
        assert!(fds.is_empty());
        let (second, fds) = service.recv::<ToService>(MAX_FRAME).unwrap();
        assert_eq!(second, req);
        assert_eq!(fds.len(), 3);
        for (fd, r) in fds.into_iter().zip([&mut r0, &mut r1, &mut r2]) {
            let mut w = std::fs::File::from(fd);
            w.write_all(b"hi").unwrap();
            drop(w);
            let mut got = String::new();
            r.read_to_string(&mut got).unwrap();
            assert_eq!(got, "hi");
        }
    }

    #[test]
    fn large_frame_crosses_the_socket_buffer() {
        let (mut client, mut service) = pair();
        let req = request(
            vec![OsString::from_vec(vec![b'x'; MAX_REQUEST - 16])],
            vec![1; MAX_SIG],
        );
        let sent = std::thread::scope(|s| {
            s.spawn(|| client.send(&req, &[]).unwrap());
            service.recv::<ToService>(MAX_FRAME).unwrap().0
        });
        assert_eq!(sent, req);
    }

    #[test]
    fn frame_over_max_is_too_large() {
        let (mut client, mut service) = pair();
        client
            .send(&ToClient::Refused("x".repeat(100)), &[])
            .unwrap();
        assert!(matches!(
            service.recv::<ToClient>(64),
            Err(ProtoError::TooLarge)
        ));
    }

    #[test]
    fn closed_and_timeout() {
        let (client, mut service) = pair();
        let deadline = Instant::now() + Duration::from_millis(50);
        assert!(matches!(
            service.recv_deadline::<ToService>(MAX_FRAME, deadline),
            Err(ProtoError::Timeout)
        ));
        drop(client);
        assert!(matches!(
            service.recv::<ToService>(MAX_FRAME),
            Err(ProtoError::Closed)
        ));
    }

    /// True if no write end of the pipe is open any more (a read gives EOF).
    fn writers_closed(r: &mut std::io::PipeReader) -> bool {
        // SAFETY: fcntl on a pipe fd this test owns.
        unsafe { libc::fcntl(r.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        match r.read(&mut [0; 1]) {
            Ok(0) => true,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
            other => panic!("unexpected read: {other:?}"),
        }
    }

    fn open_fds() -> usize {
        std::fs::read_dir("/dev/fd").unwrap().count()
    }

    /// Runs `check` in a fresh copy of this test binary that runs only the
    /// test `name`: other tests fork in parallel, and a forked child holds
    /// copies of our fds, which would skew the fd count and the pipe EOF.
    fn in_fresh_process(name: &str, check: impl FnOnce()) {
        const CHILD: &str = "PROTO_FD_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            return check();
        }
        let module = module_path!().split_once("::").unwrap().1;
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([&format!("{module}::{name}"), "--exact", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stdout}{stderr}");
        assert!(stdout.contains("1 passed"), "{stdout}{stderr}");
    }

    /// Sends `n` copies of a pipe's write end with one frame and returns
    /// what `recv` made of it. Asserts that afterwards every received copy
    /// is closed and the process holds as many fds as before.
    fn recv_with_fds(n: usize) -> Result<usize, ProtoError> {
        let before = open_fds();
        let (got, closed) = {
            let (client, mut service) = pair();
            let (mut r, w) = std::io::pipe().unwrap();
            client.send_raw(&ToService::Signal(1), &vec![w.as_raw_fd(); n]);
            drop(w);
            let got = service.recv::<ToService>(MAX_FRAME).map(|(f, fds)| {
                assert_eq!(f, ToService::Signal(1));
                fds.len()
            });
            (got, writers_closed(&mut r))
        };
        assert!(closed, "a received fd leaked ({n} sent)");
        assert_eq!(open_fds(), before, "fd count changed ({n} sent)");
        got
    }

    #[test]
    fn up_to_max_fds_are_received() {
        in_fresh_process("up_to_max_fds_are_received", || {
            assert_eq!(recv_with_fds(MAX_FDS).unwrap(), MAX_FDS);
        });
    }

    #[test]
    fn one_fd_too_many_is_malformed_and_none_leak() {
        in_fresh_process("one_fd_too_many_is_malformed_and_none_leak", || {
            let got = recv_with_fds(MAX_FDS + 1);
            assert!(matches!(got, Err(ProtoError::Malformed)), "{got:?}");
        });
    }

    #[test]
    fn hundreds_of_fds_are_malformed_and_none_leak() {
        in_fresh_process("hundreds_of_fds_are_malformed_and_none_leak", || {
            // 254 is the most macOS lets a peer send in one message.
            for n in [200, 254] {
                let got = recv_with_fds(n);
                assert!(matches!(got, Err(ProtoError::Malformed)), "{got:?}");
            }
        });
    }

    /// Control data with one `SCM_RIGHTS` header claiming `len` bytes,
    /// followed by `fds`.
    fn control(len: usize, fds: &[RawFd]) -> Vec<u8> {
        // SAFETY: cmsghdr is plain data; all-zero is a valid value.
        let mut hdr: libc::cmsghdr = unsafe { std::mem::zeroed() };
        hdr.cmsg_len = len as _;
        hdr.cmsg_level = libc::SOL_SOCKET;
        hdr.cmsg_type = libc::SCM_RIGHTS;
        // SAFETY: CMSG_LEN only computes a size.
        let mut out = vec![0u8; unsafe { libc::CMSG_LEN(0) } as usize];
        // SAFETY: `out` holds at least size_of::<cmsghdr>() bytes.
        unsafe {
            out.as_mut_ptr()
                .cast::<libc::cmsghdr>()
                .write_unaligned(hdr)
        };
        for fd in fds {
            out.extend_from_slice(&fd.to_ne_bytes());
        }
        out
    }

    #[test]
    fn control_walk_never_trusts_cmsg_len() {
        let mut fds = Vec::new();
        // Too short to be a header: rejected, no endless loop.
        assert!(!take_fds(&control(0, &[]), &mut fds));
        assert!(!take_fds(&control(4, &[]), &mut fds));
        assert!(!take_fds(&[0; 3], &mut fds));
        assert!(fds.is_empty());
        // Claims three fds but holds one: that one is taken, nothing past it.
        let (_r, w) = std::io::pipe().unwrap();
        let fd = std::os::fd::IntoRawFd::into_raw_fd(w);
        // SAFETY: CMSG_LEN only computes a size.
        let three = unsafe { libc::CMSG_LEN(3 * 4) } as usize;
        assert!(!take_fds(&control(three, &[fd]), &mut fds));
        assert_eq!(fds.len(), 1);
        assert_eq!(fds[0].as_raw_fd(), fd);
        // SAFETY: CMSG_LEN only computes a size.
        let none = unsafe { libc::CMSG_LEN(0) } as usize;
        assert!(take_fds(&control(none, &[]), &mut fds));
    }

    #[test]
    fn passes_only_terminal_and_locale_env() {
        for name in ["TERM", "COLORTERM", "LANG", "LC_ALL", "LC_CTYPE"] {
            assert!(passes_env(OsStr::new(name), OsStr::new("C")), "{name}");
        }
        for name in [
            "PATH",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH",
            "DYLD_FALLBACK_LIBRARY_PATH",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "IFS",
            "CDPATH",
            "BASH_ENV",
            "ENV",
            "PS4",
            "SHELLOPTS",
            "BASHOPTS",
            "PERL5LIB",
            "PERL5OPT",
            "PYTHONPATH",
            "PYTHONSTARTUP",
            "RUBYOPT",
            "RUBYLIB",
            "NODE_OPTIONS",
            "JAVA_TOOL_OPTIONS",
            "TZ",
            "HOME",
            "USER",
            "LOGNAME",
            "SHELL",
            "SUDO_USER",
            "SUDO_UID",
            "SUDO_GID",
            "SUDO_COMMAND",
            "SUDO_ASKPASS",
            "LANGUAGE",
            "LC",
            "SSH_AUTH_SOCK",
            "TERMINFO",
            "TERMINFO_DIRS",
            "BASH_FUNC_TERM%%",
            "LC_ALL=x",
            "LC_=",
        ] {
            assert!(!passes_env(OsStr::new(name), OsStr::new("C")), "{name}");
        }
    }

    /// sudo `env_check` (sudo-tests E4, E5): allowed names with a path, a format string or a
    /// bash function as value never pass; ordinary values do.
    #[test]
    fn drops_allowed_names_with_bad_values() {
        let good = [
            ("TERM", "xterm-256color"),
            ("COLORTERM", "truecolor"),
            ("LANG", "en_US.UTF-8"),
            ("LC_ALL", "C"),
            ("LC_CTYPE", ""),
            ("LANG", "de_DE.UTF-8@euro"),
            ("TERM", "x(y)"),
        ];
        for (name, value) in good {
            assert!(
                passes_env(OsStr::new(name), OsStr::new(value)),
                "{name}={value}"
            );
        }
        let bad = [
            ("TERM", "../../tmp/t"),
            ("TERM", "/usr/share/terminfo/x"),
            ("TERM", "() { :;}; echo x"),
            ("TERM", "()"),
            ("COLORTERM", "%n%n%n"),
            ("COLORTERM", "truecolor%"),
            ("LANG", "/tmp/locale"),
            ("LANG", "en_US.UTF-8/../x"),
            ("LC_ALL", "%s"),
            ("LC_MESSAGES", "() { id; }"),
            ("LC_CTYPE", "a/b"),
        ];
        for (name, value) in bad {
            assert!(
                !passes_env(OsStr::new(name), OsStr::new(value)),
                "{name}={value}"
            );
        }
    }

    #[test]
    fn filter_env_keeps_only_the_first_value_per_name() {
        let vars = [
            ("PATH", "/evil"),
            ("LC_ALL", "/tmp/x"),
            ("LC_ALL", "C"),
            ("TERM", "xterm"),
            ("LANG", "C"),
            ("LANG", "en_US.UTF-8"),
            ("TERM", "vt100"),
            ("LANG", "/tmp/y"),
        ]
        .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let want =
            [("TERM", "xterm"), ("LANG", "C")].map(|(k, v)| (OsString::from(k), OsString::from(v)));
        assert_eq!(filter_env(vars), want);
    }
}
