//! macOS FFI: peer credentials of a unix socket, the unified log, fork safety.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};

/// uid, gid and pid of the process at the other end of `s` (`getpeereid` + `LOCAL_PEERPID`).
pub(crate) fn peer(s: &UnixStream) -> io::Result<(u32, u32, i32)> {
    let fd = s.as_raw_fd();
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: valid socket fd, out pointers to live locals.
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: valid socket fd, out pointer and length describe `pid`.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((uid, gid, pid))
}

/// Name of the socket entry in the LaunchDaemon plist.
pub(crate) const LISTENER: &str = "Listener";

unsafe extern "C" {
    fn launch_activate_socket(
        name: *const libc::c_char,
        fds: *mut *mut libc::c_int,
        cnt: *mut libc::size_t,
    ) -> libc::c_int;
}

/// The socket launchd opened for the plist entry `key` (`launch_activate_socket`).
pub(crate) fn launchd_listener(key: &str) -> io::Result<UnixListener> {
    let name = std::ffi::CString::new(key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in socket name"))?;
    let mut fds: *mut libc::c_int = std::ptr::null_mut();
    let mut cnt: libc::size_t = 0;
    // SAFETY: valid name, out pointers to live locals.
    let rc = unsafe { launch_activate_socket(name.as_ptr(), &mut fds, &mut cnt) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    // SAFETY: on success `fds` is null or points to `cnt` descriptors in
    // malloc'd memory that only we free.
    let all = unsafe { take_launchd_fds(fds, cnt) };
    let [fd] = all[..] else {
        for fd in all {
            // SAFETY: descriptors launchd gave us and nobody else owns.
            unsafe { libc::close(fd) };
        }
        return Err(io::Error::other("expected exactly one launchd socket"));
    };
    // SAFETY: launchd handed this descriptor to us; nothing else owns it.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // Root commands must not inherit the listening socket.
    set_cloexec(fd.as_fd())?;
    Ok(UnixListener::from(fd))
}

/// The `cnt` descriptors at `fds` from `launch_activate_socket`, which then
/// frees the array. A null `fds` or a `cnt` of 0 gives none.
///
/// # Safety
///
/// `fds` is null or points to `cnt` ints in malloc'd memory nobody else frees.
unsafe fn take_launchd_fds(fds: *mut libc::c_int, cnt: libc::size_t) -> Vec<libc::c_int> {
    let all = if fds.is_null() || cnt == 0 {
        Vec::new()
    } else {
        // SAFETY: non-null, and the caller vouches for `cnt` ints behind it.
        unsafe { std::slice::from_raw_parts(fds, cnt) }.to_vec()
    };
    // SAFETY: malloc'd and ours by the caller's contract; free(NULL) does nothing.
    unsafe { libc::free(fds.cast()) };
    all
}

/// Marks `fd` close-on-exec (`FD_CLOEXEC`).
fn set_cloexec(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: valid descriptor; F_SETFD takes an int flag.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

unsafe extern "C" {
    fn notify_is_valid_token(val: libc::c_int) -> bool;
}

/// Call before every `fork` in a process with threads. libSystem's fork
/// handler in the child reads libnotify's state, which the first `notify_*`
/// call creates (`getpwnam` makes one). A fork while another thread is still
/// creating it kills the child with SIGKILL ("os_once_t is corrupt"), so a
/// command would seem killed. This creates it first, or waits for the thread
/// that does.
pub(crate) fn before_fork() {
    // SAFETY: takes a plain int, any value is fine; only the side effect counts.
    unsafe { notify_is_valid_token(0) };
}

#[expect(non_camel_case_types, reason = "the C type's name from <os/log.h>")]
type os_log_t = *mut libc::c_void;

unsafe extern "C" {
    static __dso_handle: u8;
    fn os_log_create(subsystem: *const libc::c_char, category: *const libc::c_char) -> os_log_t;
    fn _os_log_impl(
        dso: *const libc::c_void,
        log: os_log_t,
        kind: u8,
        format: *const libc::c_char,
        buf: *const u8,
        size: u32,
    );
}

/// One default-level message in the unified log under `subsystem`, with the
/// text public (not `<private>`). Interior NULs end the text early.
pub(crate) fn log(subsystem: &str, text: &str) {
    const OS_LOG_TYPE_DEFAULT: u8 = 0;
    // Argument buffer of `%{public}s`: summary, count, then descriptor
    // (public | string), size and the pointer.
    const PUBLIC_STRING: u8 = 0x22;
    // Summary flag: the buffer holds a non-scalar (pointer) argument.
    const HAS_NON_SCALAR: u8 = 2;
    let (Ok(sub), Ok(cat), Ok(text)) = (
        std::ffi::CString::new(subsystem),
        std::ffi::CString::new("audit"),
        std::ffi::CString::new(text.split('\0').next().unwrap_or("")),
    ) else {
        return;
    };
    let mut buf = [0u8; 12];
    buf[0] = HAS_NON_SCALAR;
    buf[1] = 1;
    buf[2] = PUBLIC_STRING;
    buf[3] = std::mem::size_of::<*const libc::c_char>() as u8;
    buf[4..].copy_from_slice(&(text.as_ptr() as usize).to_ne_bytes());
    // SAFETY: valid C strings; the buffer follows the os_log encoding for one
    // string argument and `text` outlives the call. The log object is never freed.
    unsafe {
        let log = os_log_create(sub.as_ptr(), cat.as_ptr());
        _os_log_impl(
            std::ptr::addr_of!(__dso_handle).cast(),
            log,
            OS_LOG_TYPE_DEFAULT,
            c"%{public}s".as_ptr(),
            buf.as_ptr(),
            buf.len() as u32,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_of_a_pair_is_this_process() {
        let (a, _b) = UnixStream::pair().unwrap();
        // SAFETY: plain getters without preconditions.
        let me = unsafe { (libc::geteuid(), libc::getegid(), libc::getpid()) };
        assert_eq!(peer(&a).unwrap(), me);
    }

    #[test]
    fn set_cloexec_marks_the_fd_close_on_exec() {
        let mut p = [0; 2];
        // SAFETY: out pointer to two live ints.
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        // SAFETY: fresh descriptors from `pipe`, owned only here.
        let (r, _w) = unsafe { (OwnedFd::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1])) };
        // SAFETY: valid fd, F_GETFD has no other argument.
        let flags = || unsafe { libc::fcntl(r.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(flags() & libc::FD_CLOEXEC, 0);
        set_cloexec(r.as_fd()).unwrap();
        assert_ne!(flags() & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn launchd_fds_null_or_empty_give_none() {
        // SAFETY: null pointers are allowed by the contract.
        assert!(unsafe { take_launchd_fds(std::ptr::null_mut(), 0) }.is_empty());
        // SAFETY: as above; a null array is never read, whatever `cnt` says.
        assert!(unsafe { take_launchd_fds(std::ptr::null_mut(), 3) }.is_empty());
        // SAFETY: malloc has no preconditions; the call below frees the block.
        let empty = unsafe { libc::malloc(4) }.cast::<libc::c_int>();
        // SAFETY: `empty` is malloc'd and ours; 0 ints are read.
        assert!(unsafe { take_launchd_fds(empty, 0) }.is_empty());
    }

    #[test]
    fn launchd_fds_are_copied_and_the_array_freed() {
        let n = 2;
        // SAFETY: malloc has no preconditions; the call below frees the block.
        let fds =
            unsafe { libc::malloc(n * std::mem::size_of::<libc::c_int>()) }.cast::<libc::c_int>();
        assert!(!fds.is_null());
        // SAFETY: `fds` holds room for `n` ints.
        unsafe { std::ptr::copy_nonoverlapping([7, 9].as_ptr(), fds, n) };
        // SAFETY: malloc'd, `n` ints written, nobody else frees it.
        assert_eq!(unsafe { take_launchd_fds(fds, n) }, [7, 9]);
    }
}
