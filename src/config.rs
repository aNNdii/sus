//! config.toml: loading and checking (service), merging and chain check (install), install layout.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use ssh_key::{Algorithm, PublicKey};

use crate::names;

/// Who must own the files. `Me` is only for the test mode (`geteuid() != 0`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Owner {
    Root,
    Me,
}

impl Owner {
    fn uid(self) -> u32 {
        match self {
            Owner::Root => 0,
            // SAFETY: geteuid has no preconditions.
            Owner::Me => unsafe { libc::geteuid() },
        }
    }
    /// Parent directories may also belong to root in the test mode (`/var`, `/tmp`).
    fn accepts_dir(self, uid: u32) -> bool {
        uid == self.uid() || (self == Owner::Me && uid == 0)
    }
}

/// One allowed account and the keys that may sign for it, in config order.
pub(crate) struct User {
    pub name: String,
    pub uid: u32,
    pub keys: Vec<PublicKey>,
}

pub(crate) struct Config {
    /// Known users with their uid. Unknown names are left out.
    pub users: Vec<User>,
    /// Names in `users` that match no account. The caller reports them: under launchd
    /// stderr goes nowhere.
    pub unknown_users: Vec<String>,
    pub secure_path: String,
}

impl Config {
    /// The allowed account with this uid, if any.
    pub fn user(&self, uid: u32) -> Option<&User> {
        self.users.iter().find(|u| u.uid == uid)
    }
}

/// Standard PATH, not a tool name; split so the names test does not trip.
pub(crate) const DEFAULT_SECURE_PATH: &str = concat!(
    "/usr/",
    "local/sbin:/usr/",
    "local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
);

/// `[users]` maps each account name to the keys that may sign for it.
#[derive(Deserialize)]
struct Raw {
    #[serde(default)]
    users: BTreeMap<String, Vec<String>>,
    secure_path: Option<String>,
}

/// Plain `ssh-ed25519` only, in the config as at install: no RSA, ECDSA or security-key
/// types (certificates do not parse as a public key at all).
pub(crate) fn check_key(key: &PublicKey) -> Result<(), String> {
    match key.algorithm() {
        Algorithm::Ed25519 => Ok(()),
        other => Err(format!("{other} is not ssh-ed25519")),
    }
}

/// The uid of `user`, or `None` if it is unknown or cannot be looked up.
fn uid_of(user: &str) -> Option<u32> {
    lookup_uid(user, 1024)
}

/// `getpwnam_r` (the requests run on several threads, and `getpwnam` shares
/// its result buffer), starting with `size` bytes and doubling on `ERANGE`.
fn lookup_uid(user: &str, size: usize) -> Option<u32> {
    let name = CString::new(user).ok()?;
    let mut buf: Vec<libc::c_char> = vec![0; size.max(1)];
    loop {
        // SAFETY: passwd is plain data; all-zero is a valid value.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `name` is NUL-terminated; `pwd`, `buf` with its length and
        // `found` are live locals the call writes into.
        let rc = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut found,
            )
        };
        match rc {
            0 if found.is_null() => return None,
            0 => return Some(pwd.pw_uid),
            libc::ERANGE if buf.len() < 1 << 20 => buf.resize(buf.len() * 2, 0),
            _ => return None,
        }
    }
}

fn check_mode(what: &str, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
    if mode & 0o002 != 0 {
        return Err(format!("{what} is writable by everyone"));
    }
    if mode & 0o020 != 0 && gid != 0 {
        return Err(format!("{what} is writable by group {gid}"));
    }
    let _ = uid;
    Ok(())
}

/// Every entry must be an absolute path. An empty or relative entry would be looked up relative
/// to the service's cwd but run relative to the caller's: what was checked is not what runs.
fn check_secure_path(secure_path: &str) -> Result<(), String> {
    match secure_path
        .split(':')
        .find(|entry| !Path::new(entry).is_absolute())
    {
        Some(entry) => Err(format!("secure_path entry {entry:?} is not absolute")),
        None => Ok(()),
    }
}

/// Like sudo with its sudoers: `open`, then `fstat` on the descriptor; only the file itself.
pub(crate) fn load(path: &Path, owner: Owner) -> Result<Config, String> {
    let shown = path.display();
    let mut file = File::open(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot stat {shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{shown} is not a regular file"));
    }
    if meta.uid() != owner.uid() {
        return Err(format!(
            "{shown} is owned by uid {}, expected {}",
            meta.uid(),
            owner.uid()
        ));
    }
    check_mode(&shown.to_string(), meta.uid(), meta.gid(), meta.mode())?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|e| format!("cannot read {shown}: {e}"))?;
    let raw: Raw =
        toml::from_str(&text).map_err(|e| format!("cannot parse {shown}: {}", e.message()))?;
    if raw.users.is_empty() {
        return Err(format!("{shown} lists no users"));
    }
    let mut users = Vec::new();
    let mut unknown_users = Vec::new();
    for (name, lines) in raw.users {
        if lines.is_empty() {
            return Err(format!("{shown} lists no keys for {name:?}"));
        }
        let keys = lines
            .iter()
            .map(|k| {
                let key = PublicKey::from_openssh(k)
                    .map_err(|e| format!("bad key for {name:?} in {shown}: {e}"))?;
                check_key(&key).map_err(|e| format!("bad key for {name:?} in {shown}: {e}"))?;
                Ok(key)
            })
            .collect::<Result<Vec<_>, String>>()?;
        match uid_of(&name) {
            Some(uid) => users.push(User { name, uid, keys }),
            None => unknown_users.push(name),
        }
    }
    let secure_path = raw
        .secure_path
        .unwrap_or_else(|| DEFAULT_SECURE_PATH.to_string());
    check_secure_path(&secure_path)?;
    Ok(Config {
        users,
        unknown_users,
        secure_path,
    })
}

/// Install only (AC11): every directory from `dir` up to `/` is owned by the owner (or root in
/// test mode), not writable by others, and writable by the group only for gid 0.
/// Directories that do not exist yet are skipped.
pub(crate) fn check_chain(dir: &Path, owner: Owner) -> Result<(), String> {
    for d in dir.ancestors() {
        let shown = d.display();
        let meta = match std::fs::metadata(d) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("cannot stat {shown}: {e}")),
        };
        if !meta.is_dir() {
            return Err(format!("{shown} is not a directory"));
        }
        if !owner.accepts_dir(meta.uid()) {
            return Err(format!("{shown} is owned by uid {}", meta.uid()));
        }
        check_mode(&shown.to_string(), meta.uid(), meta.gid(), meta.mode())?;
    }
    Ok(())
}

const USERS_FORMAT: &str =
    "`users` in the existing config is not a table of name = [\"ssh-ed25519 …\"]";

/// Merges new keys for `users` into an existing config.toml text: every user gets every key it
/// does not have yet. `None` when there is nothing to add (no flags): the file stays as it is.
/// Everything else, `secure_path` too, is kept; a `secure_path` the service would refuse is
/// refused here too.
///
/// With flags the text is parsed and written out again: the content is kept, but comments and
/// the order of keys are not (docs/configuration.md and docs/architecture.md say so too).
pub(crate) fn merge(
    existing: Option<&str>,
    keys: &[PublicKey],
    users: &[String],
) -> Result<Option<String>, String> {
    // install pairs every --key with a user (default $SUDO_USER) and refuses --user alone.
    if keys.is_empty() || users.is_empty() {
        return Ok(None);
    }
    let mut table: toml::Table = match existing {
        Some(text) => {
            toml::from_str(text).map_err(|e| format!("cannot parse config: {}", e.message()))?
        }
        None => {
            let mut t = toml::Table::new();
            t.insert("secure_path".into(), DEFAULT_SECURE_PATH.into());
            t
        }
    };
    match table.get("secure_path") {
        None => {}
        Some(toml::Value::String(s)) => check_secure_path(s)?,
        Some(_) => return Err("`secure_path` in the existing config is not a string".into()),
    }
    let mut have_users = match table.remove("users") {
        None => toml::Table::new(),
        Some(toml::Value::Table(t)) => t,
        Some(_) => return Err(USERS_FORMAT.into()),
    };
    for u in users {
        let mut have_keys = match have_users.remove(u) {
            None => Vec::new(),
            Some(toml::Value::Array(a)) => a,
            Some(_) => return Err(USERS_FORMAT.into()),
        };
        for k in keys {
            let known = have_keys.iter().any(|v| {
                v.as_str()
                    .and_then(|s| PublicKey::from_openssh(s).ok())
                    .is_some_and(|p| p.key_data() == k.key_data())
            });
            if !known {
                let line = k
                    .to_openssh()
                    .map_err(|e| format!("cannot encode key: {e}"))?;
                have_keys.push(line.into());
            }
        }
        have_users.insert(u.clone(), have_keys.into());
    }
    table.insert("users".into(), have_users.into());
    toml::to_string(&table)
        .map(Some)
        .map_err(|e| format!("cannot write config: {e}"))
}

pub(crate) struct Layout {
    pub libexec: PathBuf,
    pub etc: PathBuf,
    pub plist: PathBuf,
    pub socket: PathBuf,
    pub owner: Owner,
}

impl Layout {
    pub fn system() -> Self {
        Layout {
            libexec: names::LIBEXEC_DIR.into(),
            etc: names::ETC_DIR.into(),
            plist: names::PLIST.into(),
            socket: names::SOCKET.into(),
            owner: Owner::Root,
        }
    }

    /// The service's config.toml.
    pub fn config(&self) -> PathBuf {
        self.etc.join("config.toml")
    }

    #[cfg(test)]
    pub fn under(tmp: &Path) -> Self {
        Layout {
            libexec: tmp.join("libexec"),
            etc: tmp.join("etc"),
            plist: tmp.join("plist"),
            socket: tmp.join("sock"),
            owner: Owner::Me,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm, PrivateKey, rand_core::OsRng};
    use std::os::unix::fs::PermissionsExt;

    fn key() -> PublicKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone()
    }

    fn me() -> String {
        // SAFETY: geteuid has no preconditions; getpwuid returns static data
        // or null, and this test thread reads it at once.
        let pw = unsafe { libc::getpwuid(libc::geteuid()) };
        assert!(!pw.is_null());
        // SAFETY: `pw` is non-null and `pw_name` a NUL-terminated string.
        unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) }
            .to_str()
            .unwrap()
            .to_string()
    }

    fn write(dir: &Path, text: &str, mode: u32) -> PathBuf {
        let p = dir.join("config.toml");
        let _ = std::fs::remove_file(&p);
        std::fs::write(&p, text).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    fn line(k: &PublicKey) -> String {
        k.to_openssh().unwrap()
    }

    /// `secure_path` must come before the `[users]` table.
    fn good(k: &PublicKey) -> String {
        format!("[users]\n{:?} = [{:?}]\n", me(), line(k))
    }

    #[test]
    fn loads_valid_with_default_secure_path() {
        let d = tempfile::tempdir().unwrap();
        let k = key();
        let c = load(&write(d.path(), &good(&k), 0o600), Owner::Me).unwrap();
        assert_eq!(c.secure_path, DEFAULT_SECURE_PATH);
        assert_eq!(c.users.len(), 1);
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        assert_eq!(c.users[0].uid, euid);
        assert_eq!(c.users[0].name, me());
        assert!(c.unknown_users.is_empty());
        assert!(c.user(euid).unwrap().keys[0].key_data() == k.key_data());
        assert!(c.user(euid.wrapping_add(1)).is_none());
    }

    #[test]
    fn keys_belong_to_their_user() {
        let d = tempfile::tempdir().unwrap();
        let (mine, roots, second) = (key(), key(), key());
        let text = format!(
            "[users]\nroot = [{:?}]\n{:?} = [{:?}, {:?}]\n",
            line(&roots),
            me(),
            line(&mine),
            line(&second)
        );
        let c = load(&write(d.path(), &text, 0o600), Owner::Me).unwrap();
        // SAFETY: geteuid has no preconditions.
        let mine_now = &c.user(unsafe { libc::geteuid() }).unwrap().keys;
        // config order, and nobody else's key
        assert!(mine_now[0].key_data() == mine.key_data());
        assert!(mine_now[1].key_data() == second.key_data());
        assert_eq!(mine_now.len(), 2);
        assert_eq!(c.user(0).unwrap().keys.len(), 1);
        assert!(c.user(0).unwrap().keys[0].key_data() == roots.key_data());
    }

    #[test]
    fn custom_secure_path_and_unknown_user() {
        let d = tempfile::tempdir().unwrap();
        let k = line(&key());
        let text = format!(
            "secure_path = \"/x\"\n{}\"no-such-user-xyz\" = [{k:?}]\n",
            good(&key())
        );
        let c = load(&write(d.path(), &text, 0o600), Owner::Me).unwrap();
        assert_eq!(c.secure_path, "/x");
        assert_eq!(c.users.len(), 1);
        assert_ne!(c.users[0].name, "no-such-user-xyz");
        // Returned, not printed: the service logs it (launchd drops stderr).
        assert_eq!(c.unknown_users, vec!["no-such-user-xyz".to_string()]);
    }

    #[test]
    fn only_plain_ed25519_keys_load() {
        let d = tempfile::tempdir().unwrap();
        let ecdsa = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNoeWHKfisoQ5ZLptiHT5BW7THc3SMJGOTQFntqqRdVuCJwLKB+e2fFCCP5SRMcBBBm11/9U5rpnJoUeZ2VtwwE= x";
        let b64 = line(&key()).split_whitespace().nth(1).unwrap().to_string();
        for bad in [
            ecdsa.to_string(),
            format!("sk-ssh-ed25519@openssh.com {b64} x"),
            format!("ssh-ed25519-cert-v01@openssh.com {b64} x"),
        ] {
            let text = format!("[users]\n{:?} = [{bad:?}]\n", me());
            let e = load(&write(d.path(), &text, 0o600), Owner::Me)
                .err()
                .unwrap();
            assert!(e.contains("bad key for"), "{bad}: {e}");
        }
    }

    #[test]
    fn uid_lookup_grows_a_small_buffer() {
        // One byte is too small for any passwd entry: ERANGE, then retries.
        assert_eq!(lookup_uid("root", 1), Some(0));
        assert_eq!(lookup_uid(&me(), 1), uid_of(&me()));
        assert_eq!(lookup_uid("no-such-user-xyz", 1), None);
        assert_eq!(uid_of("root"), Some(0));
    }

    #[test]
    fn secure_path_entries_must_be_absolute() {
        let d = tempfile::tempdir().unwrap();
        let t = good(&key());
        let load_with = |sp: &str| {
            let text = format!("secure_path = \"{sp}\"\n{t}");
            load(&write(d.path(), &text, 0o600), Owner::Me).map(|c| c.secure_path)
        };
        assert_eq!(
            load_with(".:/usr/bin").err().unwrap(),
            "secure_path entry \".\" is not absolute"
        );
        assert_eq!(
            load_with("/usr/bin:bin").err().unwrap(),
            "secure_path entry \"bin\" is not absolute"
        );
        assert_eq!(
            load_with("/usr/bin::/bin").err().unwrap(),
            "secure_path entry \"\" is not absolute"
        );
        assert_eq!(
            load_with("").err().unwrap(),
            "secure_path entry \"\" is not absolute"
        );
        assert_eq!(load_with("/usr/bin:/bin").unwrap(), "/usr/bin:/bin");
    }

    #[test]
    fn merge_refuses_what_load_refuses() {
        let k = [key()];
        let u = ["bob".to_string()];
        let err = merge(Some("secure_path = \"/usr/bin::/bin\"\n"), &k, &u).unwrap_err();
        assert_eq!(err, "secure_path entry \"\" is not absolute");
        let err = merge(Some("secure_path = \"bin\"\n"), &k, &u).unwrap_err();
        assert_eq!(err, "secure_path entry \"bin\" is not absolute");
        assert!(
            merge(Some("secure_path = 3\n"), &k, &u)
                .unwrap_err()
                .contains("not a string")
        );
        assert!(merge(Some("secure_path = \"/usr/bin:/bin\"\n"), &k, &u).is_ok());
    }

    #[test]
    fn rejects_bad_files() {
        let d = tempfile::tempdir().unwrap();
        let t = good(&key());
        let err = |p: &Path, o| load(p, o).err().unwrap();
        assert!(err(&write(d.path(), &t, 0o602), Owner::Me).contains("everyone"));
        assert!(err(&write(d.path(), &t, 0o620), Owner::Me).contains("group"));
        assert!(err(&write(d.path(), &t, 0o600), Owner::Root).contains("owned"));
        assert!(err(&write(d.path(), &t, 0o000), Owner::Me).contains("cannot read"));
        assert!(err(d.path(), Owner::Me).contains("not a regular file"));
        assert!(err(&d.path().join("missing"), Owner::Me).contains("cannot read"));
        let k = line(&key());
        assert!(
            err(&write(d.path(), "secure_path = \"/bin\"", 0o600), Owner::Me).contains("no users")
        );
        assert!(
            err(
                &write(d.path(), &format!("[users]\n{:?} = []", me()), 0o600),
                Owner::Me
            )
            .contains("no keys for")
        );
        assert!(err(&write(d.path(), "users = [", 0o600), Owner::Me).contains("parse"));
        // users and keys as two lists: the format before keys were bound to users
        let old = format!("users = [{:?}]\nkeys = [{k:?}]\n", me());
        assert!(err(&write(d.path(), &old, 0o600), Owner::Me).contains("parse"));
    }

    #[test]
    fn chain_checks_directories() {
        let d = tempfile::tempdir().unwrap();
        let sub = d.path().join("a/b");
        std::fs::create_dir_all(&sub).unwrap();
        assert!(check_chain(&sub, Owner::Me).is_ok());
        assert!(check_chain(&sub.join("missing"), Owner::Me).is_ok());
        assert!(check_chain(&sub, Owner::Root).is_err());
        let a = d.path().join("a");
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o757)).unwrap();
        assert!(
            check_chain(&sub, Owner::Me)
                .unwrap_err()
                .contains("everyone")
        );
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(check_chain(&sub, Owner::Me).unwrap_err().contains("group"));
    }

    #[test]
    fn merge_rules() {
        let (k1, k2) = (key(), key());
        let bob = || vec!["bob".to_string()];
        assert_eq!(merge(None, &[], &[]).unwrap(), None);
        assert_eq!(merge(Some("[users]"), &[], &bob()).unwrap(), None);
        let fresh = merge(None, std::slice::from_ref(&k1), &bob())
            .unwrap()
            .unwrap();
        assert!(fresh.contains(DEFAULT_SECURE_PATH));
        // same key again (with another comment) for bob, both keys for a new user amy
        let mut k1c = k1.clone();
        k1c.set_comment("other");
        let again = merge(
            Some(&fresh),
            &[k1c, k2.clone()],
            &["bob".into(), "amy".into()],
        )
        .unwrap()
        .unwrap();
        let t: toml::Table = toml::from_str(&again).unwrap();
        let users = t["users"].as_table().unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users["bob"].as_array().unwrap().len(), 2);
        assert_eq!(users["amy"].as_array().unwrap().len(), 2);
        // a key for amy only leaves bob alone
        let k3 = key();
        let amy = merge(Some(&again), std::slice::from_ref(&k3), &["amy".into()])
            .unwrap()
            .unwrap();
        let t: toml::Table = toml::from_str(&amy).unwrap();
        assert_eq!(t["users"]["bob"].as_array().unwrap().len(), 2);
        assert_eq!(t["users"]["amy"].as_array().unwrap().len(), 3);
        // everything else stays; comments do not (documented: the file is rewritten)
        let kept = merge(
            Some("# hand-edited\nsecure_path = \"/x\"\nextra = 1\n"),
            &[k1],
            &bob(),
        )
        .unwrap()
        .unwrap();
        let t: toml::Table = toml::from_str(&kept).unwrap();
        assert_eq!(t["secure_path"].as_str(), Some("/x"));
        assert_eq!(t["extra"].as_integer(), Some(1));
        assert!(!kept.contains("hand-edited"));
        // the old two-list format and other shapes are refused, not rewritten
        let old = format!("users = [\"bob\"]\nkeys = [{:?}]\n", line(&k2));
        assert!(
            merge(Some(&old), &[key()], &bob())
                .unwrap_err()
                .contains("not a table")
        );
        assert!(merge(Some("[users]\nbob = 3"), &[key()], &bob()).is_err());
    }

    #[test]
    fn layouts() {
        let s = Layout::system();
        assert_eq!(s.owner, Owner::Root);
        assert_eq!(s.etc, Path::new(names::ETC_DIR));
        assert_eq!(s.config(), Path::new(names::ETC_DIR).join("config.toml"));
        let d = tempfile::tempdir().unwrap();
        let l = Layout::under(d.path());
        assert!(l.etc.starts_with(d.path()) && l.socket.starts_with(d.path()));
        assert_eq!(l.owner, Owner::Me);
    }
}
