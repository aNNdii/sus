//! `susd install` and `susd uninstall` (AC11).

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ssh_key::{Algorithm, PublicKey};

use crate::config::{self, Layout, Owner};
use crate::macos;
use crate::names;

pub(crate) fn install(args: &[OsString], layout: &Layout) -> Result<(), String> {
    install_as(args, layout, std::env::var("SUDO_USER").ok())
}

/// `sudo_user` is `$SUDO_USER`, the default for `--user`.
fn install_as(args: &[OsString], layout: &Layout, sudo_user: Option<String>) -> Result<(), String> {
    let (keys, mut users) = parse(args)?;
    let config_path = layout.config();
    let existing = match fs::read_to_string(&config_path) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => return Err(format!("cannot read {}: {e}", config_path.display())),
    };
    if existing.is_none() && keys.is_empty() {
        return Err("a first install needs at least one --key".into());
    }
    if keys.is_empty() && !users.is_empty() {
        return Err("--user needs a --key: keys are given to the users named with them".into());
    }
    if users.is_empty() && !keys.is_empty() {
        users.push(
            sudo_user.filter(|u| !u.is_empty()).ok_or(
                "no --user given and $SUDO_USER is empty; run through sudo or pass --user",
            )?,
        );
    }
    if let Some(u) = users.iter().find(|u| u.is_empty() || *u == "root") {
        return Err(format!("user {u:?} is not allowed (empty or root)"));
    }
    let merged = config::merge(existing.as_deref(), &keys, &users)?;

    config::check_chain(&layout.libexec, layout.owner)?;
    config::check_chain(&layout.etc, layout.owner)?;
    make_dir(&layout.libexec, layout.owner)?;
    make_dir(&layout.etc, layout.owner)?;

    let exe = std::env::current_exe().map_err(|e| format!("cannot find myself: {e}"))?;
    let program = layout.libexec.join(names::DAEMON);
    let bytes = fs::read(&exe).map_err(|e| format!("cannot read {}: {e}", exe.display()))?;
    write_file(&program, &bytes, 0o755, layout.owner)?;
    if let Some(text) = merged {
        write_file(&config_path, text.as_bytes(), 0o600, layout.owner)?;
    }
    let plist = plist(&program, &layout.socket);
    write_file(&layout.plist, plist.as_bytes(), 0o644, layout.owner)?;
    if layout.owner == Owner::Root {
        ignore_hangups();
        // Reload: a running copy keeps the old binary until it is replaced.
        unload()?;
        if !launchctl(&["bootstrap", "system", &layout.plist.to_string_lossy()]) {
            return Err("launchctl bootstrap failed".into());
        }
    }
    Ok(())
}

pub(crate) fn uninstall(layout: &Layout) -> Result<(), String> {
    if layout.owner == Owner::Root {
        ignore_hangups();
        unload()?;
    }
    remove(&layout.plist, false)?;
    remove(&layout.libexec, true)?;
    remove(&layout.etc, true)?;
    remove(&layout.socket, false)
}

/// Run as a command of the service (`sus susd install`), bootout's SIGTERM makes
/// susd SIGHUP every running group, this one included, before bootstrap ran.
/// Ignored signals stay ignored across exec, so launchctl survives too.
fn ignore_hangups() {
    for sig in [libc::SIGHUP, libc::SIGTERM] {
        // SAFETY: installs SIG_IGN, no handler code runs.
        unsafe { libc::signal(sig, libc::SIG_IGN) };
    }
}

fn target() -> String {
    format!("system/{}", names::LABEL)
}

/// Longer than the service's SIGTERM grace (5 s), which it may spend waiting
/// for running commands, this install among them when run through the client.
const UNLOAD_TIMEOUT: Duration = Duration::from_secs(15);

/// Boots the job out if it is loaded and waits until launchd has really
/// removed it: `bootout` returns earlier, and a `bootstrap` before that fails
/// with "5: Input/output error". Not loaded is fine and prints nothing.
fn unload() -> Result<(), String> {
    let loaded = || launchctl_quiet(&["print", &target()]);
    if !loaded() {
        return Ok(());
    }
    launchctl_quiet(&["bootout", &target()]);
    if wait_until(UNLOAD_TIMEOUT, Duration::from_millis(100), || !loaded()) {
        Ok(())
    } else {
        Err(format!(
            "{} is still loaded after {UNLOAD_TIMEOUT:?}",
            names::LABEL
        ))
    }
}

/// Polls `done` every `step` until it holds or `timeout` has passed.
fn wait_until(timeout: Duration, step: Duration, mut done: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + timeout;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(step);
    }
}

/// Runs launchctl; true on success.
fn launchctl(args: &[&str]) -> bool {
    Command::new("/bin/launchctl")
        .args(args)
        .status()
        .is_ok_and(|s| s.success())
}

/// Like `launchctl`, without its output: for probes whose failure is expected.
fn launchctl_quiet(args: &[&str]) -> bool {
    Command::new("/bin/launchctl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn remove(path: &Path, dir: bool) -> Result<(), String> {
    let r = if dir {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    match r {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot remove {}: {e}", path.display())),
    }
}

/// `--key <file>` and `--user <name>`, each repeatable.
fn parse(args: &[OsString]) -> Result<(Vec<PublicKey>, Vec<String>), String> {
    let (mut keys, mut users) = (Vec::new(), Vec::new());
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("{} needs a value", flag.to_string_lossy()))?;
        if flag == "--key" {
            keys.push(read_key(Path::new(value))?);
        } else if flag == "--user" {
            users.push(
                value
                    .to_str()
                    .ok_or("--user is not valid UTF-8")?
                    .to_string(),
            );
        } else {
            return Err(format!(
                "unknown argument {}\nusage: {} install --key <file.pub> [--user <name>]",
                flag.to_string_lossy(),
                names::DAEMON
            ));
        }
    }
    Ok((keys, users))
}

/// Exactly one `ssh-ed25519` public key line.
fn read_key(path: &Path) -> Result<PublicKey, String> {
    let shown = path.display();
    let text = fs::read_to_string(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    if text.trim_start().starts_with("-----BEGIN") {
        return Err(format!("{shown} is a private key; pass the .pub file"));
    }
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let (Some(line), None) = (lines.next(), lines.next()) else {
        return Err(format!("{shown} must hold exactly one key line"));
    };
    let kind = line.split_whitespace().next().unwrap_or("");
    if kind.contains("-cert-") {
        return Err(format!("{shown} is a certificate, not a plain public key"));
    }
    let key = PublicKey::from_openssh(line)
        .map_err(|e| format!("{shown} is not an OpenSSH public key: {e}"))?;
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(format!("{shown} is not an ssh-ed25519 key"));
    }
    Ok(key)
}

fn xml(s: &OsStr) -> String {
    String::from_utf8_lossy(s.as_bytes())
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The LaunchDaemon: launchd owns the socket and starts `susd serve` on demand.
fn plist(program: &Path, socket: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{label}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{program}</string>
		<string>serve</string>
	</array>
	<key>Sockets</key>
	<dict>
		<key>{listener}</key>
		<dict>
			<key>SockPathName</key>
			<string>{socket}</string>
			<key>SockPathMode</key>
			<integer>438</integer>
		</dict>
	</dict>
</dict>
</plist>
"#,
        label = names::LABEL,
        listener = macos::LISTENER,
        program = xml(program.as_os_str()),
        socket = xml(socket.as_os_str()),
    )
}

fn chown_root(path: &Path, owner: Owner) -> Result<(), String> {
    if owner != Owner::Root {
        return Ok(());
    }
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    // SAFETY: valid NUL-terminated path.
    if unsafe { libc::chown(c.as_ptr(), 0, 0) } != 0 {
        return Err(format!(
            "cannot chown {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Creates `dir` and missing parents as 0755 (root:wheel when installing for real).
fn make_dir(dir: &Path, owner: Owner) -> Result<(), String> {
    let mut missing: Vec<&Path> = dir.ancestors().take_while(|d| !d.exists()).collect();
    missing.reverse();
    for d in missing {
        fs::create_dir(d).map_err(|e| format!("cannot create {}: {e}", d.display()))?;
        fs::set_permissions(d, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("cannot chmod {}: {e}", d.display()))?;
        chown_root(d, owner)?;
    }
    Ok(())
}

/// Writes next to `path` and renames over it, so a running binary is replaced, not overwritten.
fn write_file(path: &Path, bytes: &[u8], mode: u32, owner: Owner) -> Result<(), String> {
    let mut tmp: PathBuf = path.into();
    tmp.as_mut_os_string().push(".new");
    let err = |e: std::io::Error| format!("cannot write {}: {e}", path.display());
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .map_err(err)?;
    f.write_all(bytes).map_err(err)?;
    drop(f);
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode)).map_err(err)?;
    chown_root(&tmp, owner)?;
    fs::rename(&tmp, path).map_err(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{PrivateKey, rand_core::OsRng};
    use std::os::unix::fs::MetadataExt;

    fn keyfile(dir: &Path, name: &str, text: &str) -> OsString {
        let p = dir.join(name);
        fs::write(&p, text).unwrap();
        p.into()
    }

    fn pubkey(dir: &Path, name: &str) -> (OsString, PublicKey) {
        let k = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let pk = k.public_key().clone();
        (
            keyfile(dir, name, &format!("{}\n", pk.to_openssh().unwrap())),
            pk,
        )
    }

    fn args(items: &[&OsString]) -> Vec<OsString> {
        items.iter().map(|s| (*s).clone()).collect()
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().mode() & 0o7777
    }

    #[test]
    fn installs_twice_and_merges() {
        let d = tempfile::tempdir().unwrap();
        let l = Layout::under(d.path());
        let (f1, k1) = pubkey(d.path(), "a.pub");
        let (f2, k2) = pubkey(d.path(), "b.pub");
        let key = OsString::from("--key");
        let user = OsString::from("--user");
        let amy = OsString::from("amy");
        install_as(&args(&[&key, &f1, &user, &amy]), &l, None).unwrap();

        let cfg = l.etc.join("config.toml");
        assert_eq!(mode(&cfg), 0o600);
        assert_eq!(mode(&l.libexec.join(names::DAEMON)), 0o755);
        assert_eq!(mode(&l.libexec), 0o755);
        assert_eq!(mode(&l.plist), 0o644);
        let first = fs::read_to_string(&cfg).unwrap();
        assert!(first.contains(&k1.to_openssh().unwrap()));

        // no flags: file untouched, binary and plist replaced
        fs::write(&l.plist, "old").unwrap();
        install_as(&[], &l, None).unwrap();
        assert_eq!(fs::read_to_string(&cfg).unwrap(), first);
        assert!(fs::read_to_string(&l.plist).unwrap().contains(names::LABEL));

        // new key, default user from SUDO_USER, same key again: merged without duplicates
        install_as(&args(&[&key, &f2, &key, &f1]), &l, Some("bob".into())).unwrap();
        let t: toml::Table = toml::from_str(&fs::read_to_string(&cfg).unwrap()).unwrap();
        let users = t["users"].as_table().unwrap();
        let names: Vec<_> = users.keys().map(String::as_str).collect();
        assert_eq!(names, ["amy", "bob"]);
        // amy keeps only her key; bob has both
        assert_eq!(users["amy"].as_array().unwrap().len(), 1);
        assert_eq!(users["bob"].as_array().unwrap().len(), 2);
        assert!(
            users["bob"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str() == Some(&k2.to_openssh().unwrap()))
        );
        assert_eq!(mode(&cfg), 0o600);

        // a user alone has no key to get
        let e = install_as(&args(&[&user, &amy]), &l, None).unwrap_err();
        assert!(e.contains("--user needs a --key"), "{e}");
    }

    #[test]
    fn user_rules() {
        let d = tempfile::tempdir().unwrap();
        let l = Layout::under(d.path());
        let (f, _) = pubkey(d.path(), "a.pub");
        let a = args(&[&"--key".into(), &f]);
        assert!(install_as(&a, &l, None).unwrap_err().contains("SUDO_USER"));
        assert!(install_as(&a, &l, Some(String::new())).is_err());
        let root = args(&[&"--key".into(), &f, &"--user".into(), &"root".into()]);
        assert!(install_as(&root, &l, None).unwrap_err().contains("root"));
        assert!(install_as(&a, &l, Some("root".into())).is_err());
        assert!(!l.etc.exists(), "nothing is written on error");
        assert!(install_as(&[], &l, None).unwrap_err().contains("--key"));
    }

    #[test]
    fn unsafe_chain_aborts() {
        let d = tempfile::tempdir().unwrap();
        let l = Layout::under(d.path());
        fs::create_dir(&l.etc).unwrap();
        fs::set_permissions(&l.etc, fs::Permissions::from_mode(0o757)).unwrap();
        let (f, _) = pubkey(d.path(), "a.pub");
        let a = args(&[&"--key".into(), &f]);
        let e = install_as(&a, &l, Some("bob".into())).unwrap_err();
        assert!(e.contains("everyone"), "{e}");
        assert!(!l.libexec.exists() && !l.plist.exists());
    }

    #[test]
    fn read_key_accepts_only_plain_ed25519() {
        let d = tempfile::tempdir().unwrap();
        let (ok, k) = pubkey(d.path(), "ok.pub");
        assert!(read_key(Path::new(&ok)).unwrap().key_data() == k.key_data());

        let line = k.to_openssh().unwrap();
        let b64 = line.split_whitespace().nth(1).unwrap();
        let two = keyfile(d.path(), "two.pub", &format!("{line}\n{line}\n"));
        assert!(
            read_key(Path::new(&two))
                .unwrap_err()
                .contains("exactly one")
        );
        let empty = keyfile(d.path(), "empty.pub", "\n");
        assert!(read_key(Path::new(&empty)).is_err());

        let private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .unwrap()
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap();
        let p = keyfile(d.path(), "id", &private);
        assert!(read_key(Path::new(&p)).unwrap_err().contains("private"));

        let cert = keyfile(
            d.path(),
            "cert.pub",
            &format!("ssh-ed25519-cert-v01@openssh.com {b64} x\n"),
        );
        assert!(
            read_key(Path::new(&cert))
                .unwrap_err()
                .contains("certificate")
        );

        let rsa = keyfile(
            d.path(),
            "rsa.pub",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7 x\n",
        );
        assert!(read_key(Path::new(&rsa)).is_err());
        let sk = keyfile(
            d.path(),
            "sk.pub",
            &format!("sk-ssh-ed25519@openssh.com {b64} x\n"),
        );
        assert!(read_key(Path::new(&sk)).is_err());
        assert!(read_key(&d.path().join("missing")).is_err());
    }

    #[test]
    fn plist_comes_from_names() {
        let p = plist(Path::new("/x/y&z/susd"), Path::new("/s.sock"));
        assert!(p.contains(&format!("<string>{}</string>", names::LABEL)));
        assert!(p.contains("/x/y&amp;z/susd"));
        assert!(p.contains("<string>serve</string>"));
        assert!(p.contains("<string>/s.sock</string>"));
        assert!(p.contains("<integer>438</integer>"));
        assert!(p.contains(macos::LISTENER));
    }

    #[test]
    fn wait_until_polls_until_done_or_timeout() {
        let mut calls = 0;
        let ok = wait_until(Duration::from_secs(5), Duration::from_millis(1), || {
            calls += 1;
            calls == 3
        });
        assert!(ok);
        assert_eq!(calls, 3);

        let start = Instant::now();
        assert!(!wait_until(
            Duration::from_millis(50),
            Duration::from_millis(5),
            || false
        ));
        assert!(start.elapsed() >= Duration::from_millis(50));
    }

    #[test]
    fn ignored_hangups_survive_exec() {
        // In a forked child, so this process and its other tests keep their signals.
        // Built before fork: the child must not allocate.
        let sh = std::ffi::CString::new("/bin/sh").unwrap();
        let script = std::ffi::CString::new("kill -HUP $$; kill -TERM $$; exit 7").unwrap();
        let argv = [
            sh.as_ptr(),
            c"-c".as_ptr(),
            script.as_ptr(),
            std::ptr::null(),
        ];
        crate::macos::before_fork();
        // SAFETY: the child only calls async-signal-safe functions before exec/_exit.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                ignore_hangups();
                libc::execv(sh.as_ptr(), argv.as_ptr());
                libc::_exit(1);
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 7,
                "child status {status:#x}"
            );
        }
    }

    #[test]
    fn uninstall_twice() {
        let d = tempfile::tempdir().unwrap();
        let l = Layout::under(d.path());
        let (f, _) = pubkey(d.path(), "a.pub");
        install_as(&args(&[&"--key".into(), &f]), &l, Some("bob".into())).unwrap();
        fs::write(&l.socket, "").unwrap();
        uninstall(&l).unwrap();
        assert!(!l.libexec.exists() && !l.etc.exists());
        assert!(!l.plist.exists() && !l.socket.exists());
        uninstall(&l).unwrap();
    }
}
