//! End-to-end harness: a throwaway ssh-agent, throwaway keys and the service in
//! test mode on a temp socket (`geteuid() != 0`), all under `$TMPDIR`.

use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sus::names;

/// Longest a single client run may take before the test fails.
const RUN_LIMIT: Duration = Duration::from_secs(30);

pub fn tmpdir() -> tempfile::TempDir {
    // $TMPDIR, never /tmp: the service checks ownership and modes.
    tempfile::tempdir().unwrap()
}

fn wait_for(path: &Path) {
    let end = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < end, "{} did not appear", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// `id <flag>`, e.g. `-u` for the uid.
pub fn id(flag: &str) -> String {
    let out = Command::new("id").arg(flag).output().unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

pub fn me() -> String {
    id("-un")
}

/// A throwaway Ed25519 key pair made by ssh-keygen.
pub struct Key {
    pub private: PathBuf,
    pub public: String,
}

pub fn keygen(dir: &Path, name: &str) -> Key {
    let private = dir.join(name);
    let ok = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", name, "-f"])
        .arg(&private)
        .status()
        .unwrap()
        .success();
    assert!(ok, "ssh-keygen failed");
    let public = std::fs::read_to_string(private.with_extension("pub")).unwrap();
    Key {
        private,
        public: public.trim().to_string(),
    }
}

/// An `ssh-agent -D` of its own, stopped on drop.
pub struct Agent {
    pub socket: PathBuf,
    child: Child,
}

impl Agent {
    pub fn start(socket: PathBuf) -> Agent {
        Agent::start_with(socket, &[])
    }

    /// With extra env, e.g. `SSH_ASKPASS` for keys added with `-c`.
    pub fn start_with(socket: PathBuf, env: &[(&str, &OsStr)]) -> Agent {
        let child = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .envs(env.iter().copied())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        wait_for(&socket);
        Agent { socket, child }
    }

    pub fn add(&self, key: &Key) {
        self.add_with(key, &[]);
    }

    /// With extra `ssh-add` flags, e.g. `-c` to confirm every use.
    pub fn add_with(&self, key: &Key, flags: &[&str]) {
        let ok = Command::new("ssh-add")
            .arg("-q")
            .args(flags)
            .arg(&key.private)
            .env("SSH_AUTH_SOCK", &self.socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success();
        assert!(ok, "ssh-add failed");
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The service in test mode on `dir/service.sock` with `dir/config.toml`, stopped on drop.
pub struct Service {
    pub socket: PathBuf,
    /// For tests that signal or wait for the service themselves.
    pub child: Child,
}

impl Service {
    /// Every user in `users` may sign with every key in `keys`.
    pub fn start(dir: &Path, users: &[&str], keys: &[&Key], secure_path: &str) -> Service {
        let pairs: Vec<(&str, &[&Key])> = users.iter().map(|u| (*u, keys)).collect();
        Service::start_users(dir, &pairs, secure_path)
    }

    /// Each user with the keys that may sign for it.
    pub fn start_users(dir: &Path, users: &[(&str, &[&Key])], secure_path: &str) -> Service {
        let config = dir.join("config.toml");
        let table: toml::Table = users
            .iter()
            .map(|(u, keys)| {
                let lines = keys.iter().map(|k| k.public.clone().into()).collect();
                (u.to_string(), toml::Value::Array(lines))
            })
            .collect();
        let mut t = toml::Table::new();
        t.insert("users".into(), table.into());
        t.insert("secure_path".into(), secure_path.into());
        std::fs::write(&config, toml::to_string(&t).unwrap()).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();

        let socket = dir.join("service.sock");
        let log = std::fs::File::create(dir.join("service.log")).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_susd"))
            .arg("serve")
            .env(names::ENV_SOCKET, &socket)
            .env(names::ENV_CONFIG, &config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        wait_for(&socket);
        Service { socket, child }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The client with a clean environment: only `HOME` and a minimal `PATH`.
/// Add `SUS_SOCKET`, `SSH_AUTH_SOCK` and the rest per test.
pub fn client(home: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sus"));
    cmd.args(args)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(home);
    cmd
}

/// Runs `cmd` with `input` on stdin; fails the test if it takes longer than RUN_LIMIT.
pub fn run(mut cmd: Command, input: &[u8]) -> Output {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input).unwrap();
    drop(stdin);
    let pid = child.id() as libc::pid_t;
    let (done, finished) = mpsc::channel::<()>();
    let watchdog = std::thread::spawn(move || {
        if finished.recv_timeout(RUN_LIMIT).is_err() {
            // SAFETY: the child is not reaped yet, so the pid is still ours.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            return true;
        }
        false
    });
    let out = child.wait_with_output().unwrap();
    let _ = done.send(());
    assert!(!watchdog.join().unwrap(), "client hung: {out:?}");
    out
}

#[allow(
    dead_code,
    reason = "used by tests/run.rs and tests/signals.rs, not by every test binary \
              that includes this module (e.g. tests/audit.rs)"
)]
pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}
