//! Client and service end to end, the service in test mode on a temp socket.

mod common;

use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use common::{Agent, Key, Service, client, keygen, run, stderr, stdout, tmpdir};
use sus::names;

/// A service that allows me with key `a`, and an agent holding `a`.
struct World {
    dir: tempfile::TempDir,
    a: Key,
    agent: Agent,
    service: Service,
}

fn secure_path(dir: &Path) -> String {
    format!(
        "/usr/bin:/bin:/usr/sbin:/sbin:{}",
        dir.join("secure").display()
    )
}

fn world_with(users: &[&str], allowed: &[&str], in_agent: &[&str]) -> World {
    let dir = tmpdir();
    let keys: HashMap<&str, Key> = ["a", "b", "c"]
        .into_iter()
        .map(|n| (n, keygen(dir.path(), n)))
        .collect();
    let agent = Agent::start(dir.path().join("agent.sock"));
    for n in in_agent {
        agent.add(&keys[n]);
    }
    let allowed: Vec<&Key> = allowed.iter().map(|n| &keys[n]).collect();
    let service = Service::start(dir.path(), users, &allowed, &secure_path(dir.path()));
    let mut keys = keys;
    World {
        a: keys.remove("a").unwrap(),
        dir,
        agent,
        service,
    }
}

fn world() -> World {
    let me = common::me();
    world_with(&[&me], &["a"], &["a"])
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
}

fn exe(path: &Path, script: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn assert_one_line_failure(o: &std::process::Output, want: &str) {
    let err = stderr(o);
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    assert_eq!(err.lines().count(), 1, "{err:?}");
    assert!(err.contains(want), "{err:?} should contain {want:?}");
}

#[test]
fn stdin_and_stdout_belong_to_the_caller() {
    let w = world();
    let o = run(w.sus(&["cat"]), b"hi\n");
    assert_eq!(stdout(&o), "hi\n", "{o:?}");
    assert_eq!(o.status.code(), Some(0));
}

#[test]
fn exit_code_and_signal_come_back() {
    let w = world();
    let o = run(w.sus(&["sh", "-c", "echo oops >&2; exit 3"]), b"");
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    assert_eq!(stderr(&o), "oops\n");
    let o = run(w.sus(&["sh", "-c", "kill -TERM $$"]), b"");
    assert_eq!(o.status.code(), Some(128 + libc::SIGTERM), "{o:?}");
}

/// sudo-tests X2: a command killed by a signal leaves stderr to the command.
#[test]
fn command_killed_by_a_signal_adds_nothing_to_stderr() {
    let w = world();
    for (sig, name) in [(libc::SIGTERM, "TERM"), (libc::SIGKILL, "KILL")] {
        let o = run(w.sus(&["sh", "-c", &format!("kill -{name} $$")]), b"");
        assert_eq!(o.status.code(), Some(128 + sig), "{o:?}");
        assert_eq!(stderr(&o), "", "{o:?}");
        assert!(o.stdout.is_empty(), "{o:?}");
    }
}

/// sudo-tests M1: arguments arrive byte for byte, whatever they hold.
#[test]
fn arguments_arrive_byte_for_byte() {
    let w = world();
    let args: [&[u8]; 12] = [
        b"%s\\0",
        b"a\\",
        b"\\",
        b"",
        b"a b",
        b" ",
        b"\n",
        b"x\ny\n",
        b"\xff\xfe",
        b"--",
        b"-h",
        b"$HOME *",
    ];
    let args = args.map(OsStr::from_bytes);
    let mut cmd = w.sus(&["/usr/bin/printf"]);
    cmd.args(args);
    let o = run(cmd, b"");
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let direct = Command::new("/usr/bin/printf").args(args).output().unwrap();
    assert_eq!(o.stdout, direct.stdout);
    let mut want = Vec::new();
    for arg in &args[1..] {
        want.extend_from_slice(arg.as_bytes());
        want.push(0);
    }
    assert_eq!(o.stdout, want);
}

#[test]
fn env_is_reset_like_sudo() {
    let w = world();
    let mut cmd = w.sus(&["env"]);
    cmd.env("TERM", "xterm-test")
        .env("LC_ALL", "C")
        .env("COLORTERM", "%n%n")
        .env("LANG", "../../t")
        .env("LC_CTYPE", "() { :;}; echo x")
        .env("FOO", "bar")
        .env("DYLD_FALLBACK_LIBRARY_PATH", "/nonexistent")
        .env("SUDO_UID", "0");
    let o = run(cmd, b"");
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let got: HashMap<String, String> = stdout(&o)
        .lines()
        .map(|l| {
            let (k, v) = l.split_once('=').unwrap();
            (k.to_string(), v.to_string())
        })
        .collect();
    let want: HashMap<String, String> = [
        ("TERM", "xterm-test".to_string()),
        ("LC_ALL", "C".into()),
        ("PATH", secure_path(w.path())),
        ("HOME", "/var/root".into()),
        ("USER", "root".into()),
        ("LOGNAME", "root".into()),
        ("SHELL", "/bin/sh".into()),
        ("SUDO_USER", common::me()),
        ("SUDO_UID", common::id("-u")),
        ("SUDO_GID", common::id("-g")),
        ("SUDO_COMMAND", "/usr/bin/env".into()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    assert_eq!(got, want);
}

#[test]
fn command_gets_the_callers_umask_but_at_least_022() {
    // Like sudo: the caller's umask can only tighten the default 022.
    let w = world();
    for (caller, want) in [(0o002, "0022\n"), (0o077, "0077\n"), (0o027, "0027\n")] {
        let mut cmd = w.sus(&["sh", "-c", "umask"]);
        // SAFETY: umask is async-signal-safe and touches no memory of ours.
        unsafe {
            cmd.pre_exec(move || {
                libc::umask(caller);
                Ok(())
            });
        }
        let o = run(cmd, b"");
        assert_eq!(stdout(&o), want, "{o:?}");
    }
}

#[test]
fn large_argument_runs() {
    // argv and environment share ARG_MAX (1 MiB): a full copy of a 600 KB argv in
    // SUDO_COMMAND would make exec fail with E2BIG.
    let w = world();
    let big = "x".repeat(600_000);
    let o = run(w.sus(&["sh", "-c", "echo ${#1}", "_", &big]), b"");
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(stdout(&o), "600000\n");
}

#[test]
fn command_runs_in_the_callers_directory() {
    let w = world();
    let work = w.path().join("work");
    std::fs::create_dir(&work).unwrap();
    let mut cmd = w.sus(&["pwd"]);
    cmd.current_dir(&work);
    let o = run(cmd, b"");
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert_eq!(
        std::fs::canonicalize(stdout(&o).trim()).unwrap(),
        std::fs::canonicalize(&work).unwrap()
    );
}

#[test]
fn bare_names_use_secure_path_and_slashes_the_cwd() {
    let w = world();
    exe(&w.path().join("secure/mytool"), "echo secure");
    exe(&w.path().join("clientbin/clienttool"), "echo client");
    exe(&w.path().join("local.sh"), "echo local");

    let o = run(w.sus(&["mytool"]), b"");
    assert_eq!(stdout(&o), "secure\n", "{o:?}");
    let o = run(w.sus(&["./local.sh"]), b"");
    assert_eq!(stdout(&o), "local\n", "{o:?}");

    // On the caller's PATH but not on secure_path: nothing runs.
    let mut cmd = w.sus(&["clienttool"]);
    let path = format!("{}:/usr/bin:/bin", w.path().join("clientbin").display());
    cmd.env("PATH", path);
    let o = run(cmd, b"");
    assert_one_line_failure(&o, "not found");
    assert!(stdout(&o).is_empty());
}

#[test]
fn first_allowed_key_the_agent_has_is_used() {
    // The service offers a then b, the agent only has b.
    let me = common::me();
    let w = world_with(&[&me], &["a", "b"], &["b"]);
    let o = run(w.sus(&["sh", "-c", "echo ok"]), b"");
    assert_eq!(stdout(&o), "ok\n", "{o:?}");
}

#[test]
fn foreign_key_in_the_agent_runs_nothing() {
    let me = common::me();
    let w = world_with(&[&me], &["a"], &["b", "c"]);
    let marker = w.path().join("marker");
    let o = run(w.sus(&["touch", marker.to_str().unwrap()]), b"");
    assert_one_line_failure(&o, "no allowed key");
    assert!(!marker.exists());
}

#[test]
fn another_users_key_in_the_agent_runs_nothing() {
    // root may use b, I may use a; the agent has only b.
    let me = common::me();
    let dir = tmpdir();
    let (a, b) = (keygen(dir.path(), "a"), keygen(dir.path(), "b"));
    let agent = Agent::start(dir.path().join("agent.sock"));
    agent.add(&b);
    let service = Service::start_users(
        dir.path(),
        &[(me.as_str(), &[&a]), ("root", &[&b])],
        &secure_path(dir.path()),
    );
    let marker = dir.path().join("marker");
    let mut cmd = client(dir.path(), &["touch", marker.to_str().unwrap()]);
    cmd.env(names::ENV_SOCKET, &service.socket)
        .env("SSH_AUTH_SOCK", &agent.socket);
    let o = run(cmd, b"");
    assert_one_line_failure(&o, "no allowed key");
    assert!(!marker.exists());
}

#[test]
fn caller_not_in_users_is_refused_before_the_agent_is_asked() {
    let w = world_with(&["root"], &["a"], &["a"]);
    let marker = w.path().join("marker");
    let mut cmd = w.sus(&["touch", marker.to_str().unwrap()]);
    cmd.env_remove("SSH_AUTH_SOCK");
    let o = run(cmd, b"");
    assert_one_line_failure(&o, "not allowed");
    assert!(!marker.exists());
}

#[test]
fn socket_of_another_owner_is_not_trusted() {
    let w = world();
    // A root-owned socket that every Mac has.
    let foreign = "/var/run/mDNSResponder";
    assert!(Path::new(foreign).exists());
    let mut cmd = w.sus(&["true"]);
    cmd.env(names::ENV_SOCKET, foreign);
    let o = run(cmd, b"");
    assert_one_line_failure(&o, "owned by uid 0");
}

#[test]
fn something_else_than_a_socket_is_not_trusted() {
    let w = world();
    let file = w.path().join("plain");
    std::fs::write(&file, "").unwrap();
    let mut cmd = w.sus(&["true"]);
    cmd.env(names::ENV_SOCKET, &file);
    let o = run(cmd, b"");
    assert_one_line_failure(&o, "not a socket");
}

#[test]
fn no_service_fails_in_one_line() {
    let w = world();
    let mut cmd = w.sus(&["true"]);
    cmd.env(names::ENV_SOCKET, w.path().join("nothing.sock"));
    let o = run(cmd, b"");
    assert_one_line_failure(&o, "service not installed");
}

#[test]
fn too_many_arguments_fail_before_the_service_is_asked() {
    // MAX_ARGS + 1 empty arguments. The socket does not exist and there is no
    // agent: the size check must come first.
    let dir = tmpdir();
    let args = vec![""; 65_537];
    let mut cmd = client(dir.path(), &args);
    cmd.env(names::ENV_SOCKET, dir.path().join("nothing.sock"));
    let o = run(cmd, b"");
    assert_one_line_failure(&o, "argument list too long");
}

#[test]
fn no_agent_fails_in_one_line() {
    let w = world();
    let mut cmd = w.sus(&["true"]);
    cmd.env_remove("SSH_AUTH_SOCK");
    let o = run(cmd, b"");
    assert_one_line_failure(&o, "SSH agent");
}

#[test]
fn bitwarden_agent_is_the_fallback() {
    let w = world();
    let bitwarden = Agent::start(w.path().join(names::BITWARDEN_AGENT));
    bitwarden.add(&w.a);
    let mut cmd = w.sus(&["sh", "-c", "echo ok"]);
    cmd.env_remove("SSH_AUTH_SOCK");
    let o = run(cmd, b"");
    assert_eq!(stdout(&o), "ok\n", "{o:?}");
}

#[test]
fn empty_arguments_print_usage() {
    let w = world();
    let o = run(w.sus(&[]), b"");
    assert_one_line_failure(&o, "usage");
}
