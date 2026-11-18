//! One audit entry per request (AC13) and an invalid config (AC12), end to end.
//! The entries are read from the service's stderr mirror (test mode).

mod common;

use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Output;
use std::time::{Duration, Instant};

use common::{Agent, Key, Service, client, keygen, run, stderr, tmpdir};
use sus::names;

struct World {
    dir: tempfile::TempDir,
    agent: Agent,
    service: Service,
}

/// A service that allows `users` with key `a`; the agent holds `in_agent`.
fn world(users: &[&str], in_agent: &str) -> World {
    let dir = tmpdir();
    let a = keygen(dir.path(), "a");
    let b = keygen(dir.path(), "b");
    let agent = Agent::start(dir.path().join("agent.sock"));
    agent.add(if in_agent == "a" { &a } else { &b });
    let keys: Vec<&Key> = vec![&a];
    let service = Service::start(dir.path(), users, &keys, "/usr/bin:/bin");
    World {
        dir,
        agent,
        service,
    }
}

impl World {
    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn sus(&self, args: &[&OsStr]) -> Output {
        let mut cmd = client(self.path(), &[]);
        cmd.args(args)
            .env(names::ENV_SOCKET, &self.service.socket)
            .env("SSH_AUTH_SOCK", &self.agent.socket);
        run(cmd, b"")
    }

    /// The audit lines the service wrote so far. A line still being written
    /// (no newline yet) is left out: stderr writes it in several pieces.
    fn audit(&self) -> Vec<String> {
        let log = std::fs::read(self.path().join("service.log")).unwrap();
        String::from_utf8_lossy(&log)
            .split_inclusive('\n')
            .filter_map(|l| l.strip_suffix('\n'))
            .filter(|l| l.contains(" audit "))
            .map(str::to_string)
            .collect()
    }

    /// Whether one request's trail is fully written: its last part (`part=k/k`).
    fn has_finished_entry(&self) -> bool {
        self.audit().iter().any(|l| {
            l.split_once(" part=")
                .and_then(|(_, p)| p.split_once(' '))
                .and_then(|(n, _)| n.split_once('/'))
                .is_some_and(|(i, k)| i == k)
        })
    }

    /// One per request: the first entry and its argv parts joined, in order.
    fn entries(&self) -> Vec<Entry> {
        let mut out: Vec<(String, Entry)> = Vec::new();
        for line in self.audit() {
            let text = line.split_once(" audit ").unwrap().1;
            let (req, rest) = text.split_once(' ').unwrap();
            if let Some(part) = rest.strip_prefix("part=") {
                let (n, chunk) = part.split_once(" argv=").unwrap();
                let (_, e) = out.iter_mut().find(|(r, _)| r == req).expect(&line);
                e.parts += 1;
                assert!(n.starts_with(&format!("{}/", e.parts)), "{line}");
                e.argv.push_str(chunk);
            } else {
                let head = text.to_string();
                out.push((
                    req.to_string(),
                    Entry {
                        head,
                        argv: String::new(),
                        parts: 0,
                    },
                ));
            }
        }
        out.into_iter()
            .map(|(_, e)| {
                assert!(
                    e.head.ends_with(&format!(" parts={}", e.parts)),
                    "{}",
                    e.head
                );
                e
            })
            .collect()
    }
}

/// One request's audit trail.
struct Entry {
    /// The first entry: the fixed fields.
    head: String,
    /// The masked argv, reassembled from its parts.
    argv: String,
    parts: usize,
}

fn os(s: &str) -> &OsStr {
    OsStr::new(s)
}

#[test]
fn allowed_request_has_one_entry_with_public_fields() {
    let me = common::me();
    let w = world(&[&me], "a");
    let o = w.sus(&[os("/bin/echo"), os("hi there")]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let entries = w.entries();
    assert_eq!(entries.len(), 1, "{:?}", w.audit());
    let head = &entries[0].head;
    assert!(
        head.contains(&format!(" uid={} ", common::id("-u"))),
        "{head}"
    );
    assert!(head.contains(" pid="), "{head}");
    assert!(head.contains("result=allowed"), "{head}");
    assert!(head.contains(" argc=2 argv_bytes=18 "), "{head}");
    assert_eq!(entries[0].argv, r#"["/bin/echo" "hi there"]"#);
    for line in w.audit() {
        assert!(
            !line.contains("SSH SIGNATURE") && !line.contains("U1NIU0lH"),
            "{line}"
        );
    }
}

/// `SHA256:…` of the key in `dir/name.pub`, as `ssh-keygen -l` prints it.
fn fingerprint(dir: &Path, name: &str) -> String {
    let line = std::fs::read_to_string(dir.join(format!("{name}.pub"))).unwrap();
    ssh_key::PublicKey::from_openssh(line.trim())
        .unwrap()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string()
}

#[test]
fn entry_says_which_key_where_and_what_ran() {
    let me = common::me();
    let w = world(&[&me], "a");
    // A bare name: the entry shows what secure_path made of it.
    let o = w.sus(&[os("echo"), os("hi")]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let entries = w.entries();
    assert_eq!(entries.len(), 1, "{:?}", w.audit());
    let head = &entries[0].head;
    let want = format!(
        " key={} cwd=\"{}\" command=\"/bin/echo\" argc=2 ",
        fingerprint(w.path(), "a"),
        // The client sends the cwd as getcwd sees it: /var is /private/var.
        w.path().canonicalize().unwrap().display()
    );
    assert!(head.contains(&want), "{head}\nwant {want}");
}

#[test]
fn denied_after_the_signature_keeps_key_and_cwd() {
    let me = common::me();
    let w = world(&[&me], "a");
    let o = w.sus(&[os("no-such-command-xyz")]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    let head = &w.entries()[0].head;
    assert!(
        head.contains(&format!(" key={} ", fingerprint(w.path(), "a"))),
        "{head}"
    );
    let cwd = w.path().canonicalize().unwrap();
    assert!(
        head.contains(&format!(" cwd=\"{}\" ", cwd.display())),
        "{head}"
    );
    // Nothing resolved, so no command.
    assert!(!head.contains(" command="), "{head}");
}

#[test]
fn long_argv_survives_the_log_limit() {
    // The unified log cuts a message after about 1 KiB (AC13).
    let me = common::me();
    let w = world(&[&me], "a");
    let script = format!("true {}; echo HIDDENTAIL", "x".repeat(1100));
    let o = w.sus(&[os("/bin/sh"), os("-c"), os(&script)]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let lines = w.audit();
    for line in &lines {
        let text = line.split_once(" audit ").unwrap().1;
        assert!(text.len() < 1000, "{} bytes: {text}", text.len());
    }
    let entries = w.entries();
    assert_eq!(entries.len(), 1, "{lines:?}");
    assert!(entries[0].parts >= 2, "{lines:?}");
    assert!(entries[0].head.contains(" argc=3 "), "{}", entries[0].head);
    assert_eq!(entries[0].argv, format!(r#"["/bin/sh" "-c" "{script}"]"#));
}

#[test]
fn client_that_hangs_up_after_hello_has_one_abandoned_entry() {
    // Collecting nonce and key list must leave a trace too.
    let me = common::me();
    let w = world(&[&me], "a");
    let mut s = UnixStream::connect(&w.service.socket).unwrap();
    let mut first = [0u8; 1];
    s.read_exact(&mut first).unwrap();
    drop(s);
    // The service notices the hang-up asynchronously and writes the trail line by line.
    let end = Instant::now() + Duration::from_secs(5);
    while !w.has_finished_entry() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
    let entries = w.entries();
    assert_eq!(entries.len(), 1, "{:?}", w.audit());
    let head = &entries[0].head;
    assert!(head.contains("result=abandoned"), "{head}");
    assert!(
        head.contains(&format!(" uid={} ", common::id("-u"))),
        "{head}"
    );
    assert!(head.contains(" argc=0 "), "{head}");
}

#[test]
fn unprintable_bytes_are_masked() {
    let me = common::me();
    let w = world(&[&me], "a");
    let arg = OsStr::from_bytes(b"a\x01b\x1b[0m\"q\"\xff");
    let o = w.sus(&[os("/bin/echo"), arg]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let entries = w.entries();
    assert_eq!(entries.len(), 1, "{:?}", w.audit());
    assert_eq!(entries[0].argv, r#"["/bin/echo" "a\x01b\x1b[0m\"q\"\xff"]"#);
    for line in w.audit() {
        assert!(line.bytes().all(|b| (0x20..0x7f).contains(&b)), "{line}");
    }
}

#[test]
fn caller_not_in_users_has_one_denied_entry() {
    // Not in users.
    let w = world(&["root"], "a");
    let o = w.sus(&[os("/bin/echo"), os("x")]);
    assert_eq!(o.status.code(), Some(1));
    let entries = w.entries();
    assert_eq!(entries.len(), 1, "{:?}", w.audit());
    assert!(
        entries[0].head.contains("result=denied"),
        "{}",
        entries[0].head
    );
    assert!(
        entries[0].head.contains("is not allowed"),
        "{}",
        entries[0].head
    );
}

#[test]
fn unknown_user_in_config_is_logged_by_the_service() {
    // A typo in `users` must not vanish: launchd drops stderr, so the service logs it.
    let me = common::me();
    let w = world(&[&me, "no-such-user-xyz"], "a");
    let o = w.sus(&[os("/bin/echo"), os("x")]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let log = std::fs::read_to_string(w.path().join("service.log")).unwrap();
    let warning = format!(
        "{}: warning: unknown user \"no-such-user-xyz\"",
        names::DAEMON
    );
    assert!(log.contains(&warning), "{log}");
    assert_eq!(w.entries().len(), 1, "{:?}", w.audit());
}

#[test]
fn command_that_cannot_start_is_denied() {
    let me = common::me();
    let w = world(&[&me], "a");
    let o = w.sus(&[os("no-such-command-xyz")]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    let entries = w.entries();
    assert_eq!(entries.len(), 1, "{:?}", w.audit());
    assert!(
        entries[0].head.contains("result=denied"),
        "{}",
        entries[0].head
    );
    assert_eq!(entries[0].argv, r#"["no-such-command-xyz"]"#);
}

#[test]
fn invalid_config_is_refused_audited_and_the_service_lives_on() {
    let me = common::me();
    let w = world(&[&me], "a");
    let config = w.path().join("config.toml");
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o666)).unwrap();

    let o = w.sus(&[os("/bin/echo"), os("x")]);
    assert_eq!(o.status.code(), Some(1));
    let err = stderr(&o);
    assert!(err.contains("service config invalid:"), "{err}");
    let entries = w.entries();
    assert_eq!(entries.len(), 1, "{:?}", w.audit());
    assert!(
        entries[0].head.contains("result=denied"),
        "{}",
        entries[0].head
    );
    assert!(
        entries[0].head.contains("service config invalid"),
        "{}",
        entries[0].head
    );

    // Fixed file: the same service runs the command.
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let o = w.sus(&[os("/bin/echo"), os("x")]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(w.entries().len(), 2);
}
