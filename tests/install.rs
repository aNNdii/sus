//! `susd install`/`uninstall` refuse to run without root. The install logic itself is
//! tested in src/install.rs against a temp-dir `Layout`.

use std::process::Command;

#[test]
fn install_and_uninstall_need_root() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for cmd in ["install", "uninstall"] {
        let out = Command::new(env!("CARGO_BIN_EXE_susd"))
            .arg(cmd)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&out.stderr).contains("must run as root"));
    }
}
