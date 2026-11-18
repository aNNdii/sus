//! Every name the tool uses (binaries, socket, label, paths, namespace).
//! Renaming the tool starts with `name!` and the env prefix here; CONTRIBUTING.md
//! (Renaming) lists the other places.

macro_rules! name {
    () => {
        "sus"
    };
}

pub const NAME: &str = name!();
pub const CLIENT: &str = name!();
pub const DAEMON: &str = concat!(name!(), "d");
/// launchd label and log subsystem.
pub const LABEL: &str = concat!("io.github.anndii.", name!());
/// Log subsystem of the test mode (not root), so test runs never mix with the
/// audit of the installed service.
pub const LOG_TEST: &str = concat!("io.github.anndii.", name!(), ".test");
pub const SOCKET: &str = concat!("/var/run/", name!(), ".sock");
pub const LIBEXEC_DIR: &str = concat!("/usr/local/libexec/", name!());
pub const ETC_DIR: &str = concat!("/usr/local/etc/", name!());
pub const PLIST: &str = concat!(
    "/Library/LaunchDaemons/io.github.anndii.",
    name!(),
    ".plist"
);
/// SSHSIG namespace.
pub const NAMESPACE: &str = concat!(name!(), "@github.com/aNNdii");
/// Must equal `NAME.to_uppercase()` + `_SOCKET` (checked in tests/names.rs).
pub const ENV_SOCKET: &str = concat!("SUS", "_SOCKET");
pub const ENV_CONFIG: &str = concat!("SUS", "_CONFIG");
/// Relative to $HOME.
pub const BITWARDEN_AGENT: &str = ".bitwarden-ssh-agent.sock";
// SUDO_* variables are deliberately not here: they mimic sudo.
