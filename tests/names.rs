use std::path::Path;

use sus::names;

#[test]
fn binaries_are_named_after_names() {
    let client = Path::new(env!("CARGO_BIN_EXE_sus"));
    let daemon = Path::new(env!("CARGO_BIN_EXE_susd"));
    assert_eq!(client.file_name().unwrap(), names::CLIENT);
    assert_eq!(daemon.file_name().unwrap(), names::DAEMON);
}

#[test]
fn env_names_follow_name() {
    let upper = names::NAME.to_uppercase();
    assert_eq!(names::ENV_SOCKET, format!("{upper}_SOCKET"));
    assert_eq!(names::ENV_CONFIG, format!("{upper}_CONFIG"));
}

/// The name also lives outside src/names.rs; CONTRIBUTING.md's rename steps must say where.
#[test]
fn contributing_lists_every_place_to_rename() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let guide = std::fs::read_to_string(root.join("CONTRIBUTING.md")).unwrap();
    let missing: Vec<_> = [
        "src/names.rs",
        "Cargo.toml",
        "Cargo.lock",
        "src/bin/",
        "tests/",
        "docs/architecture.md",
        "dist-workspace.toml",
    ]
    .into_iter()
    .filter(|p| !root.join(p).exists() || !guide.contains(&format!("`{p}`")))
    .collect();
    assert!(
        missing.is_empty(),
        "CONTRIBUTING.md rename steps miss: {missing:?}"
    );
}

#[test]
fn no_name_literal_outside_names_rs() {
    fn walk(dir: &Path, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, hits);
            } else if path.extension().is_some_and(|e| e == "rs")
                && path.file_name().unwrap() != "names.rs"
            {
                let text = std::fs::read_to_string(&path).unwrap().to_lowercase();
                for lit in [
                    "\"sus",
                    "io.github.anndii",
                    "anndii",
                    "/var/run/",
                    "/usr/local/",
                ] {
                    if text.contains(lit) {
                        hits.push(format!("{}: {lit}", path.display()));
                    }
                }
            }
        }
    }
    let mut hits = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut hits,
    );
    assert!(hits.is_empty(), "name literals outside names.rs: {hits:?}");
}
