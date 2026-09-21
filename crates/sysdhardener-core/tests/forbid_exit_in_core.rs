//! Compile-time + structural guarantee: `std::process::exit` never
//! appears inside the `sysdhardener-core` source tree.
//!
//! The typed process outcome is converted to a
//! numeric exit code only at the binary boundary; the library never
//! calls `std::process::exit` directly. Two layered guards enforce
//! this contract:
//!
//! 1. The workspace clippy lint `clippy::exit` is set to `deny`, so a
//!    stray `std::process::exit(...)` call fails `cargo clippy`.
//! 2. This integration test reads every `.rs` file under
//!    `crates/sysdhardener-core/src/` and asserts that no file
//!    mentions the forbidden symbol. This catches *any* future
//!    regression even if the source was refactored to dodge the
//!    clippy lint.
//!
//! If a future change legitimately needs the binary boundary to
//! terminate the process, the change must land in
//! `crates/sysdhardener-cli/` and use `ExitCode::from(u8)` instead
//! of `std::process::exit(...)`.

use std::fs;
use std::path::PathBuf;

const FORBIDDEN_TOKENS: &[&str] = &["std::process::exit", "process::exit("];

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect_rs_files(root: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_rs_files(&p, out);
        } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

fn assert_no_forbidden_tokens_in(file: &std::path::Path) {
    let Ok(bytes) = fs::read(file) else { return };
    let text = String::from_utf8_lossy(&bytes);
    for token in FORBIDDEN_TOKENS {
        assert!(
            !text.contains(token),
            "forbidden token {token:?} found in {}; sysdhardener-core must never call std::process::exit",
            file.display()
        );
    }
}

#[test]
fn no_std_process_exit_call_in_core_src() {
    let root = crate_dir().join("src");
    let mut files = Vec::new();
    collect_rs_files(&root, &mut files);
    assert!(!files.is_empty(), "src tree must contain at least one .rs");
    for file in &files {
        assert_no_forbidden_tokens_in(file);
    }
}
