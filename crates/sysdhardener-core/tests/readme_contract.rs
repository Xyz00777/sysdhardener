//! `README` claim contract + relative-link checker.
//!
//! The `README` must describe the live-observer implementation
//! without stale fixture-only claims, without claiming deferred
//! interposition is resolved, without auto-apply or
//! installation instructions, and without claiming any external gate
//! is resolved. This test rejects any of those
//! claims and additionally verifies that every relative markdown
//! link in the `README` and the combined schema doc resolves to an
//! existing file in the repository.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap for direct assertions on the boundary contract"
)]

use std::path::{Path, PathBuf};

const README: &str = include_str!("../../../README.md");
const SCHEMAS_DOC: &str = include_str!("../../../docs/schemas.md");

const REQUIRED_README_MARKERS: &[&str] = &[
    "recommendation",
    "observe",
    "analyze-fixture",
    "never applies",
    "ptrace",
    "deferred",
    "unverified",
    "exit codes",
];

const FORBIDDEN_README_MARKERS: &[&str] = &[
    "no implementation",
    "no source code",
    "zero source code",
    "not runnable",
    "no production test suite",
    "automatically applies",
    "gates are resolved",
    "professor-approved",
    "baseline verified",
    "installation",
    "automatically applies hardening",
];

#[test]
fn readme_keeps_required_claim_markers() {
    let readme = README.to_ascii_lowercase();
    for marker in REQUIRED_README_MARKERS {
        assert!(
            readme.contains(marker),
            "README must keep the claim marker {marker:?}; it is part of the first-executable \
             status contract (recommendation-only, no live observation, deferred gates, \
             unverified baseline)"
        );
    }
}

#[test]
fn readme_rejects_stale_or_overclaiming_markers() {
    let readme = README.to_ascii_lowercase();
    for marker in FORBIDDEN_README_MARKERS {
        assert!(
            !readme.contains(marker),
            "README must not contain the stale or overclaiming marker {marker:?}"
        );
    }
}

#[test]
fn schema_docs_are_markdown_not_json_schema() {
    let (name, doc) = ("schemas.md", SCHEMAS_DOC);
    let lower = doc.to_ascii_lowercase();
    assert!(
        lower.contains("markdown prose, not a machine-readable json schema"),
        "{name} must state it is Markdown prose, not a machine-readable JSON Schema"
    );
}

fn repo_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("cargo sets CARGO_MANIFEST_DIR for integration tests");
    let crate_dir = PathBuf::from(manifest_dir);
    crate_dir
        .parent()
        .and_then(Path::parent)
        .expect("crate dir must sit two levels below the repository root")
        .to_path_buf()
}

fn extract_link_targets(md: &str) -> Vec<&str> {
    let mut targets: Vec<&str> = Vec::new();
    for line in md.lines() {
        let mut rest = line;
        while let Some(at) = rest.find("](") {
            let url_start = at + 2;
            let tail = rest
                .get(url_start..)
                .expect("find() returns a valid char boundary");
            let Some(rel_end) = tail.find(')') else {
                break;
            };
            let url = tail
                .get(..rel_end)
                .expect("find() returns a valid char boundary");
            targets.push(url);
            rest = rest
                .get(url_start + rel_end..)
                .expect("boundaries derived from find() are valid");
        }
    }
    targets
}

fn relative_targets(targets: Vec<&str>) -> Vec<&str> {
    targets
        .into_iter()
        .filter(|target| {
            !target.starts_with('#')
                && !target.starts_with("http://")
                && !target.starts_with("https://")
                && !target.starts_with("mailto:")
        })
        .collect()
}

fn extract_code_span_paths(md: &str) -> Vec<&str> {
    const REPO_ROOT_ANCHORS: &[&str] = &[
        "crates/",
        "docs/",
        "nix/",
        "scripts/",
        ".omo/",
        "flake.nix",
        "flake.lock",
        "default.nix",
        "Cargo.toml",
        "deny.toml",
        "rustfmt.toml",
        "clippy.toml",
        "rust-toolchain.toml",
        ".envrc",
        ".gitignore",
        "README.md",
    ];
    let mut paths: Vec<&str> = Vec::new();
    for line in md.lines() {
        let mut rest = line;
        while let Some(start) = rest.find('`') {
            let content_start = start + 1;
            let tail = rest
                .get(content_start..)
                .expect("find() returns a valid char boundary");
            let Some(end) = tail.find('`') else {
                break;
            };
            let span = tail
                .get(..end)
                .expect("find() returns a valid char boundary");
            if REPO_ROOT_ANCHORS
                .iter()
                .any(|anchor| span.starts_with(anchor))
            {
                paths.push(span);
            }
            rest = tail
                .get(end + 1..)
                .expect("boundaries derived from find() are valid");
        }
    }
    paths
}

#[test]
fn every_code_span_repo_path_resolves() {
    let root = repo_root();
    for (name, doc) in [("README.md", README), ("docs/schemas.md", SCHEMAS_DOC)] {
        for span in extract_code_span_paths(doc) {
            let path_only = span.split('#').next().unwrap_or(span);
            let resolved = root.join(path_only);
            assert!(
                resolved.exists(),
                "{name} code span {span:?} refers to a repository path that does not resolve ({})",
                resolved.display()
            );
        }
    }
}

#[test]
fn every_relative_link_resolves() {
    let root = repo_root();
    for (name, doc) in [("README.md", README), ("docs/schemas.md", SCHEMAS_DOC)] {
        for target in relative_targets(extract_link_targets(doc)) {
            let path_only = target.split('#').next().unwrap_or(target);
            if path_only.is_empty() {
                continue;
            }
            let resolved = root.join(path_only);
            assert!(
                resolved.exists(),
                "{name} links to {target:?} which does not resolve ({})",
                resolved.display()
            );
        }
    }
}
