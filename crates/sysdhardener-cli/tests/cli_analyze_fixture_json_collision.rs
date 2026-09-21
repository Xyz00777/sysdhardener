//! `--json <PATH>` sink-collision contract tests: a `--json` path
//! equal to a *selected* default sink's destination is a usage
//! error (exit 2, no files written); a path equal to a
//! *deselected* sink's destination is the caller's explicit choice
//! and is accepted.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap/panic for direct assertions on the boundary contract"
)]

mod common;

use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;

use common::{binary_path, fixture_path, unique_tempdir};

#[test]
fn json_path_colliding_with_selected_detailed_sink_is_rejected_with_exit_2() {
    // --json <PATH> equal to <output-dir>/findings.txt would
    // silently clobber the detailed sink's output (last-writer
    // wins); the binary must reject the collision as a usage
    // error instead of reporting success.
    let dir = unique_tempdir("json-detailed-collision");
    let colliding = dir.path().join("findings.txt");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--json")
        .arg(&colliding)
        .assert()
        .failure()
        .code(2)
        .stderr(
            predicate::str::contains("usage error").and(predicate::str::contains(
                "collides with the detailed output path",
            )),
        );
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("output dir readable")
        .filter_map(Result::ok)
        .collect();
    assert!(
        entries.is_empty(),
        "no output files may exist after a usage rejection, found: {entries:?}"
    );
}

#[test]
fn json_path_colliding_with_selected_concise_sink_is_rejected_with_exit_2() {
    let dir = unique_tempdir("json-concise-collision");
    let colliding = dir.path().join("hardening.conf");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--json")
        .arg(&colliding)
        .assert()
        .failure()
        .code(2)
        .stderr(
            predicate::str::contains("usage error").and(predicate::str::contains(
                "collides with the concise output path",
            )),
        );
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("output dir readable")
        .filter_map(Result::ok)
        .collect();
    assert!(
        entries.is_empty(),
        "no output files may be written on a usage rejection, found: {entries:?}"
    );
}

#[test]
fn json_path_matching_deselected_detailed_sink_is_accepted() {
    // Collision rejection only applies to *selected* sinks: with
    // --no-detailed the detailed sink is absent, so writing JSON
    // to <output-dir>/findings.txt is the caller's explicit choice.
    let dir = unique_tempdir("json-deselected-detailed");
    let colliding = dir.path().join("findings.txt");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--no-detailed")
        .arg("--json")
        .arg(&colliding)
        .assert()
        .success();
    let content = std::fs::read_to_string(&colliding).expect("json report readable");
    assert!(
        content.contains("schema_version"),
        "the json report must be written at the caller-chosen path"
    );
}

#[test]
fn lexical_path_variant_collision_is_rejected_with_exit_2() {
    // `--json <output-dir>/./findings.txt` is the same destination
    // as the selected detailed sink after lexical normalization; a
    // raw PathBuf equality check would let it through and silently
    // clobber the detailed output.
    let dir = unique_tempdir("json-lexical-collision");
    let colliding = dir.path().join(".").join("findings.txt");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--json")
        .arg(&colliding)
        .assert()
        .failure()
        .code(2)
        .stderr(
            predicate::str::contains("usage error").and(predicate::str::contains(
                "collides with the detailed output path",
            )),
        );
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("output dir readable")
        .filter_map(Result::ok)
        .collect();
    assert!(
        entries.is_empty(),
        "no output files may exist after a usage rejection, found: {entries:?}"
    );
}

#[test]
fn json_absolute_path_colliding_with_relative_output_dir_is_rejected_with_exit_2() {
    let cwd = std::env::current_dir().expect("cwd must resolve");
    let rel_dir = std::path::PathBuf::from("target/test-collision-rel-dir");
    let abs_json = cwd.join(&rel_dir).join("findings.txt");
    let _ = std::fs::remove_dir_all(&rel_dir);

    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(&rel_dir)
        .arg("--json")
        .arg(&abs_json)
        .assert()
        .failure()
        .code(2)
        .stderr(
            predicate::str::contains("usage error").and(predicate::str::contains(
                "collides with the detailed output path",
            )),
        );

    let _ = std::fs::remove_dir_all(&rel_dir);
}

#[test]
fn json_in_parent_dir_does_not_collide_with_relative_output_dir() {
    let rel_dir = std::path::PathBuf::from("target/test-non-collision-rel-dir");
    let non_colliding_json =
        std::path::PathBuf::from("target/test-non-collision-rel-dir/../other-findings.txt");
    let _ = std::fs::remove_dir_all(&rel_dir);
    let _ = std::fs::remove_file(&non_colliding_json);

    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(&rel_dir)
        .arg("--json")
        .arg(&non_colliding_json)
        .assert()
        .success();

    let _ = std::fs::remove_dir_all(&rel_dir);
    let _ = std::fs::remove_file(&non_colliding_json);
}
