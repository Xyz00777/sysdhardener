//! Narrative failure/bound E2E scenarios: the
//! release binary driven through the public CLI only, asserting
//! machine-consumed exit codes, stderr discriminant fields, and
//! residue-free output directories.
//!
//! Covered here: invalid-schema exit 3 with an empty output dir,
//! two simultaneous sink failures preserving the remaining
//! success, TRACE boundedness with identical artifacts, and the
//! absence of any auto-apply/install surface.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap/panic for direct assertions on the boundary contract"
)]

mod common;

use std::ffi::OsStr;

use common::{dir_entries, fixture_path, run_bin, unique_tempdir};

#[test]
fn invalid_schema_exits_three_with_empty_output_dir() {
    let dir = unique_tempdir("narrative-invalid-schema");
    let json_path = dir.path().join("report.json");
    let outcome = run_bin(&[
        OsStr::new("analyze-fixture"),
        fixture_path("unknown-schema.json").as_os_str(),
        OsStr::new("--output-dir"),
        dir.path().as_os_str(),
        OsStr::new("--json"),
        json_path.as_os_str(),
    ]);
    assert_eq!(
        outcome.code,
        Some(3),
        "invalid schema must map to exit 3, stderr: {}",
        outcome.stderr
    );
    assert_eq!(
        dir_entries(dir.path()),
        Vec::<String>::new(),
        "input rejection must leave zero residue in the output dir"
    );
}

#[test]
fn two_simultaneous_sink_failures_preserve_the_remaining_success() {
    let dir = unique_tempdir("narrative-dual-sink");
    // Block the detailed and JSON destinations with existing
    // directories; only the concise sink can succeed.
    std::fs::create_dir(dir.path().join("findings.txt")).expect("blocker dir creatable");
    std::fs::create_dir(dir.path().join("report.json")).expect("blocker dir creatable");
    let outcome = run_bin(&[
        OsStr::new("analyze-fixture"),
        fixture_path("happy.json").as_os_str(),
        OsStr::new("--output-dir"),
        dir.path().as_os_str(),
        OsStr::new("--json"),
        dir.path().join("report.json").as_os_str(),
    ]);
    assert_eq!(
        outcome.code,
        Some(5),
        "any selected sink failure must map to exit 5, stderr: {}",
        outcome.stderr
    );
    assert!(
        outcome
            .stderr
            .contains("sink: failed output sink detailed failed at"),
        "stderr must carry the detailed failure discriminant, got: {}",
        outcome.stderr
    );
    assert!(
        outcome
            .stderr
            .contains("sink: failed output sink json failed at"),
        "stderr must carry the json failure discriminant, got: {}",
        outcome.stderr
    );
    assert!(
        outcome.stderr.contains("sink: ok concise"),
        "stderr must carry the concise success discriminant, got: {}",
        outcome.stderr
    );
    assert_eq!(
        dir_entries(dir.path()),
        vec!["findings.txt", "hardening.conf", "report.json"],
        "no hidden temp residue may survive a partial failure"
    );

    // The preserved success must be byte-identical to the same
    // invocation run with the blockers removed.
    let clean_dir = unique_tempdir("narrative-dual-sink-clean");
    let outcome = run_bin(&[
        OsStr::new("analyze-fixture"),
        fixture_path("happy.json").as_os_str(),
        OsStr::new("--output-dir"),
        clean_dir.path().as_os_str(),
        OsStr::new("--json"),
        clean_dir.path().join("report.json").as_os_str(),
    ]);
    assert_eq!(outcome.code, Some(0), "stderr: {}", outcome.stderr);
    let preserved = std::fs::read(dir.path().join("hardening.conf")).expect("preserved concise");
    let expected =
        std::fs::read(clean_dir.path().join("hardening.conf")).expect("clean concise readable");
    assert_eq!(
        preserved, expected,
        "the concise success must be preserved byte-for-byte on partial failure"
    );
}

#[test]
fn trace_cap_emits_truncation_fields_and_identical_artifacts() {
    let capped_dir = unique_tempdir("narrative-trace-cap");
    let baseline_dir = unique_tempdir("narrative-trace-baseline");
    let capped_json = capped_dir.path().join("report.json");
    let baseline_json = baseline_dir.path().join("report.json");
    let happy = fixture_path("happy.json");
    let capped_args = vec![
        OsStr::new("analyze-fixture"),
        happy.as_os_str(),
        OsStr::new("--output-dir"),
        capped_dir.path().as_os_str(),
        OsStr::new("--json"),
        capped_json.as_os_str(),
        OsStr::new("--verbose"),
        OsStr::new("trace"),
        OsStr::new("--max-raw-events"),
        OsStr::new("2"),
    ];
    let capped = run_bin(&capped_args);
    assert_eq!(capped.code, Some(0), "stderr: {}", capped.stderr);

    let raw_events_path = capped_dir.path().join("raw-events.log");
    assert!(raw_events_path.is_file(), "raw-events.log must be written");
    let raw_events = std::fs::read_to_string(&raw_events_path).expect("read raw-events.log");

    let event_lines = raw_events
        .lines()
        .filter(|line| line.contains("event_index="))
        .count();
    assert_eq!(
        event_lines, 2,
        "exactly the capped number of raw events, got: {raw_events}"
    );
    assert!(
        !raw_events.contains("event_index=2"),
        "the raw-event bound must be enforced, got: {raw_events}"
    );
    assert!(
        raw_events.contains("truncated=true")
            && raw_events.contains("logged=2")
            && raw_events.contains("total=3")
            && raw_events.contains("cap=2"),
        "truncation must carry machine fields, got: {raw_events}"
    );
    assert!(
        !capped.stderr.contains("event_index="),
        "stderr must not be flooded with raw events, got: {}",
        capped.stderr
    );

    let baseline_args = vec![
        OsStr::new("analyze-fixture"),
        happy.as_os_str(),
        OsStr::new("--output-dir"),
        baseline_dir.path().as_os_str(),
        OsStr::new("--json"),
        baseline_json.as_os_str(),
    ];
    let baseline = run_bin(&baseline_args);
    assert_eq!(baseline.code, Some(0), "stderr: {}", baseline.stderr);

    for artifact in ["findings.txt", "hardening.conf", "report.json"] {
        let capped_bytes =
            std::fs::read(capped_dir.path().join(artifact)).expect("capped artifact readable");
        let baseline_bytes =
            std::fs::read(baseline_dir.path().join(artifact)).expect("baseline artifact readable");
        assert_eq!(
            capped_bytes, baseline_bytes,
            "verbosity is a dial, not a confidence input: {artifact} must be byte-identical"
        );
    }
}

#[test]
fn binary_surface_exposes_no_auto_apply_or_install_command() {
    let help = run_bin(&[OsStr::new("--help")]);
    assert_eq!(help.code, Some(0), "stderr: {}", help.stderr);
    let names = subcommand_names(&help.stdout);
    let mut expected = vec!["analyze-fixture", "observe", "attach", "help"];
    // The eBPF observation mode is compiled only when the feature is
    // enabled; the default binary does not carry it.
    if cfg!(feature = "bpf-observe") {
        expected.insert(3, "bpf-observe");
    }
    assert_eq!(
        names, expected,
        "the only subcommands are the analyzer, the observer, the attacher, clap's help, and (feature-gated) bpf-observe: {names:?}"
    );

    let sub_help = run_bin(&[OsStr::new("analyze-fixture"), OsStr::new("--help")]);
    assert_eq!(sub_help.code, Some(0), "stderr: {}", sub_help.stderr);
    assert!(
        sub_help.stdout.contains("--output-dir")
            && sub_help.stdout.contains("--json")
            && sub_help.stdout.contains("--no-detailed")
            && sub_help.stdout.contains("--no-concise")
            && sub_help.stdout.contains("--max-trace-events")
            && sub_help.stdout.contains("--trace-file")
            && sub_help.stdout.contains("--verbose"),
        "the option surface must match the documented flags, got: {}",
        sub_help.stdout
    );
    assert!(
        !contains_word(&help.stdout, "apply") && !contains_word(&help.stdout, "install"),
        "no auto-apply or install surface may appear in the top-level help"
    );
    assert!(
        !contains_word(&sub_help.stdout, "apply") && !contains_word(&sub_help.stdout, "install"),
        "no auto-apply or install surface may appear in the analyze-fixture help"
    );
}

/// Extract the subcommand names from a `--help` stdout dump: the
/// lines under the `Commands:` heading up to the next heading, each
/// tokenized on the leading two-space indentation.
fn subcommand_names(help_stdout: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_commands = false;
    for line in help_stdout.lines() {
        if line.trim_start().starts_with("Commands:") {
            in_commands = true;
            continue;
        }
        if in_commands && line.trim_start().starts_with("Options:") {
            break;
        }
        if in_commands && line.starts_with("  ") {
            if let Some(name) = line.split_whitespace().next() {
                names.push(name.to_owned());
            }
        }
    }
    names
}

/// Whether `text` contains `word` as a whole word.
fn contains_word(text: &str, word: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|token| token.eq_ignore_ascii_case(word))
}
