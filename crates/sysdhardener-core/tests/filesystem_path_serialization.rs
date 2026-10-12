//! Regression coverage for systemd-safe filesystem directive values.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests assert directly on public recommendation values"
)]

use sysdhardener_core::filesystem::{FsAccessEvent, FsAggregator, derive_filesystem_findings};
use sysdhardener_core::{Capability, CoverageQuality, EventOutcome};

fn read_write_paths_value(path: &str) -> String {
    let mut events = FsAggregator::new();
    events.record(FsAccessEvent::new(path, true, EventOutcome::Success));
    let findings =
        derive_filesystem_findings(&events, Capability::ExpectedRoot, CoverageQuality::Complete);
    findings
        .iter()
        .find(|finding| finding.directive() == "ReadWritePaths")
        .and_then(sysdhardener_core::Finding::recommended_value)
        .expect("accepted write emits a ReadWritePaths candidate")
        .to_owned()
}

#[test]
fn newline_filename_is_one_escaped_directive_value() {
    let value = read_write_paths_value("/home/alice/line\nbreak/dump.rdb");

    assert_eq!(value, "\"/home/alice/line\\nbreak\"");
    assert!(!value.contains('\n'));
}

#[test]
fn control_characters_are_escaped_in_the_path_token() {
    let value = read_write_paths_value("/var/app\t\r\u{1}\u{85}/data.db");

    assert_eq!(value, "\"/var/app\\t\\r\\x01\\u0085\"");
}

#[test]
fn literal_specifier_percent_is_doubled() {
    let value = read_write_paths_value("/home/alice/%h/data.db");

    assert_eq!(value, "/home/alice/%%h");
}

#[test]
fn quote_and_backslash_are_escaped_inside_quoted_path() {
    let value = read_write_paths_value("/var/my\"dir/with\\slash/file.db");

    assert_eq!(value, "\"/var/my\\\"dir/with\\\\slash\"");
}

#[test]
fn absolute_path_prefix_characters_remain_path_data() {
    let exclamation = read_write_paths_value("/var/!private/db");
    let plus = read_write_paths_value("/var/+private/db");
    let minus = read_write_paths_value("/var/-private/db");

    assert_eq!(exclamation, "/var/!private");
    assert_eq!(plus, "/var/+private");
    assert_eq!(minus, "/var/-private");
}
