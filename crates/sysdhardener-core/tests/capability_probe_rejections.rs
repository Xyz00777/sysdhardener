//! Capability-probe rejection tests: malformed or missing `Uid:` data
//! and unavailable status files produce typed failures that degrade to
//! `Capability::Unknown` without a panic. No malformed input is ever
//! classified as root or non-root.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the boundary contract"
)]

use sysdhardener_core::{
    Capability, ProbeError, parse_effective_uid, parse_status_visibility, read_proc_status,
};

#[test]
fn missing_uid_line_is_typed_and_unknown() {
    let text: &str = "Name:\tsystemd\nState:\tR (running)\n";
    assert_eq!(parse_status_visibility(text), Capability::Unknown);
    assert_eq!(
        parse_effective_uid(text).expect_err("missing Uid: line must be typed"),
        ProbeError::MissingUidLine
    );
}

#[test]
fn empty_text_is_typed_and_unknown() {
    assert_eq!(parse_status_visibility(""), Capability::Unknown);
    assert_eq!(
        parse_effective_uid("").expect_err("empty text must be typed"),
        ProbeError::MissingUidLine
    );
}

#[test]
fn non_numeric_effective_field_is_typed_and_unknown() {
    let text: &str = "Uid:\t0\tnot-a-number\t0\t0\n";
    assert_eq!(parse_status_visibility(text), Capability::Unknown);
    assert_eq!(
        parse_effective_uid(text).expect_err("non-numeric effective field must be typed"),
        ProbeError::MalformedUidLine
    );
}

#[test]
fn too_few_fields_is_typed_and_unknown() {
    let single: &str = "Uid:\t0\n";
    assert_eq!(parse_status_visibility(single), Capability::Unknown);
    assert_eq!(
        parse_effective_uid(single).expect_err("single-field Uid line must be typed"),
        ProbeError::MalformedUidLine
    );

    let bare: &str = "Uid:\n";
    assert_eq!(parse_status_visibility(bare), Capability::Unknown);
    assert_eq!(
        parse_effective_uid(bare).expect_err("field-less Uid line must be typed"),
        ProbeError::MalformedUidLine
    );
}

#[test]
fn overflowing_numeric_field_is_typed_and_unknown() {
    let text: &str = "Uid:\t0\t99999999999999999999\t0\t0\n";
    assert_eq!(parse_status_visibility(text), Capability::Unknown);
    assert_eq!(
        parse_effective_uid(text).expect_err("overflowing field must be typed"),
        ProbeError::MalformedUidLine
    );
}

#[test]
fn hex_and_signed_fields_are_not_recognized() {
    assert_eq!(
        parse_status_visibility("Uid:\t0\t0x0\t0\t0\n"),
        Capability::Unknown
    );
    assert_eq!(
        parse_status_visibility("Uid:\t0\t-1\t0\t0\n"),
        Capability::Unknown
    );
}

#[test]
fn unavailable_status_path_is_typed_and_unknown_at_capability_level() {
    let err: ProbeError = read_proc_status("/nonexistent/sysdhardener/status")
        .expect_err("unavailable status path must be a typed read failure");
    assert!(
        matches!(err, ProbeError::StatusUnreadable { .. }),
        "expected ProbeError::StatusUnreadable, got {err:?}"
    );
}

#[test]
fn malformed_input_never_classifies_as_root_or_nonroot() {
    for text in [
        "",
        "Name:\tsystemd\n",
        "Uid:\n",
        "Uid:\t0\n",
        "Uid:\t0\tnot-a-number\t0\t0\n",
        "Uid:\t0\t0x0\t0\t0\n",
        "Uid:\t0\t-1\t0\t0\n",
        "Uid:\t0\t99999999999999999999\t0\t0\n",
    ] {
        let parsed = parse_status_visibility(text);
        assert!(
            parsed == Capability::Unknown,
            "input {text:?} must degrade to Unknown, got {parsed:?}"
        );
    }
}
