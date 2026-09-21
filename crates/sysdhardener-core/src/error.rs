//! Typed library error for the deterministic evidence pipeline.
//!
//! Every failure at the input boundary is a discriminant that the binary
//! maps to a process outcome (or the library consumer maps to a UI
//! decision). Each variant carries the data a consumer needs to react
//! without parsing prose. The enum is `#[non_exhaustive]` so future
//! variants can be added without breaking the binary's match.

use std::fmt;
use std::path::PathBuf;

use thiserror::Error;

use crate::fixture::AddressFamily;
use crate::source_id::SourceId;

/// Fixture schema versions this build of the library currently
/// accepts.
///
/// Kept as a `const` so the value is the single source of truth for
/// both the [`Error::SchemaUnknown`] discriminant and the parser guard.
pub const SUPPORTED_FIXTURE_SCHEMA: &[u32] = &[1];
/// The set of report schema versions this build of the library currently
/// accepts.
pub const SUPPORTED_REPORT_SCHEMA: &[u32] = &[1];

/// Typed library error variants.
///
/// Each variant is a discriminant. No variant is a catch-all; the only
/// "shape" variant carries the underlying [`serde_json`] error code
/// path so the consumer can react.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The wire envelope carried a `schema_version` outside the
    /// supported set. Carries the actual value found and the supported
    /// list as data, never as prose.
    #[error("unsupported schema version {found}; supported: {supported:?}")]
    SchemaUnknown {
        /// The schema version found in the wire envelope.
        found: u32,
        /// The list of schema versions the library accepts.
        supported: &'static [u32],
    },

    /// A `source_id` did not match the `SRC-NN` shape. The string is
    /// carried for diagnostic display, but the discriminant alone is
    /// what the consumer matches on.
    #[error("malformed source_id {0:?}; expected SRC-NN with NN a non-empty digit sequence")]
    SourceIdMalformed(String),

    /// The fixture's `first_timestamp_unix_ms` is greater than
    /// `last_timestamp_unix_ms`. Equal values are accepted as a
    /// zero-width window.
    #[error(
        "fixture window reversed: first_timestamp_unix_ms={first_unix_ms} > last_timestamp_unix_ms={last_unix_ms}"
    )]
    TimestampReversed {
        /// The first timestamp from the wire envelope.
        first_unix_ms: i64,
        /// The last timestamp from the wire envelope.
        last_unix_ms: i64,
    },

    /// An event carried an `address_family` tag outside the typed set.
    #[error("unknown address_family tag {0:?}")]
    AddressFamilyUnknown(String),

    /// An event carried an `outcome` tag outside the typed set.
    #[error("unknown event outcome tag {0:?}")]
    EventOutcomeUnknown(String),

    /// A fixture's `coverage` tag is outside the typed set.
    #[error("unknown coverage tag {0:?}")]
    CoverageTagUnknown(String),

    /// A required fixture field was absent or had the wrong type.
    #[error("required fixture field {field:?} is missing")]
    FixtureFieldMissing {
        /// The field name that was missing.
        field: &'static str,
    },

    /// A required report field was absent or had the wrong type.
    #[error("required report field {field:?} is missing")]
    ReportFieldMissing {
        /// The field name that was missing.
        field: &'static str,
    },

    /// A fixture's `seen_events` count does not match the actual
    /// number of entries in the `events` array. The wire contract
    /// requires the declared count and the actual events agree;
    /// disagreement is rejected without a silent fallback.
    #[error("fixture event-count mismatch: seen_events={declared} but events[] length={actual}")]
    EventCountMismatch {
        /// The value declared in the wire envelope.
        declared: u32,
        /// The actual length of the `events` array.
        actual: u32,
    },

    /// A fixture's `dropped_events` count is greater than its
    /// `seen_events` count. The observer cannot drop more events
    /// than it observed, so this claim is logically impossible
    /// and is rejected at the boundary.
    #[error(
        "fixture event-loss claim is inconsistent: dropped_events={dropped} > seen_events={seen}"
    )]
    EventLossInconsistent {
        /// The declared `seen_events` count.
        seen: u32,
        /// The declared `dropped_events` count.
        dropped: u32,
    },

    /// Two events in a single fixture share the same `event_id`.
    /// Each event must be uniquely identifiable; duplicate IDs
    /// are rejected with this discriminant so a downstream
    /// deduplication invariant cannot be silently violated.
    #[error("fixture event_id {event_id:?} is duplicated at index {second_index}")]
    EventIdDuplicate {
        /// The duplicated `event_id` value.
        event_id: String,
        /// The first index where the duplicate was first seen.
        first_index: u32,
        /// The second index where the duplicate reappeared.
        second_index: u32,
    },

    /// A fixture's `events[]` entry carried an empty `event_id`.
    /// An empty ID is unidentifiable and is rejected at the
    /// boundary.
    #[error("fixture event at index {index} carries an empty event_id")]
    EventIdEmpty {
        /// The index of the event with the empty `event_id`.
        index: u32,
    },

    /// The fixture could not be loaded from the filesystem. Carries
    /// a stable, redacted path description (no host paths leak in
    /// the typed discriminant).
    #[error("fixture could not be loaded: {context}")]
    Io {
        /// A short, stable description of the IO failure.
        context: String,
    },

    /// The caller-selected `--output-dir` could not be created (or
    /// already exists as a non-directory). The binary creates the
    /// directory once before driving the file sinks; a failure here
    /// means no sink can possibly write, so it is a processing-phase
    /// failure (exit 4), not a per-sink partial failure (exit 5).
    #[error("output directory could not be created: {context}")]
    OutputDirUnavailable {
        /// A short, stable description of the `create_dir_all` failure.
        context: String,
    },

    /// The wire bytes were not parseable as JSON. Carries a 1-based line
    /// and column when [`serde_json`] reported them.
    #[error("malformed JSON at line {line}, column {column}")]
    JsonSyntax {
        /// 1-based line number, or 0 if the underlying error did not report one.
        line: usize,
        /// 1-based column number, or 0 if the underlying error did not report one.
        column: usize,
    },

    /// A serde-deserialize error that did not match a more specific
    /// discriminant. Carries a short, stable category tag.
    #[error("fixture/report JSON shape error: {0}")]
    JsonShape(String),

    /// The report envelope could not be serialized to wire bytes
    /// during the processing phase. Distinct from [`Error::JsonShape`],
    /// which is an *input-boundary* rejection (exit 3); this variant
    /// is a *processing-phase* failure (exit 4). In practice
    /// `serde_json` cannot fail on the plain report struct, but the
    /// type system must carry the phase distinction so a future
    /// typed findings surface does not silently downgrade a
    /// processing failure to "invalid input".
    #[error("report envelope serialization failed: {0}")]
    ReportSerialize(String),

    /// A compatibility record (or its `VersionFact::Verified`
    /// evidence) references a `SourceId` that is shape-valid but
    /// not present in the compiled registry allowlist. Carries the
    /// offending `SourceId` for diagnostic display.
    #[error(
        "compatibility evidence references unknown source {0:?}; SRC-NN must be in the registry"
    )]
    CompatibilityUnknownSource(SourceId),

    /// The concise projection cannot derive a setting line for a
    /// finding's `recommended_families`. This is the deterministic
    /// consequence of an input whose observed evidence produced an
    /// empty allow-list: the recommendation rule recommends exactly
    /// the families whose *first* observed event carried a `success`
    /// outcome. The variant carries the actual recommended
    /// allow-list as data, plus the finding index that identifies
    /// the offending input finding (or `None` for an empty input,
    /// where the projection has no finding to link the
    /// warning-only surface to).
    #[error(
        "cannot derive a RestrictAddressFamilies= setting: the recommended allow-list {recommended:?} is empty (finding_index={finding_index:?})"
    )]
    UnlinkedConciseSetting {
        /// The recommended allow-list that could not be rendered
        /// (the finding's `recommended_families`).
        recommended: Vec<AddressFamily>,
        /// The index of the offending finding, or `None` for an
        /// empty input.
        finding_index: Option<usize>,
    },

    /// An `OutputSink` write failed during its create / write /
    /// flush sequence. Carries the sink's stable name, the
    /// destination path, and the categorized failure kind. The
    /// caller maps the presence of any `SinkWriteFailed`
    /// in the partial-failure list to exit code 5 and continues
    /// with the remaining selected sinks. There is no retry, no
    /// rollback, and no deletion of successful outputs.
    #[error("output sink {sink} failed at {path:?}: {kind}")]
    SinkWriteFailed {
        /// The sink's stable name (`"detailed"`, `"concise"`,
        /// `"json"`, or another registered sink).
        sink: &'static str,
        /// The destination path the sink attempted to write.
        path: PathBuf,
        /// The categorized create / write / flush failure.
        kind: SinkWriteFailure,
    },
}

/// Categorized create / write / flush failure surfaced by an
/// `OutputSink`. The `io` field carries the underlying
/// `std::io::Error` `Display` text; consumers match on the
/// discriminant alone.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SinkWriteFailure {
    /// `File::create` (or the equivalent open-for-write) failed.
    Create {
        /// The underlying `std::io::Error` `Display` text.
        io: String,
    },
    /// `File::write_all` failed mid-write.
    Write {
        /// The underlying `std::io::Error` `Display` text.
        io: String,
    },
    /// `File::flush` (or the final `sync_all`) failed.
    Flush {
        /// The underlying `std::io::Error` `Display` text.
        io: String,
    },
    /// The destination path is a directory, not a file. The
    /// `File::create` step refuses to clobber a directory; the
    /// sink surfaces this as a distinct discriminant so the
    /// caller can tell "directory" from "permission denied" from
    /// "missing parent".
    PathIsDirectory {
        /// The underlying `std::io::Error` `Display` text.
        io: String,
    },
    /// The destination path is a symbolic link. The sink opens the
    /// destination with `O_NOFOLLOW` so a pre-placed symlink in an
    /// attacker-writable directory cannot redirect the write (the
    /// tool is expected to run as root, where symlink-following
    /// writes would clobber an arbitrary host path).
    Symlink {
        /// The underlying `std::io::Error` `Display` text.
        io: String,
    },
}

impl fmt::Display for SinkWriteFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create { io } => write!(formatter, "create failed: {io}"),
            Self::Write { io } => write!(formatter, "write failed: {io}"),
            Self::Flush { io } => write!(formatter, "flush failed: {io}"),
            Self::PathIsDirectory { io } => {
                write!(formatter, "destination is a directory: {io}")
            }
            Self::Symlink { io } => {
                write!(formatter, "destination is a symbolic link: {io}")
            }
        }
    }
}
