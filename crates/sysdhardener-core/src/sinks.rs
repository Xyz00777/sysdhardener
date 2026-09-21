//! Three independent `OutputSink` file adapters.
//!
//! Each adapter receives completed projection / report data at
//! construction time and writes it to a caller-selected path. The
//! three adapters are independent: each sink is constructed, named,
//! and written in isolation, with no shared state and no shared
//! destination.
//!
//! - [`DetailedFileSink`] writes the human-readable detailed
//!   findings list, one entry per line, with every typed label the
//!   projection exposes (basis, families, coverage, event loss,
//!   contradiction conditions, compatibility risk, validation
//!   procedure, source IDs, aggregate keys).
//! - [`ConciseFileSink`] writes the concise projection: the
//!   single [`CONCISE_WARNING`] line followed by exactly one
//!   setting line per finding. The concise view is the
//!   projection's lines, joined by `\n` and terminated by a
//!   trailing newline.
//! - [`JsonFileSink`] writes the report envelope v1 (see
//!   [`serialize_report_v1`]) byte-for-byte, preserving every
//!   typed provenance / uncertainty field through the wire
//!   round-trip.
//!
//! Each adapter's [`OutputSink::write`] runs a
//! create / `write_all` / `sync_all` sequence against the
//! caller-selected path. The three failures are surfaced as
//! distinct discriminants on the
//! [`Error::SinkWriteFailed::kind`] field, so the caller
//! can match on the kind without parsing prose. The
//! adapter does not re-read the file to "verify" the write:
//! the file system's successful return from `write_all` and
//! `sync_all` is the contract.

use std::fs::File;
use std::io::{BufWriter, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;

use crate::error::{Error, SinkWriteFailure};
use crate::finding::Finding;
use crate::ports::OutputSink;
use crate::report::{Report, serialize_report_v1};
use crate::sinks_render::{render_concise, render_detailed};

/// A sink that writes the detailed findings list to a file.
#[derive(Debug)]
pub struct DetailedFileSink {
    path: PathBuf,
    bytes: Vec<u8>,
}

impl DetailedFileSink {
    /// Build a `DetailedFileSink` that will render the given
    /// findings as the detailed text and write them to `path`.
    /// Construction serializes the findings immediately so the
    /// sink owns its bytes; the [`OutputSink::write`] call only
    /// performs I/O.
    #[must_use]
    pub fn new(path: &std::path::Path, findings: &[Finding]) -> Self {
        let projection = crate::projection::project_detailed(findings);
        let bytes = render_detailed(&projection, &[], &[], &[]);
        Self {
            path: path.to_path_buf(),
            bytes,
        }
    }

    /// Build a `DetailedFileSink` that also renders the pids of the
    /// processes that produced the evidence and the known observation
    /// gaps (live-observer mode). Pid attribution and gaps are
    /// opt-in: callers that do not want them pass empty slices.
    #[must_use]
    pub fn new_with_pids(
        path: &std::path::Path,
        findings: &[Finding],
        pids: &[i32],
        known_gaps: &[&str],
        cgroups: &[String],
    ) -> Self {
        let projection = crate::projection::project_detailed(findings);
        let bytes = render_detailed(&projection, pids, known_gaps, cgroups);
        Self {
            path: path.to_path_buf(),
            bytes,
        }
    }
}

impl DetailedFileSink {
    /// The destination path the sink writes to.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl OutputSink for DetailedFileSink {
    fn write(&self) -> Result<(), Error> {
        write_bytes(&self.path, "detailed", &self.bytes)
    }
    fn name(&self) -> &'static str {
        "detailed"
    }
    fn destination(&self) -> PathBuf {
        self.path.clone()
    }
}

/// A sink that writes the concise recommended-settings output to
/// a file.
#[derive(Debug)]
pub struct ConciseFileSink {
    path: PathBuf,
    bytes: Vec<u8>,
}

impl ConciseFileSink {
    /// Build a `ConciseFileSink` that will render the given
    /// findings as the concise text and write them to `path`.
    /// The concise text is the
    /// [`crate::projection::project_concise`] output: the single
    /// warning line followed by exactly one setting line per
    /// finding.
    ///
    /// # Errors
    /// Returns [`Error::UnlinkedConciseSetting`] if the concise
    /// projection would emit a setting that does not map to a
    /// finding's `recommended_families`. The sink refuses to be
    /// constructed with an unlinkable projection; the caller maps
    /// this rejection to the same typed discriminant.
    pub fn new(path: &std::path::Path, findings: &[Finding]) -> Result<Self, Error> {
        let projection = crate::projection::project_concise(findings)?;
        let bytes = render_concise(&projection);
        Ok(Self {
            path: path.to_path_buf(),
            bytes,
        })
    }

    /// Build a `ConciseFileSink` directly from an existing [`crate::projection::ConciseProjection`].
    #[must_use]
    pub fn from_projection(
        path: &std::path::Path,
        projection: &crate::projection::ConciseProjection,
    ) -> Self {
        let bytes = render_concise(projection);
        Self {
            path: path.to_path_buf(),
            bytes,
        }
    }
}

impl ConciseFileSink {
    /// The destination path the sink writes to.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl OutputSink for ConciseFileSink {
    fn write(&self) -> Result<(), Error> {
        write_bytes(&self.path, "concise", &self.bytes)
    }
    fn name(&self) -> &'static str {
        "concise"
    }
    fn destination(&self) -> PathBuf {
        self.path.clone()
    }
}

/// A sink that writes the report envelope v1 JSON to a file.
#[derive(Debug)]
pub struct JsonFileSink {
    path: PathBuf,
    bytes: Vec<u8>,
}

impl JsonFileSink {
    /// Build a `JsonFileSink` from already-serialized report
    /// envelope v1 wire bytes. Construction stores the bytes; the
    /// [`OutputSink::write`] call only performs I/O.
    #[must_use]
    pub fn from_bytes(path: &std::path::Path, bytes: Vec<u8>) -> Self {
        Self {
            path: path.to_path_buf(),
            bytes,
        }
    }

    /// Build a `JsonFileSink` that will serialize the given report
    /// as report envelope v1 wire bytes and write them to `path`.
    /// The bytes are produced by [`serialize_report_v1`] at
    /// construction time.
    ///
    /// # Errors
    /// Returns [`Error::SchemaUnknown`] if the report carries an
    /// unsupported schema version, or [`Error::ReportSerialize`] if
    /// `serde_json` itself fails.
    pub fn new(path: &std::path::Path, report: &Report<'_>) -> Result<Self, Error> {
        let bytes: Vec<u8> = serialize_report_v1(report)?;
        Ok(Self {
            path: path.to_path_buf(),
            bytes,
        })
    }
}

impl JsonFileSink {
    /// The destination path the sink writes to.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl OutputSink for JsonFileSink {
    fn write(&self) -> Result<(), Error> {
        write_bytes(&self.path, "json", &self.bytes)
    }
    fn name(&self) -> &'static str {
        "json"
    }
    fn destination(&self) -> PathBuf {
        self.path.clone()
    }
}

/// Open the destination file and write the pre-serialized bytes,
/// flushing the file before returning. Each step surfaces its
/// failure as a distinct `SinkWriteFailure` discriminant so the
/// caller can tell create from write from flush from "destination
/// is a directory". The successful return from `sync_all` is the
/// only verification; the sink does not re-read the file.
///
/// The destination is opened with `O_NOFOLLOW` so a pre-placed
/// symlink in an attacker-writable directory cannot redirect the
/// write. The tool is expected to run as root, where a symlink-
/// following write would clobber an arbitrary host path.
fn write_bytes(path: &std::path::Path, sink: &'static str, bytes: &[u8]) -> Result<(), Error> {
    let file: File = open_destination(path).map_err(|error| Error::SinkWriteFailed {
        sink,
        path: path.to_path_buf(),
        kind: classify_open_failure(path, &error),
    })?;
    let mut writer = BufWriter::new(file);
    writer
        .write_all(bytes)
        .map_err(|error| Error::SinkWriteFailed {
            sink,
            path: path.to_path_buf(),
            kind: SinkWriteFailure::Write {
                io: error.to_string(),
            },
        })?;
    let file = writer
        .into_inner()
        .map_err(|error| Error::SinkWriteFailed {
            sink,
            path: path.to_path_buf(),
            kind: SinkWriteFailure::Flush {
                io: format!("writer into_inner: {error}"),
            },
        })?;
    file.sync_all().map_err(|error| Error::SinkWriteFailed {
        sink,
        path: path.to_path_buf(),
        kind: SinkWriteFailure::Flush {
            io: error.to_string(),
        },
    })?;
    Ok(())
}

/// Open the destination for write with `O_NOFOLLOW`.
/// `File::create` follows symlinks; the explicit `OpenOptions` with
/// `O_NOFOLLOW` (via `libc`) refuses to follow one. A pre-existing
/// regular file is truncated and rewritten (idempotent re-run), so
/// the open mirrors `File::create` semantics minus symlink-following.
fn open_destination(path: &std::path::Path) -> std::io::Result<File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// Classify an open failure into the categorized [`SinkWriteFailure`].
/// The destination is re-stat'ed (non-following) so a symlink and a
/// directory are told apart from the generic create failure.
fn classify_open_failure(path: &std::path::Path, error: &std::io::Error) -> SinkWriteFailure {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => SinkWriteFailure::Symlink {
            io: error.to_string(),
        },
        Ok(metadata) if metadata.is_dir() => SinkWriteFailure::PathIsDirectory {
            io: error.to_string(),
        },
        _ => SinkWriteFailure::Create {
            io: error.to_string(),
        },
    }
}
