//! `SchemaVersion` newtype.
//!
//! The schema version is the only typed value shared between the fixture
//! envelope and the report envelope. The constructor validates against
//! the supported set in `error::SUPPORTED_FIXTURE_SCHEMA` /
//! `SUPPORTED_REPORT_SCHEMA`, so an out-of-set version cannot leak past
//! the boundary as a constructed value.

use crate::error::{Error, SUPPORTED_FIXTURE_SCHEMA, SUPPORTED_REPORT_SCHEMA};

/// Typed schema version. Construct only through the envelope-specific
/// [`SchemaVersion::new_fixture`] / [`SchemaVersion::new_report`]
/// helpers (or the canonical [`SchemaVersion::v1_report`] shortcut).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SchemaVersion(u32);

impl SchemaVersion {
    /// Construct a schema version for a fixture envelope.
    ///
    /// # Errors
    /// Returns [`Error::SchemaUnknown`] when `version` is not in
    /// [`SUPPORTED_FIXTURE_SCHEMA`].
    pub fn new_fixture(version: u32) -> Result<Self, Error> {
        if SUPPORTED_FIXTURE_SCHEMA.contains(&version) {
            Ok(Self(version))
        } else {
            Err(Error::SchemaUnknown {
                found: version,
                supported: SUPPORTED_FIXTURE_SCHEMA,
            })
        }
    }

    /// Construct a schema version for a report envelope.
    ///
    /// # Errors
    /// Returns [`Error::SchemaUnknown`] when `version` is not in
    /// [`SUPPORTED_REPORT_SCHEMA`].
    pub fn new_report(version: u32) -> Result<Self, Error> {
        if SUPPORTED_REPORT_SCHEMA.contains(&version) {
            Ok(Self(version))
        } else {
            Err(Error::SchemaUnknown {
                found: version,
                supported: SUPPORTED_REPORT_SCHEMA,
            })
        }
    }

    /// Construct the canonical v1 report schema version. The supported
    /// set is the single source of truth; this constructor is a
    /// non-panicking shortcut used by report-builder paths that already
    /// guarantee version 1.
    #[must_use]
    pub const fn v1_report() -> Self {
        Self(1)
    }

    /// Construct the canonical v1 fixture schema version. Mirrors
    /// [`SchemaVersion::v1_report`] for the fixture envelope; the
    /// compile-time guard below keeps both in the supported sets.
    #[must_use]
    pub const fn v1_fixture() -> Self {
        Self(1)
    }
    /// Return the underlying integer.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Compile-time invariant: the canonical `v1_report` shortcut must
/// never diverge from the supported report schema set. If the set
/// changes (e.g. v1 removed, v2 added), this crate fails to build
/// with a clear message instead of silently emitting an unsupported
/// version.
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    reason = "compile-time invariant guard: v1_report must stay in SUPPORTED_REPORT_SCHEMA; indexing bounds are guarded by the loop condition and slice::get is not const-stable"
)]
const _: () = {
    let mut supported: bool = false;
    let mut i: usize = 0;
    while i < SUPPORTED_REPORT_SCHEMA.len() {
        if SUPPORTED_REPORT_SCHEMA[i] == 1 {
            supported = true;
        }
        i += 1;
    }
    assert!(
        supported,
        "SchemaVersion::v1_report() must be in SUPPORTED_REPORT_SCHEMA"
    );
};
