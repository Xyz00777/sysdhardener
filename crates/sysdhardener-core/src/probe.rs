//! Real Linux effective-UID capability probe plus typed read/parse
//! failures and a deterministic test double.
//!
//! The probe reads `/proc/self/status`, parses the `Uid:` line, and
//! classifies the process as [`Capability::ExpectedRoot`] when the
//! *effective* UID is 0, [`Capability::DegradedNonRoot`] otherwise,
//! and [`Capability::Unknown`] when the status file cannot be read
//! or its `Uid:` line is malformed. The probe never pretends root
//! from unreadable or malformed data, never falls back to a
//! fabricated value, and cannot fail the deterministic analysis —
//! every failure degrades to [`Capability::Unknown`].
//!
//! The parser ([`parse_effective_uid`], [`parse_status_visibility`])
//! and reader ([`read_proc_status`]) are public and pure: they take
//! text or a path and return typed values, so tests can inject
//! root, non-root, malformed, and unavailable observations without
//! touching the host process or `/proc`.

use std::fs;

use crate::ports::{Capability, CapabilityProbe};

/// Typed failure of the `/proc/self/status` reader or parser.
///
/// The probe itself maps every failure to [`Capability::Unknown`]; the
/// typed discriminant exists so tests and diagnostics can distinguish
/// *why* the classification is unknown.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeError {
    /// The status file could not be read from the filesystem.
    #[error("status file could not be read: {context}")]
    StatusUnreadable {
        /// A short, stable description of the IO failure.
        context: String,
    },
    /// The status text contained no `Uid:` field at all.
    #[error("status text has no Uid: line")]
    MissingUidLine,
    /// A `Uid:` line was present but its effective-UID field was
    /// absent or not a decimal `u32`.
    #[error("status text Uid: line is malformed")]
    MalformedUidLine,
}

/// The effective UID parsed from a status file's `Uid:` line.
///
/// A distinct semantic primitive from a bare `u32`: only a
/// successfully parsed effective UID can be classified, and only
/// `is_root()` decides the visibility classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EffectiveUid(u32);

impl EffectiveUid {
    /// Whether the effective UID is root (0).
    #[must_use]
    pub const fn is_root(self) -> bool {
        self.0 == 0
    }

    /// The raw numeric effective-UID value.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// Parse the effective UID from `/proc/self/status` text.
///
/// The `Uid:` line carries four fields — real, effective, saved, and
/// filesystem UIDs. The *effective* field (the second) is the
/// discriminator: a process whose real UID is 0 but whose effective
/// UID is not 0 is not classified as root. The first matching
/// `Uid:` line wins; leading whitespace is tolerated; CRLF line
/// terminators are accepted; every other line is ignored.
///
/// # Errors
/// Returns [`ProbeError::MissingUidLine`] when no `Uid:` field
/// exists, and [`ProbeError::MalformedUidLine`] when the effective
/// field is absent or not a decimal `u32` (including overflow).
pub fn parse_effective_uid(status_text: &str) -> Result<EffectiveUid, ProbeError> {
    for line in status_text.lines() {
        let trimmed: &str = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("Uid:") else {
            continue;
        };
        let effective: &str = rest
            .split_whitespace()
            .nth(1)
            .ok_or(ProbeError::MalformedUidLine)?;
        let uid: u32 = effective
            .parse()
            .map_err(|_| ProbeError::MalformedUidLine)?;
        return Ok(EffectiveUid(uid));
    }
    Err(ProbeError::MissingUidLine)
}

/// Classify process visibility from `/proc/self/status` text.
///
/// Root effective UID yields [`Capability::ExpectedRoot`], any
/// non-root effective UID yields [`Capability::DegradedNonRoot`],
/// and unreadable or malformed input degrades to
/// [`Capability::Unknown`] — never to a fabricated root or non-root
/// claim.
#[must_use]
pub fn parse_status_visibility(status_text: &str) -> Capability {
    match parse_effective_uid(status_text) {
        Ok(uid) if uid.is_root() => Capability::ExpectedRoot,
        Ok(_) => Capability::DegradedNonRoot,
        Err(_) => Capability::Unknown,
    }
}

/// Read a status file's text from a caller-supplied path.
///
/// The path is caller-supplied so tests can inject unavailable paths;
/// the real probe calls this with `/proc/self/status`.
///
/// # Errors
/// Returns [`ProbeError::StatusUnreadable`] when the path cannot be
/// read (missing file, permission, non-UTF-8 content, etc.).
pub fn read_proc_status(path: &str) -> Result<String, ProbeError> {
    fs::read_to_string(path).map_err(|e| ProbeError::StatusUnreadable {
        context: format!("failed to read status file: {e}"),
    })
}

/// The real Linux capability probe: reads `/proc/self/status` for
/// the current process and classifies its effective-UID visibility.
///
/// The probe is a unit value with no state; every call performs a
/// fresh read so the classification reflects the current process.
/// Read or parse failure degrades to [`Capability::Unknown`]; the
/// probe never pretends root and never fails the deterministic
/// analysis.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcStatusCapabilityProbe;

impl CapabilityProbe for ProcStatusCapabilityProbe {
    fn visibility(&self) -> Capability {
        read_proc_status("/proc/self/status")
            .map_or(Capability::Unknown, |text| parse_status_visibility(&text))
    }
}

/// A deterministic [`CapabilityProbe`] fake for tests.
///
/// Compiled only under the `testing` feature, enabled with
/// `--features testing` or the workspace's `--all-features` gates.
/// Off by default so production builds never carry test doubles.
#[cfg(feature = "testing")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedCapabilityProbe {
    visibility: Capability,
}

#[cfg(feature = "testing")]
impl FixedCapabilityProbe {
    /// Build a fake probe that always reports `visibility`.
    ///
    /// The same instance reports the same [`Capability`] for every
    /// call, independent of the host process or `/proc`.
    #[must_use]
    pub const fn new(visibility: Capability) -> Self {
        Self { visibility }
    }
}

#[cfg(feature = "testing")]
impl CapabilityProbe for FixedCapabilityProbe {
    fn visibility(&self) -> Capability {
        self.visibility
    }
}
