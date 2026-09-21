//! `SourceId` newtype.
//!
//! A source ID is the deduplicated stable handle for a research source,
//! normalized to the shape `SRC-NN` where `NN` is a non-empty sequence
//! of ASCII digits. The constructor is the only way to build one; an
//! invalid string is rejected with [`Error::SourceIdMalformed`].

use std::borrow::Cow;

use serde::Serialize;

use crate::error::Error;

/// A validated, deduplicated research source identifier.
///
/// Construction enforces the `SRC-NN` shape; the type system guarantees
/// every `SourceId` you receive from a parsed fixture or from a library
/// constructor matches the contract. The internal `Cow<'static, str>`
/// lets the compiled registry allowlist embed `Borrowed(&'static str)`
/// values without runtime allocation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct SourceId(Cow<'static, str>);

impl SourceId {
    /// The required prefix for every [`SourceId`].
    pub const PREFIX: &'static str = "SRC-";

    /// Parse and validate a source ID string. The returned `SourceId`
    /// owns a copy of `raw`; for a borrowed `'static` literal use
    /// [`SourceId::from_static`].
    ///
    /// # Errors
    /// Returns [`Error::SourceIdMalformed`] when `raw` is not exactly
    /// `SRC-` followed by one or more ASCII digits.
    pub fn parse(raw: &str) -> Result<Self, Error> {
        if Self::const_looks_valid(raw) {
            Ok(Self(Cow::Owned(raw.to_owned())))
        } else {
            Err(Error::SourceIdMalformed(raw.to_owned()))
        }
    }

    /// Build a `SourceId` from a string literal whose shape is
    /// guaranteed at compile time. Used by the compiled
    /// registry-allowlist and the canonical `RestrictAddressFamilies`
    /// seam to embed known IDs without runtime parsing or fallible
    /// constructors; the shape check makes a malformed literal a
    /// compile-time error rather than a runtime panic.
    ///
    /// # Panics
    /// Panics at compile time if `raw` is not exactly `SRC-` followed
    /// by one or more ASCII digits. This is the only way a malformed
    /// source ID can be constructed, and it cannot happen at runtime.
    #[must_use]
    pub const fn from_static(raw: &'static str) -> Self {
        assert!(
            Self::const_looks_valid(raw),
            "SourceId::from_static requires SRC-NN shape"
        );
        Self(Cow::Borrowed(raw))
    }

    /// Return the source ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    const fn const_looks_valid(raw: &str) -> bool {
        let bytes: &[u8] = raw.as_bytes();
        let prefix: &[u8] = Self::PREFIX.as_bytes();
        if bytes.len() <= prefix.len() {
            return false;
        }
        let mut i: usize = 0;
        // The bounds check above guarantees `bytes[i]` and
        // `prefix[i]` are in range; `get` cannot be used inside a
        // const fn with the same ergonomics.
        #[allow(
            clippy::indexing_slicing,
            reason = "bounds checked immediately above; const fn indexing is the idiomatic primitive"
        )]
        while i < prefix.len() {
            if bytes[i] != prefix[i] {
                return false;
            }
            i += 1;
        }
        let mut j: usize = prefix.len();
        #[allow(
            clippy::indexing_slicing,
            reason = "bounds checked by `while let Some(_)` semantics: `bytes.len() > prefix.len()` was verified above and `j` only increments up to `bytes.len()`"
        )]
        while j < bytes.len() {
            if !bytes[j].is_ascii_digit() {
                return false;
            }
            j += 1;
        }
        true
    }
}

impl AsRef<str> for SourceId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
