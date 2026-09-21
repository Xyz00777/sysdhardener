//! `FixtureTimestamp` newtype and the window-ordering invariant.
//!
//! The fixture envelope carries a `first_timestamp_unix_ms` and
//! `last_timestamp_unix_ms`. The library enforces `first <= last` at
//! the boundary; equal values are accepted as a zero-width window.

use crate::error::Error;

/// A typed Unix-epoch-millisecond timestamp carried on fixture events.
///
/// The newtype is a parse-don't-validate primitive: every [`FixtureTimestamp`]
/// in the typed interior originated from a successfully parsed wire
/// field; the public type does not expose an unchecked constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FixtureTimestamp(i64);

impl FixtureTimestamp {
    /// Wrap a raw i64 timestamp. Only used internally by the wire DTO
    /// mapper after the boundary check has passed.
    #[must_use]
    pub const fn from_raw_checked(value: i64) -> Self {
        Self(value)
    }

    /// Return the underlying Unix-epoch-millisecond value.
    #[must_use]
    pub const fn unix_ms(self) -> i64 {
        self.0
    }
}

/// Validate a fixture window. Returns `Ok(())` when `first <= last`.
///
/// # Errors
/// Returns [`Error::TimestampReversed`] when `first > last`.
pub const fn check_fixture_window(first_unix_ms: i64, last_unix_ms: i64) -> Result<(), Error> {
    if first_unix_ms > last_unix_ms {
        Err(Error::TimestampReversed {
            first_unix_ms,
            last_unix_ms,
        })
    } else {
        Ok(())
    }
}
