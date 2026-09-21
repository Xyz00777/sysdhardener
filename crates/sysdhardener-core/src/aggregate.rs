//! Recommendation-local address-family evidence aggregation.
//!
//! The aggregator is **pure**:
//!
//! - It owns no global state, no cache, and no persistence layer.
//!   Each call receives a typed `&[ObservedEvent]` and a typed
//!   `&Fixture` and returns a typed bundle. Two independent calls
//!   over the same input produce byte-identical bundles.
//! - It builds one [`AddressFamilyAggregate`] per address family
//!   that appears in the event slice; families not seen are absent
//!   from the bundle (no fabricated entries).
//! - The aggregate's deterministic key is an explicit
//!   `af=<family>|src=<sorted-source-ids>` string. It is never a
//!   numeric fingerprint.
//! - `count` is the number of events folded into the aggregate.
//! - `first_timestamp_unix_ms` and `last_timestamp_unix_ms` are
//!   the min and max event timestamps seen for the family.
//! - The representative `args/outcome/event_id` prioritize successful
//!   operations (or the first event as canonical tie-breaker).
//! - `source_ids` is the deduplicated, sorted list of `SourceId`s
//!   whose events contributed.
//! - Coverage/loss metadata is propagated from the fixture onto
//!   both the bundle and every per-family entry.
//! - The bundle is permutation-invariant: shuffling the input
//!   events does not change keys, counts, first/last, or
//!   representatives; only the representative ordering rule
//!   (first-by-input-order) is the canonical tie-breaker.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::error::Error;
use crate::fixture::{AddressFamily, CoverageQuality, EventOutcome, Fixture};
use crate::observed_event::ObservedEvent;
use crate::source_id::SourceId;

/// The deterministic, snake-case family tag used inside the
/// aggregate's key and serialized payload. The mapping is total
/// (every `AddressFamily` variant has a tag) and stable.
fn family_tag(family: AddressFamily) -> String {
    #[rustfmt::skip]
    let s = match family {
        AddressFamily::Unix => "unix", AddressFamily::Inet => "inet",
        AddressFamily::Inet6 => "inet6", AddressFamily::Netlink => "netlink",
        AddressFamily::Packet => "packet", AddressFamily::Other(tag) => return tag.to_lowercase(),
    };
    s.to_owned()
}

/// The natural-order iteration order of [`AddressFamily`]. Kept in
/// one place so the bundle and the key builder use the same order.
/// `Other` variants are sorted after the well-known ones (the
/// `Other` set is closed in practice for the deterministic slice;
/// this ordering is the contract).
fn family_order(a: AddressFamily, b: AddressFamily) -> std::cmp::Ordering {
    #[rustfmt::skip]
    const fn rank(f: AddressFamily) -> u8 {
        match f {
            AddressFamily::Unix => 0, AddressFamily::Inet => 1, AddressFamily::Inet6 => 2,
            AddressFamily::Netlink => 3, AddressFamily::Packet => 4, AddressFamily::Other(_) => 5,
        }
    }
    rank(a).cmp(&rank(b)).then_with(|| match (a, b) {
        (AddressFamily::Other(x), AddressFamily::Other(y)) => x.cmp(y),
        _ => std::cmp::Ordering::Equal,
    })
}

/// A single address-family aggregate inside the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressFamilyAggregate {
    family: AddressFamily,
    key: String,
    count: u32,
    first_timestamp_unix_ms: i64,
    last_timestamp_unix_ms: i64,
    representative_args: String,
    representative_outcome: EventOutcome,
    representative_event_id: String,
    #[serde(rename = "source_ids")]
    source_ids: Vec<SourceId>,
    coverage: CoverageQuality,
    seen_events: u32,
    dropped_events: u32,
}

impl AddressFamilyAggregate {
    /// The address family this aggregate summarizes.
    #[must_use]
    pub const fn family(&self) -> AddressFamily {
        self.family
    }

    /// The explicit, stable, snake-case aggregate key. The shape is
    /// `af=<family-tag>|src=<sorted-source-ids-joined-by-comma>`. It
    /// is never a numeric hash.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Number of raw events folded into the aggregate.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Earliest event timestamp observed for this family.
    #[must_use]
    pub const fn first_timestamp_unix_ms(&self) -> i64 {
        self.first_timestamp_unix_ms
    }

    /// Latest event timestamp observed for this family.
    #[must_use]
    pub const fn last_timestamp_unix_ms(&self) -> i64 {
        self.last_timestamp_unix_ms
    }

    /// Representative arguments (from the first event in input
    /// order for this family). Treated as opaque data.
    #[must_use]
    pub fn representative_args(&self) -> &str {
        &self.representative_args
    }

    /// Representative outcome (from the first event in input order
    /// for this family).
    #[must_use]
    pub const fn representative_outcome(&self) -> EventOutcome {
        self.representative_outcome
    }

    /// Representative `event_id` (from the first event in input
    /// order for this family).
    #[must_use]
    pub fn representative_event_id(&self) -> &str {
        &self.representative_event_id
    }

    /// Deduplicated, sorted list of `SourceId`s whose events
    /// contributed to this aggregate.
    #[must_use]
    pub fn source_ids(&self) -> Vec<String> {
        self.source_ids
            .iter()
            .map(SourceId::as_str)
            .map(str::to_owned)
            .collect()
    }

    /// Coverage quality carried on the fixture envelope, propagated
    /// to every per-family entry.
    #[must_use]
    pub const fn coverage(&self) -> CoverageQuality {
        self.coverage
    }

    /// Declared `seen_events` count from the fixture envelope.
    #[must_use]
    pub const fn seen_events(&self) -> u32 {
        self.seen_events
    }

    /// Declared `dropped_events` count from the fixture envelope.
    #[must_use]
    pub const fn dropped_events(&self) -> u32 {
        self.dropped_events
    }
}

/// The recommendation-local bundle of address-family evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressFamilyBundle {
    entries: Vec<AddressFamilyAggregate>,
    coverage: CoverageQuality,
    seen_events: u32,
    dropped_events: u32,
}

impl AddressFamilyBundle {
    /// Borrow the per-family entries in stable order.
    pub fn entries(&self) -> impl Iterator<Item = &AddressFamilyAggregate> {
        self.entries.iter()
    }

    /// Look up a per-family aggregate by family. Returns `None` for
    /// families that were not seen in the input (the aggregator
    /// never fabricates entries for unobserved families).
    #[must_use]
    pub fn get(&self, family: AddressFamily) -> Option<&AddressFamilyAggregate> {
        self.entries.iter().find(|e| e.family == family)
    }

    /// Coverage quality from the fixture envelope.
    #[must_use]
    pub const fn coverage(&self) -> CoverageQuality {
        self.coverage
    }

    /// Declared `seen_events` count from the fixture envelope.
    #[must_use]
    pub const fn seen_events(&self) -> u32 {
        self.seen_events
    }

    /// Declared `dropped_events` count from the fixture envelope.
    #[must_use]
    pub const fn dropped_events(&self) -> u32 {
        self.dropped_events
    }
}

/// Build a recommendation-local address-family evidence bundle
/// from a typed event slice and a typed [`Fixture`].
///
/// The aggregator is **pure**: no I/O, no wall clock, no random,
/// no global cache, no persistence, no logging, no sink. The
/// returned bundle is determined entirely by the inputs.
///
/// # Errors
/// Returns [`Error::EventCountMismatch`] when the event slice
/// length does not equal the fixture's declared `seen_events`. The
/// boundary already enforces that the fixture's events array length
/// matches `seen_events`, so the only way this fails is a
/// caller-side mismatch (e.g. a recommendation rule that filters
/// the events before passing them to the aggregator without
/// recomputing the count).
pub fn aggregate_address_family_evidence(
    events: &[ObservedEvent],
    fixture: &Fixture,
) -> Result<AddressFamilyBundle, Error> {
    let actual: u32 = u32::try_from(events.len()).map_err(|_| Error::EventCountMismatch {
        declared: fixture.seen_events(),
        actual: u32::MAX,
    })?;
    if actual != fixture.seen_events() {
        return Err(Error::EventCountMismatch {
            declared: fixture.seen_events(),
            actual,
        });
    }

    // Per-family running state. We use a Vec in the canonical
    // family-order, not a HashMap, so the per-family running
    // structure is itself deterministic across runs.
    let mut per_family: Vec<(AddressFamily, FamilyBuilder)> = Vec::new();

    for event in events {
        let family = event.address_family();
        if let Some((_, builder)) = per_family.iter_mut().find(|(f, _)| *f == family) {
            builder.fold(event);
        } else {
            let mut builder = FamilyBuilder::new();
            builder.fold(event);
            per_family.push((family, builder));
        }
    }

    // Sort the per-family entries in stable natural order. The
    // aggregation itself is order-invariant, but the *bundle's
    // iteration order* must be stable across runs.
    per_family.sort_by(|a, b| family_order(a.0, b.0));

    let coverage: CoverageQuality = fixture.coverage();
    let seen_events: u32 = fixture.seen_events();
    let dropped_events: u32 = fixture.dropped_events();

    let entries: Vec<AddressFamilyAggregate> = per_family
        .into_iter()
        .map(|(family, builder)| {
            let source_ids: Vec<SourceId> = builder.source_ids.into_iter().collect();
            let key: String = build_key(family, &source_ids);
            AddressFamilyAggregate {
                family,
                key,
                count: builder.count,
                first_timestamp_unix_ms: builder.first_unix_ms,
                last_timestamp_unix_ms: builder.last_unix_ms,
                representative_args: builder.representative_args,
                representative_outcome: builder.representative_outcome,
                representative_event_id: builder.representative_event_id,
                source_ids,
                coverage,
                seen_events,
                dropped_events,
            }
        })
        .collect();

    Ok(AddressFamilyBundle {
        entries,
        coverage,
        seen_events,
        dropped_events,
    })
}

/// Build the explicit, stable aggregate key for a family +
/// deduplicated sorted source-id set. The shape is
/// `af=<family-tag>|src=<ids-joined-by->`. The shape is the
/// contract; a future migration must keep the prefix `af=` and the
/// `|src=` segment to remain backward-compatible.
fn build_key(family: AddressFamily, source_ids: &[SourceId]) -> String {
    let tag: String = family_tag(family);
    let ids: String = source_ids
        .iter()
        .map(SourceId::as_str)
        .collect::<Vec<_>>()
        .join(",");
    format!("af={tag}|src={ids}")
}

/// Per-family running accumulator. Holds the running state used by
/// [`aggregate_address_family_evidence`]; converted to an
/// [`AddressFamilyAggregate`] once the input is exhausted.
struct FamilyBuilder {
    count: u32,
    first_unix_ms: i64,
    last_unix_ms: i64,
    representative_args: String,
    representative_outcome: EventOutcome,
    representative_event_id: String,
    /// `BTreeSet` so source IDs are always sorted on iteration,
    /// giving the key builder a deterministic order.
    source_ids: BTreeSet<SourceId>,
}

impl FamilyBuilder {
    const fn new() -> Self {
        // i64 sentinels are reserved by the wire contract and never
        // appear in a real fixture (the boundary rejects them).
        // Every emitted aggregate is built only after at least one
        // fold has run, so these placeholders are never observed.
        Self {
            count: 0,
            first_unix_ms: i64::MAX,
            last_unix_ms: i64::MIN,
            representative_args: String::new(),
            representative_outcome: EventOutcome::Unknown,
            representative_event_id: String::new(),
            source_ids: BTreeSet::new(),
        }
    }

    fn fold(&mut self, event: &ObservedEvent) {
        if self.count == 0 {
            self.first_unix_ms = event.timestamp_unix_ms();
            self.last_unix_ms = event.timestamp_unix_ms();
            self.set_representative(event);
        } else {
            let ts: i64 = event.timestamp_unix_ms();
            if ts < self.first_unix_ms {
                self.first_unix_ms = ts;
            }
            if ts > self.last_unix_ms {
                self.last_unix_ms = ts;
            }
            if event.outcome() == EventOutcome::Success
                && self.representative_outcome != EventOutcome::Success
                || self.representative_outcome == EventOutcome::Error
                    && event.outcome() != EventOutcome::Error
            {
                self.set_representative(event);
            }
        }
        self.count = self.count.saturating_add(1);
        self.source_ids.insert(event.source_id().clone());
    }

    fn set_representative(&mut self, event: &ObservedEvent) {
        event.args().clone_into(&mut self.representative_args);
        self.representative_outcome = event.outcome();
        event
            .event_id()
            .clone_into(&mut self.representative_event_id);
    }
}
