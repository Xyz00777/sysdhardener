//! Bridge from the eBPF ring-buffer wire events to the typed
//! `ObservedEvent` the analysis engine consumes.
//!
//! The cgroup sockaddr hooks fire **before** the operation completes, so
//! the eBPF path cannot observe success or failure. Every event is stamped
//! `EventOutcome::Unknown`. For `RestrictAddressFamilies=`, an attempted
//! family is treated as needed: `Success` and `Unknown` outcomes remain
//! in the allow-list; only a known `Error` excludes a family and records
//! a contradiction. Stamping `Success` or `Error` directly would fabricate
//! evidence the hook did not observe.

use sysdhardener_core::{AddressFamily, EventOutcome, FixtureTimestamp, ObservedEvent, SourceId};
use sysdhardener_wire_format::{FsEvent, FsOp, SockEvent, SockOp};

/// The source ID the eBPF observer stamps on every captured event. The
/// registry row is SRC-14 (eBPF observer).
pub const EBPF_SOURCE_ID: SourceId = SourceId::from_static("SRC-14");

/// Map a raw `sa_family_t` value to the typed [`AddressFamily`].
///
/// The Linux ABI family numbers are stable constants; matching them as
/// u32 literals avoids the cast lints. Unknown families map to
/// `Other("unknown")` (the engine excludes `Other` from the
/// recommendation set, so an unrecognized family is never recommended).
const fn family_from_sa_family(family: u32) -> AddressFamily {
    match family {
        1 => AddressFamily::Unix,
        2 => AddressFamily::Inet,
        10 => AddressFamily::Inet6,
        16 => AddressFamily::Netlink,
        17 => AddressFamily::Packet,
        _ => AddressFamily::Other("unknown"),
    }
}

/// The human-readable operation tag for the event `args`.
const fn op_tag(op: SockOp) -> &'static str {
    match op {
        SockOp::Bind => "bind",
        SockOp::Connect => "connect",
        SockOp::SendMsg => "sendmsg",
        SockOp::RecvMsg => "recvmsg",
    }
}

/// Convert one decoded [`SockEvent`] into a typed [`ObservedEvent`].
///
/// The outcome is always [`EventOutcome::Unknown`]: the
/// cgroup sockaddr hook fires pre-operation and cannot observe
/// success/failure. The event carries the producing pid and a stable
/// event ID derived from the operation and the kernel timestamp.
fn sock_event_to_observed_indexed(
    event: &SockEvent,
    index: usize,
    cgroup: Option<&str>,
) -> ObservedEvent {
    let op_name: &str = SockOp::from_u32(event.op).map_or("unknown", op_tag);
    let family: AddressFamily = family_from_sa_family(event.family);
    let event_id: String = format!("ebpf-{op_name}-{}-{index}", event.timestamp_ms);
    let args: String = format!("ebpf op={op_name} family={family:?}");
    ObservedEvent::new_with_pid_cgroup(
        EBPF_SOURCE_ID,
        event_id,
        FixtureTimestamp::from_raw_checked(i64::try_from(event.timestamp_ms).unwrap_or(i64::MAX)),
        family,
        EventOutcome::Unknown,
        args,
        Some(i32::try_from(event.pid).unwrap_or(i32::MAX)),
        cgroup.map(ToOwned::to_owned),
    )
}

/// Convert one decoded [`SockEvent`] into a typed [`ObservedEvent`] with an optional cgroup path.
#[must_use]
pub fn sock_event_to_observed_with_cgroup(
    event: &SockEvent,
    cgroup: Option<&str>,
) -> ObservedEvent {
    sock_event_to_observed_indexed(event, 0, cgroup)
}

/// Convert one decoded [`SockEvent`] into a typed [`ObservedEvent`].
///
/// The outcome is always [`EventOutcome::Unknown`]: the
/// cgroup sockaddr hook fires pre-operation and cannot observe
/// success/failure. The event carries the producing pid and a stable
/// event ID derived from the operation and the kernel timestamp.
#[must_use]
pub fn sock_event_to_observed(event: &SockEvent) -> ObservedEvent {
    sock_event_to_observed_with_cgroup(event, None)
}

/// Convert a decoded ring-buffer event stream into typed observed
/// events with an optional cgroup path, preserving the kernel's delivery order.
#[must_use]
pub fn sock_events_to_observed_with_cgroup(
    events: &[SockEvent],
    cgroup: Option<&str>,
) -> Vec<ObservedEvent> {
    events
        .iter()
        .enumerate()
        .map(|(idx, e)| sock_event_to_observed_indexed(e, idx, cgroup))
        .collect()
}

/// Convert a decoded ring-buffer event stream into typed observed
/// events, preserving the kernel's delivery order.
#[must_use]
pub fn sock_events_to_observed(events: &[SockEvent]) -> Vec<ObservedEvent> {
    sock_events_to_observed_with_cgroup(events, None)
}

/// Convert one decoded [`FsEvent`] into a typed [`ObservedEvent`].
#[must_use]
pub fn fs_event_to_observed_with_cgroup(
    event: &FsEvent,
    index: usize,
    cgroup: Option<&str>,
) -> ObservedEvent {
    let is_write = event.op == FsOp::Write.as_u32();
    let path_len = usize::try_from(event.path_len).unwrap_or(0).min(256);
    let path_slice = event.path.get(..path_len).unwrap_or(&[]);
    let end = path_slice
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(path_slice.len());
    let path_str = String::from_utf8_lossy(path_slice.get(..end).unwrap_or(path_slice));
    let event_id = format!("ebpf-fs-{}-{index}", event.timestamp_ms);
    let args = format!("fs family=fs ret=0 path={path_str} write={is_write}");
    ObservedEvent::new_with_pid_cgroup(
        EBPF_SOURCE_ID,
        event_id,
        FixtureTimestamp::from_raw_checked(i64::try_from(event.timestamp_ms).unwrap_or(i64::MAX)),
        AddressFamily::Other("fs"),
        EventOutcome::Success,
        args,
        Some(i32::try_from(event.pid).unwrap_or(i32::MAX)),
        cgroup.map(ToOwned::to_owned),
    )
}

/// Convert decoded [`FsEvent`] items into typed [`ObservedEvent`] items.
#[must_use]
pub fn fs_events_to_observed_with_cgroup(
    events: &[FsEvent],
    cgroup: Option<&str>,
) -> Vec<ObservedEvent> {
    events
        .iter()
        .enumerate()
        .map(|(idx, e)| fs_event_to_observed_with_cgroup(e, idx, cgroup))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> SockEvent {
        SockEvent {
            pid: 42,
            family: 2, // AF_INET
            op: SockOp::Connect.as_u32(),
            timestamp_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn bridge_stamps_unknown_outcome() {
        let event = sock_event_to_observed(&sample_event());
        assert_eq!(event.outcome(), EventOutcome::Unknown);
    }

    #[test]
    fn bridge_maps_family_and_pid() {
        let event = sock_event_to_observed(&sample_event());
        assert_eq!(event.address_family(), AddressFamily::Inet);
        assert_eq!(event.pid(), Some(42));
        assert_eq!(event.source_id().as_str(), "SRC-14");
    }

    #[test]
    fn bridge_maps_unknown_family_to_other() {
        let mut e = sample_event();
        e.family = 99;
        let event = sock_event_to_observed(&e);
        assert_eq!(event.address_family(), AddressFamily::Other("unknown"));
    }

    #[test]
    fn bridge_preserves_order() {
        let mut a = sample_event();
        a.timestamp_ms = 1;
        let mut b = sample_event();
        b.timestamp_ms = 2;
        let events = sock_events_to_observed(&[a, b]);
        assert_eq!(events.len(), 2);
        assert_eq!(
            events.first().map(ObservedEvent::timestamp_unix_ms),
            Some(1)
        );
        assert_eq!(events.get(1).map(ObservedEvent::timestamp_unix_ms), Some(2));
    }

    #[test]
    fn bridge_propagates_cgroup_when_provided() {
        let e = sample_event();
        let event = sock_event_to_observed_with_cgroup(
            &e,
            Some("/sys/fs/cgroup/system.slice/test.service"),
        );
        assert_eq!(
            event.cgroup(),
            Some("/sys/fs/cgroup/system.slice/test.service")
        );

        let events = sock_events_to_observed_with_cgroup(
            &[e],
            Some("/sys/fs/cgroup/system.slice/test.service"),
        );
        assert_eq!(
            events.first().and_then(ObservedEvent::cgroup),
            Some("/sys/fs/cgroup/system.slice/test.service")
        );
    }

    #[test]
    fn bridge_disambiguates_event_ids_for_same_timestamp() {
        let a = sample_event();
        let b = sample_event();
        let events = sock_events_to_observed(&[a, b]);
        assert_eq!(events.len(), 2);
        let id0 = events.first().map(ObservedEvent::event_id);
        let id1 = events.get(1).map(ObservedEvent::event_id);
        assert_ne!(id0, id1);
    }

    #[test]
    fn bridge_maps_unknown_op_to_unknown_tag() {
        let mut e = sample_event();
        e.op = 999;
        let event = sock_event_to_observed(&e);
        assert!(event.event_id().starts_with("ebpf-unknown-"));
        assert!(event.args().contains("op=unknown"));
    }

    #[test]
    fn bridge_converts_fs_events() {
        let mut path = [0u8; 256];
        path[..9].copy_from_slice(b"/etc/test");
        let fs_ev = FsEvent {
            pid: 50,
            op: FsOp::Write.as_u32(),
            timestamp_ms: 1_234_567,
            path_len: 9,
            path,
        };
        let observed = fs_event_to_observed_with_cgroup(&fs_ev, 0, Some("/sys/fs/cgroup/test"));
        assert_eq!(observed.pid(), Some(50));
        assert_eq!(observed.address_family(), AddressFamily::Other("fs"));
        assert!(observed.args().contains("path=/etc/test"));
        assert!(observed.args().contains("write=true"));
        assert_eq!(observed.cgroup(), Some("/sys/fs/cgroup/test"));
    }

    #[test]
    fn bridge_strips_null_terminator_from_fs_path() {
        let mut path = [0u8; 256];
        path[..10].copy_from_slice(b"/etc/test\0");
        let fs_ev = FsEvent {
            pid: 50,
            op: FsOp::Read.as_u32(),
            timestamp_ms: 1_234_567,
            path_len: 10,
            path,
        };
        let observed = fs_event_to_observed_with_cgroup(&fs_ev, 0, None);
        assert!(observed.args().contains("path=/etc/test "));
        assert!(!observed.args().contains('\0'));
    }
}
