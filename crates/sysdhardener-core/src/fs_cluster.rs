//! Clustering and simplification of observed write paths for `ReadWritePaths=`.

#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) satisfies unreachable_pub lint while documenting crate-internal visibility"
)]

use std::collections::BTreeSet;
use std::path::Path;

use crate::filesystem::FsAccessEvent;
use crate::fixture::EventOutcome;

/// Check if `path` equals or is a descendant of `prefix`.
#[must_use]
pub(crate) fn touches(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Cluster observed write access events into a minimal sorted list of directory paths.
#[must_use]
pub(crate) fn cluster_write_paths(events: &[FsAccessEvent]) -> Vec<String> {
    let mut dirs = BTreeSet::new();
    for event in events {
        if event.is_write()
            && event.outcome() != EventOutcome::Error
            && event.outcome() != EventOutcome::Interrupted
        {
            let p = event.path();
            if !p.starts_with('/')
                || touches(p, "/dev")
                || touches(p, "/proc")
                || touches(p, "/sys")
            {
                continue;
            }
            let parent_str = match Path::new(p).parent() {
                Some(parent) if !parent.as_os_str().is_empty() => {
                    parent.to_string_lossy().to_string()
                }
                _ => p.to_string(),
            };
            dirs.insert(parent_str);
        }
    }
    let all_dirs: Vec<String> = dirs.into_iter().collect();
    let mut simplified = Vec::new();
    for dir in &all_dirs {
        let is_sub = all_dirs
            .iter()
            .any(|other| other != dir && touches(dir, other));
        if !is_sub {
            simplified.push(dir.clone());
        }
    }
    simplified.sort();
    simplified
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_touches_root() {
        assert!(touches("/", "/"));
        assert!(touches("/etc", "/"));
        assert!(touches("/etc/systemd", "/"));
        assert!(!touches("etc", "/"));
    }

    #[test]
    fn test_touches_prefix() {
        assert!(touches("/var/log", "/var"));
        assert!(touches("/var", "/var"));
        assert!(!touches("/variable", "/var"));
    }

    #[test]
    fn test_cluster_write_paths_simplification() {
        let events = vec![
            FsAccessEvent::new("/var/log/app.log", true, EventOutcome::Success),
            FsAccessEvent::new("/var/log/nginx/access.log", true, EventOutcome::Success),
            FsAccessEvent::new("/etc/myconf.conf", true, EventOutcome::Success),
        ];
        let clustered = cluster_write_paths(&events);
        assert_eq!(clustered, vec!["/etc", "/var/log"]);
    }

    #[test]
    fn test_cluster_write_paths_unknown_outcome_included() {
        let events = vec![
            FsAccessEvent::new("/var/data/state.db", true, EventOutcome::Unknown),
            FsAccessEvent::new("/var/data/corrupted.db", true, EventOutcome::Error),
        ];
        let clustered = cluster_write_paths(&events);
        assert_eq!(clustered, vec!["/var/data"]);
    }
}
