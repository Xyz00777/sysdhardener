//! Pure lexical path normalization without filesystem I/O.

use std::path::{Component, Path, PathBuf};

/// Normalize a filesystem path lexically:
/// - folds redundant slashes and `.` components;
/// - resolves `..` components by popping the preceding component (bounded by root for absolute paths);
/// - retains leading `..` for relative paths that traverse past the start.
#[must_use]
pub fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => match normalized.components().next_back() {
                Some(Component::Normal(_)) => {
                    normalized.pop();
                }
                Some(Component::RootDir) => {}
                _ => {
                    normalized.push(component.as_os_str());
                }
            },
            Component::Normal(c) => normalized.push(c),
        }
    }
    if normalized.as_os_str().is_empty() && !path.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        normalized
    }
}

/// Normalize a path string lexically, preserving the original string if empty.
#[must_use]
pub fn normalize_path_str(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let norm = normalize_path(Path::new(raw));
    norm.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_absolute_paths() {
        assert_eq!(
            normalize_path(Path::new("/var/lib/../log/app.log")),
            PathBuf::from("/var/log/app.log")
        );
        assert_eq!(
            normalize_path(Path::new("/usr/bin/../../etc/passwd")),
            PathBuf::from("/etc/passwd")
        );
        assert_eq!(normalize_path(Path::new("/..")), PathBuf::from("/"));
        assert_eq!(
            normalize_path(Path::new("/a/./b/../c/")),
            PathBuf::from("/a/c")
        );
        assert_eq!(normalize_path(Path::new("/")), PathBuf::from("/"));
    }

    #[test]
    fn test_normalize_relative_paths() {
        assert_eq!(normalize_path(Path::new("a/b/../c")), PathBuf::from("a/c"));
        assert_eq!(
            normalize_path(Path::new("../foo/bar")),
            PathBuf::from("../foo/bar")
        );
        assert_eq!(
            normalize_path(Path::new("../../foo")),
            PathBuf::from("../../foo")
        );
        assert_eq!(normalize_path(Path::new("../..")), PathBuf::from("../.."));
        assert_eq!(
            normalize_path(Path::new("a/../../b")),
            PathBuf::from("../b")
        );
        assert_eq!(normalize_path(Path::new(".")), PathBuf::from("."));
        assert_eq!(normalize_path(Path::new("")), PathBuf::from(""));
    }
}
