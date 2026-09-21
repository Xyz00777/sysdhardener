//! Filesystem syscall argument inspection for ptrace.

#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(super) markers document the helper module's crate-local intent"
)]

pub(super) const fn is_write_flags(flags: u64) -> bool {
    let acc = flags & 3;
    acc == libc::O_WRONLY as u64
        || acc == libc::O_RDWR as u64
        || (flags & (libc::O_CREAT as u64 | libc::O_TRUNC as u64 | libc::O_APPEND as u64) != 0)
}

pub(super) fn read_tracee_string(pid: libc::pid_t, addr: u64, max_len: usize) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let mut buf = vec![0u8; max_len];
    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: max_len,
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: max_len,
    };
    let nread = unsafe {
        libc::process_vm_readv(
            pid,
            std::ptr::addr_of!(local_iov),
            1,
            std::ptr::addr_of!(remote_iov),
            1,
            0,
        )
    };
    if let Ok(n) = usize::try_from(nread) {
        if let Some(slice) = buf.get(..n) {
            if let Some(pos) = slice.iter().position(|&b| b == 0) {
                if let Some(path_bytes) = slice.get(..pos) {
                    return Some(String::from_utf8_lossy(path_bytes).into_owned());
                }
            }
        }
    }
    let mut bytes = Vec::with_capacity(64);
    let mut cur = addr;
    while bytes.len() < max_len {
        unsafe {
            *libc::__errno_location() = 0;
        }
        let word = unsafe {
            libc::ptrace(
                libc::PTRACE_PEEKDATA,
                pid,
                cur as *mut libc::c_void,
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        if word == -1 && unsafe { *libc::__errno_location() } != 0 {
            break;
        }
        for b in word.to_ne_bytes() {
            if b == 0 {
                return Some(String::from_utf8_lossy(&bytes).into_owned());
            }
            if bytes.len() >= max_len {
                return None;
            }
            bytes.push(b);
        }
        cur += std::mem::size_of::<libc::c_long>() as u64;
    }
    None
}

pub(super) fn read_tracee_u64(pid: libc::pid_t, addr: u64) -> Option<u64> {
    if addr == 0 {
        return None;
    }
    let mut val = 0u64;
    let local_iov = libc::iovec {
        iov_base: std::ptr::addr_of_mut!(val).cast(),
        iov_len: std::mem::size_of::<u64>(),
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: std::mem::size_of::<u64>(),
    };
    let nread = unsafe {
        libc::process_vm_readv(
            pid,
            std::ptr::addr_of!(local_iov),
            1,
            std::ptr::addr_of!(remote_iov),
            1,
            0,
        )
    };
    if usize::try_from(nread) == Ok(std::mem::size_of::<u64>()) {
        return Some(val);
    }
    unsafe {
        *libc::__errno_location() = 0;
        let word = libc::ptrace(
            libc::PTRACE_PEEKDATA,
            pid,
            addr as *mut libc::c_void,
            std::ptr::null_mut::<libc::c_void>(),
        );
        if *libc::__errno_location() == 0 {
            Some(u64::from_ne_bytes(word.to_ne_bytes()))
        } else {
            None
        }
    }
}

#[inline]
#[allow(
    clippy::cast_possible_truncation,
    reason = "registers store 32-bit dirfd"
)]
pub(super) fn dirfd_arg(raw: u64) -> i64 {
    i64::from(raw as i32)
}

pub(super) fn resolve_path(pid: libc::pid_t, dirfd: i64, raw_path: &str) -> String {
    let full = if raw_path.starts_with('/') {
        std::path::PathBuf::from(raw_path)
    } else {
        let base = if dirfd == i64::from(libc::AT_FDCWD) {
            std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
        } else if dirfd >= 0 {
            std::fs::read_link(format!("/proc/{pid}/fd/{dirfd}")).ok()
        } else {
            None
        };
        base.map_or_else(
            || std::path::PathBuf::from(raw_path),
            |base_path| clean_procfs_path(&base_path).join(raw_path),
        )
    };
    sysdhardener_core::normalize_path(&full)
        .to_string_lossy()
        .into_owned()
}

pub(super) fn capture_fs_entry(
    pid: libc::pid_t,
    regs: &crate::arch::SyscallRegs,
) -> Option<(String, bool)> {
    crate::arch::capture_fs_args(pid, regs)
}

pub(super) fn clean_procfs_path(path: &std::path::Path) -> std::path::PathBuf {
    let s = path.to_string_lossy();
    s.strip_suffix(" (deleted)")
        .map_or_else(|| path.to_path_buf(), std::path::PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn clean_procfs_path_strips_deleted_marker() {
        assert_eq!(
            clean_procfs_path(Path::new("/tmp/unlinked_dir (deleted)")),
            Path::new("/tmp/unlinked_dir")
        );
        assert_eq!(
            clean_procfs_path(Path::new("/var/log")),
            Path::new("/var/log")
        );
    }
}
