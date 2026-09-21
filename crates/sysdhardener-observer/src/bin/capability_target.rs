//! Capability-relevant syscall target.
//!
//! Exercises the capability-gated syscalls from
//! `docs/research.md` so the observer
//! can be verified against real kernel behavior. The target runs
//! unprivileged, so capability-gated operations that require a
//! capability fail with `EPERM` — the observer must record the
//! failed attempt as an `Error` outcome (a failed attempt is not
//! evidence of use).
//!
//! The target is built only under the `test-target` feature so
//! production builds never ship it.

#![allow(
    clippy::expect_used,
    reason = "test target asserts its own syscalls succeed; a failure here means the test environment is broken"
)]

use std::ffi::CString;

fn main() {
    // --- Capability-gated syscalls that succeed unprivileged ---

    // chown/fchown/lchown (CAP_CHOWN): chown to self succeeds.
    let tmp = std::env::temp_dir().join(format!("sysdhardener-cap-{}.txt", std::process::id()));
    std::fs::write(&tmp, b"x").expect("write temp file");
    let tmp_c = CString::new(tmp.to_string_lossy().as_bytes()).expect("path has no NUL");
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let _ = unsafe { libc::chown(tmp_c.as_ptr(), uid, gid) };
    let _ = unsafe { libc::lchown(tmp_c.as_ptr(), uid, gid) };

    // chmod/fchmod (CAP_FOWNER): chmod to self-owned file succeeds.
    let _ = unsafe { libc::chmod(tmp_c.as_ptr(), 0o600) };
    let f = std::fs::File::open(&tmp).expect("open temp");
    let _ = unsafe { libc::fchmod(std::os::fd::AsRawFd::as_raw_fd(&f), 0o600) };

    // setuid/setgid to self (CAP_SETUID/CAP_SETGID): succeeds.
    let _ = unsafe { libc::setuid(uid) };
    let _ = unsafe { libc::setgid(gid) };

    // setpriority (CAP_SYS_NICE): setting own priority succeeds.
    let _ = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 0) };

    // mlock (CAP_IPC_LOCK): locking a small buffer succeeds.
    let mut buf = [0u8; 4096];
    let _ = unsafe { libc::mlock(buf.as_mut_ptr().cast(), buf.len()) };
    let _ = unsafe { libc::munlock(buf.as_mut_ptr().cast(), buf.len()) };

    // --- Capability-gated syscalls that FAIL unprivileged ---

    // mount (CAP_SYS_ADMIN): must fail with EPERM.
    let mount_rc = unsafe {
        libc::mount(
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            std::ptr::null(),
        )
    };
    assert!(mount_rc < 0, "mount must fail unprivileged");

    // chroot (CAP_SYS_CHROOT): must fail with EPERM.
    let chroot_path = CString::new("/").expect("no NUL");
    let chroot_rc = unsafe { libc::chroot(chroot_path.as_ptr()) };
    assert!(chroot_rc < 0, "chroot must fail unprivileged");

    // setns (CAP_SYS_ADMIN): must fail with EPERM.
    let setns_rc = unsafe { libc::setns(0, 0) };
    assert!(setns_rc < 0, "setns must fail unprivileged");

    // sethostname (CAP_SYS_ADMIN): must fail with EPERM.
    let hostname = CString::new("x").expect("no NUL");
    let sethostname_rc = unsafe { libc::sethostname(hostname.as_ptr(), 1) };
    assert!(sethostname_rc < 0, "sethostname must fail unprivileged");

    // reboot (CAP_SYS_BOOT): must fail with EPERM.
    let reboot_rc = unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_RESTART) };
    assert!(reboot_rc < 0, "reboot must fail unprivileged");

    // iopl (CAP_SYS_RAWIO): must fail with EPERM (x86_64 only).
    #[cfg(target_arch = "x86_64")]
    {
        let iopl_rc = unsafe { libc::iopl(3) };
        assert!(iopl_rc < 0, "iopl must fail unprivileged");
    }

    // --- Syscalls that succeed but are capability-relevant ---

    // openat (CAP_DAC_OVERRIDE context): opening own file succeeds.
    let _ = std::fs::File::open(&tmp).expect("openat own file");

    // readlink (CAP_DAC_READ_SEARCH context): reading /proc/self/exe.
    let _ = std::fs::read_link("/proc/self/exe").expect("readlink /proc/self/exe");

    // prctl (CAP_SETPCAP context): reading own name succeeds.
    let mut name = [0u8; 16];
    let name_ptr: *mut libc::c_void = name.as_mut_ptr().cast();
    let _ = unsafe { libc::prctl(libc::PR_GET_NAME, name_ptr, 0, 0, 0) };

    // setrlimit (CAP_SYS_RESOURCE context): setting own soft limit.
    let rl = libc::rlimit {
        rlim_cur: 1024,
        rlim_max: 1024,
    };
    let rl_ptr: *const libc::rlimit = std::ptr::addr_of!(rl);
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, rl_ptr) };

    // --- Cleanup ---
    let _ = std::fs::remove_file(&tmp);
}
