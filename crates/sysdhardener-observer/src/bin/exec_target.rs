//! Target that tests execve in a child process and a syscall returning -ENOSYS.

#![allow(clippy::expect_used, reason = "test target asserts")]

use std::ffi::CString;

fn main() {
    if std::env::args().any(|a| a == "--child-worker") {
        let s = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
        assert!(s >= 0, "child socket must succeed");
        unsafe {
            libc::close(s);
            libc::_exit(0);
        }
    }

    // 1. Syscall returning -ENOSYS
    unsafe {
        libc::syscall(999);
    }

    // 2. Child calling execve
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        let exe = std::env::current_exe().expect("current_exe");
        let prog = CString::new(exe.to_str().expect("str")).expect("no nul");
        let arg = CString::new("--child-worker").expect("no nul");
        let argv = [prog.as_ptr(), arg.as_ptr(), std::ptr::null()];
        unsafe {
            libc::execvp(prog.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }
    let mut status = 0;
    unsafe {
        libc::waitpid(pid, &raw mut status, 0);
    }
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child must exit cleanly with 0, got status {status}"
    );

    // 3. Socket call after -ENOSYS and child exec
    let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(s >= 0, "socket must succeed");
    unsafe {
        libc::close(s);
    }
}
