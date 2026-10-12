//! Process spawning under `PTRACE_TRACEME`.

#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(super) markers document the sibling-module contract"
)]

use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::process::Command;

use crate::capture::ObserveError;

fn build_child_env(command: &Command) -> Result<Option<Vec<CString>>, ObserveError> {
    if command.get_envs().next().is_none() {
        return Ok(None);
    }
    let mut map: HashMap<std::ffi::OsString, std::ffi::OsString> = std::env::vars_os().collect();
    for (k, v) in command.get_envs() {
        if let Some(v) = v {
            map.insert(k.to_os_string(), v.to_os_string());
        } else {
            map.remove(k);
        }
    }
    let mut envs = Vec::new();
    for (k, v) in map {
        let mut line = k;
        line.push("=");
        line.push(v);
        let cstr = CString::new(line.as_os_str().as_bytes())
            .map_err(|_| ObserveError::Spawn("environment variable contains NUL".to_owned()))?;
        envs.push(cstr);
    }
    Ok(Some(envs))
}

/// Fork the tracee under `PTRACE_TRACEME` and exec the target.
pub(super) fn spawn_tracee(command: &Command) -> Result<libc::pid_t, ObserveError> {
    let program: CString = CString::new(command.get_program().as_bytes())
        .map_err(|_| ObserveError::Spawn("program path contains NUL".to_owned()))?;
    let arg_strings: Vec<CString> = command
        .get_args()
        .map(|arg| CString::new(arg.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|_| ObserveError::Spawn("argument contains NUL".to_owned()))?;
    let cwd: Option<CString> = command
        .get_current_dir()
        .map(|p| CString::new(p.as_os_str().as_bytes()))
        .transpose()
        .map_err(|_| ObserveError::Spawn("working directory contains NUL".to_owned()))?;
    let env_strings = build_child_env(command)?;
    let envp: Option<Vec<*const libc::c_char>> = env_strings.as_ref().map(|envs| {
        let mut ptrs: Vec<*const libc::c_char> = envs.iter().map(|e| e.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        ptrs
    });
    let mut argv: Vec<*const libc::c_char> = arg_strings.iter().map(|a| a.as_ptr()).collect();
    argv.insert(0, program.as_ptr());
    argv.push(std::ptr::null());

    // SAFETY: the child calls PTRACE_TRACEME before exec, so the
    // parent's ptrace calls target a child it owns. The child then
    // execs the target program; on exec failure we call _exit(127)
    // so the child never returns into the caller's stack frame.
    let pid: libc::pid_t = unsafe { libc::fork() };
    if pid < 0 {
        return Err(ObserveError::Spawn("fork failed".to_owned()));
    }
    if pid == 0 {
        // Child: change working directory if configured, request tracing, then exec the target.
        // SAFETY: PTRACE_TRACEME on self is the standard pre-exec
        // trace request; the parent is the tracer by construction.
        unsafe {
            if let Some(ref dir) = cwd {
                if libc::chdir(dir.as_ptr()) != 0 {
                    libc::_exit(127);
                }
            }
            if libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            ) < 0
            {
                libc::_exit(127);
            }
            if let Some(ref envp_ptrs) = envp {
                libc::execvpe(program.as_ptr(), argv.as_ptr(), envp_ptrs.as_ptr());
            } else {
                libc::execvp(program.as_ptr(), argv.as_ptr());
            }
            libc::_exit(127);
        }
    }
    Ok(pid)
}
