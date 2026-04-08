//! Seccomp-BPF filter construction and sandbox setup for the vault subprocess.
//!
//! Applied immediately after fork, before any Bitwarden CLI interaction.
//! The sandbox reduces the attack surface to only the syscalls required by
//! Node.js (which backs the `bw` CLI) and basic process management.

use std::collections::BTreeMap;
use std::os::unix::io::RawFd;

use nix::sys::prctl;
use nix::sys::resource::{Resource, setrlimit};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
use tracing::warn;

use crate::VaultError;

/// Apply the full sandbox to the current process.
///
/// Steps:
/// 1. `prctl(PR_SET_DUMPABLE, 0)` — disable core dumps.
/// 2. `setrlimit(RLIMIT_CORE, 0, 0)` — belt-and-suspenders core dump prevention.
/// 3. Optionally unshare PID namespace (best-effort; logs warning on failure).
/// 4. Apply seccomp-BPF filter.
///
/// `sandbox_enabled` controls whether the PID namespace isolation and seccomp
/// filter are applied. The dumpable/core limits are always set.
pub fn apply_sandbox(sandbox_enabled: bool) -> Result<(), VaultError> {
    // Always disable core dumps.
    prctl::set_dumpable(false)
        .map_err(|e| VaultError::Sandbox(format!("prctl PR_SET_DUMPABLE: {e}")))?;

    setrlimit(Resource::RLIMIT_CORE, 0, 0)
        .map_err(|e| VaultError::Sandbox(format!("setrlimit RLIMIT_CORE: {e}")))?;

    if sandbox_enabled {
        // Try to unshare the PID namespace.  This requires CAP_SYS_ADMIN or a
        // permissive kernel (e.g. user namespaces enabled). Failure is non-fatal
        // because seccomp still provides the primary confinement.
        #[cfg(target_os = "linux")]
        {
            use nix::sched::{CloneFlags, unshare};
            if let Err(e) = unshare(CloneFlags::CLONE_NEWPID) {
                warn!("vault sandbox: CLONE_NEWPID unshare failed (non-fatal): {e}");
            }
        }

        // Apply the seccomp filter.
        let bpf = build_seccomp_filter()?;
        seccompiler::apply_filter(&bpf)
            .map_err(|e| VaultError::Sandbox(format!("seccomp apply_filter: {e}")))?;
    }

    Ok(())
}

/// Build the seccomp-BPF program allowing the syscalls needed by the `bw` CLI
/// (Node.js) and the parent subprocess loop.
///
/// Default action is `ERRNO(EPERM)` — not kill — because Node.js probes for
/// optional syscalls and handles EPERM gracefully, whereas SIGKILL would
/// terminate the process on any unrecognised probe.
fn build_seccomp_filter() -> Result<BpfProgram, VaultError> {
    // Each entry maps a syscall number to an empty Vec<SeccompRule>, meaning
    // "allow unconditionally on any arguments".
    let allowed: &[i64] = &[
        // I/O
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_openat,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_lseek,
        // Memory
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_mremap,
        // Process
        libc::SYS_execve,
        libc::SYS_exit_group,
        libc::SYS_exit,
        libc::SYS_wait4,
        libc::SYS_clone3,
        libc::SYS_clone,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_arch_prctl,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_fork,
        libc::SYS_vfork,
        // Socket
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_bind,
        libc::SYS_getpeername,
        libc::SYS_getsockname,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        // File system
        libc::SYS_access,
        libc::SYS_getcwd,
        libc::SYS_readlink,
        libc::SYS_readlinkat,
        libc::SYS_ioctl,
        libc::SYS_fcntl,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_dup3,
        libc::SYS_pipe2,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_getdents64,
        libc::SYS_unlink,
        libc::SYS_rename,
        libc::SYS_mkdir,
        libc::SYS_fchmod,
        libc::SYS_fchown,
        libc::SYS_utimensat,
        libc::SYS_fallocate,
        libc::SYS_ftruncate,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_writev,
        libc::SYS_readv,
        // Signal
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        // Misc
        libc::SYS_futex,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_gettimeofday,
        libc::SYS_getrandom,
        libc::SYS_prlimit64,
        libc::SYS_prctl,
        libc::SYS_poll,
        libc::SYS_ppoll,
        libc::SYS_select,
        libc::SYS_pselect6,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_pwait,
        libc::SYS_eventfd2,
        libc::SYS_nanosleep,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_gettid,
        libc::SYS_uname,
        libc::SYS_madvise,
        libc::SYS_statx,
        libc::SYS_rseq,
        libc::SYS_membarrier,
    ];

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &syscall in allowed {
        // Empty Vec means "allow on any arguments".
        rules.insert(syscall, vec![]);
    }

    let arch = TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|e| VaultError::Sandbox(format!("unsupported architecture: {e}")))?;

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32), // default: return EPERM
        SeccompAction::Allow,                     // on match: allow
        arch,
    )
    .map_err(|e| VaultError::Sandbox(format!("SeccompFilter::new: {e}")))?;

    let bpf = BpfProgram::try_from(filter)
        .map_err(|e| VaultError::Sandbox(format!("SeccompFilter compile: {e}")))?;

    Ok(bpf)
}

/// Close all file descriptors except stdin (0), stdout (1), stderr (2), and
/// `keep_fd`.
///
/// Uses `/proc/self/fd` to enumerate open descriptors; falls back to iterating
/// over a fixed upper bound if `/proc` is unavailable.
pub fn close_extra_fds(keep_fd: RawFd) {
    let protected: [RawFd; 4] = [0, 1, 2, keep_fd];

    // Try /proc/self/fd first for efficiency.
    if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
        let fds: Vec<RawFd> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_string_lossy().parse::<RawFd>().ok())
            .filter(|fd| !protected.contains(fd))
            .collect();

        for fd in fds {
            // SAFETY: We own the file descriptor and have deliberately chosen
            // to close it. We skip stdin/stdout/stderr and keep_fd above.
            unsafe { libc::close(fd) };
        }
    } else {
        // Fallback: iterate up to a reasonable upper bound.
        let max_fd = 1024;
        for fd in 3..max_fd {
            if protected.contains(&fd) {
                continue;
            }
            unsafe { libc::close(fd) };
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_filter_compiles_without_error() {
        let result = build_seccomp_filter();
        assert!(
            result.is_ok(),
            "seccomp filter should compile: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_apply_sandbox_disabled_does_not_fail() {
        // With sandbox_enabled=false, only dumpable and core limit are set.
        let result = apply_sandbox(false);
        assert!(
            result.is_ok(),
            "apply_sandbox(false) should not fail: {:?}",
            result.err()
        );
    }
}
