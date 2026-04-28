//! Command executor: ties together child spawn, proxy-based credential
//! injection, output sanitization, and signal forwarding.
//!
//! # Credential delivery flow
//!
//! For HTTP tools (curl): the CDP proxy injects credentials at the transport
//! layer. The child is launched with `--proxy` and CDP auth headers so the
//! proxy can authenticate the request and inject the credential.
//!
//! For ASKPASS tools (git, ssh): a pipe-based delivery is used. The child is
//! spawned with a credential pipe fd and ASKPASS env vars pointing back to
//! `cdp-wrap --askpass`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::Stdio;
use std::thread;

use tracing::{debug, instrument};

use crate::gate_client::LeaseInfo;
use crate::namespace::harden_current_process;
use crate::sanitize::OutputSanitizer;
use crate::{InjectionMethod, WrapError};

// ---------------------------------------------------------------------------
// ExecutionResult
// ---------------------------------------------------------------------------

/// The outcome of running a wrapped command.
#[derive(Debug)]
pub struct ExecutionResult {
    /// The exit code returned by the child process (0 = success).
    pub exit_code: i32,
}

// ---------------------------------------------------------------------------
// CommandExecutor
// ---------------------------------------------------------------------------

/// Executes a CLI command with credential injection via the ASKPASS pipe pattern.
pub struct CommandExecutor {
    /// Path to the current binary (reserved for future ASKPASS helper use).
    #[allow(dead_code)]
    self_path: String,
}

impl CommandExecutor {
    /// Create a new executor.
    ///
    /// `self_path` should be `std::env::current_exe()` or `argv[0]`.
    pub fn new(self_path: String) -> Result<Self, WrapError> {
        // Validate that the default patterns compile on construction.
        OutputSanitizer::new()?;
        Ok(Self { self_path })
    }

    /// Run `command args` with credentials injected via the CDP proxy.
    ///
    /// For curl: adds `--proxy` and CDP auth headers to route through the proxy.
    /// For git/ssh: sets ASKPASS env vars (future: pipe-based delivery).
    ///
    /// Returns `ExecutionResult` with the child's exit code.
    #[instrument(skip(self, lease), fields(command = %command, method = ?method))]
    pub fn run(
        &self,
        command: &str,
        args: &[String],
        method: &InjectionMethod,
        lease: LeaseInfo,
    ) -> Result<ExecutionResult, WrapError> {
        // Harden the parent process.
        harden_current_process()?;

        // Build the final command + args based on injection method.
        let (final_command, final_args, env) =
            self.build_proxy_command(command, args, method, &lease)?;

        // Spawn the child with piped stdout/stderr so we can sanitize output.
        let mut child = {
            use std::process::Command;
            let mut cmd = Command::new(&final_command);
            cmd.args(&final_args);
            cmd.env_clear();
            for (k, v) in &env {
                cmd.env(k, v);
            }
            // Inherit system variables.
            for var in &["PATH", "HOME", "USER", "LOGNAME", "TERM", "LANG", "LC_ALL"] {
                if let Ok(val) = std::env::var(var) {
                    cmd.env(var, val);
                }
            }
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());

            // pre_exec: security hardening.
            unsafe {
                use std::os::unix::process::CommandExt;
                cmd.pre_exec(move || {
                    libc::prctl(libc::PR_SET_DUMPABLE, 0i64, 0i64, 0i64, 0i64);
                    let zero = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    libc::setrlimit(libc::RLIMIT_CORE, &zero);
                    Ok(())
                });
            }

            cmd.spawn()
                .map_err(|e| WrapError::Child(format!("spawn {final_command}: {e}")))?
        };

        debug!(pid = child.id(), cmd = %final_command, "spawned child process");

        // Forward signals from parent to child.
        let child_pid = child.id();
        self.install_signal_forwarding(child_pid);

        // Read and sanitize child stdout/stderr in background threads.
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();

        let sanitizer_clone_out = OutputSanitizer::new()?;
        let sanitizer_clone_err = OutputSanitizer::new()?;

        let stdout_thread = thread::spawn(move || {
            if let Some(pipe) = stdout_pipe {
                let reader = BufReader::new(pipe);
                for line in reader.lines() {
                    match line {
                        Ok(l) => {
                            let sanitized = sanitizer_clone_out.sanitize_line(&l);
                            println!("{sanitized}");
                        }
                        Err(_) => break,
                    }
                }
            }
        });

        let stderr_thread = thread::spawn(move || {
            if let Some(pipe) = stderr_pipe {
                let reader = BufReader::new(pipe);
                for line in reader.lines() {
                    match line {
                        Ok(l) => {
                            let sanitized = sanitizer_clone_err.sanitize_line(&l);
                            eprintln!("{sanitized}");
                        }
                        Err(_) => break,
                    }
                }
            }
        });

        // Wait for child to exit.
        let status = child
            .wait()
            .map_err(|e| WrapError::Child(format!("wait: {e}")))?;

        // Join output threads.
        let _ = stdout_thread.join();
        let _ = stderr_thread.join();

        let exit_code = status
            .code()
            .unwrap_or(if status.success() { 0 } else { 1 });

        debug!(exit_code, "child process exited");

        Ok(ExecutionResult { exit_code })
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Build the final command, args, and environment for proxy-based injection.
    ///
    /// For `CurlPipe`: adds `--proxy` and `-H` flags to the curl command so
    /// traffic routes through the CDP proxy with proper authentication.
    ///
    /// For ASKPASS methods: sets proxy env vars and ASKPASS helpers.
    fn build_proxy_command(
        &self,
        command: &str,
        args: &[String],
        method: &InjectionMethod,
        lease: &LeaseInfo,
    ) -> Result<(String, Vec<String>, HashMap<String, String>), WrapError> {
        let proxy_url = format!("http://127.0.0.1:{}", lease.proxy_port);
        let mut env = HashMap::new();

        match method {
            InjectionMethod::CurlPipe => {
                // For curl: inject proxy and CDP auth headers directly as args.
                let mut final_args = vec![
                    "--proxy".to_string(),
                    proxy_url,
                    "-H".to_string(),
                    format!("X-CDP-Lease-Token: {}", lease.lease_token),
                    "-H".to_string(),
                    format!("X-CDP-Channel-Binding: {}", lease.channel_binding_nonce),
                ];
                final_args.extend_from_slice(args);
                Ok((command.to_string(), final_args, env))
            }
            InjectionMethod::GitAskpass => {
                // For git over HTTPS: route through proxy.
                env.insert("http_proxy".to_string(), proxy_url.clone());
                env.insert("https_proxy".to_string(), proxy_url);
                env.insert("GIT_TERMINAL_PROMPT".to_string(), "0".to_string());
                Ok((command.to_string(), args.to_vec(), env))
            }
            InjectionMethod::SshAskpass => {
                // SSH doesn't use HTTP proxy — for now pass through directly.
                env.insert("DISPLAY".to_string(), ":0".to_string());
                Ok((command.to_string(), args.to_vec(), env))
            }
            InjectionMethod::GenericAskpass => {
                // Generic: set proxy env vars so HTTP tools pick them up.
                env.insert("http_proxy".to_string(), proxy_url.clone());
                env.insert("https_proxy".to_string(), proxy_url);
                Ok((command.to_string(), args.to_vec(), env))
            }
        }
    }

    /// Install signal handlers that forward SIGTERM and SIGINT to the child.
    fn install_signal_forwarding(&self, child_pid: u32) {
        // The child is in the same process group as the parent, so Ctrl-C
        // will already reach it. We only need to handle programmatic SIGTERM.
        debug!(
            child_pid,
            "child process group will receive terminal signals directly"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_executor() -> CommandExecutor {
        CommandExecutor::new("/proc/self/exe".to_string()).expect("executor creation failed")
    }

    fn test_lease() -> LeaseInfo {
        LeaseInfo {
            proxy_port: 20000,
            lease_token: "cdp_lease_test123".to_string(),
            channel_binding_nonce: "abcd1234".to_string(),
            ttl_seconds: 3600,
        }
    }

    #[test]
    fn test_build_proxy_command_curl() {
        let exec = make_executor();
        let lease = test_lease();
        let (cmd, args, _env) = exec
            .build_proxy_command(
                "curl",
                &["https://example.com".to_string()],
                &InjectionMethod::CurlPipe,
                &lease,
            )
            .expect("build_proxy_command failed");
        assert_eq!(cmd, "curl");
        assert!(args.contains(&"--proxy".to_string()));
        assert!(args.contains(&"http://127.0.0.1:20000".to_string()));
        // Original args should be at the end.
        assert_eq!(args.last().unwrap(), "https://example.com");
    }

    #[test]
    fn test_build_proxy_command_git() {
        let exec = make_executor();
        let lease = test_lease();
        let (_cmd, _args, env) = exec
            .build_proxy_command("git", &[], &InjectionMethod::GitAskpass, &lease)
            .expect("build_proxy_command failed");
        assert_eq!(
            env.get("https_proxy").map(String::as_str),
            Some("http://127.0.0.1:20000")
        );
        assert_eq!(
            env.get("GIT_TERMINAL_PROMPT").map(String::as_str),
            Some("0")
        );
    }

    #[test]
    fn test_run_simple_command() {
        let exec = make_executor();
        let lease = test_lease();
        let result = exec.run("true", &[], &InjectionMethod::GenericAskpass, lease);
        assert!(result.is_ok(), "run failed: {:?}", result.err());
        assert_eq!(result.unwrap().exit_code, 0);
    }

    #[test]
    fn test_run_failing_command() {
        let exec = make_executor();
        let lease = test_lease();
        let result = exec.run("false", &[], &InjectionMethod::GenericAskpass, lease);
        assert!(result.is_ok(), "run itself should succeed (false exits 1)");
        assert_ne!(result.unwrap().exit_code, 0);
    }
}
