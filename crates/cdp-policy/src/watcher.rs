//! Policy directory watcher.
//!
//! Monitors a directory of TOML policy files for changes and sends reloaded
//! [`PolicyEntry`] sets through a channel whenever the on-disk policies are
//! modified.
//!
//! Uses the Linux `inotify` API to receive filesystem events.  After any
//! event, a 100ms debounce window absorbs burst writes (editors typically
//! write a file in several steps) before triggering a reload.
//!
//! As a best-effort security heuristic, the watcher tries to identify which
//! process modified a file by scanning `/proc/*/fd/` for open file descriptors
//! that point to the modified path.  If the modifying process is not a
//! recognised editor, a warning is emitted so operators can detect unexpected
//! policy mutations.

use std::path::{Path, PathBuf};
use std::time::Duration;

use inotify::{EventMask, Inotify, WatchMask};
use tracing::{error, info, warn};

use crate::error::PolicyError;
use crate::parser::{load_policies_from_dir, PolicyEntry};

// ---------------------------------------------------------------------------
// Known editor binaries (heuristic for modifier identification)
// ---------------------------------------------------------------------------

const KNOWN_EDITORS: &[&str] = &[
    "vim", "nvim", "nano", "code", "kate", "gedit", "emacs", "helix", "subl",
    "micro", "vi",
];

// ---------------------------------------------------------------------------
// Public type
// ---------------------------------------------------------------------------

/// Watches a policy directory for filesystem changes and triggers reloads.
#[derive(Debug)]
pub struct PolicyWatcher {
    policy_dir: PathBuf,
}

impl PolicyWatcher {
    /// Create a new `PolicyWatcher` for the given directory.
    ///
    /// The directory is not opened or validated at construction time; any
    /// errors are surfaced when [`watch`] is called.
    pub fn new(policy_dir: PathBuf) -> Self {
        Self { policy_dir }
    }

    /// Run the watcher event loop.
    ///
    /// Blocks (asynchronously) until the `reload_tx` sender is dropped, the
    /// inotify file descriptor is closed, or an unrecoverable error occurs.
    ///
    /// On any relevant filesystem event in `policy_dir`:
    ///
    /// 1. A 100ms debounce window absorbs additional events.
    /// 2. The modifying process is identified on a best-effort basis.
    /// 3. If the modifier is not a recognised editor, a security warning is
    ///    logged.
    /// 4. All `.toml` files in the directory are reloaded via
    ///    [`load_policies_from_dir`].
    /// 5. If parsing succeeds, the new policy set is sent through `reload_tx`.
    ///    Parse errors are logged but do not crash the loop.
    ///
    /// # Errors
    ///
    /// - [`PolicyError::Watcher`] — inotify could not be initialised, the
    ///   watch could not be added, or a non-recoverable read error occurred.
    pub async fn watch(
        &self,
        reload_tx: tokio::sync::mpsc::Sender<Vec<PolicyEntry>>,
    ) -> Result<(), PolicyError> {
        let inotify = Inotify::init()
            .map_err(|e| PolicyError::Watcher(format!("inotify init failed: {e}")))?;

        inotify
            .watches()
            .add(
                &self.policy_dir,
                WatchMask::MODIFY
                    | WatchMask::CREATE
                    | WatchMask::DELETE
                    | WatchMask::MOVED_TO,
            )
            .map_err(|e| {
                PolicyError::Watcher(format!(
                    "failed to add watch on {}: {e}",
                    self.policy_dir.display()
                ))
            })?;

        info!(
            dir = %self.policy_dir.display(),
            "policy watcher started"
        );

        // The inotify blocking reads are performed in a spawn_blocking task to
        // avoid stalling the async runtime.  A debounce is applied in async
        // context between the blocking read and the reload.
        loop {
            // Block until at least one inotify event arrives (runs on thread pool).
            let policy_dir = self.policy_dir.clone();
            let event_info: Result<Vec<EventInfo>, PolicyError> =
                tokio::task::spawn_blocking(move || read_inotify_events(&policy_dir))
                    .await
                    .map_err(|e| PolicyError::Watcher(format!("spawn_blocking panicked: {e}")))?;

            let events = match event_info {
                Ok(ev) => ev,
                Err(PolicyError::Watcher(msg)) if msg.contains("channel closed") => {
                    // Inotify fd closed — normal shutdown.
                    info!("inotify watch closed; policy watcher exiting");
                    break;
                }
                Err(e) => {
                    error!("inotify read error: {e}");
                    return Err(e);
                }
            };

            for ev in &events {
                info!(
                    event = ?ev.mask,
                    file = ev.name.as_deref().unwrap_or("<unknown>"),
                    "policy file event"
                );
            }

            // Debounce: wait for the burst of writes to settle.
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Best-effort: identify which process modified one of the affected files.
            for ev in &events {
                let modified_path = ev
                    .name
                    .as_deref()
                    .map(|n| self.policy_dir.join(n));

                if let Some(path) = modified_path {
                    match identify_modifier(&path) {
                        Some((pid, binary)) => {
                            if is_known_editor(&binary) {
                                info!(
                                    pid,
                                    binary = %binary.display(),
                                    file = %path.display(),
                                    "policy file modified by editor"
                                );
                            } else {
                                warn!(
                                    pid,
                                    binary = %binary.display(),
                                    file = %path.display(),
                                    "security alert: policy file modified by non-editor process: {}",
                                    binary.file_name()
                                        .and_then(|n| n.to_str())
                                        .unwrap_or("<unknown>")
                                );
                            }
                        }
                        None => {
                            info!(
                                file = %path.display(),
                                "policy file modified; modifier process could not be identified \
                                 (file may already be closed)"
                            );
                        }
                    }
                }
            }

            // Reload all policies.
            match load_policies_from_dir(&self.policy_dir) {
                Ok(entries) => {
                    info!(count = entries.len(), "policies reloaded");
                    if reload_tx.send(entries).await.is_err() {
                        // Receiver dropped — caller shut down, exit cleanly.
                        info!("policy reload receiver dropped; watcher exiting");
                        break;
                    }
                }
                Err(e) => {
                    error!("policy reload failed (keeping previous policies): {e}");
                    // Non-fatal: keep running and retry on next event.
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal: EventInfo — minimal data extracted from an inotify event
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct EventInfo {
    mask: EventMask,
    name: Option<String>,
}

/// Read at least one batch of inotify events synchronously (blocking).
///
/// This function is intended to be called from [`tokio::task::spawn_blocking`].
fn read_inotify_events(policy_dir: &Path) -> Result<Vec<EventInfo>, PolicyError> {
    // We need a fresh Inotify instance that we can use synchronously here, but
    // the caller already set up the watch.  Because inotify instances are not
    // Send, we instead re-open the directory watch here for blocking reads.
    //
    // The approach: create a short-lived synchronous inotify, add the watch,
    // perform a blocking read, then return.  This means each iteration of the
    // loop pays the overhead of one watch setup — acceptable for a low-frequency
    // operation like policy file changes.
    let mut inotify = Inotify::init()
        .map_err(|e| PolicyError::Watcher(format!("inotify init failed in thread: {e}")))?;

    inotify
        .watches()
        .add(
            policy_dir,
            WatchMask::MODIFY
                | WatchMask::CREATE
                | WatchMask::DELETE
                | WatchMask::MOVED_TO,
        )
        .map_err(|e| {
            PolicyError::Watcher(format!(
                "failed to add inotify watch in thread on {}: {e}",
                policy_dir.display()
            ))
        })?;

    let mut buffer = [0u8; 4096];
    let events = inotify
        .read_events_blocking(&mut buffer)
        .map_err(|e| PolicyError::Watcher(format!("inotify read error: {e}")))?;

    let infos: Vec<EventInfo> = events
        .map(|ev| EventInfo {
            mask: ev.mask,
            name: ev.name.map(|n| n.to_string_lossy().into_owned()),
        })
        .collect();

    Ok(infos)
}

// ---------------------------------------------------------------------------
// Best-effort process identification via /proc
// ---------------------------------------------------------------------------

/// Scan `/proc/*/fd/` for a symlink pointing to `file_path`.
///
/// Returns the PID and resolved binary path of the first matching process, or
/// `None` if no process is found with the file open.
///
/// This is inherently racy: the process may have closed the file descriptor
/// between the inotify event and this scan.  Any errors during scanning are
/// silently ignored — the function is best-effort only.
pub(crate) fn identify_modifier(file_path: &Path) -> Option<(u32, PathBuf)> {
    // Canonicalize the target so symlink-resolved paths compare correctly.
    let target = std::fs::canonicalize(file_path).unwrap_or_else(|_| file_path.to_path_buf());

    let proc_dir = std::fs::read_dir("/proc").ok()?;

    for entry in proc_dir.flatten() {
        let pid_str = entry.file_name();
        // Non-numeric /proc entries (e.g. /proc/self, /proc/net) must be
        // skipped, not cause an early return via `?`.
        let Some(pid_str_s) = pid_str.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str_s.parse::<u32>() else {
            continue;
        };

        let fd_dir = entry.path().join("fd");
        let fds = match std::fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue, // permission denied or process exited
        };

        for fd_entry in fds.flatten() {
            // Each fd entry is a symlink to the actual file path.
            let link_target = match std::fs::read_link(fd_entry.path()) {
                Ok(t) => t,
                Err(_) => continue,
            };

            if link_target == target {
                // Found a match.  Resolve the binary path.
                let exe_path = PathBuf::from(format!("/proc/{}/exe", pid));
                let binary = std::fs::read_link(&exe_path).unwrap_or(exe_path);
                return Some((pid, binary));
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Known editor check
// ---------------------------------------------------------------------------

/// Returns `true` if `binary_path`'s filename (without directory) is in the
/// list of known editor binaries.
pub(crate) fn is_known_editor(binary_path: &Path) -> bool {
    binary_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|name| KNOWN_EDITORS.contains(&name))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::Duration;

    use tempfile::TempDir;
    use tokio::sync::mpsc;

    use super::*;

    // -----------------------------------------------------------------------
    // Test 1: is_known_editor with all known editors
    // -----------------------------------------------------------------------

    #[test]
    fn is_known_editor_known_names() {
        for name in KNOWN_EDITORS {
            let path = PathBuf::from(format!("/usr/bin/{}", name));
            assert!(
                is_known_editor(&path),
                "{name} should be recognised as a known editor"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test 2: is_known_editor with unknown binaries
    // -----------------------------------------------------------------------

    #[test]
    fn is_known_editor_unknown_names() {
        let unknowns = [
            "/usr/bin/curl",
            "/bin/sh",
            "/usr/bin/python3",
            "/usr/local/bin/my-script",
            "/proc/self/exe",
        ];
        for path_str in unknowns {
            let path = PathBuf::from(path_str);
            assert!(
                !is_known_editor(&path),
                "{path_str} should NOT be recognised as a known editor"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test 3: is_known_editor with full paths to known editors
    // -----------------------------------------------------------------------

    #[test]
    fn is_known_editor_full_path_to_known_editor() {
        assert!(is_known_editor(&PathBuf::from("/usr/local/bin/nvim")));
        assert!(is_known_editor(&PathBuf::from("/usr/bin/vim")));
        assert!(is_known_editor(&PathBuf::from("/usr/bin/code")));
    }

    // -----------------------------------------------------------------------
    // Test 4: is_known_editor with empty path
    // -----------------------------------------------------------------------

    #[test]
    fn is_known_editor_empty_path_returns_false() {
        assert!(!is_known_editor(&PathBuf::from("")));
    }

    // -----------------------------------------------------------------------
    // Test 5: PolicyWatcher::new stores the policy_dir
    // -----------------------------------------------------------------------

    #[test]
    fn policy_watcher_new_stores_dir() {
        let dir = PathBuf::from("/tmp/cdp-test-policies");
        let watcher = PolicyWatcher::new(dir.clone());
        assert_eq!(watcher.policy_dir, dir);
    }

    // -----------------------------------------------------------------------
    // Test 6: Integration test — write file → watcher fires reload
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn watcher_fires_on_file_creation() {
        let dir = TempDir::new().expect("tempdir creation failed");
        let policy_dir = dir.path().to_path_buf();

        let (tx, mut rx) = mpsc::channel::<Vec<PolicyEntry>>(4);
        let watcher = PolicyWatcher::new(policy_dir.clone());

        // Run the watcher on a background task.
        let watcher_handle = tokio::spawn(async move {
            let _ = watcher.watch(tx).await;
        });

        // Give the watcher a moment to set up its inotify watch.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Write a valid policy file into the watched directory.
        let policy_toml = r#"
[[policy]]
name = "test-policy"

[policy.match]
credential_ref = "test_cred"

[policy.allow]
hosts = ["example.com"]
methods = ["GET"]
"#;
        let file_path = policy_dir.join("test.toml");
        {
            let mut f = std::fs::File::create(&file_path).expect("file create failed");
            f.write_all(policy_toml.as_bytes()).expect("write failed");
        }

        // Wait for the reload event, with a generous timeout.
        let received = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;

        // Cancel the watcher before asserting so the test doesn't hang.
        watcher_handle.abort();

        let entries = received
            .expect("timed out waiting for reload event")
            .expect("channel closed before receiving reload");

        assert_eq!(entries.len(), 1, "expected 1 policy entry after reload");
        assert_eq!(entries[0].name, "test-policy");
    }

    // -----------------------------------------------------------------------
    // Test 7: Watcher exits cleanly when sender is dropped
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn watcher_exits_when_receiver_dropped() {
        let dir = TempDir::new().expect("tempdir creation failed");
        let policy_dir = dir.path().to_path_buf();

        let (tx, rx) = mpsc::channel::<Vec<PolicyEntry>>(4);
        // Drop the receiver immediately so any send fails.
        drop(rx);

        let watcher = PolicyWatcher::new(policy_dir.clone());

        // The watcher should start, then the first successful reload will find
        // the channel closed and exit.
        let handle = tokio::spawn(async move {
            let _ = watcher.watch(tx).await;
        });

        // Write a file to trigger a reload → send fails → watcher exits.
        let policy_toml = r#"
[[policy]]
name = "exit-test"

[policy.match]
credential_ref = "cred"

[policy.allow]
hosts = ["example.com"]
"#;
        tokio::time::sleep(Duration::from_millis(50)).await;
        std::fs::write(policy_dir.join("exit.toml"), policy_toml).expect("write failed");

        // The watcher task should finish within a reasonable timeout.
        let result =
            tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(
            result.is_ok(),
            "watcher task should exit cleanly after receiver is dropped"
        );
    }

    // -----------------------------------------------------------------------
    // Test 8: Watcher sends updated entries after file modification
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn watcher_sends_updated_entries_on_modify() {
        let dir = TempDir::new().expect("tempdir creation failed");
        let policy_dir = dir.path().to_path_buf();

        // Pre-create a policy file so the directory is non-empty on start.
        let initial_toml = r#"
[[policy]]
name = "initial"

[policy.match]
credential_ref = "cred"

[policy.allow]
hosts = ["example.com"]
"#;
        let file_path = policy_dir.join("policy.toml");
        std::fs::write(&file_path, initial_toml).expect("write failed");

        let (tx, mut rx) = mpsc::channel::<Vec<PolicyEntry>>(8);
        let watcher = PolicyWatcher::new(policy_dir.clone());

        let handle = tokio::spawn(async move {
            let _ = watcher.watch(tx).await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Overwrite the file with a different policy name.
        let updated_toml = r#"
[[policy]]
name = "updated"

[policy.match]
credential_ref = "cred"

[policy.allow]
hosts = ["updated.example.com"]
"#;
        std::fs::write(&file_path, updated_toml).expect("write failed");

        let received = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
        handle.abort();

        let entries = received
            .expect("timed out waiting for reload")
            .expect("channel closed");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "updated");
        assert_eq!(
            entries[0].match_block.credential_ref,
            "cred"
        );
    }
}
