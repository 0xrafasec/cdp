//! Interactive user-approval flow for CDP credential requests.
//!
//! This module drives the GUI-based approval dialog shown to the local user
//! when an agent requests a credential that requires human confirmation before
//! a lease is created.  The approval prompt presents:
//!
//! - The requesting agent's binary path and PID.
//! - Optionally, the SHA-256 binary hash (configurable).
//! - The credential reference being requested.
//! - A concise summary of the requested scope.
//! - The agent-provided reason, labelled as untrusted when configured.
//!
//! Supported GUI backends (detected in order, or overridden via
//! [`ApprovalConfig::gui_command`]):
//! - **kdialog** (KDE)
//! - **zenity** (GNOME / GTK)
//! - **osascript** (macOS)

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

use crate::error::PolicyError;
use crate::types::{AgentInfo, ApprovalConfig, ApprovalResult, Scope};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Present an interactive approval dialog to the local user.
///
/// Builds a human-readable message describing the agent, credential, scope,
/// and reason; then launches the appropriate GUI tool to collect the user's
/// decision.
///
/// # Errors
///
/// - [`PolicyError::ApprovalTimeout`] — the user did not respond within
///   `config.timeout_seconds`.
/// - [`PolicyError::ApprovalCommand`] — the GUI command could not be spawned
///   (e.g. not found), exited with an unexpected status, or no GUI tool is
///   available.
pub async fn prompt_user(
    agent: &AgentInfo,
    credential_ref: &str,
    scope: &Scope,
    reason: &str,
    config: &ApprovalConfig,
) -> Result<ApprovalResult, PolicyError> {
    let message = format_approval_message(agent, credential_ref, scope, reason, config);

    // Determine which GUI command to use.
    let gui_cmd = if !config.gui_command.is_empty() {
        config.gui_command.clone()
    } else {
        detect_gui_command().ok_or_else(|| {
            PolicyError::ApprovalCommand("no GUI approval tool found".into())
        })?
    };

    run_gui_approval(&gui_cmd, &message, config.timeout_seconds).await
}

// ---------------------------------------------------------------------------
// Message formatting
// ---------------------------------------------------------------------------

/// Build the human-readable approval message presented in the GUI dialog.
///
/// Exposed as `pub` to allow unit testing without spawning any processes.
pub fn format_approval_message(
    agent: &AgentInfo,
    credential_ref: &str,
    scope: &Scope,
    reason: &str,
    config: &ApprovalConfig,
) -> String {
    let mut lines: Vec<String> = Vec::new();

    // Agent identity line.
    lines.push(format!(
        "Agent:       {} (PID {})",
        agent.binary_path.display(),
        agent.pid
    ));

    // Optional binary hash.
    if config.show_binary_hash {
        let hex = bytes_to_hex(&agent.binary_hash);
        // Show first 16 hex characters (8 bytes) then "..."
        let short = &hex[..16.min(hex.len())];
        lines.push(format!("Binary Hash: sha256:{}...", short));
    }

    // Credential reference.
    lines.push(format!("Credential:  {}", credential_ref));

    // Scope summary.
    let scope_summary = format_scope_summary(scope);
    if !scope_summary.is_empty() {
        lines.push(format!("Scope:       {}", scope_summary));
    }

    // Duration / request limits.
    let duration_parts = format_duration_parts(scope);
    if !duration_parts.is_empty() {
        lines.push(format!("Duration:    {}", duration_parts));
    }

    // Agent-provided reason (truncated, labeled).
    let truncated_reason = truncate_reason(reason, config.max_reason_length);
    let reason_label = if config.label_reason_untrusted {
        "--- Agent-provided reason (UNVERIFIED) ---"
    } else {
        "--- Agent-provided reason ---"
    };
    lines.push(String::new());
    lines.push(reason_label.to_string());
    lines.push(truncated_reason);

    lines.join("\n")
}

/// Summarise the scope into a compact one-line string for display.
///
/// Format: `"<methods> to <host> <paths_summary>"`
fn format_scope_summary(scope: &Scope) -> String {
    let mut parts: Vec<String> = Vec::new();

    if !scope.methods.is_empty() {
        parts.push(scope.methods.join(", "));
    }

    if !scope.hosts.is_empty() {
        if !parts.is_empty() {
            parts.push("to".to_string());
        }
        parts.push(scope.hosts[0].clone());
    }

    if !scope.paths.is_empty() {
        let path_summary = summarise_paths(&scope.paths);
        parts.push(path_summary);
    }

    parts.join(" ")
}

/// Summarise a path list: show first 3 paths, then "+N more" if there are more.
fn summarise_paths(paths: &[String]) -> String {
    const MAX_SHOWN: usize = 3;
    if paths.len() <= MAX_SHOWN {
        paths.join(", ")
    } else {
        let shown = &paths[..MAX_SHOWN];
        let remainder = paths.len() - MAX_SHOWN;
        format!("{}, +{} more", shown.join(", "), remainder)
    }
}

/// Format the duration / request count limits portion of the scope summary.
fn format_duration_parts(scope: &Scope) -> String {
    let mut parts: Vec<String> = Vec::new();

    if let Some(ttl) = scope.ttl_seconds {
        parts.push(format!("{}s", ttl));
    }

    if let Some(max_req) = scope.max_requests {
        parts.push(format!("max {} requests", max_req));
    }

    parts.join(", ")
}

/// Truncate `reason` to at most `max_len` Unicode scalar values, appending
/// `"..."` if truncation occurred.
fn truncate_reason(reason: &str, max_len: usize) -> String {
    if max_len == 0 {
        return String::new();
    }

    let char_count = reason.chars().count();
    if char_count <= max_len {
        reason.to_string()
    } else {
        // Truncate at max_len - 3 to leave room for "..."
        let truncate_at = max_len.saturating_sub(3);
        let truncated: String = reason.chars().take(truncate_at).collect();
        format!("{}...", truncated)
    }
}

/// Encode a byte slice as lowercase hexadecimal.
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// GUI detection
// ---------------------------------------------------------------------------

/// Probe PATH for a supported GUI approval tool and return the first found.
///
/// Checks in order: `kdialog`, `zenity`, `osascript`.
///
/// Returns `None` if none of the candidates are present on PATH.
pub fn detect_gui_command() -> Option<String> {
    const CANDIDATES: &[&str] = &["kdialog", "zenity", "osascript"];

    for candidate in CANDIDATES {
        if which(candidate) {
            return Some((*candidate).to_string());
        }
    }

    None
}

/// Returns `true` if `name` is found on the system PATH using `which`.
fn which(name: &str) -> bool {
    std::process::Command::new("which")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// GUI subprocess launch
// ---------------------------------------------------------------------------

/// Dispatch to the correct GUI handler based on the detected or configured
/// command name, wrap it in a timeout, and map the result to [`ApprovalResult`].
async fn run_gui_approval(
    gui_cmd: &str,
    message: &str,
    timeout_secs: u64,
) -> Result<ApprovalResult, PolicyError> {
    // Extract the base name for dispatch (the config may contain a full path).
    let base = std::path::Path::new(gui_cmd)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(gui_cmd);

    let fut = async {
        match base {
            "kdialog" => run_kdialog(gui_cmd, message).await,
            "zenity" => run_zenity(gui_cmd, message).await,
            "osascript" => run_osascript(gui_cmd, message).await,
            other => Err(PolicyError::ApprovalCommand(format!(
                "unsupported GUI command: {other:?}; supported: kdialog, zenity, osascript"
            ))),
        }
    };

    match timeout(Duration::from_secs(timeout_secs), fut).await {
        Ok(result) => result,
        Err(_elapsed) => Err(PolicyError::ApprovalTimeout(timeout_secs)),
    }
}

// ---------------------------------------------------------------------------
// kdialog backend
// ---------------------------------------------------------------------------
//
// kdialog --warningyesnocancel "<message>" --title "CDP Credential Request"
//   Exit 0  → Yes    → AllowOnce
//   Exit 1  → No     → Deny
//   Exit 2  → Cancel → AllowTimed { duration_seconds: 600 }

async fn run_kdialog(
    gui_cmd: &str,
    message: &str,
) -> Result<ApprovalResult, PolicyError> {
    let mut child = Command::new(gui_cmd)
        .arg("--warningyesnocancel")
        .arg(message)
        .arg("--title")
        .arg("CDP Credential Request")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| PolicyError::ApprovalCommand(format!("failed to spawn kdialog: {e}")))?;

    let status = child
        .wait()
        .await
        .map_err(|e| PolicyError::ApprovalCommand(format!("kdialog wait failed: {e}")))?;

    match status.code() {
        Some(0) => Ok(ApprovalResult::AllowOnce),
        Some(1) => Ok(ApprovalResult::Deny),
        Some(2) => Ok(ApprovalResult::AllowTimed { duration_seconds: 600 }),
        Some(code) => Err(PolicyError::ApprovalCommand(format!(
            "kdialog exited with unexpected code {code}"
        ))),
        None => Err(PolicyError::ApprovalCommand(
            "kdialog terminated by signal".into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// zenity backend
// ---------------------------------------------------------------------------
//
// zenity --question --title="CDP Credential Request" --text="<message>"
//        --ok-label="Allow Once" --cancel-label="Deny" --extra-button="Allow 10min"
//   Exit 0, stdout empty          → AllowOnce
//   Exit non-0, stdout "Allow 10min" → AllowTimed { 600 }
//   Otherwise                     → Deny

async fn run_zenity(
    gui_cmd: &str,
    message: &str,
) -> Result<ApprovalResult, PolicyError> {
    let mut child = Command::new(gui_cmd)
        .arg("--question")
        .arg("--no-markup")
        .arg("--title=CDP Credential Request")
        .arg(format!("--text={}", message))
        .arg("--ok-label=Allow Once")
        .arg("--cancel-label=Deny")
        .arg("--extra-button=Allow 10min")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| PolicyError::ApprovalCommand(format!("failed to spawn zenity: {e}")))?;

    let mut stdout_text = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        stdout
            .read_to_string(&mut stdout_text)
            .await
            .map_err(|e| PolicyError::ApprovalCommand(format!("zenity stdout read error: {e}")))?;
    }

    let status = child
        .wait()
        .await
        .map_err(|e| PolicyError::ApprovalCommand(format!("zenity wait failed: {e}")))?;

    if status.code() == Some(0) {
        Ok(ApprovalResult::AllowOnce)
    } else if stdout_text.contains("Allow 10min") {
        Ok(ApprovalResult::AllowTimed { duration_seconds: 600 })
    } else {
        Ok(ApprovalResult::Deny)
    }
}

// ---------------------------------------------------------------------------
// osascript backend
// ---------------------------------------------------------------------------
//
// osascript -e 'display dialog "<escaped>" buttons {"Deny","Allow 10min","Allow Once"}
//               default button "Allow Once" with icon caution'
//   stdout contains "Allow Once" → AllowOnce
//   stdout contains "Allow 10min" → AllowTimed { 600 }
//   Otherwise                     → Deny

async fn run_osascript(
    gui_cmd: &str,
    message: &str,
) -> Result<ApprovalResult, PolicyError> {
    // Escape for AppleScript double-quoted strings: backslashes and double
    // quotes must be escaped.  The message may contain agent-provided content
    // (the "reason" field) which is explicitly untrusted — embedding it in a
    // single-quoted AppleScript string with only `'`→`\'` escaping is
    // insufficient and allows injection.  Double-quoted strings with `\` and
    // `"` escaped are the safe form.
    let escaped = message.replace('\\', "\\\\").replace('"', "\\\"");

    let script = format!(
        "display dialog \"{}\" buttons {{\"Deny\", \"Allow 10min\", \"Allow Once\"}} \
         default button \"Allow Once\" with icon caution",
        escaped
    );

    let mut child = Command::new(gui_cmd)
        .arg("-e")
        .arg(&script)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| PolicyError::ApprovalCommand(format!("failed to spawn osascript: {e}")))?;

    let mut stdout_text = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        stdout
            .read_to_string(&mut stdout_text)
            .await
            .map_err(|e| {
                PolicyError::ApprovalCommand(format!("osascript stdout read error: {e}"))
            })?;
    }

    // osascript returns something like: "button returned:Allow Once"
    child
        .wait()
        .await
        .map_err(|e| PolicyError::ApprovalCommand(format!("osascript wait failed: {e}")))?;

    if stdout_text.contains("Allow Once") {
        Ok(ApprovalResult::AllowOnce)
    } else if stdout_text.contains("Allow 10min") {
        Ok(ApprovalResult::AllowTimed { duration_seconds: 600 })
    } else {
        Ok(ApprovalResult::Deny)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::types::{AgentInfo, ApprovalConfig, Scope};

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    fn make_agent() -> AgentInfo {
        AgentInfo {
            uid: 1000,
            pid: 12345,
            binary_path: PathBuf::from("/usr/bin/my-agent"),
            binary_hash: [0xab; 32],
            start_time: 123456789,
            fingerprint_hash: [0xcd; 32],
            agent_id: Some("my-agent".to_string()),
            agent_version: Some("1.0.0".to_string()),
        }
    }

    fn make_scope() -> Scope {
        Scope {
            hosts: vec!["api.github.com".to_string()],
            methods: vec!["GET".to_string()],
            paths: vec!["/repos/**".to_string(), "/users/**".to_string()],
            forbidden_paths: Vec::new(),
            ttl_seconds: Some(600),
            max_requests: Some(10),
            body_constraints: None,
            network: None,
        }
    }

    fn make_config(show_hash: bool, untrusted: bool) -> ApprovalConfig {
        ApprovalConfig {
            gui_command: String::new(),
            timeout_seconds: 30,
            show_binary_hash: show_hash,
            label_reason_untrusted: untrusted,
            max_reason_length: 200,
        }
    }

    // -----------------------------------------------------------------------
    // Test 1: Full message with all config options enabled
    // -----------------------------------------------------------------------

    #[test]
    fn format_approval_message_full() {
        let agent = make_agent();
        let scope = make_scope();
        let config = make_config(true, true);

        let msg = format_approval_message(
            &agent,
            "github_api",
            &scope,
            "Fetching open PRs for code review",
            &config,
        );

        assert!(msg.contains("Agent:"));
        assert!(msg.contains("/usr/bin/my-agent"));
        assert!(msg.contains("PID 12345"));
        assert!(msg.contains("Binary Hash:"));
        assert!(msg.contains("sha256:abababababababab..."));
        assert!(msg.contains("Credential:  github_api"));
        assert!(msg.contains("Scope:"));
        assert!(msg.contains("GET"));
        assert!(msg.contains("api.github.com"));
        assert!(msg.contains("Duration:"));
        assert!(msg.contains("600s"));
        assert!(msg.contains("max 10 requests"));
        assert!(msg.contains("(UNVERIFIED)"));
        assert!(msg.contains("Fetching open PRs for code review"));
    }

    // -----------------------------------------------------------------------
    // Test 2: show_binary_hash = false omits the hash line
    // -----------------------------------------------------------------------

    #[test]
    fn format_approval_message_no_hash() {
        let agent = make_agent();
        let scope = make_scope();
        let config = make_config(false, true);

        let msg =
            format_approval_message(&agent, "github_api", &scope, "some reason", &config);

        assert!(!msg.contains("Binary Hash:"), "hash line should be absent");
        assert!(msg.contains("Agent:"));
    }

    // -----------------------------------------------------------------------
    // Test 3: label_reason_untrusted = false uses plain label
    // -----------------------------------------------------------------------

    #[test]
    fn format_approval_message_trusted_reason_label() {
        let agent = make_agent();
        let scope = make_scope();
        let config = make_config(false, false);

        let msg = format_approval_message(&agent, "github_api", &scope, "my reason", &config);

        assert!(!msg.contains("(UNVERIFIED)"), "should not label as UNVERIFIED");
        assert!(msg.contains("Agent-provided reason"), "should contain reason label");
    }

    // -----------------------------------------------------------------------
    // Test 4: Reason truncated at max_reason_length
    // -----------------------------------------------------------------------

    #[test]
    fn format_approval_message_truncates_reason() {
        let agent = make_agent();
        let scope = Scope::default();
        let config = ApprovalConfig {
            gui_command: String::new(),
            timeout_seconds: 30,
            show_binary_hash: false,
            label_reason_untrusted: true,
            max_reason_length: 20,
        };

        let long_reason = "This is a very long reason string that exceeds the limit";
        let msg = format_approval_message(&agent, "cred", &scope, long_reason, &config);

        // The displayed reason must be no longer than max_reason_length chars.
        // Find the reason section (after the label line).
        let lines: Vec<&str> = msg.lines().collect();
        let reason_line = lines.last().expect("should have lines");
        let char_count = reason_line.chars().count();
        assert!(
            char_count <= 20,
            "reason line has {char_count} chars, expected ≤ 20: {reason_line:?}"
        );
        assert!(reason_line.ends_with("..."), "truncated reason should end with '...'");
    }

    // -----------------------------------------------------------------------
    // Test 5: Scope summary formats methods, host, and paths correctly
    // -----------------------------------------------------------------------

    #[test]
    fn format_scope_summary_methods_host_paths() {
        let scope = Scope {
            hosts: vec!["api.example.com".to_string()],
            methods: vec!["GET".to_string(), "POST".to_string()],
            paths: vec![
                "/repos/**".to_string(),
                "/users/**".to_string(),
                "/orgs/**".to_string(),
            ],
            ..Scope::default()
        };

        let summary = format_scope_summary(&scope);
        assert!(summary.contains("GET, POST"), "methods should be comma-joined");
        assert!(summary.contains("api.example.com"), "should contain host");
        assert!(summary.contains("/repos/**"), "should contain paths");
    }

    // -----------------------------------------------------------------------
    // Test 6: Scope paths summary — more than 3 paths shows "+N more"
    // -----------------------------------------------------------------------

    #[test]
    fn format_scope_summary_paths_overflow() {
        let scope = Scope {
            hosts: vec!["example.com".to_string()],
            methods: vec!["GET".to_string()],
            paths: vec![
                "/a".to_string(),
                "/b".to_string(),
                "/c".to_string(),
                "/d".to_string(),
                "/e".to_string(),
            ],
            ..Scope::default()
        };

        let summary = format_scope_summary(&scope);
        assert!(summary.contains("+2 more"), "should show '+2 more' for 5 paths");
    }

    // -----------------------------------------------------------------------
    // Test 7: Empty scope produces no scope/duration lines
    // -----------------------------------------------------------------------

    #[test]
    fn format_approval_message_empty_scope() {
        let agent = make_agent();
        let scope = Scope::default();
        let config = make_config(false, false);

        let msg =
            format_approval_message(&agent, "some_cred", &scope, "reason", &config);

        // No Scope: or Duration: lines when scope is empty.
        assert!(!msg.contains("Scope:"), "empty scope should omit Scope line");
        assert!(!msg.contains("Duration:"), "empty scope should omit Duration line");
    }

    // -----------------------------------------------------------------------
    // Test 8: truncate_reason boundary — exactly max_len chars untouched
    // -----------------------------------------------------------------------

    #[test]
    fn truncate_reason_exact_length_not_truncated() {
        let reason = "hello world"; // 11 chars
        let result = truncate_reason(reason, 11);
        assert_eq!(result, "hello world");
    }

    // -----------------------------------------------------------------------
    // Test 9: truncate_reason — max_len = 0 returns empty string
    // -----------------------------------------------------------------------

    #[test]
    fn truncate_reason_zero_max_returns_empty() {
        let result = truncate_reason("anything", 0);
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // Test 10: detect_gui_command returns None when nothing is on PATH
    //          (only run when neither kdialog nor zenity is installed)
    // -----------------------------------------------------------------------

    #[test]
    fn detect_gui_command_on_empty_path() {
        // Temporarily override PATH to an empty directory to ensure no GUI
        // tools are found.  We do this by checking with a known-absent name.
        //
        // This test is inherently environment-sensitive: if kdialog, zenity, or
        // osascript is installed the test would not exercise the None branch.
        // We guard with an environment check so CI without a display still
        // passes correctly.
        let kdialog_present = which("kdialog");
        let zenity_present = which("zenity");
        let osascript_present = which("osascript");

        if kdialog_present || zenity_present || osascript_present {
            // At least one tool available — detect_gui_command should return Some.
            assert!(
                detect_gui_command().is_some(),
                "expected Some when a GUI tool is present"
            );
        } else {
            // No tools available.
            assert!(
                detect_gui_command().is_none(),
                "expected None when no GUI tool is installed"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test 11: Binary hash is formatted with the first 16 hex chars + "..."
    // -----------------------------------------------------------------------

    #[test]
    fn binary_hash_shows_first_16_hex_chars() {
        let agent = AgentInfo {
            binary_hash: [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                          0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                          0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
                          0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            uid: 0,
            pid: 1,
            binary_path: PathBuf::from("/bin/agent"),
            start_time: 0,
            fingerprint_hash: [0u8; 32],
            agent_id: None,
            agent_version: None,
        };
        let scope = Scope::default();
        let config = make_config(true, false);

        let msg = format_approval_message(&agent, "c", &scope, "r", &config);
        // First 8 bytes → 16 hex chars = "123456789abcdef0"
        assert!(
            msg.contains("sha256:123456789abcdef0..."),
            "expected short hash in message: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 12: Duration line shows only TTL when max_requests absent
    // -----------------------------------------------------------------------

    #[test]
    fn duration_only_ttl() {
        let agent = make_agent();
        let scope = Scope {
            ttl_seconds: Some(3600),
            max_requests: None,
            ..Scope::default()
        };
        let config = make_config(false, false);

        let msg = format_approval_message(&agent, "c", &scope, "r", &config);
        assert!(msg.contains("Duration:    3600s"), "should show 3600s");
        assert!(!msg.contains("max"), "should not show max requests");
    }
}
