//! CDP policy crate — policy loading, evaluation, and approval.
//!
//! This crate is standalone: it does NOT depend on `cdp-gate`. The gate
//! constructs lightweight [`AgentInfo`] values from its internal
//! `AgentFingerprint` before calling into the policy engine.
//!
//! # Architecture
//!
//! - **parser** — deserialises TOML files, validates constraints.
//! - **evaluator** — three-tier priority matching, scope intersection.
//! - **approval** — interactive GUI prompt (kdialog / zenity / osascript).
//! - **watcher** — inotify directory watch with debounced reload.
//! - **glob** — URL path glob matching (`*`, `**`).
//!
//! The [`PolicyEngine`] struct ties these together behind a single facade.

pub mod approval;
pub mod error;
pub mod evaluator;
pub mod glob;
pub mod parser;
pub mod types;
pub mod watcher;

pub use error::PolicyError;
pub use evaluator::PolicyEvaluator;
pub use parser::{
    PolicyAllow, PolicyApproval, PolicyDelegation, PolicyEntry, PolicyFile, PolicyMatch,
    load_policies_from_dir, validate_policy,
};
pub use types::{
    AgentInfo, ApprovalConfig, ApprovalResult, BodyConstraints, NetworkConstraints,
    PolicyConstraints, PolicyDecision, Scope,
};
pub use watcher::PolicyWatcher;

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{error, info};

// ---------------------------------------------------------------------------
// PolicyEngine — high-level facade
// ---------------------------------------------------------------------------

/// Top-level policy engine that loads policies from disk, evaluates credential
/// requests, and optionally drives user-approval prompts.
///
/// Internally wraps a [`PolicyEvaluator`] behind an `Arc<RwLock<>>` so the
/// watcher can hot-reload policies without blocking in-flight evaluations.
pub struct PolicyEngine {
    evaluator: Arc<RwLock<PolicyEvaluator>>,
    policy_dir: PathBuf,
    approval_config: ApprovalConfig,
}

impl PolicyEngine {
    /// Load policies from `policy_dir` and create a new engine.
    ///
    /// If the directory does not exist it is created (matching the Gate's
    /// first-run experience). If the directory is empty, the engine starts
    /// with an empty policy set (every request will be denied).
    pub fn new(policy_dir: PathBuf, approval_config: ApprovalConfig) -> Result<Self, PolicyError> {
        if !policy_dir.exists() {
            std::fs::create_dir_all(&policy_dir).map_err(|e| {
                PolicyError::Io(std::io::Error::new(
                    e.kind(),
                    format!("failed to create policy dir {}: {e}", policy_dir.display()),
                ))
            })?;
        }

        let policies = load_policies_from_dir(&policy_dir)?;
        info!(count = policies.len(), dir = %policy_dir.display(), "policies loaded");

        let evaluator = PolicyEvaluator::new(policies);
        Ok(Self {
            evaluator: Arc::new(RwLock::new(evaluator)),
            policy_dir,
            approval_config,
        })
    }

    /// Evaluate a credential request against loaded policies.
    ///
    /// Returns [`PolicyDecision::AutoApprove`], [`RequiresApproval`], or
    /// [`Denied`] without prompting the user. Callers that need the full
    /// approval flow should use [`evaluate_with_approval`] instead.
    pub async fn evaluate(
        &self,
        agent: &AgentInfo,
        credential_ref: &str,
        requested_scope: &Scope,
    ) -> PolicyDecision {
        let eval = self.evaluator.read().await;
        eval.evaluate(agent, credential_ref, requested_scope)
    }

    /// Evaluate and, if the matched policy requires it, prompt the user for
    /// approval via the configured GUI tool.
    ///
    /// Returns:
    /// - `Ok(AutoApprove { .. })` — policy auto-approved, or user clicked
    ///   "Allow Once" / "Allow Timed".
    /// - `Ok(Denied { .. })` — no matching policy, or user clicked "Deny".
    /// - `Err(PolicyError::ApprovalTimeout)` — user did not respond in time.
    /// - `Err(PolicyError::ApprovalCommand)` — GUI tool failed to launch.
    pub async fn evaluate_with_approval(
        &self,
        agent: &AgentInfo,
        credential_ref: &str,
        requested_scope: &Scope,
        reason: &str,
    ) -> Result<PolicyDecision, PolicyError> {
        let decision = self.evaluate(agent, credential_ref, requested_scope).await;

        match &decision {
            PolicyDecision::RequiresApproval {
                granted_scope,
                policy_name,
                constraints,
            } => {
                let result = approval::prompt_user(
                    agent,
                    credential_ref,
                    granted_scope,
                    reason,
                    &self.approval_config,
                )
                .await?;

                match result {
                    ApprovalResult::AllowOnce | ApprovalResult::AllowTimed { .. } => {
                        Ok(PolicyDecision::AutoApprove {
                            granted_scope: granted_scope.clone(),
                            policy_name: policy_name.clone(),
                            constraints: constraints.clone(),
                        })
                    }
                    ApprovalResult::Deny => Ok(PolicyDecision::Denied {
                        reason: "user denied the request".to_string(),
                    }),
                }
            }
            // Auto-approve and deny pass through unchanged.
            _ => Ok(decision),
        }
    }

    /// Spawn a background task that watches the policy directory for changes
    /// and hot-reloads the evaluator.
    ///
    /// Returns a `JoinHandle` that runs until the engine is dropped or an
    /// unrecoverable inotify error occurs.
    pub fn start_watcher(&self) -> tokio::task::JoinHandle<()> {
        let evaluator = Arc::clone(&self.evaluator);
        let policy_dir = self.policy_dir.clone();

        tokio::spawn(async move {
            let watcher = PolicyWatcher::new(policy_dir);
            let (tx, mut rx) = tokio::sync::mpsc::channel(4);

            // Spawn the inotify loop.
            let watch_handle = tokio::spawn(async move {
                if let Err(e) = watcher.watch(tx).await {
                    error!(error = %e, "policy watcher failed");
                }
            });

            // Apply reloaded policy sets as they arrive.
            while let Some(new_policies) = rx.recv().await {
                let count = new_policies.len();
                let mut eval = evaluator.write().await;
                eval.reload(new_policies);
                info!(count, "policies hot-reloaded");
            }

            // If the channel closes, the watcher task exited.
            let _ = watch_handle.await;
        })
    }

    /// Return a snapshot of the current policy count (useful for health
    /// checks and debugging).
    pub async fn policy_count(&self) -> usize {
        let eval = self.evaluator.read().await;
        eval.policy_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_engine_with_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let config = ApprovalConfig {
            gui_command: "echo".to_string(),
            timeout_seconds: 5,
            show_binary_hash: true,
            label_reason_untrusted: true,
            max_reason_length: 200,
        };
        let engine = PolicyEngine::new(dir.path().to_path_buf(), config).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let count = rt.block_on(engine.policy_count());
        assert_eq!(count, 0);
    }

    #[test]
    fn new_engine_creates_missing_dir() {
        let base = tempfile::tempdir().unwrap();
        let policy_dir = base.path().join("policies");
        let config = ApprovalConfig {
            gui_command: "echo".to_string(),
            timeout_seconds: 5,
            show_binary_hash: true,
            label_reason_untrusted: true,
            max_reason_length: 200,
        };
        assert!(!policy_dir.exists());
        let _engine = PolicyEngine::new(policy_dir.clone(), config).unwrap();
        assert!(policy_dir.exists());
    }

    #[test]
    fn evaluate_denies_with_no_policies() {
        let dir = tempfile::tempdir().unwrap();
        let config = ApprovalConfig {
            gui_command: "echo".to_string(),
            timeout_seconds: 5,
            show_binary_hash: true,
            label_reason_untrusted: true,
            max_reason_length: 200,
        };
        let engine = PolicyEngine::new(dir.path().to_path_buf(), config).unwrap();

        let agent = AgentInfo {
            uid: 1000,
            pid: 42,
            binary_path: PathBuf::from("/usr/bin/agent"),
            binary_hash: [0xab; 32],
            start_time: 1234,
            fingerprint_hash: [0xcd; 32],
            agent_id: Some("test".to_string()),
            agent_version: None,
        };
        let scope = Scope::default();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let decision = rt.block_on(engine.evaluate(&agent, "some_cred", &scope));
        assert!(matches!(decision, PolicyDecision::Denied { .. }));
    }

    #[test]
    fn evaluate_with_loaded_policy() {
        let dir = tempfile::tempdir().unwrap();

        // Write a policy that auto-approves by binary hash.
        let hash_hex = "ab".repeat(32);
        let policy_toml = format!(
            r#"
[[policy]]
name = "test-auto"
[policy.match]
agent_binary_hash = "sha256:{hash_hex}"
credential_ref = "my_cred"
[policy.allow]
hosts = ["api.example.com"]
methods = ["GET"]
paths = ["/data/**"]
[policy.approval]
mode = "auto"
"#
        );
        std::fs::write(dir.path().join("test.toml"), &policy_toml).unwrap();

        let config = ApprovalConfig {
            gui_command: "echo".to_string(),
            timeout_seconds: 5,
            show_binary_hash: true,
            label_reason_untrusted: true,
            max_reason_length: 200,
        };
        let engine = PolicyEngine::new(dir.path().to_path_buf(), config).unwrap();

        let agent = AgentInfo {
            uid: 1000,
            pid: 42,
            binary_path: PathBuf::from("/usr/bin/agent"),
            binary_hash: [0xab; 32],
            start_time: 1234,
            fingerprint_hash: [0xcd; 32],
            agent_id: Some("test".to_string()),
            agent_version: None,
        };
        let scope = Scope {
            hosts: vec!["api.example.com".to_string()],
            methods: vec!["GET".to_string()],
            paths: vec!["/data/reports".to_string()],
            ..Default::default()
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let decision = rt.block_on(engine.evaluate(&agent, "my_cred", &scope));
        match decision {
            PolicyDecision::AutoApprove {
                granted_scope,
                policy_name,
                ..
            } => {
                assert_eq!(policy_name, "test-auto");
                assert_eq!(granted_scope.hosts, vec!["api.example.com"]);
                assert_eq!(granted_scope.methods, vec!["GET"]);
            }
            other => panic!("expected AutoApprove, got {other:?}"),
        }
    }
}
