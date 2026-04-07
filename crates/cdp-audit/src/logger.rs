//! Audit logger: append-only, hash-chained JSONL entries.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::AuditError;

// ---------------------------------------------------------------------------
// AuditEventType
// ---------------------------------------------------------------------------

/// All auditable events produced by the CDP gate.
///
/// Serialized as dot-separated strings (e.g., `"agent.registered"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEventType {
    #[serde(rename = "agent.registered")]
    AgentRegistered,
    #[serde(rename = "agent.died")]
    AgentDied,
    #[serde(rename = "lease.requested")]
    LeaseRequested,
    #[serde(rename = "lease.approved")]
    LeaseApproved,
    #[serde(rename = "lease.denied")]
    LeaseDenied,
    #[serde(rename = "lease.granted")]
    LeaseGranted,
    #[serde(rename = "lease.used")]
    LeaseUsed,
    #[serde(rename = "lease.renewed")]
    LeaseRenewed,
    #[serde(rename = "lease.revoked")]
    LeaseRevoked,
    #[serde(rename = "lease.expired")]
    LeaseExpired,
    #[serde(rename = "lease.delegated")]
    LeaseDelegated,
    #[serde(rename = "credential.rotated")]
    CredentialRotated,
    #[serde(rename = "security.alert")]
    SecurityAlert,
    #[serde(rename = "proxy.blocked")]
    ProxyBlocked,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Serialize to a temporary string and use it for display.
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "unknown".to_string());
        f.write_str(&s)
    }
}

// ---------------------------------------------------------------------------
// AuditFields
// ---------------------------------------------------------------------------

/// Optional context fields attached to an audit entry.
///
/// Fields that are `None` are omitted from JSON output.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_fingerprint: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_binary_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<serde_json::Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_matched: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_method: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

// ---------------------------------------------------------------------------
// AuditEntry
// ---------------------------------------------------------------------------

/// A single record in the audit log file.
///
/// Stored as a compact JSON line (`\n`-terminated).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub event: AuditEventType,
    #[serde(flatten)]
    pub fields: AuditFields,
    pub prev_hash: String,
    pub hash: String,
}

// ---------------------------------------------------------------------------
// Hash computation
// ---------------------------------------------------------------------------

/// Encode bytes as a lowercase hex string.
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{b:02x}").expect("write to String is infallible");
            s
        })
}

/// Write a length-prefixed field into the hasher.
///
/// The length is encoded as an 8-byte big-endian `u64` to prevent
/// field-shifting attacks (identical to the pattern in `cdp-crypto`).
fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

/// Compute the SHA-256 hash for an [`AuditEntry`].
///
/// The `hash` field of the entry is ignored; all other fields are hashed in
/// a deterministic, length-prefixed order so that any modification to any
/// field changes the digest.
pub(crate) fn compute_entry_hash(entry: &AuditEntry) -> String {
    let mut hasher = Sha256::new();

    let seq_str = entry.sequence.to_string();
    hash_field(&mut hasher, seq_str.as_bytes());

    let ts_str = entry.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    hash_field(&mut hasher, ts_str.as_bytes());

    let event_str = entry.event.to_string();
    hash_field(&mut hasher, event_str.as_bytes());

    hash_field(
        &mut hasher,
        entry
            .fields
            .lease_id
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    hash_field(
        &mut hasher,
        entry
            .fields
            .agent_fingerprint
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    hash_field(
        &mut hasher,
        entry
            .fields
            .agent_binary_path
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    hash_field(
        &mut hasher,
        entry
            .fields
            .credential_ref
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );

    let scope_str = entry
        .fields
        .scope
        .as_ref()
        .map(|v| v.to_string())
        .unwrap_or_default();
    hash_field(&mut hasher, scope_str.as_bytes());

    hash_field(
        &mut hasher,
        entry
            .fields
            .policy_matched
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    hash_field(
        &mut hasher,
        entry
            .fields
            .approval_method
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    hash_field(
        &mut hasher,
        entry.fields.detail.as_deref().unwrap_or("").as_bytes(),
    );
    hash_field(&mut hasher, entry.prev_hash.as_bytes());

    let digest = hasher.finalize();
    format!("sha256:{}", bytes_to_hex(&digest))
}

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

/// Append-only, hash-chained audit logger.
///
/// Writes compact JSON lines to `path`. Each entry's `hash` covers all entry
/// fields and the previous entry's `hash`, forming a tamper-evident chain.
/// The first entry ever has `prev_hash = "genesis"`.
///
/// The logger is safe to use concurrently from multiple tasks; it serialises
/// writes via internal `Mutex` guards.
pub struct AuditLogger {
    path: PathBuf,
    file: Mutex<tokio::fs::File>,
    sequence: AtomicU64,
    prev_hash: Mutex<String>,
}

impl AuditLogger {
    /// Open (or create) an audit log at `path`.
    ///
    /// - `None` → `$XDG_DATA_HOME/cdp/audit.jsonl` or
    ///   `~/.local/share/cdp/audit.jsonl`
    /// - Parent directories are created if absent.
    /// - File permissions are set to `0600`.
    /// - If the file already contains entries, the logger resumes from the
    ///   last recorded sequence number and hash so the chain remains intact.
    pub async fn new(path: Option<PathBuf>) -> Result<Self, AuditError> {
        let path = match path {
            Some(p) => p,
            None => {
                let base = std::env::var_os("XDG_DATA_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| {
                        dirs_fallback_home().join(".local").join("share")
                    });
                base.join("cdp").join("audit.jsonl")
            }
        };

        // Create parent directories.
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Open file in append + create mode.
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;

        // Set permissions to 0600.
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(&path, perms).await?;

        // Resume from existing content if any.
        let (sequence, prev_hash) = read_last_entry_state(&path).await?;

        Ok(Self {
            path,
            file: Mutex::new(file),
            sequence: AtomicU64::new(sequence),
            prev_hash: Mutex::new(prev_hash),
        })
    }

    /// Return the path this logger writes to.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Append an audit entry to the log.
    ///
    /// Internally: increments the sequence counter, stamps the time, chains
    /// the hash, serialises to JSON, and flushes to disk.
    pub async fn log(
        &self,
        event: AuditEventType,
        fields: AuditFields,
    ) -> Result<(), AuditError> {
        let timestamp = Utc::now();

        // Lock prev_hash for the duration of hash computation + write so that
        // concurrent calls cannot interleave and produce conflicting chains.
        // The sequence counter is incremented inside the lock to guarantee
        // monotonic ordering in the log file.
        let mut prev_hash_guard = self.prev_hash.lock().await;
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;

        let mut entry = AuditEntry {
            sequence,
            timestamp,
            event,
            fields,
            prev_hash: prev_hash_guard.clone(),
            hash: String::new(), // placeholder — filled below
        };

        let hash = compute_entry_hash(&entry);
        entry.hash = hash.clone();

        let line = serde_json::to_string(&entry)?;

        {
            let mut file_guard = self.file.lock().await;
            file_guard
                .write_all(line.as_bytes())
                .await?;
            file_guard.write_all(b"\n").await?;
            file_guard.flush().await?;
        }

        *prev_hash_guard = hash;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Returns `(next_sequence, prev_hash)` by inspecting the last line of `path`.
///
/// If the file is empty, returns `(0, "genesis")`.
async fn read_last_entry_state(path: &std::path::Path) -> Result<(u64, String), AuditError> {
    let content = tokio::fs::read_to_string(path).await?;
    let last_line = content
        .lines()
        .rfind(|l| !l.trim().is_empty());

    let Some(line) = last_line else {
        return Ok((0, "genesis".to_string()));
    };

    let entry: AuditEntry = serde_json::from_str(line)
        .map_err(|e| AuditError::InvalidEntry(0, e.to_string()))?;

    Ok((entry.sequence, entry.hash))
}

/// Best-effort home directory fallback (avoids pulling in the `dirs` crate).
fn dirs_fallback_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    async fn make_logger(dir: &std::path::Path) -> AuditLogger {
        AuditLogger::new(Some(dir.join("audit.jsonl")))
            .await
            .expect("logger creation should succeed")
    }

    fn sample_fields() -> AuditFields {
        AuditFields {
            lease_id: Some("lease-001".to_string()),
            agent_fingerprint: Some("fp-abc".to_string()),
            ..Default::default()
        }
    }

    async fn read_entries(path: &std::path::Path) -> Vec<AuditEntry> {
        let content = tokio::fs::read_to_string(path).await.unwrap();
        content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("entry must be valid JSON"))
            .collect()
    }

    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_single_entry_has_genesis_prev_hash() {
        let dir = tempdir().unwrap();
        let logger = make_logger(dir.path()).await;

        logger
            .log(AuditEventType::AgentRegistered, AuditFields::default())
            .await
            .unwrap();

        let entries = read_entries(&logger.path).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].prev_hash, "genesis");
        assert!(entries[0].hash.starts_with("sha256:"));
    }

    #[tokio::test]
    async fn test_multiple_entries_form_chain() {
        let dir = tempdir().unwrap();
        let logger = make_logger(dir.path()).await;

        for _ in 0..3 {
            logger
                .log(AuditEventType::LeaseGranted, sample_fields())
                .await
                .unwrap();
        }

        let entries = read_entries(&logger.path).await;
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].prev_hash, "genesis");
        assert_eq!(entries[1].prev_hash, entries[0].hash);
        assert_eq!(entries[2].prev_hash, entries[1].hash);
    }

    #[tokio::test]
    async fn test_hash_is_deterministic() {
        let dir = tempdir().unwrap();
        let logger = make_logger(dir.path()).await;

        logger
            .log(AuditEventType::LeaseGranted, sample_fields())
            .await
            .unwrap();

        let entries = read_entries(&logger.path).await;
        assert_eq!(entries.len(), 1);

        // Re-compute hash from the stored entry and verify it matches.
        let expected = compute_entry_hash(&entries[0]);
        assert_eq!(entries[0].hash, expected);
    }

    #[tokio::test]
    async fn test_resume_from_existing_file() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");

        // First logger session: write 2 entries.
        {
            let logger = AuditLogger::new(Some(log_path.clone()))
                .await
                .unwrap();
            logger
                .log(AuditEventType::AgentRegistered, AuditFields::default())
                .await
                .unwrap();
            logger
                .log(AuditEventType::LeaseGranted, sample_fields())
                .await
                .unwrap();
        }

        // Second logger session: write 1 more entry.
        {
            let logger = AuditLogger::new(Some(log_path.clone()))
                .await
                .unwrap();
            logger
                .log(AuditEventType::LeaseUsed, AuditFields::default())
                .await
                .unwrap();
        }

        let entries = read_entries(&log_path).await;
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].sequence, 3);
        // Verify chain continuity across sessions.
        assert_eq!(entries[1].prev_hash, entries[0].hash);
        assert_eq!(entries[2].prev_hash, entries[1].hash);
    }

    #[tokio::test]
    async fn test_file_permissions_are_0600() {
        let dir = tempdir().unwrap();
        let logger = make_logger(dir.path()).await;

        let meta = std::fs::metadata(&logger.path).unwrap();
        let mode = meta.permissions().mode();
        // Mask out file type bits; keep only the permission bits.
        assert_eq!(mode & 0o777, 0o600, "permissions should be 0600");
    }

    #[tokio::test]
    async fn test_event_type_serialization() {
        let cases: &[(AuditEventType, &str)] = &[
            (AuditEventType::AgentRegistered, "\"agent.registered\""),
            (AuditEventType::AgentDied, "\"agent.died\""),
            (AuditEventType::LeaseRequested, "\"lease.requested\""),
            (AuditEventType::LeaseApproved, "\"lease.approved\""),
            (AuditEventType::LeaseDenied, "\"lease.denied\""),
            (AuditEventType::LeaseGranted, "\"lease.granted\""),
            (AuditEventType::LeaseUsed, "\"lease.used\""),
            (AuditEventType::LeaseRenewed, "\"lease.renewed\""),
            (AuditEventType::LeaseRevoked, "\"lease.revoked\""),
            (AuditEventType::LeaseExpired, "\"lease.expired\""),
            (AuditEventType::LeaseDelegated, "\"lease.delegated\""),
            (AuditEventType::CredentialRotated, "\"credential.rotated\""),
            (AuditEventType::SecurityAlert, "\"security.alert\""),
            (AuditEventType::ProxyBlocked, "\"proxy.blocked\""),
        ];

        for (event, expected_json) in cases {
            let serialized = serde_json::to_string(event).unwrap();
            assert_eq!(&serialized, expected_json, "event {event} mismatch");
        }
    }

    #[tokio::test]
    async fn test_audit_fields_skip_none() {
        let dir = tempdir().unwrap();
        let logger = make_logger(dir.path()).await;

        // Log with all fields None.
        logger
            .log(AuditEventType::AgentRegistered, AuditFields::default())
            .await
            .unwrap();

        let raw = tokio::fs::read_to_string(&logger.path).await.unwrap();
        let line = raw.lines().next().unwrap();

        // None fields must not appear in the JSON output.
        for key in &[
            "lease_id",
            "agent_fingerprint",
            "agent_binary_path",
            "credential_ref",
            "scope",
            "policy_matched",
            "approval_method",
            "detail",
        ] {
            assert!(
                !line.contains(key),
                "None field '{key}' should not appear in JSON"
            );
        }
    }
}
