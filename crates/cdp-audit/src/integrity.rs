//! Audit chain integrity verification.
//!
//! Reads a JSONL audit file and verifies that every entry's hash matches
//! its content and that the `prev_hash` chain is unbroken.

use std::path::Path;

use crate::{AuditError, logger::{AuditEntry, compute_entry_hash}};

// ---------------------------------------------------------------------------
// ChainStatus
// ---------------------------------------------------------------------------

/// Result of verifying a hash-chained audit file.
#[derive(Debug, PartialEq, Eq)]
pub enum ChainStatus {
    /// Every entry is self-consistent and linked to the previous one.
    Valid { entries: u64 },
    /// A hash mismatch was found at `at_sequence`.
    Broken {
        at_sequence: u64,
        expected_hash: String,
        actual_hash: String,
    },
    /// The file exists but contains no entries.
    Empty,
}

// ---------------------------------------------------------------------------
// verify_chain
// ---------------------------------------------------------------------------

/// Verify the integrity of the hash chain in `path`.
///
/// Returns [`ChainStatus::Empty`] for a zero-length or whitespace-only file,
/// [`ChainStatus::Valid`] when every entry passes, and
/// [`ChainStatus::Broken`] (or an [`AuditError`]) on the first problem found.
pub async fn verify_chain(path: &Path) -> Result<ChainStatus, AuditError> {
    let content = tokio::fs::read_to_string(path).await?;

    let lines: Vec<&str> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();

    if lines.is_empty() {
        return Ok(ChainStatus::Empty);
    }

    let mut expected_prev = "genesis".to_string();
    let mut count: u64 = 0;

    for (line_idx, raw_line) in lines.iter().enumerate() {
        let line_num = line_idx as u64 + 1;

        let entry: AuditEntry = serde_json::from_str(raw_line)
            .map_err(|e| AuditError::InvalidEntry(line_num, e.to_string()))?;

        // Check that prev_hash matches what we expect.
        if entry.prev_hash != expected_prev {
            return Ok(ChainStatus::Broken {
                at_sequence: entry.sequence,
                expected_hash: expected_prev,
                actual_hash: entry.prev_hash,
            });
        }

        // Recompute the entry's hash (ignoring the stored `hash` field).
        let computed = compute_entry_hash(&entry);
        if computed != entry.hash {
            return Ok(ChainStatus::Broken {
                at_sequence: entry.sequence,
                expected_hash: computed,
                actual_hash: entry.hash,
            });
        }

        expected_prev = entry.hash.clone();
        count += 1;
    }

    Ok(ChainStatus::Valid { entries: count })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger::{AuditEventType, AuditFields, AuditLogger};
    use tempfile::tempdir;

    async fn make_logger(path: std::path::PathBuf) -> AuditLogger {
        AuditLogger::new(Some(path)).await.unwrap()
    }

    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_valid_chain() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = make_logger(log_path.clone()).await;

        for i in 0..5u32 {
            logger
                .log(
                    AuditEventType::LeaseGranted,
                    AuditFields {
                        lease_id: Some(format!("lease-{i}")),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
        }

        let status = verify_chain(&log_path).await.unwrap();
        assert_eq!(status, ChainStatus::Valid { entries: 5 });
    }

    #[tokio::test]
    async fn test_empty_file_returns_empty() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        // Create the file but don't write anything.
        tokio::fs::write(&log_path, b"").await.unwrap();

        let status = verify_chain(&log_path).await.unwrap();
        assert_eq!(status, ChainStatus::Empty);
    }

    #[tokio::test]
    async fn test_tampered_entry_detected() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = make_logger(log_path.clone()).await;

        for i in 0..5u32 {
            logger
                .log(
                    AuditEventType::LeaseGranted,
                    AuditFields {
                        credential_ref: Some(format!("cred-{i}")),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
        }

        // Read all lines.
        let raw = tokio::fs::read_to_string(&log_path).await.unwrap();
        let mut lines: Vec<String> = raw.lines().map(String::from).collect();

        // Tamper with entry 3 (index 2): change credential_ref.
        let mut entry: serde_json::Value =
            serde_json::from_str(&lines[2]).expect("must parse");
        entry["credential_ref"] = serde_json::Value::String("TAMPERED".to_string());
        lines[2] = serde_json::to_string(&entry).unwrap();

        tokio::fs::write(&log_path, lines.join("\n") + "\n")
            .await
            .unwrap();

        let status = verify_chain(&log_path).await.unwrap();
        match status {
            ChainStatus::Broken { at_sequence, .. } => {
                assert_eq!(at_sequence, 3, "break should be detected at sequence 3");
            }
            other => panic!("expected Broken, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_broken_prev_hash_detected() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = make_logger(log_path.clone()).await;

        for _ in 0..3u32 {
            logger
                .log(AuditEventType::AgentRegistered, AuditFields::default())
                .await
                .unwrap();
        }

        let raw = tokio::fs::read_to_string(&log_path).await.unwrap();
        let mut lines: Vec<String> = raw.lines().map(String::from).collect();

        // Corrupt the prev_hash field of entry 2 (index 1).
        let mut entry: serde_json::Value =
            serde_json::from_str(&lines[1]).expect("must parse");
        entry["prev_hash"] =
            serde_json::Value::String("sha256:deadbeefdeadbeef".to_string());
        lines[1] = serde_json::to_string(&entry).unwrap();

        tokio::fs::write(&log_path, lines.join("\n") + "\n")
            .await
            .unwrap();

        let status = verify_chain(&log_path).await.unwrap();
        match status {
            ChainStatus::Broken { at_sequence, .. } => {
                assert_eq!(at_sequence, 2, "break should be detected at sequence 2");
            }
            other => panic!("expected Broken, got {other:?}"),
        }
    }
}
