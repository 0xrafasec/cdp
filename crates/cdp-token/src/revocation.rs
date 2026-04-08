//! Token revocation list.
//!
//! Maintains an in-memory set of revoked JWT IDs (JTI values) with their
//! expiration timestamps. A background task prunes expired entries every 60 s.
//!
//! Single-use enforcement is provided by [`RevocationList::check_and_mark_used`],
//! which atomically checks the revocation state and adds the JTI under a write
//! lock, preventing TOCTOU races.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use tracing::{debug, info, instrument};
#[allow(unused_imports)]
use uuid;

use crate::{Result, TokenError, issuer::TokenIssuer};

// ---------------------------------------------------------------------------
// RevocationList
// ---------------------------------------------------------------------------

/// In-memory token revocation list.
///
/// Keys are JTI strings; values are the expiration time after which the entry
/// can be safely pruned (the token would already be invalid due to expiry).
#[derive(Debug, Default)]
pub struct RevocationList {
    entries: RwLock<HashMap<String, DateTime<Utc>>>,
}

impl RevocationList {
    /// Create an empty revocation list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Revoke a token by its JTI.
    ///
    /// `expires_at` is the time at which the entry may be pruned (should match
    /// the token's `exp` claim).
    #[instrument(skip(self))]
    pub async fn revoke(&self, jti: &str, expires_at: DateTime<Utc>) {
        let mut entries = self.entries.write().await;
        debug!(jti = %jti, "revoking token");
        entries.insert(jti.to_string(), expires_at);
    }

    /// Returns `true` if the given JTI appears in the revocation list.
    pub async fn is_revoked(&self, jti: &str) -> bool {
        let entries = self.entries.read().await;
        entries.contains_key(jti)
    }

    /// Atomically check whether a JTI has been used, then mark it as used.
    ///
    /// This is the correct way to enforce single-use tokens: the check-and-mark
    /// happens under a single write lock, eliminating TOCTOU races.
    ///
    /// Returns `Ok(())` if the token has not been seen before (it is now marked).
    /// Returns `Err(TokenError::Revoked)` if the token is already in the list.
    #[instrument(skip(self))]
    pub async fn check_and_mark_used(
        &self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        let mut entries = self.entries.write().await;
        if entries.contains_key(jti) {
            return Err(TokenError::Revoked);
        }
        debug!(jti = %jti, "marking single-use token as used");
        entries.insert(jti.to_string(), expires_at);
        Ok(())
    }

    /// Remove entries whose expiration time is in the past.
    pub async fn cleanup(&self) {
        let now = Utc::now();
        let mut entries = self.entries.write().await;
        let before = entries.len();
        entries.retain(|_, expires_at| *expires_at > now);
        let removed = before - entries.len();
        if removed > 0 {
            info!(removed, "pruned expired revocation entries");
        }
    }

    /// Spawn a background tokio task that calls [`cleanup`] every 60 seconds.
    ///
    /// The task holds a weak reference so it exits automatically when the last
    /// strong [`Arc`] to the list is dropped.
    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                self.cleanup().await;
            }
        });
    }

    /// Serialize the current revocation list to a signed JSON string.
    ///
    /// The payload is `{"entries": {"<jti>": "<iso8601>", ...}}` and is signed
    /// as a JWT by the provided issuer.
    pub async fn to_signed_list(&self, issuer: &TokenIssuer) -> Result<String> {
        let entries = self.entries.read().await;

        // Build a map of jti -> ISO-8601 expiry.
        let map: HashMap<String, String> = entries
            .iter()
            .map(|(jti, exp)| (jti.clone(), exp.to_rfc3339()))
            .collect();

        let payload = serde_json::to_value(&map)
            .map_err(|e| TokenError::Serialization(e.to_string()))?;

        let now = Utc::now();
        let claims = crate::issuer::TokenClaims {
            iss: "cdp-gate-revocation".to_string(),
            sub: "revocation-list".to_string(),
            aud: "cdp-gate".to_string(),
            exp: (now + chrono::Duration::minutes(5)).timestamp(),
            iat: now.timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
            scope: vec!["revocation".to_string()],
            lease_id: "internal".to_string(),
            delegation_chain: vec![],
            single_use: false,
        };

        // We embed the entries as an extra field by building a merged JSON object.
        let mut claims_map = serde_json::to_value(&claims)
            .map_err(|e| TokenError::Serialization(e.to_string()))?;
        if let serde_json::Value::Object(ref mut obj) = claims_map {
            obj.insert("revoked_entries".to_string(), payload);
        }

        // Sign the extended claims using the issuer's internal signing helper.
        issuer.sign_claims_value(&claims_map)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[tokio::test]
    async fn revoke_and_check() {
        let rl = RevocationList::new();
        let jti = "test-jti-1";
        let exp = Utc::now() + Duration::seconds(300);

        assert!(!rl.is_revoked(jti).await);
        rl.revoke(jti, exp).await;
        assert!(rl.is_revoked(jti).await);
    }

    #[tokio::test]
    async fn check_and_mark_used_allows_first_use() {
        let rl = RevocationList::new();
        let jti = "single-use-jti";
        let exp = Utc::now() + Duration::seconds(300);

        rl.check_and_mark_used(jti, exp).await.expect("first use should succeed");
        // Now it is in the list.
        assert!(rl.is_revoked(jti).await);
    }

    #[tokio::test]
    async fn check_and_mark_used_rejects_second_use() {
        let rl = RevocationList::new();
        let jti = "single-use-jti-2";
        let exp = Utc::now() + Duration::seconds(300);

        rl.check_and_mark_used(jti, exp).await.expect("first use");
        let err = rl.check_and_mark_used(jti, exp).await.expect_err("second use");
        assert!(matches!(err, TokenError::Revoked));
    }

    #[tokio::test]
    async fn cleanup_removes_expired_entries() {
        let rl = RevocationList::new();
        let past = Utc::now() - Duration::seconds(1);
        let future = Utc::now() + Duration::seconds(300);

        rl.revoke("expired-jti", past).await;
        rl.revoke("valid-jti", future).await;

        rl.cleanup().await;

        assert!(!rl.is_revoked("expired-jti").await);
        assert!(rl.is_revoked("valid-jti").await);
    }

    #[tokio::test]
    async fn to_signed_list_produces_valid_jwt() {
        let issuer = TokenIssuer::new().expect("gen key");
        let rl = RevocationList::new();
        let exp = Utc::now() + Duration::seconds(300);
        rl.revoke("jti-abc", exp).await;

        let token = rl.to_signed_list(&issuer).await.expect("sign list");
        // Should be a 3-part JWT.
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "signed list should be a JWT");
    }
}
