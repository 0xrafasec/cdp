//! Credential provider trait — abstraction for fetching decrypted credential
//! values and presenting them as HTTP request headers.

use cdp_crypto::SecureBuffer;

use crate::ProxyError;

// ---------------------------------------------------------------------------
// CredentialHeader
// ---------------------------------------------------------------------------

/// A single HTTP header name/value pair carrying a credential value.
///
/// The `value` field is a [`SecureBuffer`] so the credential bytes are
/// mlock'd and zeroed on drop.
// Note: SecureBuffer does not implement Debug deliberately (it holds secrets).
pub struct CredentialHeader {
    /// Header name (e.g. `"Authorization"`).
    pub name: String,
    /// Header value held in locked, zeroize-on-drop memory.
    pub value: SecureBuffer,
}

// ---------------------------------------------------------------------------
// CredentialProvider trait
// ---------------------------------------------------------------------------

/// Abstraction over the credential store used by the proxy.
///
/// Implementations are responsible for decrypting credentials from the vault
/// and returning them as [`CredentialHeader`] values ready for injection into
/// outbound HTTP requests.
///
/// # Security
///
/// Implementors must ensure that returned [`SecureBuffer`] values are never
/// logged and that any intermediate String allocations containing credential
/// material are zeroized before being dropped.
pub trait CredentialProvider: Send + Sync {
    /// Fetch the credential identified by `credential_ref` for the given
    /// `lease_id` and return the HTTP headers to inject.
    ///
    /// `credential_ref` is the opaque vault key (e.g. `"cred-001"`).
    /// `lease_id` is used for audit attribution.
    ///
    /// Returns a [`BoxFuture`] so that the trait is dyn-compatible and can be
    /// stored behind `Arc<dyn CredentialProvider>`.
    fn fetch_credential<'a>(
        &'a self,
        credential_ref: &'a str,
        lease_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<CredentialHeader>, ProxyError>> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// MockCredentialProvider (test / test-support feature only)
// ---------------------------------------------------------------------------

/// A test-only [`CredentialProvider`] that returns pre-configured plaintext
/// credentials as `Authorization` headers.
///
/// **Never use in production.** The stored values are plain `String`s and
/// are not backed by `mlock`.
#[cfg(any(test, feature = "test-support"))]
pub struct MockCredentialProvider {
    credentials: std::collections::HashMap<String, String>,
}

#[cfg(any(test, feature = "test-support"))]
impl MockCredentialProvider {
    /// Create an empty provider.
    pub fn new() -> Self {
        Self {
            credentials: std::collections::HashMap::new(),
        }
    }

    /// Register a credential under `credential_ref`.
    ///
    /// The `value` string will be returned verbatim as the value of an
    /// `Authorization` header when [`fetch_credential`] is called with the
    /// matching `credential_ref`.
    pub fn add(&mut self, credential_ref: impl Into<String>, value: impl Into<String>) {
        self.credentials.insert(credential_ref.into(), value.into());
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Default for MockCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl CredentialProvider for MockCredentialProvider {
    fn fetch_credential<'a>(
        &'a self,
        credential_ref: &'a str,
        _lease_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<CredentialHeader>, ProxyError>> + Send + 'a>> {
        let result = match self.credentials.get(credential_ref) {
            Some(value) => {
                let header = CredentialHeader {
                    name: "Authorization".to_string(),
                    value: SecureBuffer::new(value.as_bytes().to_vec()),
                };
                Ok(vec![header])
            }
            None => Err(ProxyError::CredentialInjection(format!(
                "credential not found: {credential_ref}"
            ))),
        };
        Box::pin(async move { result })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_provider_returns_credential() {
        let mut provider = MockCredentialProvider::new();
        provider.add("cred-001", "Bearer test-token-abc");

        let headers = provider
            .fetch_credential("cred-001", "lease-xyz")
            .await
            .expect("should succeed");

        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name, "Authorization");
        assert_eq!(&*headers[0].value, b"Bearer test-token-abc");
    }

    #[tokio::test]
    async fn test_mock_provider_missing_credential() {
        let provider = MockCredentialProvider::new();
        let result = provider
            .fetch_credential("nonexistent", "lease-xyz")
            .await;

        match result {
            Err(ProxyError::CredentialInjection(_)) => {}
            other => panic!("expected CredentialInjection error, got: {other:?}",
                other = other.map(|_| "Ok(...)").map_err(|e| e.to_string())),
        }
    }

    #[tokio::test]
    async fn test_mock_provider_multiple_credentials() {
        let mut provider = MockCredentialProvider::new();
        provider.add("cred-api-key", "ApiKey secret123");
        provider.add("cred-bearer", "Bearer jwt.token.here");

        let h1 = provider
            .fetch_credential("cred-api-key", "lease-1")
            .await
            .expect("should succeed");
        assert_eq!(&*h1[0].value, b"ApiKey secret123");

        let h2 = provider
            .fetch_credential("cred-bearer", "lease-1")
            .await
            .expect("should succeed");
        assert_eq!(&*h2[0].value, b"Bearer jwt.token.here");
    }

    #[test]
    fn test_credential_header_value_is_secure_buffer() {
        let header = CredentialHeader {
            name: "X-API-Key".to_string(),
            value: SecureBuffer::new(b"my-secret-key".to_vec()),
        };
        assert_eq!(header.name, "X-API-Key");
        assert_eq!(&*header.value, b"my-secret-key");
    }

    #[test]
    fn test_mock_provider_default_is_empty() {
        let provider = MockCredentialProvider::default();
        assert!(provider.credentials.is_empty());
    }
}
