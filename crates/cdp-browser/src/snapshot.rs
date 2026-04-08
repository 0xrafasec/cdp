//! Session snapshot: orchestrate the full browser login flow.
//!
//! [`SessionSnapshot::capture`] drives the browser through:
//! 1. Navigate to the login URL.
//! 2. Fill username and password fields.
//! 3. Submit the login form.
//! 4. Optionally handle 2FA (via a caller-supplied async callback).
//! 5. Wait for a success indicator (URL change, cookie presence, or selector).
//! 6. Extract all cookies from the session.
//! 7. SIGKILL the browser subprocess unconditionally.
//!
//! The subprocess is always killed whether the flow succeeds or fails.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use cdp_crypto::SecureBuffer;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::BrowserError;
use crate::cookies::Cookie;
use crate::sandbox::{
    BrowserCommand, BrowserResponse, BrowserSandbox, SandboxConfig, SandboxedProcess,
    SuccessIndicatorMsg,
};

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

/// How to detect successful login completion.
#[derive(Debug, Clone)]
pub enum SuccessIndicator {
    /// Login succeeds when the URL changes to match this pattern.
    UrlChange { pattern: String },
    /// Login succeeds when a cookie with this name appears.
    CookiePresent { name: String },
    /// Login succeeds when an element matching this CSS selector appears.
    SelectorAppears { selector: String },
}

impl SuccessIndicator {
    fn to_msg(&self) -> SuccessIndicatorMsg {
        match self {
            Self::UrlChange { pattern } => SuccessIndicatorMsg::UrlChange {
                pattern: pattern.clone(),
            },
            Self::CookiePresent { name } => {
                SuccessIndicatorMsg::CookiePresent { name: name.clone() }
            }
            Self::SelectorAppears { selector } => SuccessIndicatorMsg::SelectorAppears {
                selector: selector.clone(),
            },
        }
    }
}

/// How to detect and handle a 2FA challenge.
#[derive(Debug, Clone)]
pub struct TwoFactorDetector {
    /// URL substring or CSS selector that indicates a 2FA page is shown.
    /// Checked after form submission.
    pub trigger: TwoFactorTrigger,
    /// CSS selector of the 2FA code input field.
    pub input_selector: String,
    /// CSS selector of the 2FA submit button.
    pub submit_selector: String,
}

/// What triggers 2FA detection.
#[derive(Debug, Clone)]
pub enum TwoFactorTrigger {
    /// A URL pattern (substring match) indicating the 2FA page.
    UrlPattern(String),
    /// A CSS selector that appears when 2FA is required.
    Selector(String),
}

/// Full configuration for a login snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotConfig {
    /// URL of the login page.
    pub login_url: String,
    /// CSS selector for the username field.
    /// Default: `"input[name=username],input[type=email]"`.
    pub username_selector: String,
    /// CSS selector for the password field.
    /// Default: `"input[type=password]"`.
    pub password_selector: String,
    /// CSS selector for the submit button.
    /// Default: `"button[type=submit],input[type=submit]"`.
    pub submit_selector: String,
    /// How to detect successful login.
    pub success_indicator: SuccessIndicator,
    /// Optional 2FA configuration.
    pub twofa_detector: Option<TwoFactorDetector>,
    /// How long to wait for the login flow to complete (seconds).
    pub timeout_seconds: u64,
    /// Browser sandbox configuration.
    pub sandbox_config: SandboxConfig,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            login_url: String::new(),
            username_selector: "input[name=username],input[type=email]".to_string(),
            password_selector: "input[type=password]".to_string(),
            submit_selector: "button[type=submit],input[type=submit]".to_string(),
            success_indicator: SuccessIndicator::UrlChange {
                pattern: String::new(),
            },
            twofa_detector: None,
            timeout_seconds: 30,
            sandbox_config: SandboxConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// LoginCredential
// ---------------------------------------------------------------------------

/// Credentials used to log in to a web service.
pub struct LoginCredential {
    /// Plaintext username or email address.
    pub username: String,
    /// Password in a secure (mlock'd, zeroize-on-drop) buffer.
    pub password: SecureBuffer,
}

impl LoginCredential {
    /// Create a new `LoginCredential`.
    ///
    /// `password_bytes` is consumed and locked into RAM.
    pub fn new(username: impl Into<String>, password_bytes: Vec<u8>) -> Self {
        Self {
            username: username.into(),
            password: SecureBuffer::new(password_bytes),
        }
    }
}

// ---------------------------------------------------------------------------
// 2FA callback type
// ---------------------------------------------------------------------------

/// Async callback that the Gate supplies to prompt the user for a 2FA code.
///
/// Returns the 6-8 digit code as a `String` wrapped in `Zeroizing` so it is
/// wiped from memory after use.
pub type TwoFaCallback = Box<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<Zeroizing<String>, BrowserError>> + Send>>
        + Send
        + Sync,
>;

// ---------------------------------------------------------------------------
// SessionSnapshot
// ---------------------------------------------------------------------------

/// Orchestrates a complete browser login flow and returns the captured cookies.
pub struct SessionSnapshot {
    config: SnapshotConfig,
}

impl SessionSnapshot {
    /// Create a new `SessionSnapshot` with the given configuration.
    pub fn new(config: SnapshotConfig) -> Self {
        Self { config }
    }

    /// Run the full login flow and return extracted cookies.
    ///
    /// The browser subprocess is SIGKILL'd whether this function succeeds or fails.
    ///
    /// # Parameters
    ///
    /// - `credential`: username + password for the login form.
    /// - `twofa_callback`: optional async function that retrieves the 2FA code.
    ///   Required if `config.twofa_detector` is set and the login page triggers 2FA.
    pub async fn capture(
        &self,
        credential: LoginCredential,
        twofa_callback: Option<&TwoFaCallback>,
    ) -> Result<Vec<Cookie>, BrowserError> {
        let sandbox = BrowserSandbox::new(self.config.sandbox_config.clone());

        let mut process = tokio::time::timeout(
            Duration::from_secs(self.config.timeout_seconds),
            sandbox.spawn(None),
        )
        .await
        .map_err(|_| BrowserError::Timeout("browser spawn timed out".to_string()))??;

        let result = self
            .run_login_flow(&mut process, credential, twofa_callback)
            .await;

        // Always kill the subprocess — even if the flow failed.
        process.kill();
        info!("browser subprocess killed after snapshot");

        result
    }

    /// Internal: drive the login flow on an already-spawned subprocess.
    async fn run_login_flow(
        &self,
        process: &mut SandboxedProcess,
        credential: LoginCredential,
        twofa_callback: Option<&TwoFaCallback>,
    ) -> Result<Vec<Cookie>, BrowserError> {
        // Step 1: Navigate to the login page.
        debug!("navigating to {}", self.config.login_url);
        self.send_expect_ok(
            process,
            &BrowserCommand::Navigate {
                url: self.config.login_url.clone(),
            },
        )
        .await?;

        // Step 2: Fill credentials.
        debug!("filling credentials for user '{}'", credential.username);
        let password_str = String::from_utf8(credential.password.to_vec())
            .map_err(|_| BrowserError::Login("password contains invalid UTF-8".to_string()))?;

        self.send_expect_ok(
            process,
            &BrowserCommand::FillCredentials {
                username: credential.username.clone(),
                password: password_str,
                username_selector: self.config.username_selector.clone(),
                password_selector: self.config.password_selector.clone(),
            },
        )
        .await?;

        // Step 3: Submit the form.
        debug!("submitting login form");
        self.send_expect_ok(
            process,
            &BrowserCommand::Submit {
                selector: self.config.submit_selector.clone(),
            },
        )
        .await?;

        // Step 4: Optionally handle 2FA.
        if let Some(detector) = &self.config.twofa_detector {
            match self
                .try_handle_twofa(process, detector, twofa_callback)
                .await
            {
                Ok(handled) => {
                    if handled {
                        debug!("2FA handled successfully");
                    } else {
                        debug!("no 2FA challenge detected");
                    }
                }
                Err(e) => {
                    warn!("2FA handling failed: {e}");
                    return Err(e);
                }
            }
        }

        // Step 5: Wait for the success indicator.
        debug!("waiting for login success indicator");
        self.send_expect_ok(
            process,
            &BrowserCommand::WaitForLogin {
                success_indicator: self.config.success_indicator.to_msg(),
            },
        )
        .await?;

        // Step 6: Extract cookies.
        debug!("extracting cookies");
        let cookies = self.extract_cookies(process).await?;
        info!("captured {} cookies from login session", cookies.len());

        Ok(cookies)
    }

    /// Send a command and expect an `Ok` response, mapping errors.
    async fn send_expect_ok(
        &self,
        process: &mut SandboxedProcess,
        cmd: &BrowserCommand,
    ) -> Result<(), BrowserError> {
        let timeout_dur = Duration::from_secs(self.config.timeout_seconds);

        let response = tokio::time::timeout(timeout_dur, process.send_command(cmd))
            .await
            .map_err(|_| {
                BrowserError::Timeout(format!("command {:?} timed out", cmd_name(cmd)))
            })??;

        match response {
            BrowserResponse::Ok { .. } => Ok(()),
            BrowserResponse::Error { message } => {
                Err(BrowserError::Login(format!("browser error: {message}")))
            }
            BrowserResponse::TwoFaRequired { hint } => Err(BrowserError::TwoFactor(format!(
                "unexpected 2FA challenge: {hint}"
            ))),
        }
    }

    /// Attempt to detect and handle a 2FA challenge.
    ///
    /// Returns `Ok(true)` if 2FA was detected and handled, `Ok(false)` if not detected.
    async fn try_handle_twofa(
        &self,
        process: &mut SandboxedProcess,
        detector: &TwoFactorDetector,
        twofa_callback: Option<&TwoFaCallback>,
    ) -> Result<bool, BrowserError> {
        // Send a "check for 2FA" command by trying to wait for the trigger selector/URL.
        // We probe by sending a WaitForLogin with the 2FA trigger as the indicator.
        // If we get TwoFaRequired back, 2FA is needed.

        // Check by sending a Navigate to verify if we're on the 2FA page.
        // We detect by submitting a WaitForLogin with the 2FA trigger.
        let twofa_indicator = match &detector.trigger {
            TwoFactorTrigger::UrlPattern(pattern) => SuccessIndicatorMsg::UrlChange {
                pattern: pattern.clone(),
            },
            TwoFactorTrigger::Selector(selector) => SuccessIndicatorMsg::SelectorAppears {
                selector: selector.clone(),
            },
        };

        let timeout_dur = Duration::from_secs(5); // Short check for 2FA
        let response = tokio::time::timeout(
            timeout_dur,
            process.send_command(&BrowserCommand::WaitForLogin {
                success_indicator: twofa_indicator,
            }),
        )
        .await;

        let detected = match response {
            Ok(Ok(BrowserResponse::TwoFaRequired { .. })) => true,
            Ok(Ok(BrowserResponse::Ok { .. })) => true, // 2FA page detected
            Ok(Ok(BrowserResponse::Error { .. })) => false, // Not on 2FA page
            Ok(Err(_)) | Err(_) => false,               // Timeout or error = no 2FA
        };

        if !detected {
            return Ok(false);
        }

        // 2FA is required; get the code from the callback.
        let callback = twofa_callback.ok_or_else(|| {
            BrowserError::TwoFactor("2FA challenge detected but no callback provided".to_string())
        })?;

        let code = callback().await?;

        // Submit the 2FA code.
        self.send_expect_ok(
            process,
            &BrowserCommand::Enter2Fa {
                code: code.to_string(),
            },
        )
        .await?;

        Ok(true)
    }

    /// Send `ExtractCookies` and parse the response.
    async fn extract_cookies(
        &self,
        process: &mut SandboxedProcess,
    ) -> Result<Vec<Cookie>, BrowserError> {
        let timeout_dur = Duration::from_secs(self.config.timeout_seconds);

        let response = tokio::time::timeout(
            timeout_dur,
            process.send_command(&BrowserCommand::ExtractCookies),
        )
        .await
        .map_err(|_| BrowserError::Timeout("ExtractCookies timed out".to_string()))??;

        match response {
            BrowserResponse::Ok { data: Some(data) } => {
                let cookies: Vec<Cookie> = serde_json::from_value(data).map_err(|e| {
                    BrowserError::CookieExtraction(format!("deserialize cookies: {e}"))
                })?;
                if cookies.is_empty() {
                    Err(BrowserError::CookieExtraction(
                        "no cookies returned by browser".to_string(),
                    ))
                } else {
                    Ok(cookies)
                }
            }
            BrowserResponse::Ok { data: None } => Err(BrowserError::CookieExtraction(
                "browser returned Ok but no cookie data".to_string(),
            )),
            BrowserResponse::Error { message } => Err(BrowserError::CookieExtraction(format!(
                "browser error extracting cookies: {message}"
            ))),
            BrowserResponse::TwoFaRequired { .. } => Err(BrowserError::CookieExtraction(
                "unexpected 2FA challenge during cookie extraction".to_string(),
            )),
        }
    }
}

/// Return a short name for a command (for logging/errors), without exposing credentials.
fn cmd_name(cmd: &BrowserCommand) -> &'static str {
    match cmd {
        BrowserCommand::Navigate { .. } => "Navigate",
        BrowserCommand::FillCredentials { .. } => "FillCredentials",
        BrowserCommand::Submit { .. } => "Submit",
        BrowserCommand::WaitForLogin { .. } => "WaitForLogin",
        BrowserCommand::ExtractCookies => "ExtractCookies",
        BrowserCommand::Enter2Fa { .. } => "Enter2FA",
        BrowserCommand::Shutdown => "Shutdown",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_config_default() {
        let cfg = SnapshotConfig::default();
        assert_eq!(
            cfg.username_selector,
            "input[name=username],input[type=email]"
        );
        assert_eq!(cfg.password_selector, "input[type=password]");
        assert_eq!(
            cfg.submit_selector,
            "button[type=submit],input[type=submit]"
        );
        assert_eq!(cfg.timeout_seconds, 30);
        assert!(cfg.twofa_detector.is_none());
    }

    #[test]
    fn test_success_indicator_to_msg_url_change() {
        let ind = SuccessIndicator::UrlChange {
            pattern: "dashboard".to_string(),
        };
        let msg = ind.to_msg();
        assert!(matches!(msg, SuccessIndicatorMsg::UrlChange { .. }));
    }

    #[test]
    fn test_success_indicator_to_msg_cookie_present() {
        let ind = SuccessIndicator::CookiePresent {
            name: "session_id".to_string(),
        };
        let msg = ind.to_msg();
        assert!(matches!(msg, SuccessIndicatorMsg::CookiePresent { .. }));
    }

    #[test]
    fn test_success_indicator_to_msg_selector_appears() {
        let ind = SuccessIndicator::SelectorAppears {
            selector: ".dashboard-header".to_string(),
        };
        let msg = ind.to_msg();
        assert!(matches!(msg, SuccessIndicatorMsg::SelectorAppears { .. }));
    }

    #[test]
    fn test_login_credential_new() {
        let cred = LoginCredential::new("alice@example.com", b"supersecret".to_vec());
        assert_eq!(cred.username, "alice@example.com");
        // SecureBuffer — just verify it's non-empty.
        assert!(!cred.password.is_empty());
    }

    #[test]
    fn test_cmd_name() {
        assert_eq!(
            cmd_name(&BrowserCommand::Navigate { url: "x".into() }),
            "Navigate"
        );
        assert_eq!(
            cmd_name(&BrowserCommand::FillCredentials {
                username: "u".into(),
                password: "p".into(),
                username_selector: "s".into(),
                password_selector: "s".into(),
            }),
            "FillCredentials"
        );
        assert_eq!(cmd_name(&BrowserCommand::ExtractCookies), "ExtractCookies");
        assert_eq!(cmd_name(&BrowserCommand::Shutdown), "Shutdown");
    }

    #[test]
    fn test_twofa_trigger_url_pattern() {
        let detector = TwoFactorDetector {
            trigger: TwoFactorTrigger::UrlPattern("two-factor".to_string()),
            input_selector: "input[name=code]".to_string(),
            submit_selector: "button[type=submit]".to_string(),
        };
        assert!(matches!(detector.trigger, TwoFactorTrigger::UrlPattern(_)));
    }

    #[test]
    fn test_snapshot_config_with_twofa() {
        let cfg = SnapshotConfig {
            login_url: "https://example.com/login".to_string(),
            twofa_detector: Some(TwoFactorDetector {
                trigger: TwoFactorTrigger::Selector("#twofa-input".to_string()),
                input_selector: "#code".to_string(),
                submit_selector: "#submit-code".to_string(),
            }),
            ..Default::default()
        };
        assert!(cfg.twofa_detector.is_some());
    }
}
