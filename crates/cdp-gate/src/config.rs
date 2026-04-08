use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::GateError;

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

/// Gate configuration parsed from `~/.config/cdp/gate.toml`.
///
/// Every field has a sensible default so the Gate can start with no config file.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GateConfig {
    pub gate: GateSection,
    pub vault: VaultSection,
    pub approval: ApprovalSection,
    pub security: SecuritySection,
    pub proxy: ProxySection,
    pub browser: BrowserSection,
}

// ---------------------------------------------------------------------------
// [gate]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GateSection {
    pub socket_path: String,
    pub log_level: String,
    pub audit_log_path: String,
    pub fingerprint_path: String,
    pub tls: TlsSection,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TlsSection {
    pub enabled: bool,
    pub bind_address: String,
    pub cert_path: String,
    pub key_path: String,
    pub client_ca_path: String,
}

// ---------------------------------------------------------------------------
// [vault]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct VaultSection {
    pub backend: String,
    pub subprocess_sandbox: bool,
    pub bitwarden: BitwardenSection,
    pub file: FileSection,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BitwardenSection {
    pub cli_path: String,
    pub session_timeout_minutes: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FileSection {
    pub path: String,
}

impl Default for FileSection {
    fn default() -> Self {
        Self {
            path: "~/.config/cdp/dev-vault.json.enc".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// [approval]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ApprovalSection {
    pub default_method: String,
    pub gui_command: String,
    pub timeout_seconds: u64,
    pub cooldown_seconds: u64,
    pub show_binary_hash: bool,
    pub label_reason_untrusted: bool,
    pub max_reason_length: usize,
}

// ---------------------------------------------------------------------------
// [security]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SecuritySection {
    pub max_delegation_depth: u32,
    pub default_lease_ttl_seconds: u64,
    pub max_lease_ttl_seconds: u64,
    pub max_renewals_per_lease: u32,
    pub max_cumulative_ttl_seconds: u64,
    pub remote_max_ttl_seconds: u64,
    pub remote_single_use: bool,
    pub encrypted_memory: bool,
    pub per_credential_keys: bool,
    pub disable_core_dumps: bool,
    pub require_binary_hash_for_auto: bool,
    pub policy_signing: bool,
    pub policy_signing_key: String,
    pub nonce_window_seconds: u64,
    pub nonce_max_entries: usize,
    pub dns: DnsSection,
    pub proxy: SecurityProxySection,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DnsSection {
    pub pin_at_lease_creation: bool,
    pub allow_dynamic_dns: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SecurityProxySection {
    pub follow_redirects: bool,
    pub strip_set_cookie: bool,
    pub strip_auth_echo: bool,
}

// ---------------------------------------------------------------------------
// [proxy]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProxySection {
    pub bind_address: String,
    pub port_range: String,
}

// ---------------------------------------------------------------------------
// [browser]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BrowserSection {
    pub sandbox_method: String,
    pub default_mode: String,
    pub mitm_ca_validity_hours: u64,
    pub mitm_ca_name_constrained: bool,
    pub kill_after_snapshot: bool,
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

fn default_socket_path() -> String {
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        format!("{xdg}/cdp/gate.sock")
    } else {
        "/run/cdp/gate.sock".to_string()
    }
}

impl Default for GateSection {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            log_level: "info".to_string(),
            audit_log_path: "~/.local/share/cdp/audit.jsonl".to_string(),
            fingerprint_path: "~/.config/cdp/gate.fingerprint".to_string(),
            tls: TlsSection::default(),
        }
    }
}

impl Default for TlsSection {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "127.0.0.1".to_string(),
            cert_path: "~/.config/cdp/gate.crt".to_string(),
            key_path: "~/.config/cdp/gate.key".to_string(),
            client_ca_path: "~/.config/cdp/client-ca.crt".to_string(),
        }
    }
}

impl Default for VaultSection {
    fn default() -> Self {
        Self {
            backend: "bitwarden".to_string(),
            subprocess_sandbox: true,
            bitwarden: BitwardenSection::default(),
            file: FileSection::default(),
        }
    }
}

impl Default for BitwardenSection {
    fn default() -> Self {
        Self {
            cli_path: "/usr/bin/bw".to_string(),
            session_timeout_minutes: 60,
        }
    }
}

impl Default for ApprovalSection {
    fn default() -> Self {
        Self {
            default_method: "gui".to_string(),
            gui_command: "kdialog".to_string(),
            timeout_seconds: 30,
            cooldown_seconds: 5,
            show_binary_hash: true,
            label_reason_untrusted: true,
            max_reason_length: 200,
        }
    }
}

impl Default for SecuritySection {
    fn default() -> Self {
        Self {
            max_delegation_depth: 3,
            default_lease_ttl_seconds: 3600,
            max_lease_ttl_seconds: 86400,
            max_renewals_per_lease: 3,
            max_cumulative_ttl_seconds: 14400,
            remote_max_ttl_seconds: 300,
            remote_single_use: true,
            encrypted_memory: true,
            per_credential_keys: true,
            disable_core_dumps: true,
            require_binary_hash_for_auto: true,
            policy_signing: false,
            policy_signing_key: String::new(),
            nonce_window_seconds: 300,
            nonce_max_entries: 100_000,
            dns: DnsSection::default(),
            proxy: SecurityProxySection::default(),
        }
    }
}

impl Default for DnsSection {
    fn default() -> Self {
        Self {
            pin_at_lease_creation: true,
            allow_dynamic_dns: false,
        }
    }
}

impl Default for SecurityProxySection {
    fn default() -> Self {
        Self {
            follow_redirects: false,
            strip_set_cookie: true,
            strip_auth_echo: true,
        }
    }
}

impl Default for ProxySection {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".to_string(),
            port_range: "19000-19999".to_string(),
        }
    }
}

impl Default for BrowserSection {
    fn default() -> Self {
        Self {
            sandbox_method: "bubblewrap".to_string(),
            default_mode: "proxy_only".to_string(),
            mitm_ca_validity_hours: 24,
            mitm_ca_name_constrained: true,
            kill_after_snapshot: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Expand a leading `~` to `$HOME`.
pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    } else if path == "~"
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home);
    }
    PathBuf::from(path)
}

impl GateConfig {
    /// Expand `~` in all path-typed fields.
    pub fn expand_paths(&mut self) {
        self.gate.socket_path = expand_tilde(&self.gate.socket_path)
            .to_string_lossy()
            .into_owned();
        self.gate.audit_log_path = expand_tilde(&self.gate.audit_log_path)
            .to_string_lossy()
            .into_owned();
        self.gate.fingerprint_path = expand_tilde(&self.gate.fingerprint_path)
            .to_string_lossy()
            .into_owned();
        self.gate.tls.cert_path = expand_tilde(&self.gate.tls.cert_path)
            .to_string_lossy()
            .into_owned();
        self.gate.tls.key_path = expand_tilde(&self.gate.tls.key_path)
            .to_string_lossy()
            .into_owned();
        self.gate.tls.client_ca_path = expand_tilde(&self.gate.tls.client_ca_path)
            .to_string_lossy()
            .into_owned();
        self.vault.file.path = expand_tilde(&self.vault.file.path)
            .to_string_lossy()
            .into_owned();
    }
}

/// Load config from `~/.config/cdp/gate.toml`, falling back to defaults.
pub fn load_config() -> Result<GateConfig, GateError> {
    let config_path = expand_tilde("~/.config/cdp/gate.toml");
    let mut config = if config_path.exists() {
        let contents = std::fs::read_to_string(&config_path).map_err(|e| {
            GateError::Config(format!("failed to read {}: {e}", config_path.display()))
        })?;
        toml::from_str::<GateConfig>(&contents)
            .map_err(|e| GateError::Config(format!("failed to parse config: {e}")))?
    } else {
        GateConfig::default()
    };
    config.expand_paths();
    Ok(config)
}

/// Load config from a specific path (for testing or CLI override).
pub fn load_config_from(path: &Path) -> Result<GateConfig, GateError> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| GateError::Config(format!("failed to read {}: {e}", path.display())))?;
    let mut config = toml::from_str::<GateConfig>(&contents)
        .map_err(|e| GateError::Config(format!("failed to parse config: {e}")))?;
    config.expand_paths();
    Ok(config)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = GateConfig::default();
        assert_eq!(config.gate.log_level, "info");
        assert_eq!(config.security.max_renewals_per_lease, 3);
        assert_eq!(config.security.max_cumulative_ttl_seconds, 14400);
        assert_eq!(config.approval.timeout_seconds, 30);
        assert_eq!(config.security.nonce_max_entries, 100_000);
        assert!(config.security.disable_core_dumps);
        assert!(config.security.require_binary_hash_for_auto);
        assert!(!config.security.dns.allow_dynamic_dns);
    }

    #[test]
    fn parse_empty_toml_gives_defaults() {
        let config: GateConfig = toml::from_str("").unwrap();
        assert_eq!(config.gate.log_level, "info");
        assert_eq!(config.security.max_delegation_depth, 3);
    }

    #[test]
    fn parse_partial_toml() {
        let toml_str = r#"
[gate]
log_level = "debug"

[security]
max_renewals_per_lease = 5
"#;
        let config: GateConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.gate.log_level, "debug");
        assert_eq!(config.security.max_renewals_per_lease, 5);
        // Others should be defaults.
        assert_eq!(config.security.max_delegation_depth, 3);
        assert_eq!(config.approval.gui_command, "kdialog");
    }

    #[test]
    fn tilde_expansion() {
        // We can only test this if HOME is set.
        if let Ok(home) = std::env::var("HOME") {
            let expanded = expand_tilde("~/some/path");
            assert_eq!(expanded, PathBuf::from(format!("{home}/some/path")));

            let expanded = expand_tilde("~");
            assert_eq!(expanded, PathBuf::from(&home));

            // No tilde — unchanged.
            let expanded = expand_tilde("/absolute/path");
            assert_eq!(expanded, PathBuf::from("/absolute/path"));
        }
    }

    #[test]
    fn parse_full_config() {
        let toml_str = r#"
[gate]
socket_path = "/tmp/test.sock"
log_level = "trace"
audit_log_path = "/tmp/audit.jsonl"
fingerprint_path = "/tmp/gate.fingerprint"

[gate.tls]
enabled = true
cert_path = "/tmp/cert.pem"
key_path = "/tmp/key.pem"
client_ca_path = "/tmp/ca.pem"

[vault]
backend = "1password"
subprocess_sandbox = false

[vault.bitwarden]
cli_path = "/usr/local/bin/bw"
session_timeout_minutes = 120

[vault.file]
path = "/tmp/dev-vault.json.enc"

[approval]
default_method = "cli"
gui_command = "zenity"
timeout_seconds = 60
cooldown_seconds = 10
show_binary_hash = false
label_reason_untrusted = false
max_reason_length = 500

[security]
max_delegation_depth = 5
default_lease_ttl_seconds = 7200
max_lease_ttl_seconds = 172800
max_renewals_per_lease = 10
max_cumulative_ttl_seconds = 28800
remote_max_ttl_seconds = 600
remote_single_use = false
encrypted_memory = false
per_credential_keys = false
disable_core_dumps = false
require_binary_hash_for_auto = false
policy_signing = true
policy_signing_key = "base64key"
nonce_window_seconds = 600
nonce_max_entries = 200000

[security.dns]
pin_at_lease_creation = false
allow_dynamic_dns = true

[security.proxy]
follow_redirects = true
strip_set_cookie = false
strip_auth_echo = false

[proxy]
bind_address = "0.0.0.0"
port_range = "20000-20999"

[browser]
sandbox_method = "unshare"
default_mode = "full_snapshot"
mitm_ca_validity_hours = 48
mitm_ca_name_constrained = false
kill_after_snapshot = false
"#;
        let config: GateConfig = toml::from_str(toml_str).unwrap();
        assert!(config.gate.tls.enabled);
        assert_eq!(config.vault.backend, "1password");
        assert_eq!(config.vault.file.path, "/tmp/dev-vault.json.enc");
        assert_eq!(config.approval.gui_command, "zenity");
        assert_eq!(config.security.max_delegation_depth, 5);
        assert!(config.security.dns.allow_dynamic_dns);
        assert!(config.security.proxy.follow_redirects);
        assert_eq!(config.proxy.port_range, "20000-20999");
        assert_eq!(config.browser.sandbox_method, "unshare");
    }
}
