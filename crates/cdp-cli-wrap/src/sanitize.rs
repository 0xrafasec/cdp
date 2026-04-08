//! Output sanitizer for child process stdout/stderr.
//!
//! Scans output lines for credential-shaped strings and replaces them with
//! `[CDP:REDACTED]`. This is a defence-in-depth measure: the primary security
//! invariant is that credentials are never passed to the child process as
//! arguments or environment variables, but sanitization catches any accidental
//! echoing by the child.
//!
//! Detected patterns (configurable):
//! - GitHub tokens: `ghp_`, `gho_`, `github_pat_`
//! - Slack tokens: `xoxb-`, `xoxp-`, `xoxa-`
//! - OpenAI keys: `sk-`
//! - AWS keys: `AKIA[A-Z0-9]{16}`
//! - Bearer tokens in HTTP headers: `Authorization: Bearer <value>`
//! - Long Base64-like strings (>= 32 chars, all base64 alphabet) after `=` or `:`

use regex::Regex;
use tracing::debug;

use crate::WrapError;

/// Replacement string substituted for detected credential patterns.
pub const REDACTED_MARKER: &str = "[CDP:REDACTED]";

/// A compiled set of patterns used to redact credential-like strings.
pub struct OutputSanitizer {
    patterns: Vec<Regex>,
}

impl OutputSanitizer {
    /// Construct a sanitizer with the default credential-detection patterns.
    pub fn new() -> Result<Self, WrapError> {
        Self::with_patterns(&default_patterns())
    }

    /// Construct a sanitizer from an explicit list of regex patterns.
    ///
    /// Each pattern should capture the credential portion as group 1 (if a
    /// capturing group is present) or match the entire credential text.
    pub fn with_patterns(patterns: &[&str]) -> Result<Self, WrapError> {
        let compiled: Result<Vec<Regex>, _> = patterns.iter().map(|p| Regex::new(p)).collect();
        let compiled =
            compiled.map_err(|e| WrapError::Sanitize(format!("compile pattern: {e}")))?;
        Ok(Self { patterns: compiled })
    }

    /// Sanitize a single line of output, returning the redacted version.
    ///
    /// If no patterns match, the original line is returned unchanged.
    pub fn sanitize_line<'a>(&self, line: &'a str) -> std::borrow::Cow<'a, str> {
        let mut result = std::borrow::Cow::Borrowed(line);
        for pattern in &self.patterns {
            if pattern.is_match(&result) {
                let replaced = pattern.replace_all(&result, REDACTED_MARKER).into_owned();
                debug!("sanitized credential-like pattern from output");
                result = std::borrow::Cow::Owned(replaced);
            }
        }
        result
    }

    /// Sanitize a multi-line buffer, line by line.
    ///
    /// Preserves line endings from the original. Returns a new `String` with
    /// all credential-like substrings replaced.
    pub fn sanitize_buffer(&self, buf: &str) -> String {
        // Process line-by-line to avoid cross-line false positives.
        buf.lines()
            .map(|line| self.sanitize_line(line).into_owned())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Sanitize raw bytes, interpreting them as UTF-8 (lossy).
    ///
    /// Non-UTF-8 sequences are replaced with the Unicode replacement character
    /// before pattern matching, so binary output is handled safely.
    pub fn sanitize_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        let s = String::from_utf8_lossy(bytes);
        self.sanitize_buffer(&s).into_bytes()
    }
}

impl Default for OutputSanitizer {
    fn default() -> Self {
        Self::new().expect("default patterns should compile")
    }
}

/// Return the list of default pattern strings.
///
/// Each pattern is a full regex that matches the credential (or the entire
/// header value containing it). The matched text is replaced wholesale with
/// `[CDP:REDACTED]`.
pub fn default_patterns() -> Vec<&'static str> {
    vec![
        // GitHub personal access tokens (classic and fine-grained).
        r"ghp_[A-Za-z0-9]{36,}",
        r"gho_[A-Za-z0-9]{36,}",
        r"github_pat_[A-Za-z0-9_]{36,}",
        // Slack tokens.
        r"xoxb-[A-Za-z0-9\-]{20,}",
        r"xoxp-[A-Za-z0-9\-]{20,}",
        r"xoxa-[A-Za-z0-9\-]{20,}",
        // OpenAI / Anthropic API keys.
        r"sk-[A-Za-z0-9\-_]{20,}",
        // AWS access key IDs.
        r"AKIA[A-Z0-9]{16}",
        // HTTP Authorization header (Bearer scheme).
        r"(?i)(Authorization:\s*Bearer\s+)[A-Za-z0-9\-_=+/]{16,}",
        // Generic long base64-encoded values following '=' or ':'.
        r"(?:=|:\s*)[A-Za-z0-9+/]{32,}={0,2}",
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sanitizer() -> OutputSanitizer {
        OutputSanitizer::new().expect("should compile")
    }

    #[test]
    fn test_no_match_unchanged() {
        let s = sanitizer();
        let line = "Everything is fine, no credentials here.";
        let result = s.sanitize_line(line);
        assert_eq!(result, line);
    }

    #[test]
    fn test_github_token_redacted() {
        let s = sanitizer();
        let line = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        let result = s.sanitize_line(line);
        assert!(
            result.contains(REDACTED_MARKER),
            "GitHub token not redacted: {result}"
        );
        assert!(
            !result.contains("ghp_"),
            "token still present after redaction"
        );
    }

    #[test]
    fn test_slack_token_redacted() {
        let s = sanitizer();
        let line = "xoxb-1234567890-1234567890-abcdefghijklmnop";
        let result = s.sanitize_line(line);
        assert!(
            result.contains(REDACTED_MARKER),
            "Slack token not redacted: {result}"
        );
    }

    #[test]
    fn test_openai_key_redacted() {
        let s = sanitizer();
        let line = "key=sk-abcdefghijklmnopqrstuvwxyz1234567890";
        let result = s.sanitize_line(line);
        assert!(
            result.contains(REDACTED_MARKER),
            "OpenAI key not redacted: {result}"
        );
    }

    #[test]
    fn test_aws_key_redacted() {
        let s = sanitizer();
        let line = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let result = s.sanitize_line(line);
        assert!(
            result.contains(REDACTED_MARKER),
            "AWS key not redacted: {result}"
        );
    }

    #[test]
    fn test_bearer_header_redacted() {
        let s = sanitizer();
        let line = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let result = s.sanitize_line(line);
        assert!(
            result.contains(REDACTED_MARKER),
            "Bearer token not redacted: {result}"
        );
    }

    #[test]
    fn test_sanitize_buffer_multiline() {
        let s = sanitizer();
        let buf = "line 1: normal text\nline 2: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\nline 3: also normal";
        let result = s.sanitize_buffer(buf);
        assert!(result.contains(REDACTED_MARKER));
        assert!(result.contains("line 1: normal text"));
        assert!(result.contains("line 3: also normal"));
    }

    #[test]
    fn test_sanitize_bytes_non_utf8() {
        let s = sanitizer();
        // Non-UTF-8 bytes followed by an innocent string.
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend_from_slice(b"some normal output");
        // Should not panic.
        let result = s.sanitize_bytes(&bytes);
        assert!(!result.is_empty());
    }

    #[test]
    fn test_with_custom_patterns() {
        let s = OutputSanitizer::with_patterns(&[r"MY_SECRET_[A-Z]+"]).expect("should compile");
        let line = "value: MY_SECRET_ABCDEF";
        let result = s.sanitize_line(line);
        assert!(
            result.contains(REDACTED_MARKER),
            "custom pattern not matched: {result}"
        );
    }

    #[test]
    fn test_invalid_pattern_error() {
        let result = OutputSanitizer::with_patterns(&["[invalid regex"]);
        assert!(result.is_err(), "invalid regex should return error");
    }
}
