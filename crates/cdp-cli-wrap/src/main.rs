//! `cdp-wrap` — CDP CLI wrapper entry point.
//!
//! Usage:
//!   cdp-wrap <command> [args...]
//!   cdp-wrap --askpass          (invoked by child as the ASKPASS helper)
//!
//! When invoked as the ASKPASS helper (either via `--askpass` flag or by
//! having the binary name contain "cdp-askpass"), the binary reads a
//! credential from the fd specified in `CDP_PIPE_FD` and writes it to stdout.
//!
//! In normal mode, `cdp-wrap`:
//!   1. Reads the Gate fingerprint from `~/.config/cdp/gate.fingerprint`.
//!   2. Connects to the Gate Unix socket and sends `cdp.register`.
//!   3. Sends `cdp.requestCredential` for the configured credential ref.
//!   4. Determines the injection method from the command name.
//!   5. Creates an anonymous pipe, spawns the command (via `spawn_isolated`),
//!      and writes the credential to the pipe's write end.
//!   6. Waits for the child and exits with its exit code.

use std::process;

use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use cdp_cli_wrap::askpass::{is_askpass_mode, run_askpass};
use cdp_cli_wrap::exec::CommandExecutor;
use cdp_cli_wrap::gate_client::{GateClient, GateFingerprint};
use cdp_cli_wrap::{InjectionMethod, WrapError};

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

/// Parsed CLI arguments for normal (non-askpass) mode.
struct WrapArgs {
    /// The command to execute (e.g. "git").
    command: String,
    /// Arguments to pass to the command.
    args: Vec<String>,
    /// Credential reference to request from the Gate.
    credential_ref: String,
}

fn parse_args() -> Result<WrapArgs, WrapError> {
    let all_args: Vec<String> = std::env::args().collect();

    // Skip argv[0] (our own path).
    let rest: &[String] = if all_args.len() > 1 {
        &all_args[1..]
    } else {
        &[]
    };

    if rest.is_empty() {
        eprintln!("Usage: cdp-wrap [--credential-ref <ref>] <command> [args...]");
        eprintln!("       cdp-wrap --askpass");
        process::exit(2);
    }

    // Parse optional --credential-ref flag.
    let mut credential_ref = String::new();
    let mut iter = rest.iter().peekable();
    if iter.peek().map(|s| s.as_str()) == Some("--credential-ref") {
        iter.next(); // consume --credential-ref
        credential_ref = iter
            .next()
            .cloned()
            .ok_or_else(|| WrapError::Config("--credential-ref requires a value".to_string()))?;
    }

    let command = iter
        .next()
        .cloned()
        .ok_or_else(|| WrapError::Config("command is required".to_string()))?;
    let args: Vec<String> = iter.cloned().collect();

    // If no credential ref given, derive a default from the command name.
    if credential_ref.is_empty() {
        let name = std::path::Path::new(&command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&command)
            .to_string();
        credential_ref = format!("cli/{name}");
    }

    Ok(WrapArgs {
        command,
        args,
        credential_ref,
    })
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    // Initialise tracing from RUST_LOG (default: warn).
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let all_args: Vec<String> = std::env::args().collect();
    let argv0 = all_args.first().map(String::as_str).unwrap_or("cdp-wrap");
    let rest = if all_args.len() > 1 {
        all_args[1..].to_vec()
    } else {
        vec![]
    };

    // --- ASKPASS mode ---
    if is_askpass_mode(argv0, &rest) {
        match run_askpass() {
            Ok(()) => process::exit(0),
            Err(e) => {
                eprintln!("cdp-wrap askpass error: {e}");
                process::exit(1);
            }
        }
    }

    // --- Normal wrapper mode ---
    let code = match run_wrap() {
        Ok(exit_code) => exit_code,
        Err(e) => {
            error!("cdp-wrap: {e}");
            eprintln!("cdp-wrap: {e}");
            1
        }
    };

    process::exit(code);
}

/// Core wrapper logic. Returns the child's exit code on success.
fn run_wrap() -> Result<i32, WrapError> {
    let wrap_args = parse_args()?;

    // Determine injection method from the command name.
    let method = InjectionMethod::from_command(&wrap_args.command);
    info!(
        command = %wrap_args.command,
        method = ?method,
        credential_ref = %wrap_args.credential_ref,
        "starting cdp-wrap"
    );

    // Load Gate fingerprint and connect.
    let fingerprint = GateFingerprint::load()?;
    let mut gate = GateClient::connect(&fingerprint.socket_path)?;
    gate.register()?;

    // Request a credential lease (returns proxy info, not the credential itself).
    let lease = gate.request_credential(&wrap_args.credential_ref, &wrap_args.command)?;

    // Determine the path to this binary (used as ASKPASS helper).
    let self_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| {
            std::env::args()
                .next()
                .unwrap_or_else(|| "cdp-wrap".to_string())
        });

    // Execute the command with credential injection via the CDP proxy.
    let executor = CommandExecutor::new(self_path)?;
    let result = executor.run(&wrap_args.command, &wrap_args.args, &method, lease)?;

    Ok(result.exit_code)
}
