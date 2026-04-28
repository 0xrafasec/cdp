//! Creates an encrypted dev vault for testing.
//!
//! Usage: cargo run -p cdp-vault --example create_dev_vault

use std::collections::HashMap;
use std::path::PathBuf;

use cdp_vault::file::{DevCredential, create_dev_vault};

fn main() {
    let path = PathBuf::from(dirs_path().join("dev-vault.json.enc"));

    let password = "devpass";

    let mut credentials = HashMap::new();
    credentials.insert(
        "my-api-key".to_string(),
        DevCredential {
            value: "Bearer test-cdp-token-12345".to_string(),
            name: "Test API Key".to_string(),
        },
    );

    create_dev_vault(&path, password, &credentials).expect("failed to create dev vault");

    println!("Dev vault created at: {}", path.display());
    println!("Password: {password}");
    println!("Credentials:");
    for (ref_id, cred) in &credentials {
        println!("  {ref_id}: {} ({})", cred.value, cred.name);
    }
}

fn dirs_path() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME not set");
    PathBuf::from(home).join(".config/cdp")
}
