use std::fs;
use std::path::Path;
use tempfile::tempdir;
use vavavult::common::metadata::MetadataEntry;
use vavavult::file::VaultPath;
use vavavult::vault::{Vault};

fn create_dummy_file(dir: &Path, name: &str, content: &[u8]) -> std::io::Result<()> {
    fs::write(dir.join(name), content)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create a temporary directory for our vault.
    let dir = tempdir()?;
    let vault_path = dir.path();
    let password = "a_very_secret_password";

    // --- Create a new ENCRYPTED Vault ---
    println!("Creating a new ENCRYPTED vault with password...");
    let mut vault = Vault::create_vault(vault_path, "secure-vault", Some(password))?;
    println!("Encrypted vault created successfully!");

    // --- Add multiple files with tags and metadata ---
    println!("\nAdding files with tags and metadata...");
    create_dummy_file(dir.path(), "report.txt", b"This is the annual report.")?;
    create_dummy_file(dir.path(), "logo.png", b"Fake PNG data")?;

    let report_hash = vault.add_file(&dir.path().join("report.txt"), &VaultPath::from("work/2025/annual_report.txt"))?;
    let logo_hash = vault.add_file(&dir.path().join("logo.png"), &VaultPath::from("assets/logo.png"))?;

    // Add tags
    vault.add_tags(&report_hash, &["work", "finance", "report"])?;
    vault.add_tag(&logo_hash, "asset")?;
    println!("Tags added.");

    // Set metadata
    vault.set_file_metadata(&report_hash, MetadataEntry {
        key: "author".to_string(),
        value: "John Doe".to_string(),
    })?;
    vault.set_file_metadata(&report_hash, MetadataEntry {
        key: "status".to_string(),
        value: "final".to_string(),
    })?;
    println!("Metadata set.");

    // --- Perform advanced queries ---
    println!("\nPerforming advanced searches...");
    let finance_files = vault.find_by_tag("finance")?;
    assert_eq!(finance_files.len(), 1);
    println!("Found {} file(s) with tag 'finance'.", finance_files.len());

    let report_files = vault.find_by_name_fuzzy("report")?;
    assert_eq!(report_files.len(), 1);
    println!("Found {} file(s) with 'report' in the name.", report_files.len());

    // --- Extract a file ---
    println!("\nExtracting file '{}'...", report_hash);
    let extract_path = dir.path().join("extracted_report.txt");
    vault.extract_file(&report_hash, &extract_path)?;

    let content = fs::read_to_string(&extract_path)?;
    assert_eq!(content, "This is the annual report.");
    println!("File extracted successfully to: {:?}", extract_path);
    println!("  - Extracted content: '{}'", content);

    drop(vault);

    // --- Re-open the encrypted vault with the correct password ---
    println!("\nRe-opening encrypted vault with correct password...");
    let reopened_vault = Vault::open_vault(vault_path, Some(password))?;
    assert_eq!(reopened_vault.config.name, "secure-vault");
    println!("Successfully re-opened encrypted vault!");

    // --- Attempt to open with wrong password (should fail) ---
    println!("\nAttempting to re-open with wrong password...");
    let result = Vault::open_vault(vault_path, Some("wrong_password"));
    assert!(result.is_err());
    println!("As expected, opening with wrong password failed.");

    println!("\nAdvanced example finished successfully!");
    Ok(())
}