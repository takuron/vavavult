use std::fs::File;
use std::io::Write;
use tempfile::tempdir;
use vavavult::vault::{QueryResult, Vault};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create a temporary directory for our vault.
    let dir = tempdir()?;
    let vault_path = dir.path();
    println!("Temporary vault will be created at: {:?}", vault_path);

    // --- Create a new Vault ---
    println!("\nCreating a new vault named 'my-first-vault'...");
    let vault = Vault::create_vault(vault_path, "my-first-vault", None)?;
    println!("Vault created successfully!");
    assert_eq!(vault.config.name, "my-first-vault");

    // --- Add a file to the Vault ---
    println!("\nAdding a new file 'hello.txt' to the vault...");
    let source_file_path = dir.path().join("hello.txt");
    let mut file = File::create(&source_file_path)?;
    file.write_all(b"Hello from vavavult example!")?;

    let file_hash = vault.add_file(&source_file_path, Some("docs/greeting/hello.txt"))?;
    println!("File added successfully! SHA256 Hash: {}", file_hash);

    // --- Query the file by its hash ---
    println!("\nQuerying the file by its hash...");
    match vault.find_by_hash(&file_hash)? {
        QueryResult::Found(entry) => {
            println!("File found by hash!");
            println!("  - Name in vault: {}", entry.name);
            println!("  - SHA256: {}", entry.sha256sum);
        }
        QueryResult::NotFound => {
            panic!("File should have been found!");
        }
    }

    // --- Query the file by its name ---
    println!("\nQuerying the file by its name...");
    let file_name_in_vault = "/docs/greeting/hello.txt";
    match vault.find_by_name(file_name_in_vault)? {
        QueryResult::Found(entry) => {
            println!("File found by name '{}'!", entry.name);
        }
        QueryResult::NotFound => {
            panic!("File should have been found by name!");
        }
    }

    // Drop the vault instance to simulate closing the application
    drop(vault);

    // --- Re-open the existing Vault ---
    println!("\nRe-opening the existing vault...");
    let reopened_vault = Vault::open_vault(vault_path, None)?;
    println!("Vault re-opened successfully. Vault name: {}", reopened_vault.config.name);

    // Verify that the file still exists in the re-opened vault
    let result = reopened_vault.find_by_hash(&file_hash)?;
    assert!(matches!(result, QueryResult::Found(_)));
    println!("Verified that the file still exists in the re-opened vault.");

    println!("\nExample finished successfully!");
    Ok(())
}