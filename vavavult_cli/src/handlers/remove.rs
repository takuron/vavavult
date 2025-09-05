use std::error::Error;
use vavavult::vault::Vault;
use crate::utils::{confirm_action, find_file_entry};

pub fn handle_remove(vault: &Vault, vault_name: Option<String>, sha256: Option<String>) -> Result<(), Box<dyn Error>>{
    let file_entry = find_file_entry(vault, vault_name, sha256)?;

    if !confirm_action(&format!(
        "Are you sure you want to PERMANENTLY DELETE '{}'?",
        file_entry.name
    ))? {
        println!("Operation cancelled.");
        return Ok(());
    }

    println!("Deleting '{}' from vault...", file_entry.name);
    vault.remove_file(&file_entry.sha256sum)?;
    println!("File successfully deleted.");
    Ok(())
}
