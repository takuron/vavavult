use crate::core::helpers::get_all_files_recursively;
use crate::errors::CliError;
use vavavult::file::{FileEntry, VaultPath};
use vavavult::vault::{DirectoryEntry, Vault};

/// Represents the data returned by the list handler, to be processed by a view/printer.
pub enum ListResult {
    Shallow(Vec<DirectoryEntry>),
    Recursive(Vec<FileEntry>),
}

/// Handles the business logic for the 'ls' command, returning data instead of printing it.
pub fn handle_list(
    vault: &Vault,
    path: Option<String>,
    recursive: bool,
) -> Result<(ListResult, VaultPath), CliError> {
    let target_path_str = path.unwrap_or_else(|| "/".to_string());
    let target_vault_path = VaultPath::from(target_path_str.as_str());

    if target_vault_path.is_file() {
        return Err(CliError::InvalidTarget(format!(
            "Cannot list '{}': Path is a file, not a directory. 'ls' is for directories.",
            target_vault_path
        )));
    }

    if recursive {
        let all_files = get_all_files_recursively(vault, target_vault_path.as_str())?;
        Ok((ListResult::Recursive(all_files), target_vault_path))
    } else {
        let entries = vault.list_by_path(&target_vault_path)?;
        Ok((ListResult::Shallow(entries), target_vault_path))
    }
}
