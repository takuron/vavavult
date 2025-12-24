use crate::errors::CliError;
use vavavult::file::FileEntry;
use vavavult::vault::Vault;

/// Handles the business logic for the 'search' command, returning data instead of printing.
pub fn handle_search(vault: &Vault, keyword: &str) -> Result<Vec<FileEntry>, CliError> {
    Ok(vault.find_by_keyword(keyword)?)
}
