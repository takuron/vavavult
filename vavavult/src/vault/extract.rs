use std::path::Path;
use std::fs;
use crate::vault::{query, QueryResult, Vault};

#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("Database query error: {0}")]
    QueryError(#[from] query::QueryError),

    #[error("File system error: {0}")]
    FileSystemError(#[from] std::io::Error),

    #[error("File with SHA256 '{0}' not found.")]
    FileNotFound(String),
}

/// Extracts a file from the vault to a destination path.
pub fn extract_file(
    vault: &Vault,
    sha256sum: &str,
    destination_path: &Path,
) -> Result<(), ExtractError> {
    // 1. Check if the file exists in the vault's database.
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(ExtractError::FileNotFound(sha256sum.to_string()));
    }

    // 2. Determine the source path within the vault.
    let internal_path = vault.root_path.join(sha256sum);

    // 3. Ensure the destination directory exists.
    if let Some(parent_dir) = destination_path.parent() {
        fs::create_dir_all(parent_dir)?;
    }

    // 4. Copy the file.
    fs::copy(&internal_path, destination_path)?;

    Ok(())
}