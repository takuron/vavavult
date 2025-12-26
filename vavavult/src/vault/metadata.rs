use rusqlite::params;
use crate::common::constants::{META_FILE_UPDATE_TIME, META_PREFIX, META_VAULT_UPDATE_TIME};
use crate::common::hash::VaultHash;
use crate::common::metadata::MetadataEntry;
use crate::utils::time::now_as_rfc3339_string;
use crate::vault::{query, QueryResult, Vault};

/// Defines errors that can occur during metadata operations.
//
// // 定义在元数据操作期间可能发生的错误。
#[derive(Debug, thiserror::Error)]
pub enum MetadataError {
    /// A database query failed.
    //
    // // 数据库查询失败。
    #[error("Database query error: {0}")]
    QueryError(#[from] query::QueryError),

    /// An error occurred while executing a database update.
    //
    // // 执行数据库更新时发生错误。
    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    /// The file specified for metadata update was not found.
    //
    // // 未找到指定要更新元数据的文件。
    #[error("File with SHA256 '{0}' not found.")]
    FileNotFound(String),

    /// The specified metadata key was not found.
    //
    // // 未找到指定的元数据键。
    #[error("Metadata key '{0}' not found.")]
    MetadataKeyNotFound(String),
}

// --- File Metadata Operations ---

/// Sets a metadata key-value pair for a file (upsert operation).
pub(crate) fn set_file_metadata(
    vault: &Vault,
    sha256sum: &VaultHash,
    metadata: MetadataEntry
) -> Result<(), MetadataError> {
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(MetadataError::FileNotFound(sha256sum.to_string()));
    }
    vault.database_connection.execute(
        "INSERT OR REPLACE INTO metadata (file_sha256sum, meta_key, meta_value) VALUES (?1, ?2, ?3)",
        params![sha256sum, metadata.key, metadata.value],
    )?;

    // Check to prevent infinite recursion if we are updating the timestamp itself
    if !metadata.key.starts_with(META_PREFIX) {
        touch_file_update_time(vault, sha256sum)?;
    }
    Ok(())
}

/// Removes a metadata key-value pair from a file.
pub(crate) fn remove_file_metadata(
    vault: &Vault,
    sha256sum: &VaultHash,
    key: &str
) -> Result<(), MetadataError> {
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(MetadataError::FileNotFound(sha256sum.to_string()));
    }
    vault.database_connection.execute(
        "DELETE FROM metadata WHERE file_sha256sum = ?1 AND meta_key = ?2",
        params![sha256sum, key],
    )?;

    if !key.starts_with(META_PREFIX) {
        touch_file_update_time(vault, sha256sum)?;
    }
    Ok(())
}

/// Updates the `_vavavult_update_time` metadata for a file.
pub(crate) fn touch_file_update_time(vault: &Vault, sha256sum: &VaultHash) -> Result<(), MetadataError> {
    let now = now_as_rfc3339_string();
    let metadata_entry = MetadataEntry {
        key: META_FILE_UPDATE_TIME.to_string(),
        value: now,
    };
    // Helper calling helper: This is safe because key starts with META_PREFIX
    set_file_metadata(vault, sha256sum, metadata_entry)
}

// --- Vault Metadata Operations ---

/// Retrieves a vault-level metadata value.
pub(crate) fn get_vault_metadata(vault: &Vault, key: &str) -> Result<String, MetadataError> {
    vault.database_connection.query_row(
        "SELECT meta_value FROM vault_metadata WHERE meta_key = ?1",
        params![key],
        |row| row.get(0)
    ).map_err(|e| {
        if let rusqlite::Error::QueryReturnedNoRows = e {
            MetadataError::MetadataKeyNotFound(key.to_string())
        } else {
            MetadataError::DatabaseError(e)
        }
    })
}

/// Sets a vault-level metadata key-value pair (upsert).
pub(crate) fn set_vault_metadata(vault: &Vault, metadata_entry: MetadataEntry) -> Result<(), MetadataError> {
    vault.database_connection.execute(
        "INSERT OR REPLACE INTO vault_metadata (meta_key, meta_value) VALUES (?1, ?2)",
        params![metadata_entry.key, metadata_entry.value],
    )?;
    Ok(())
}

/// Removes a vault-level metadata key-value pair.
pub(crate) fn remove_vault_metadata(vault: &Vault, key: &str) -> Result<(), MetadataError> {
    let rows_affected = vault.database_connection.execute(
        "DELETE FROM vault_metadata WHERE meta_key = ?1",
        params![key],
    )?;
    if rows_affected == 0 {
        return Err(MetadataError::MetadataKeyNotFound(key.to_string()));
    }
    Ok(())
}

/// Updates the `_vavavult_update_time` metadata for the vault.
pub(crate) fn touch_vault_update_time(vault: &Vault) -> Result<(), MetadataError> {
    let now = now_as_rfc3339_string();
    set_vault_metadata(vault, MetadataEntry {
        key: META_VAULT_UPDATE_TIME.to_string(),
        value: now,
    })
}