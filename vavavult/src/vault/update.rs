use std::fs;
use rusqlite::params;
use crate::common::constants::{META_VAULT_FEATURES};
use crate::common::hash::{HashParseError, VaultHash};
use crate::common::metadata::MetadataEntry;
use crate::file::{PathError, VaultPath};
use crate::vault::{query, QueryResult, Vault};
use crate::vault::metadata::{self, MetadataError};

/// Defines errors that can occur during file path or vault configuration update operations.
//
// // 定义在文件路径或保险库配置更新操作期间可能发生的错误。
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// A database query failed.
    //
    // // 数据库查询失败。
    #[error("Database query error: {0}")]
    QueryError(#[from] query::QueryError),

    /// An error occurred while executing a database update.
    //
    // // 执行数据库更新时发生错误。
    #[error("Database update error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    /// An error occurred during `VaultPath` construction.
    //
    // // `VaultPath` 构建期间发生错误。
    #[error("VaultPath error: {0}")]
    VaultPathError(#[from] PathError),

    /// The file to be updated was not found.
    //
    // // 未找到要更新的文件。
    #[error("File with SHA256 '{0}' not found.")]
    FileNotFound(String),

    /// The target `VaultPath` is already in use by another file.
    //
    // // 目标 `VaultPath` 已被另一个文件占用。
    #[error("Target path '{0}' is already taken.")]
    DuplicateTargetPath(String),

    /// The new filename is invalid (e.g., contains path separators).
    //
    // // 新文件名无效 (例如包含路径分隔符)。
    #[error("Invalid new filename '{0}': contains path separators.")]
    InvalidFilename(String),

    /// An I/O error occurred while writing the `master.json` config file.
    //
    // // 写入 `master.json` 配置文件时发生 I/O 错误。
    #[error("Failed to write configuration file: {0}")]
    ConfigWriteError(#[from] std::io::Error),

    /// Failed to serialize the `master.json` configuration.
    //
    // // 序列化 `master.json` 配置失败。
    #[error("Failed to serialize configuration: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// The feature name is invalid (e.g., contains spaces).
    //
    // // 功能名称无效 (例如包含空格)。
    #[error("Invalid feature name '{0}': Feature names cannot contain spaces.")]
    InvalidFeatureName(String),

    /// Hash parsing failed.
    //
    // // 哈希解析失败。
    #[error("Wrong hash error: {0}")]
    HashParseError(#[from] HashParseError),

    /// A metadata operation failed (e.g., updating timestamps).
    //
    // // 元数据操作失败 (例如更新时间戳)。
    #[error("Metadata operation failed: {0}")]
    MetadataError(#[from] MetadataError),
}

/// Moves a file within the vault to a new path.
pub(crate) fn move_file(
    vault: &Vault,
    hash: &VaultHash,
    target_path: &VaultPath
) -> Result<(), UpdateError> {
    // 1. Find original entry
    let original_entry = match query::check_by_hash(vault, hash)? {
        QueryResult::Found(entry) => entry,
        QueryResult::NotFound => return Err(UpdateError::FileNotFound(hash.to_string())),
    };
    let original_vault_path = original_entry.path.clone();

    // 2. Resolve final path
    let final_path = if target_path.is_dir() {
        let original_filename = original_vault_path.file_name()
            .ok_or_else(|| UpdateError::VaultPathError(PathError::JoinToFile))?;
        target_path.join(original_filename)?
    } else {
        target_path.clone()
    };

    // 3. Check for duplicates
    if let QueryResult::Found(existing) = query::check_by_path(vault, &final_path)? {
        return if existing.sha256sum != *hash {
            Err(UpdateError::DuplicateTargetPath(final_path.as_str().to_string()))
        } else {
            Ok(())
        };
    }

    // 4. Execute update
    let rows_affected = vault.database_connection.execute(
        "UPDATE files SET path = ?1 WHERE sha256sum = ?2",
        params![final_path.as_str(), hash],
    )?;

    if rows_affected == 0 {
        return Err(UpdateError::FileNotFound(hash.to_string()));
    }

    // 5. Update timestamp (using metadata module)
    metadata::touch_file_update_time(vault, hash)?;
    Ok(())
}

/// Renames a file in-place (keeping the same parent directory).
pub(crate) fn rename_file_inplace(
    vault: &Vault,
    hash: &VaultHash,
    new_filename: &str
) -> Result<(), UpdateError> {
    if new_filename.contains('/') || new_filename.contains('\\') {
        return Err(UpdateError::InvalidFilename(new_filename.to_string()));
    }

    let original_entry = match query::check_by_hash(vault, hash)? {
        QueryResult::Found(entry) => entry,
        QueryResult::NotFound => return Err(UpdateError::FileNotFound(hash.to_string())),
    };

    let parent_dir = original_entry.path.parent()?;
    let final_path = parent_dir.join(new_filename)?;

    if let QueryResult::Found(existing) = query::check_by_path(vault, &final_path)? {
        if existing.sha256sum != *hash {
            return Err(UpdateError::DuplicateTargetPath(final_path.as_str().to_string()));
        } else {
            return Ok(());
        }
    }

    let rows_affected = vault.database_connection.execute(
        "UPDATE files SET path = ?1 WHERE sha256sum = ?2",
        params![final_path.as_str(), hash],
    )?;

    if rows_affected == 0 {
        return Err(UpdateError::FileNotFound(hash.to_string()));
    }

    metadata::touch_file_update_time(vault, hash)?;
    Ok(())
}

// --- Vault Config Operations ---

/// Sets the vault name.
pub(crate) fn set_name(vault: &mut Vault, new_name: &str) -> Result<(), UpdateError> {
    vault.config.name = new_name.to_string();
    _save_config(vault)
}

/// Enables a vault extension feature.
pub(crate) fn enable_vault_feature(vault: &mut Vault, feature_name: &str) -> Result<(), UpdateError> {
    if feature_name.contains(' ') || feature_name.trim().is_empty() {
        return Err(UpdateError::InvalidFeatureName(feature_name.to_string()));
    }

    // Reuse metadata module logic
    let current_value = match metadata::get_vault_metadata(vault, META_VAULT_FEATURES) {
        Ok(v) => v,
        Err(MetadataError::MetadataKeyNotFound(_)) => String::new(),
        Err(e) => return Err(e.into()),
    };

    let mut features: Vec<&str> = current_value.split_whitespace().collect();
    if features.contains(&feature_name) {
        return Ok(());
    }

    features.push(feature_name);
    let new_value = features.join(" ");

    // This calls set_vault_metadata which updates timestamp implicitly?
    // Wait, metadata::set_vault_metadata does NOT auto-update vault timestamp (unlike file metadata logic).
    // But `enable_vault_feature` implies a vault update.

    metadata::set_vault_metadata(vault, MetadataEntry {
        key: META_VAULT_FEATURES.to_string(),
        value: new_value,
    })?;

    metadata::touch_vault_update_time(vault)?;
    Ok(())
}

/// Saves the current configuration to `master.json`.
fn _save_config(vault: &Vault) -> Result<(), UpdateError> {
    let config_json = serde_json::to_string(&vault.config)?;
    let config_path = vault.root_path.join("master.json");
    fs::write(config_path, config_json.as_bytes())?;
    Ok(())
}