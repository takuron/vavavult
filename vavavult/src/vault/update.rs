use crate::common::constants::META_VAULT_FEATURES;
use crate::common::hash::{HashParseError, VaultHash};
use crate::common::metadata::MetadataEntry;
use crate::crypto::encrypt::{EncryptError, create_v2_encrypt_check, verify_v2_encrypt_check};
use crate::file::{PathError, VaultPath};
use crate::storage::StorageBackend;
use crate::vault::config::VaultConfig;
use crate::vault::metadata::{self, MetadataError};
use crate::vault::open::OpenError;
use crate::vault::{QueryResult, Vault, query};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::Path;

const BUFFER_LEN: usize = 8192;

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

    /// An I/O error occurred.
    //
    // // 发生 I/O 错误。
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

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

    /// The calculated hash of the encrypted content does not match its identifier hash.
    //
    // // 加密内容的计算哈希与其标识符哈希不匹配。
    #[error("File is corrupt: integrity check failed for hash {0}")]
    IntegrityMismatch(String),

    /// An error occurred while trying to open or read the vault configuration.
    #[error("Failed to open or read vault configuration: {0}")]
    Open(#[from] OpenError),

    /// The provided old password was incorrect.
    #[error("The provided old password is not correct.")]
    InvalidOldPassword,

    /// An error occurred during the creation of the encryption check string.
    #[error("Encryption check creation error: {0}")]
    EncryptCheck(#[from] EncryptError),
}

/// Moves a file within the vault to a new path.
pub(crate) fn move_file(
    vault: &Vault,
    hash: &VaultHash,
    target_path: &VaultPath,
) -> Result<(), UpdateError> {
    // 1. Find original entry
    let original_entry = match query::check_by_hash(vault, hash)? {
        QueryResult::Found(entry) => entry,
        QueryResult::NotFound => return Err(UpdateError::FileNotFound(hash.to_string())),
    };
    let original_vault_path = original_entry.path.clone();

    // 2. Resolve final path
    let final_path = if target_path.is_dir() {
        let original_filename = original_vault_path
            .file_name()
            .ok_or_else(|| UpdateError::VaultPathError(PathError::JoinToFile))?;
        target_path.join(original_filename)?
    } else {
        target_path.clone()
    };

    // 3. Check for duplicates
    if let QueryResult::Found(existing) = query::check_by_path(vault, &final_path)? {
        return if existing.sha256sum != *hash {
            Err(UpdateError::DuplicateTargetPath(
                final_path.as_str().to_string(),
            ))
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
    new_filename: &str,
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
            return Err(UpdateError::DuplicateTargetPath(
                final_path.as_str().to_string(),
            ));
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
pub(crate) fn enable_vault_feature(
    vault: &mut Vault,
    feature_name: &str,
) -> Result<(), UpdateError> {
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

    metadata::set_vault_metadata(
        vault,
        MetadataEntry {
            key: META_VAULT_FEATURES.to_string(),
            value: new_value,
        },
    )?;

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

/// Verifies the integrity of an encrypted file by re-calculating its SHA256 hash
/// and comparing it to the expected hash (which is also its ID).
/// This is a fast, I/O-bound operation that does not perform decryption.
//
// // 通过重新计算加密文件的 SHA256 哈希并与预期哈希（即其 ID）进行比较，来验证其完整性。
// // 这是一个快速的、受 I/O 限制的操作，不执行解密。
pub fn verify_encrypted_file_hash(
    storage: &dyn StorageBackend,
    hash: &VaultHash,
) -> Result<(), UpdateError> {
    let mut reader = storage.reader(hash)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let calculated_hash = VaultHash::new(hasher.finalize().into());

    if calculated_hash == *hash {
        Ok(())
    } else {
        Err(UpdateError::IntegrityMismatch(hash.to_string()))
    }
}

/// Updates the master password for an encrypted vault.
///
/// This function performs a "shallow" update:
/// 1. Verifies the old password.
/// 2. Generates a new encryption verification marker (`encrypt_check`).
/// 3. Updates `master.json` with the new marker.
/// 4. Re-keys the encrypted SQLite database with the new password.
///
/// It does **not** re-encrypt the individual files stored within the vault.
///
/// # Arguments
/// * `vault_path` - The path to the vault's root directory.
/// * `old_password` - The current master password.
/// * `new_password` - The new master password to set.
///
/// # Returns
/// `Ok(())` on success, or an `UpdateError` on failure.
pub fn update_password(
    vault_path: &Path,
    old_password: &str,
    new_password: &str,
) -> Result<(), UpdateError> {
    // 1. Read and parse the existing configuration
    let config_path = vault_path.join("master.json");
    if !config_path.exists() {
        return Err(UpdateError::Open(OpenError::ConfigNotFound));
    }
    let config_content = fs::read_to_string(&config_path)?;
    let mut config: VaultConfig = serde_json::from_str(&config_content)?;

    // 2. Verify the old password
    if !config.encrypted {
        // This operation is only meaningful for encrypted vaults.
        // For now, we can treat it as a no-op success or return an error.
        // Let's return success as there's no password to update.
        return Ok(());
    }

    if !verify_v2_encrypt_check(&config.encrypt_check, old_password) {
        return Err(UpdateError::InvalidOldPassword);
    }

    // 3. Connect to the database with the old password
    let db_path = vault_path.join(&config.database);
    let conn = Connection::open(db_path)?;
    conn.pragma_update(None, "key", old_password)?;

    // Verify connection by making a simple query
    let verification_query = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table'",
        [],
        |row| row.get::<_, i64>(0),
    );
    if verification_query.is_err() {
        // This could happen if the pragma key failed silently.
        return Err(UpdateError::InvalidOldPassword);
    }

    // 4. Re-key the database to the new password
    let rekey_sql = format!("PRAGMA rekey = '{}'", new_password.replace('\'', "''"));
    conn.execute_batch(&rekey_sql)?;

    // 5. Generate the new encrypt_check and update the config
    let new_encrypt_check = create_v2_encrypt_check(new_password)?;
    config.encrypt_check = new_encrypt_check;

    // 6. Write the updated config back to master.json
    let new_config_content = serde_json::to_string_pretty(&config)?;
    fs::write(config_path, new_config_content)?;

    Ok(())
}
