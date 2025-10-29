use std::fs;
use rusqlite::params;
use crate::common::constants::{META_FILE_UPDATE_TIME, META_PREFIX, META_VAULT_UPDATE_TIME};
use crate::common::metadata::MetadataEntry;
use crate::file::VaultPath;
use crate::utils::time::now_as_rfc3339_string;
use crate::vault::{query, QueryResult, Vault};

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("Database query error: {0}")]
    QueryError(#[from] query::QueryError),

    #[error("Database update error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("File with SHA256 '{0}' not found.")]
    FileNotFound(String),

    #[error("The new path '{0}' is already taken.")]
    DuplicateFileName(String),

    #[error("The new path '{0}' is invalid: must be a file path, not a directory path.")]
    InvalidNewFilePath(String),

    #[error("Failed to write configuration file: {0}")]
    ConfigWriteError(#[from] std::io::Error),

    #[error("Failed to serialize configuration: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Metadata key '{0}' not found.")]
    MetadataKeyNotFound(String),
}

/// 重命名保险库中的一个文件 (更新其路径)。
pub fn rename_file(vault: &Vault, sha256sum: &str, new_path: &VaultPath) -> Result<(), UpdateError> {

    // [新增] 1. 验证 new_path 必须是一个文件路径
    if !new_path.is_file() {
        return Err(UpdateError::InvalidNewFilePath(new_path.as_str().to_string()));
    }

    // [修改] 2. 规范化步骤被移除, 直接使用 as_str()
    let normalized_new_path = new_path.as_str();

    // [修改] 3. 检查新路径是否已被占用 (逻辑不变，变量名更新)
    if let QueryResult::Found(entry) = query::check_by_name(vault, normalized_new_path)? {
        return if entry.sha256sum != sha256sum {
            Err(UpdateError::DuplicateFileName(normalized_new_path.to_string()))
        } else {
            Ok(()) // 路径未改变
        }
    }

    // 4. 检查文件是否存在 (不变)
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(UpdateError::FileNotFound(sha256sum.to_string()));
    }

    // 5. 执行更新 (不变)
    let rows_affected = vault.database_connection.execute(
        // [修改] "name" -> "path"
        "UPDATE files SET path = ?1 WHERE sha256sum = ?2",
        params![normalized_new_path, sha256sum],
    )?;

    if rows_affected == 0 {
        return Err(UpdateError::FileNotFound(sha256sum.to_string()));
    }

    touch_file_update_time(vault, sha256sum)?;
    Ok(())
}


// --- 文件标签操作 (不变) ---

/// 为文件添加一个标签。
pub fn add_tag(vault: &Vault, sha256sum: &str, tag: &str) -> Result<(), UpdateError> {
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(UpdateError::FileNotFound(sha256sum.to_string()));
    }
    vault.database_connection.execute(
        "INSERT OR IGNORE INTO tags (file_sha256sum, tag) VALUES (?1, ?2)",
        params![sha256sum, tag],
    )?;
    touch_file_update_time(vault, sha256sum)?;
    Ok(())
}

/// 为文件批量添加多个标签。
pub fn add_tags(vault: &mut Vault, sha256sum: &str, tags: &[&str]) -> Result<(), UpdateError> {
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(UpdateError::FileNotFound(sha256sum.to_string()));
    }
    let tx = vault.database_connection.transaction()?;
    {
        let mut stmt = tx.prepare("INSERT OR IGNORE INTO tags (file_sha256sum, tag) VALUES (?1, ?2)")?;
        for tag in tags {
            stmt.execute(params![sha256sum, tag])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// 从文件中删除一个标签。
pub fn remove_tag(vault: &Vault, sha256sum: &str, tag: &str) -> Result<(), UpdateError> {
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(UpdateError::FileNotFound(sha256sum.to_string()));
    }
    vault.database_connection.execute(
        "DELETE FROM tags WHERE file_sha256sum = ?1 AND tag = ?2",
        params![sha256sum, tag],
    )?;
    touch_file_update_time(vault, sha256sum)?;
    Ok(())
}

/// 删除一个文件的所有标签。
pub fn clear_tags(vault: &Vault, sha256sum: &str) -> Result<(), UpdateError> {
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(UpdateError::FileNotFound(sha256sum.to_string()));
    }
    vault.database_connection.execute(
        "DELETE FROM tags WHERE file_sha256sum = ?1",
        params![sha256sum],
    )?;
    touch_file_update_time(vault, sha256sum)?;
    Ok(())
}

// --- 文件元数据操作 (不变) ---

/// Sets a metadata key-value pair for a file (upsert operation).
pub fn set_file_metadata(vault: &Vault, sha256sum: &str, metadata:MetadataEntry) -> Result<(), UpdateError> {
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(UpdateError::FileNotFound(sha256sum.to_string()));
    }
    vault.database_connection.execute(
        "INSERT OR REPLACE INTO metadata (file_sha256sum, meta_key, meta_value) VALUES (?1, ?2, ?3)",
        params![sha256sum, metadata.key, metadata.value],
    )?;
    if !metadata.key.starts_with(META_PREFIX) {
        touch_file_update_time(vault, sha256sum)?;
    }
    Ok(())
}

/// Removes a metadata key-value pair from a file.
pub fn remove_file_metadata(vault: &Vault, sha256sum: &str, key: &str) -> Result<(), UpdateError> {
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(UpdateError::FileNotFound(sha256sum.to_string()));
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

// --- 保险库操作 ---

/// 设置保险库的新名称。
pub fn set_name(vault: &mut Vault, new_name: &str) -> Result<(), UpdateError> {
    vault.config.name = new_name.to_string();
    // [修改] 只保存配置，不触碰元数据
    _save_config(vault)
}

/// 从数据库获取保险库元数据。
pub fn get_vault_metadata(vault: &Vault, key: &str) -> Result<String, UpdateError> {
    vault.database_connection.query_row(
        "SELECT meta_value FROM vault_metadata WHERE meta_key = ?1",
        params![key],
        |row| row.get(0)
    ).map_err(|e| {
        if let rusqlite::Error::QueryReturnedNoRows = e {
            UpdateError::MetadataKeyNotFound(key.to_string())
        } else {
            UpdateError::DatabaseError(e)
        }
    })
}

/// 为保险库设置一个元数据键值对 (upsert 操作)。
pub fn set_vault_metadata(vault: &mut Vault, metadata_entry: MetadataEntry) -> Result<(), UpdateError> {
    // 直接操作数据库
    vault.database_connection.execute(
        "INSERT OR REPLACE INTO vault_metadata (meta_key, meta_value) VALUES (?1, ?2)",
        params![metadata_entry.key, metadata_entry.value],
    )?;
    Ok(())
}

/// 从保险库中移除一个元数据键值对。
pub fn remove_vault_metadata(vault: &mut Vault, key: &str) -> Result<(), UpdateError> {
    // [修改] 直接操作数据库
    let rows_affected = vault.database_connection.execute(
        "DELETE FROM vault_metadata WHERE meta_key = ?1",
        params![key],
    )?;
    if rows_affected == 0 {
        return Err(UpdateError::MetadataKeyNotFound(key.to_string()));
    }
    Ok(())
}

// --- [V2 修改] 私有辅助函数 ---

/// 仅负责将当前的配置状态保存到 `master.json`。
fn _save_config(vault: &Vault) -> Result<(), UpdateError> {
    let config_json = serde_json::to_string(&vault.config)?;
    let config_path = vault.root_path.join("master.json");
    fs::write(config_path, config_json.as_bytes())?;
    Ok(())
}

/// 更新保险库的 `_vavavult_update_time` 元数据。
pub(super) fn touch_vault_update_time(vault: &mut Vault) -> Result<(), UpdateError> {
    let now = now_as_rfc3339_string();
    // [修改] 使用 set_vault_metadata 函数
    set_vault_metadata(vault, MetadataEntry {
        key: META_VAULT_UPDATE_TIME.to_string(),
        value: now,
    })
}

/// 更新文件的 `_vavavult_update_time` 元数据。 (不变)
pub(super) fn touch_file_update_time(vault: &Vault, sha256sum: &str) -> Result<(), UpdateError> {
    let now = now_as_rfc3339_string();
    let metadata_entry = MetadataEntry {
        key: META_FILE_UPDATE_TIME.to_string(),
        value: now,
    };
    set_file_metadata(vault, sha256sum, metadata_entry)
}