use std::fs;
use rusqlite::params;
use crate::common::constants::{META_FILE_UPDATE_TIME, META_PREFIX, META_VAULT_UPDATE_TIME};
use crate::common::hash::{HashParseError, VaultHash};
use crate::common::metadata::MetadataEntry;
use crate::file::{PathError, VaultPath};
use crate::utils::time::now_as_rfc3339_string;
use crate::vault::{query, QueryResult, Vault};

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("Database query error: {0}")]
    QueryError(#[from] query::QueryError),

    #[error("Database update error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("VaultPath error: {0}")]
    VaultPathError(#[from] PathError),

    #[error("File with SHA256 '{0}' not found.")]
    FileNotFound(String),

    #[error("Target path '{0}' is already taken.")]
    DuplicateTargetPath(String),

    #[error("Target path '{0}' is invalid: must be a file path, not a directory path.")]
    InvalidTargetFilePath(String),

    #[error("Invalid new filename '{0}': contains path separators.")]
    InvalidFilename(String),

    #[error("Failed to write configuration file: {0}")]
    ConfigWriteError(#[from] std::io::Error),

    #[error("Failed to serialize configuration: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Metadata key '{0}' not found.")]
    MetadataKeyNotFound(String),

    #[error("Wrong hash error: {0}")]
    HashPauseError(#[from] HashParseError),
}

/// 移动保险库中的文件到新的路径。
///
/// - 如果 `target_path` 是目录 (e.g., `/new/dir/`), 文件会被移动到该目录下，保持原文件名。
/// - 如果 `target_path` 是文件 (e.g., `/new/dir/new_name.txt`), 文件会被移动并重命名。
pub fn move_file(
    vault: &Vault,
    hash: &VaultHash,
    target_path: &VaultPath
) -> Result<(), UpdateError> {
    // 1. 查找原始文件信息
    let original_entry = match query::check_by_hash(vault, hash)? {
        QueryResult::Found(entry) => entry,
        QueryResult::NotFound => return Err(UpdateError::FileNotFound(hash.to_string())),
    };
    let original_vault_path = original_entry.path.clone();

    // 2. 解析最终的目标路径
    let final_path = if target_path.is_dir() {
        // 目标是目录，保留原文件名
        let original_filename = original_vault_path.file_name()
            .ok_or_else(|| UpdateError::VaultPathError(PathError::JoinToFile))?; // 理论上不会发生，因为库中存的总是文件路径
        target_path.join(original_filename)?
    } else {
        // 目标是文件，直接使用
        target_path.clone()
    };

    // 3. 检查目标路径是否已被占用 (排除自身)
    if let QueryResult::Found(existing) = query::check_by_path(vault, &final_path)? {
        return if existing.sha256sum != *hash {
            Err(UpdateError::DuplicateTargetPath(final_path.as_str().to_string()))
        } else {
            // 目标路径就是当前路径，无需操作
            Ok(())
        }
    }

    // 4. 执行更新
    let rows_affected = vault.database_connection.execute(
        "UPDATE files SET path = ?1 WHERE sha256sum = ?2",
        params![final_path.as_str(), hash],
    )?;

    if rows_affected == 0 {
        // 理论上不应该发生，因为我们已经确认文件存在
        return Err(UpdateError::FileNotFound(hash.to_string()));
    }

    touch_file_update_time(vault, hash)?;
    Ok(())
}

/// 在当前目录下重命名文件。
///
/// 只改变文件的名称部分，保持其父目录不变。
pub fn rename_file_inplace(
    vault: &Vault,
    hash: &VaultHash,
    new_filename: &str
) -> Result<(), UpdateError> {
    // 1. 验证新文件名不包含路径分隔符
    if new_filename.contains('/') || new_filename.contains('\\') {
        return Err(UpdateError::InvalidFilename(new_filename.to_string()));
    }

    // 2. 查找原始文件信息
    let original_entry = match query::check_by_hash(vault, hash)? {
        QueryResult::Found(entry) => entry,
        QueryResult::NotFound => return Err(UpdateError::FileNotFound(hash.to_string())),
    };
    let original_vault_path = original_entry.path.clone();

    // 3. 获取父目录
    let parent_dir = original_vault_path.parent()?; // parent() 返回 Result

    // 4. 构建新的文件路径
    let final_path = parent_dir.join(new_filename)?;

    // 5. 检查目标路径是否已被占用 (排除自身)
    if let QueryResult::Found(existing) = query::check_by_path(vault, &final_path)? {
        if existing.sha256sum != *hash {
            return Err(UpdateError::DuplicateTargetPath(final_path.as_str().to_string()));
        } else {
            // 目标路径就是当前路径，无需操作
            return Ok(());
        }
    }

    // 6. 执行更新
    let rows_affected = vault.database_connection.execute(
        "UPDATE files SET path = ?1 WHERE sha256sum = ?2",
        params![final_path.as_str(), hash],
    )?;

    if rows_affected == 0 {
        // 理论上不应该发生
        return Err(UpdateError::FileNotFound(hash.to_string()));
    }

    touch_file_update_time(vault, hash)?;
    Ok(())
}

// [废弃] 重命名保险库中的一个文件 (更新其路径)。
// #[deprecated(since="0.3.0", note="Use `move_file` or `rename_file_inplace` instead")]
// pub fn rename_file(vault: &Vault, sha256sum: &VaultHash, new_path: &VaultPath) -> Result<(), UpdateError> {
//     // 保留旧实现，但标记为废弃
//     if !new_path.is_file() {
//         return Err(UpdateError::InvalidTargetFilePath(new_path.as_str().to_string()));
//     }
//     let normalized_new_path = new_path.as_str();
//     if let QueryResult::Found(entry) = query::check_by_path(vault, new_path)? {
//         return if &entry.sha256sum != sha256sum {
//             Err(UpdateError::DuplicateTargetPath(normalized_new_path.to_string()))
//         } else {
//             Ok(())
//         }
//     }
//     if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
//         return Err(UpdateError::FileNotFound(sha256sum.to_string()));
//     }
//     let rows_affected = vault.database_connection.execute(
//         "UPDATE files SET path = ?1 WHERE sha256sum = ?2",
//         params![normalized_new_path, sha256sum],
//     )?;
//     if rows_affected == 0 {
//         return Err(UpdateError::FileNotFound(sha256sum.to_string()));
//     }
//     touch_file_update_time(vault, sha256sum)?;
//     Ok(())
// }


// --- 文件标签操作 (不变) ---

/// 为文件添加一个标签。
pub fn add_tag(vault: &Vault, sha256sum: &VaultHash, tag: &str) -> Result<(), UpdateError> {
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
pub fn add_tags(vault: &mut Vault, sha256sum: &VaultHash, tags: &[&str]) -> Result<(), UpdateError> {
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
pub fn remove_tag(vault: &Vault, sha256sum: &VaultHash, tag: &str) -> Result<(), UpdateError> {
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
pub fn clear_tags(vault: &Vault, sha256sum: &VaultHash) -> Result<(), UpdateError> {
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
pub fn set_file_metadata(vault: &Vault, sha256sum: &VaultHash, metadata:MetadataEntry) -> Result<(), UpdateError> {
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
pub fn remove_file_metadata(vault: &Vault, sha256sum: &VaultHash, key: &str) -> Result<(), UpdateError> {
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
pub(super) fn touch_file_update_time(vault: &Vault, sha256sum: &VaultHash) -> Result<(), UpdateError> {
    let now = now_as_rfc3339_string();
    let metadata_entry = MetadataEntry {
        key: META_FILE_UPDATE_TIME.to_string(),
        value: now,
    };
    set_file_metadata(vault, sha256sum, metadata_entry)
}