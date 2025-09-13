use std::fs;
use rusqlite::params;
use crate::common::constants::{META_FILE_UPDATE_TIME, META_PREFIX, META_VAULT_UPDATE_TIME};
use crate::common::metadata::MetadataEntry;
use crate::utils::path::normalize_path_name;
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

    #[error("The new name '{0}' is already taken.")]
    DuplicateFileName(String),

    #[error("Failed to write configuration file: {0}")]
    ConfigWriteError(#[from] std::io::Error),

    #[error("Failed to serialize configuration: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// 重命名保险库中的一个文件。
///
/// # Arguments
/// * `vault` - 一个 Vault 实例。
/// * `sha256sum` - 要重命名的文件的哈希值。
/// * `new_name` - 文件的新名称。
pub fn rename_file(vault: &Vault, sha256sum: &str, new_name: &str) -> Result<(), UpdateError> {
    // 1. 规范化新名称
    let normalized_new_name = normalize_path_name(new_name);

    // 2. 检查新名称是否已被占用
    if let QueryResult::Found(entry) = query::check_by_name(vault, &normalized_new_name)? {
        // 如果找到的文件就是我们自己，那么什么都不用做
        return if entry.sha256sum != sha256sum {
            Err(UpdateError::DuplicateFileName(normalized_new_name))
        } else {
            Ok(()) // 名称未改变，操作成功
        }
    }

    // 3. 检查要重命名的文件是否存在
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(UpdateError::FileNotFound(sha256sum.to_string()));
    }

    // 4. 执行更新操作
    let rows_affected = vault.database_connection.execute(
        "UPDATE files SET name = ?1 WHERE sha256sum = ?2",
        params![normalized_new_name, sha256sum],
    )?;

    if rows_affected == 0 {
        // 理论上这不应该发生，因为我们已经用 check_by_hash 确认过文件存在
        return Err(UpdateError::FileNotFound(sha256sum.to_string()));
    }

    touch_file_update_time(vault, sha256sum)?;

    Ok(())
}

/// 为文件添加一个标签。如果标签已存在，则不执行任何操作。
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
/// 此操作在一个事务中执行，以保证原子性和高性能。
pub fn add_tags(vault: &mut Vault, sha256sum: &str, tags: &[&str]) -> Result<(), UpdateError> {
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(UpdateError::FileNotFound(sha256sum.to_string()));
    }

    // 1. 开始一个数据库事务
    // tx 会在作用域结束时自动提交 (commit)。如果中间发生错误，它会自动回滚 (rollback)。
    let tx = vault.database_connection.transaction()?;

    // 2. 在事务内部，准备一次 SQL 语句
    {
        let mut stmt = tx.prepare("INSERT OR IGNORE INTO tags (file_sha256sum, tag) VALUES (?1, ?2)")?;

        // 3. 循环执行插入操作
        for tag in tags {
            // 如果任何一次 execute 失败，? 会立即返回错误，tx 将被丢弃并触发回滚
            stmt.execute(params![sha256sum, tag])?;
        }
    } // stmt 在这里被销毁

    // 4. 提交事务
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

/// Sets a metadata key-value pair for a file (upsert operation).
pub fn set_file_metadata(vault: &Vault, sha256sum: &str, metadata:MetadataEntry) -> Result<(), UpdateError> {
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(UpdateError::FileNotFound(sha256sum.to_string()));
    }

    vault.database_connection.execute(
        "INSERT OR REPLACE INTO metadata (file_sha256sum, meta_key, meta_value) VALUES (?1, ?2, ?3)",
        params![sha256sum, metadata.key, metadata.value],
    )?;

    // --- 只有当被修改的键不是系统保留键时，才更新文件时间戳 ---
    // 这可以防止对系统元数据的直接修改触发更新循环，并保护了系统字段。
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

    // --- 只有当被修改的键不是系统保留键时，才更新文件时间戳 ---
    // 这可以防止对系统元数据的直接修改触发更新循环，并保护了系统字段。
    if !key.starts_with(META_PREFIX) {
        touch_file_update_time(vault, sha256sum)?;
    }

    Ok(())
}

/// 设置保险库的新名称。
pub fn set_name(vault: &mut Vault, new_name: &str) -> Result<(), UpdateError> {
    vault.config.name = new_name.to_string();
    save_config(vault)
}

/// 为保险库设置一个元数据键值对 (upsert 操作)。
pub fn set_vault_metadata(vault: &mut Vault, metadata_entry: MetadataEntry) -> Result<(), UpdateError> {
    // 如果键已存在，则更新它的值
    if let Some(existing) = vault.config.metadata.iter_mut().find(|m| m.key == metadata_entry.key) {
        existing.value = metadata_entry.value;
    } else {
        // 否则，添加新的键值对
        vault.config.metadata.push(metadata_entry);
    }
    save_config(vault)
}

/// 从保险库中移除一个元数据键值对。
pub fn remove_vault_metadata(vault: &mut Vault, key: &str) -> Result<(), UpdateError> {
    vault.config.metadata.retain(|m| m.key != key);
    save_config(vault)
}

// --- 私有辅助函数 ---

/// 仅负责将当前的配置状态保存到 `master.json`。
fn save_config(vault: &Vault) -> Result<(), UpdateError> {
    let config_json = serde_json::to_string(&vault.config)?;
    let config_path = vault.root_path.join("master.json");
    fs::write(config_path, config_json.as_bytes())?;
    Ok(())
}

/// 更新保险库的 `_vavavult_update_time` 元数据并保存。
/// 这是所有修改操作都应调用的核心函数。
pub(super) fn touch_vault_update_time(vault: &mut Vault) -> Result<(), UpdateError> {
    let now = now_as_rfc3339_string();
    if let Some(update_meta) = vault.config.metadata.iter_mut().find(|m| m.key == META_VAULT_UPDATE_TIME) {
        update_meta.value = now;
    } else {
        // 如果 _vavavult_update_time 不存在 (可能来自旧版本)，则添加它
        vault.config.metadata.push(MetadataEntry {
            key: META_VAULT_UPDATE_TIME.to_string(),
            value: now,
        });
    }
    save_config(vault)
}

/// **新增**: 更新文件的 `_vavavult_update_time` 元数据。
/// 这是一个内部函数，它直接调用 set_file_metadata 来完成工作。
pub(super) fn touch_file_update_time(vault: &Vault, sha256sum: &str) -> Result<(), UpdateError> {
    let now = now_as_rfc3339_string();
    let metadata_entry = MetadataEntry {
        key: META_FILE_UPDATE_TIME.to_string(),
        value: now,
    };
    // 直接复用 set_file_metadata 的 "upsert" 逻辑来更新或插入时间戳
    set_file_metadata(vault, sha256sum, metadata_entry)
}