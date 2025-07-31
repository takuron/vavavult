use rusqlite::params;
use crate::common::metadata::MetadataEntry;
use crate::vault::{query, QueryResult, Vault};
use crate::vault::common::normalize_path_name;

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

    Ok(())
}

/// 为文件批量添加多个标签。
pub fn add_tags(vault: &mut Vault, sha256sum: &str, tags: &[&str]) -> Result<(), UpdateError> {
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(UpdateError::FileNotFound(sha256sum.to_string()));
    }

    let tx = vault.database_connection.transaction()?;
    for tag in tags {
        tx.execute(
            "INSERT OR IGNORE INTO tags (file_sha256sum, tag) VALUES (?1, ?2)",
            params![sha256sum, tag],
        )?;
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

    Ok(())
}

/// Sets a metadata key-value pair for a file (upsert operation).
pub fn set_metadata(vault: &Vault, sha256sum: &str, metadata:MetadataEntry) -> Result<(), UpdateError> {
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(UpdateError::FileNotFound(sha256sum.to_string()));
    }

    vault.database_connection.execute(
        "INSERT OR REPLACE INTO metadata (file_sha256sum, meta_key, meta_value) VALUES (?1, ?2, ?3)",
        params![sha256sum, metadata.key, metadata.value],
    )?;

    Ok(())
}

/// Removes a metadata key-value pair from a file.
pub fn remove_metadata(vault: &Vault, sha256sum: &str, key: &str) -> Result<(), UpdateError> {
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(UpdateError::FileNotFound(sha256sum.to_string()));
    }

    vault.database_connection.execute(
        "DELETE FROM metadata WHERE file_sha256sum = ?1 AND meta_key = ?2",
        params![sha256sum, key],
    )?;

    Ok(())
}