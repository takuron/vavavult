use rusqlite::params;
use crate::common::hash::VaultHash;
use crate::vault::{query, QueryResult, Vault};
use crate::vault::metadata::{touch_file_update_time, MetadataError};

/// Defines errors that can occur during tag operations.
//
// // 定义在标签操作期间可能发生的错误。
#[derive(Debug, thiserror::Error)]
pub enum TagError {
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

    /// The file specified for tagging was not found.
    //
    // // 未找到指定要标记的文件。
    #[error("File with SHA256 '{0}' not found.")]
    FileNotFound(String),

    /// Failed to update the file's modification timestamp.
    //
    // // 更新文件的修改时间戳失败。
    #[error("Failed to update timestamp: {0}")]
    TimestampError(#[from] MetadataError),
}

/// Adds a single tag to a file.
pub(crate) fn add_tag(vault: &Vault, sha256sum: &VaultHash, tag: &str) -> Result<(), TagError> {
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(TagError::FileNotFound(sha256sum.to_string()));
    }
    vault.database_connection.execute(
        "INSERT OR IGNORE INTO tags (file_sha256sum, tag) VALUES (?1, ?2)",
        params![sha256sum, tag],
    )?;

    touch_file_update_time(vault, sha256sum)?;
    Ok(())
}

/// Adds multiple tags to a file in a transaction.
pub(crate) fn add_tags(vault: &mut Vault, sha256sum: &VaultHash, tags: &[&str]) -> Result<(), TagError> {
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(TagError::FileNotFound(sha256sum.to_string()));
    }
    let tx = vault.database_connection.transaction()?;
    {
        let mut stmt = tx.prepare("INSERT OR IGNORE INTO tags (file_sha256sum, tag) VALUES (?1, ?2)")?;
        for tag in tags {
            stmt.execute(params![sha256sum, tag])?;
        }
    }
    tx.commit()?;

    touch_file_update_time(vault, sha256sum)?;
    Ok(())
}

/// Removes a single tag from a file.
pub(crate) fn remove_tag(vault: &Vault, sha256sum: &VaultHash, tag: &str) -> Result<(), TagError> {
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(TagError::FileNotFound(sha256sum.to_string()));
    }
    vault.database_connection.execute(
        "DELETE FROM tags WHERE file_sha256sum = ?1 AND tag = ?2",
        params![sha256sum, tag],
    )?;

    touch_file_update_time(vault, sha256sum)?;
    Ok(())
}

/// Removes all tags from a file.
pub(crate) fn clear_tags(vault: &Vault, sha256sum: &VaultHash) -> Result<(), TagError> {
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(TagError::FileNotFound(sha256sum.to_string()));
    }
    vault.database_connection.execute(
        "DELETE FROM tags WHERE file_sha256sum = ?1",
        params![sha256sum],
    )?;

    touch_file_update_time(vault, sha256sum)?;
    Ok(())
}