use crate::file::VaultPath;
use crate::vault::metadata::{touch_file_update_time, MetadataError};
use crate::vault::{query, Vault};
use rusqlite::params;

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
    #[error("File at path '{0}' not found.")]
    FileNotFound(String),

    /// Failed to update the file's modification timestamp.
    //
    // // 更新文件的修改时间戳失败。
    #[error("Failed to update timestamp: {0}")]
    TimestampError(#[from] MetadataError),
}

fn resolve_file_entry(
    vault: &Vault,
    path: &VaultPath,
) -> Result<(i64, crate::common::hash::VaultHash), TagError> {
    query::resolve_file_entry(vault, path)?.ok_or_else(|| TagError::FileNotFound(path.to_string()))
}

/// Adds a single tag to a file path.
pub(crate) fn add_tag(vault: &Vault, path: &VaultPath, tag: &str) -> Result<(), TagError> {
    let (file_entry_id, sha256sum) = resolve_file_entry(vault, path)?;
    vault.database_connection.execute(
        "INSERT OR IGNORE INTO tags (file_entry_id, tag) VALUES (?1, ?2)",
        params![file_entry_id, tag],
    )?;

    touch_file_update_time(vault, &sha256sum)?;
    Ok(())
}

/// Adds multiple tags to a file path in a transaction.
pub(crate) fn add_tags(vault: &mut Vault, path: &VaultPath, tags: &[&str]) -> Result<(), TagError> {
    let (file_entry_id, sha256sum) = resolve_file_entry(vault, path)?;
    let tx = vault.database_connection.transaction()?;
    {
        let mut stmt =
            tx.prepare("INSERT OR IGNORE INTO tags (file_entry_id, tag) VALUES (?1, ?2)")?;
        for tag in tags {
            stmt.execute(params![file_entry_id, tag])?;
        }
    }
    tx.commit()?;

    touch_file_update_time(vault, &sha256sum)?;
    Ok(())
}

/// Removes a single tag from a file path.
pub(crate) fn remove_tag(vault: &Vault, path: &VaultPath, tag: &str) -> Result<(), TagError> {
    let (file_entry_id, sha256sum) = resolve_file_entry(vault, path)?;
    vault.database_connection.execute(
        "DELETE FROM tags WHERE file_entry_id = ?1 AND tag = ?2",
        params![file_entry_id, tag],
    )?;

    touch_file_update_time(vault, &sha256sum)?;
    Ok(())
}

/// Removes all tags from a file path.
pub(crate) fn clear_tags(vault: &Vault, path: &VaultPath) -> Result<(), TagError> {
    let (file_entry_id, sha256sum) = resolve_file_entry(vault, path)?;
    vault.database_connection.execute(
        "DELETE FROM tags WHERE file_entry_id = ?1",
        params![file_entry_id],
    )?;

    touch_file_update_time(vault, &sha256sum)?;
    Ok(())
}
