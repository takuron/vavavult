use crate::vault::{Vault, query, QueryResult, UpdateError};
use rusqlite::params;
use std::fs as std_fs;

#[derive(Debug, thiserror::Error)]
pub enum RemoveError {
    #[error("Database query error: {0}")]
    QueryError(#[from] query::QueryError),

    #[error("Database delete error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("File system error: {0}")]
    FileSystemError(#[from] std::io::Error),

    #[error("File with SHA256 '{0}' not found.")]
    FileNotFound(String),

    #[error("Failed to update vault timestamp: {0}")]
    TimestampUpdateError(#[from] UpdateError),
}

/// 从保险库中删除一个文件。
///
/// 此操作会：
/// 1. 从数据库中删除文件的记录（以及通过级联删除关联的标签和元数据）。
/// 2. 从文件系统中删除物理文件。
///
/// # Arguments
/// * `vault` - 一个 Vault 实例。
/// * `sha256sum` - 要删除的文件的哈希值。
pub fn remove_file(vault: &Vault, sha256sum: &str) -> Result<(), RemoveError> {
    // 1. 确认文件存在于数据库中
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(RemoveError::FileNotFound(sha256sum.to_string()));
    }

    // 2. 从文件系统中删除物理文件
    let file_path = vault.root_path.join(sha256sum);
    // 如果文件存在，则删除它。如果不存在，我们也可以继续，因为目标是确保它消失。
    if file_path.exists() {
        std_fs::remove_file(file_path)?;
    }

    // 3. 从数据库中删除记录
    // 由于外键设置了 ON DELETE CASCADE，相关的 tags 和 metadata 记录会自动被删除。
    let rows_affected = vault.database_connection.execute(
        "DELETE FROM files WHERE sha256sum = ?1",
        params![sha256sum],
    )?;

    if rows_affected == 0 {
        // 这理论上不应该发生，因为我们一开始就检查了文件是否存在。
        // 但作为一个额外的安全检查，我们还是处理这种情况。
        return Err(RemoveError::FileNotFound(sha256sum.to_string()));
    }

    Ok(())
}