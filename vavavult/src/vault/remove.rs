use crate::common::constants::DATA_SUBDIR;
use crate::vault::{Vault, query, QueryResult, UpdateError};
use rusqlite::params;
use std::fs as std_fs;
use crate::common::hash::{HashParseError, VaultHash};

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

    #[error("Wrong hash error: {0}")]
    HashPauseError(#[from] HashParseError),
}

/// [V2 修改] 从保险库中删除一个文件。
///
/// 此操作会：
/// 1. 从数据库中删除文件的记录 (级联删除标签和元数据)。
/// 2. 从文件系统 (`data/` 子目录) 中删除物理文件。
///
/// # Arguments
/// * `vault` - 一个 Vault 实例。
/// * `sha256sum` - 要删除的文件的加密后内容的 Base64 哈希。
pub fn remove_file(vault: &Vault, sha256sum: &VaultHash) -> Result<(), RemoveError> {
    // 1. 确认文件存在于数据库中 (query::check_by_hash 已更新为 V2)
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(RemoveError::FileNotFound(sha256sum.to_string()));
    }

    // 2. [V2 修改] 从文件系统中删除物理文件 (在 data/ 子目录下)
    let file_path = vault.root_path.join(DATA_SUBDIR).join(sha256sum.to_string());
    if file_path.exists() {
        std_fs::remove_file(file_path)?;
    } // 如果文件不存在，也继续，目标是确保数据库记录被删除

    // 3. 从数据库中删除记录 (SQL 语句不变，外键级联删除)
    let rows_affected = vault.database_connection.execute(
        "DELETE FROM files WHERE sha256sum = ?1",
        params![sha256sum],
    )?;

    if rows_affected == 0 {
        // 理论上不应该发生，因为我们先检查了文件是否存在
        return Err(RemoveError::FileNotFound(sha256sum.to_string()));
    }

    Ok(())
}