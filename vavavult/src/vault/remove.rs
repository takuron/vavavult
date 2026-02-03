use crate::common::hash::{HashParseError, VaultHash};
use crate::vault::metadata::MetadataError;
use crate::vault::{QueryResult, Vault, query};
use rusqlite::params;

/// Defines errors that can occur during the file removal process.
//
// // 定义在文件删除过程中可能发生的错误。
#[derive(Debug, thiserror::Error)]
pub enum RemoveError {
    /// A database query failed.
    //
    // // 数据库查询失败。
    #[error("Database query error: {0}")]
    QueryError(#[from] query::QueryError),

    /// An error occurred while deleting the file record from the database.
    //
    // // 从数据库删除文件记录时发生错误。
    #[error("Database delete error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    /// An I/O error occurred while deleting the physical file from the `data/` directory.
    //
    // // 从 `data/` 目录删除物理文件时发生 I/O 错误。
    #[error("File system error: {0}")]
    FileSystemError(#[from] std::io::Error),

    /// The file to be removed was not found in the database.
    //
    // // 在数据库中未找到要删除的文件。
    #[error("File with SHA256 '{0}' not found.")]
    FileNotFound(String),

    /// Failed to update the vault's last-modified timestamp.
    //
    // // 更新保险库的最后修改时间戳失败。
    #[error("Failed to update vault timestamp: {0}")]
    TimestampUpdateError(#[from] MetadataError),

    /// The hash string provided was in an invalid format.
    //
    // // 提供的哈希字符串格式无效。
    #[error("Wrong hash error: {0}")]
    HashParseError(#[from] HashParseError),
}

/// Defines errors that can occur during the forced file removal process.
//
// // 定义在强制文件删除过程中可能发生的错误。
#[derive(Debug, thiserror::Error)]
pub enum ForceRemoveError {
    /// An error occurred while deleting the file record from the database.
    //
    // // 从数据库删除文件记录时发生错误。
    #[error("Database delete error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    /// An I/O error occurred while trying to delete the physical file.
    /// Note: A "Not Found" error is ignored, but other I/O errors are reported.
    //
    // // 尝试删除物理文件时发生 I/O 错误。
    // // 注意：“未找到”错误会被忽略，但其他 I/O 错误会被报告。
    #[error("File system error: {0}")]
    FileSystemError(std::io::Error),

    /// Failed to update the vault's last-modified timestamp.
    //
    // // 更新保险库的最后修改时间戳失败。
    #[error("Failed to update vault timestamp: {0}")]
    TimestampUpdateError(#[from] MetadataError),

    /// The hash string provided was in an invalid format.
    //
    // // 提供的哈希字符串格式无效。
    #[error("Wrong hash error: {0}")]
    HashParseError(#[from] HashParseError),
}

/// 从保险库中删除一个文件。
///
/// 此操作会：
/// 1. 从数据库中删除文件的记录 (级联删除标签和元数据)。
/// 2. 从文件系统 (`data/` 子目录) 中删除物理文件。
///
/// # Arguments
/// * `vault` - 一个 Vault 实例。
/// * `sha256sum` - 要删除的文件的加密后内容的 Base64 哈希。
pub(crate) fn remove_file(vault: &Vault, sha256sum: &VaultHash) -> Result<(), RemoveError> {
    // 1. 确认文件存在于数据库中
    if let QueryResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(RemoveError::FileNotFound(sha256sum.to_string()));
    }

    // 2. 从存储后端删除物理文件
    // 后端实现通常是幂等的（如果文件不存在则不报错），但我们已经检查了数据库存在
    vault.storage.delete(sha256sum)?;

    // 3. 从数据库中删除记录 (SQL 语句不变，外键级联删除)
    let rows_affected = vault
        .database_connection
        .execute("DELETE FROM files WHERE sha256sum = ?1", params![sha256sum])?;

    if rows_affected == 0 {
        // 理论上不应该发生，因为我们先检查了文件是否存在
        return Err(RemoveError::FileNotFound(sha256sum.to_string()));
    }

    Ok(())
}

/// 强制从保险库中删除一个文件记录。
///
/// 此操作会：
/// 1. 尝试从文件系统 (`data/` 子目录) 中删除物理文件。如果文件不存在，操作将被忽略。
/// 2. 从数据库中强制删除文件的记录 (级联删除标签和元数据)。如果记录不存在，操作将被忽略。
///
/// # Arguments
/// * `vault` - 一个 Vault 实例。
/// * `sha256sum` - 要删除的文件的加密后内容的 Base64 哈希。
pub(crate) fn force_remove_file(
    vault: &Vault,
    sha256sum: &VaultHash,
) -> Result<(), ForceRemoveError> {
    // 1. 尝试从存储后端删除物理文件。
    // 我们明确处理 NotFound 错误，因为即使 StorageBackend::delete 尝试幂等，
    // 在 `exists()` 和 `remove_file()` 之间可能存在竞态条件导致返回 NotFound 错误。
    if let Err(e) = vault.storage.delete(sha256sum) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(ForceRemoveError::FileSystemError(e));
        }
        // 如果是 NotFound，则忽略错误并继续
    }

    // 2. 从数据库中强制删除记录。
    // 我们不关心文件是否真的在数据库中，只要确保操作后它不存在即可。
    // 因此，我们不检查 `rows_affected` 或文件是否先前存在。
    vault
        .database_connection
        .execute("DELETE FROM files WHERE sha256sum = ?1", params![sha256sum])?;

    Ok(())
}
