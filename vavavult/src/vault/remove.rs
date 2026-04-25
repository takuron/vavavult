use crate::common::hash::{HashParseError, VaultHash};
use crate::vault::metadata::MetadataError;
use crate::vault::{QueryFileResult, Vault, query};
use rusqlite::params;

fn delete_storage_if_present(vault: &Vault, sha256sum: &VaultHash) -> Result<(), std::io::Error> {
    if let Err(error) = vault.storage.delete(sha256sum) {
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(error);
        }
    }

    Ok(())
}

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

/// 从保险库中删除一个文件实体及其全部路径映射。
///
/// 此操作会删除该哈希对应的所有路径映射，然后删除文件实体和物理存储。
pub(crate) fn remove_file(vault: &Vault, sha256sum: &VaultHash) -> Result<(), RemoveError> {
    // 1. 确认文件存在于数据库中
    if let QueryFileResult::NotFound = query::check_by_hash(vault, sha256sum)? {
        return Err(RemoveError::FileNotFound(sha256sum.to_string()));
    }

    // 2. 删除该文件实体的全部路径映射。
    if query::remove_file_entries_by_hash_in_conn(&vault.database_connection, sha256sum)? == 0 {
        return Err(RemoveError::FileNotFound(sha256sum.to_string()));
    }

    // 3. 删除文件实体和物理存储。底层文件缺失不阻断数据库清理。
    delete_storage_if_present(vault, sha256sum)?;
    vault
        .database_connection
        .execute("DELETE FROM files WHERE sha256sum = ?1", params![sha256sum])?;

    Ok(())
}

/// 从保险库中删除指定路径上的文件映射。
pub(crate) fn remove_file_by_path(
    vault: &Vault,
    path: &crate::file::VaultPath,
) -> Result<(), RemoveError> {
    // 1. 查找并删除路径映射。
    let Some(sha256sum) =
        query::remove_file_entry_by_path_in_conn(&vault.database_connection, path)?
    else {
        return Err(RemoveError::FileNotFound(path.as_str().to_string()));
    };

    // 2. 仍有引用时保留实体。
    if query::file_entry_ref_count_in_conn(&vault.database_connection, &sha256sum)? > 0 {
        return Ok(());
    }

    // 3. 最后一条引用已解除，删除物理文件与 files 记录。底层文件缺失不阻断数据库清理。
    delete_storage_if_present(vault, &sha256sum)?;
    vault.database_connection.execute(
        "DELETE FROM files WHERE sha256sum = ?1",
        params![&sha256sum],
    )?;

    Ok(())
}
