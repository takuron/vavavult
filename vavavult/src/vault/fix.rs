//! This module implements the logic for legitimately fixing a lost file.
//
// // 该模块实现了合法地修复一个已丢失文件的逻辑。

use crate::common::constants::{
    META_FILE_ADD_TIME, META_FILE_SIZE, META_FILE_UPDATE_TIME, META_SOURCE_MODIFIED_TIME,
};
use rusqlite::params;
use std::collections::HashSet;
use std::path::Path;
use thiserror::Error;

use crate::common::hash::VaultHash;
use crate::file::VaultPath;
use crate::vault::Vault;
use crate::vault::add::{AddFileError, prepare_addition_task_standalone};
use crate::vault::metadata::MetadataError;
use crate::vault::query::{QueryError, QueryResult};
use crate::vault::remove::ForceRemoveError;
use crate::vault::tags::TagError;

/// Defines errors that can occur during the file fixing process.
//
// // 定义在文件修复过程中可能发生的错误。
#[derive(Debug, Error)]
pub enum FixError {
    /// The file metadata was not found at the specified vault path.
    //
    // // 在指定的保险库路径未找到文件元数据。
    #[error(
        "File metadata not found at path: {0}. This operation is only for fixing existing entries with lost data."
    )]
    NotFound(String),

    /// The operation was attempted on a directory path, but a file path was required.
    //
    // // 尝试在目录路径上执行操作，但需要的是文件路径。
    #[error("The provided vault path is a directory, not a file: {0}")]
    PathIsDirectory(String),

    /// The original hash of the provided file does not match the one stored in the vault.
    //
    // // 提供的文件的原始哈希与保险库中存储的哈希不匹配。
    #[error(
        "Original hash mismatch. The provided file's content does not match the original version stored in the vault."
    )]
    HashMismatch,

    /// A database query failed.
    //
    // // 数据库查询失败。
    #[error("Error querying vault: {0}")]
    Query(#[from] QueryError),

    /// An error occurred during a direct database operation.
    //
    // // 在直接的数据库操作期间发生错误。
    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    /// An error occurred while preparing the new file for addition (e.g., encryption failed).
    //
    // // 准备要添加的新文件时发生错误（例如加密失败）。
    #[error("Error preparing new file: {0}")]
    Add(#[from] AddFileError),

    /// An I/O error occurred while interacting with the storage backend.
    //
    // // 与存储后端交互时发生 I/O 错误。
    #[error("Error during storage operation: {0}")]
    StorageError(#[from] std::io::Error),

    /// An error occurred while trying to remove the old file entry.
    //
    // // 尝试移除旧文件条目时发生错误。
    #[error("Error removing old file entry: {0}")]
    Remove(#[from] ForceRemoveError),

    /// An error occurred while re-applying tags to the new file.
    //
    // // 将标签重新应用到新文件时发生错误。
    #[error("Error applying tags to new file: {0}")]
    Tag(#[from] TagError),

    /// Failed to update the vault's last-modified timestamp.
    //
    // // 更新保险库的最后修改时间戳失败。
    #[error("Failed to update vault timestamp: {0}")]
    Metadata(#[from] MetadataError),
}
pub(crate) fn fix_file(
    vault: &mut Vault,
    source_path: &Path,
    vault_path: &VaultPath,
) -> Result<VaultHash, FixError> {
    // 1. 确保目标路径不是一个目录
    if vault_path.is_dir() {
        return Err(FixError::PathIsDirectory(vault_path.as_str().to_string()));
    }

    // 2. 查找现有的文件元数据记录，但不检查物理文件是否存在
    let old_entry = match crate::vault::query::check_by_path_no_validation(vault, vault_path)? {
        QueryResult::Found(entry) => entry,
        QueryResult::NotFound => return Err(FixError::NotFound(vault_path.as_str().to_string())),
    };

    // 3. 对新文件流式加密暂存
    let addition_task =
        prepare_addition_task_standalone(vault.storage.as_ref(), source_path, vault_path)?;

    // 4. 校验替换是否合法
    if addition_task.file_entry.original_sha256sum != old_entry.original_sha256sum {
        return Err(FixError::HashMismatch);
    }

    // 5. 保存旧文件的tag和metadata
    let old_tags = old_entry.tags;
    let old_add_time = old_entry
        .metadata
        .iter()
        .find(|m| m.key == META_FILE_ADD_TIME)
        .map(|m| m.value.clone());

    let auto_generated_meta_keys: HashSet<&str> = [
        META_FILE_ADD_TIME,
        META_FILE_UPDATE_TIME,
        META_FILE_SIZE,
        META_SOURCE_MODIFIED_TIME,
    ]
    .iter()
    .cloned()
    .collect();
    let custom_metadata_to_preserve: Vec<_> = old_entry
        .metadata
        .into_iter()
        .filter(|meta| !auto_generated_meta_keys.contains(meta.key.as_str()))
        .collect();

    let new_entry = addition_task.file_entry;
    let new_hash = new_entry.sha256sum.clone();

    // 6. 用sql构建一个事务来删除旧的记录和添加新的记录
    let tx = vault.database_connection.transaction()?;

    {
        // -- BEGIN TRANSACTION SCOPE --

        // 6a. 删除旧的文件记录 (外键的 ON DELETE CASCADE 会自动删除关联的 tags 和 metadata)
        tx.execute(
            "DELETE FROM files WHERE sha256sum = ?1",
            params![&old_entry.sha256sum],
        )?;

        // 6b. 插入新的文件记录
        tx.execute(
            "INSERT INTO files (sha256sum, path, original_sha256sum, encrypt_password) VALUES (?1, ?2, ?3, ?4)",
            params![
                &new_entry.sha256sum,
                &new_entry.path,
                &new_entry.original_sha256sum,
                &new_entry.encrypt_password,
            ],
        )?;

        // 6c. 重新添加tag和metadata
        let mut meta_stmt = tx.prepare(
            "INSERT OR REPLACE INTO metadata (file_sha256sum, meta_key, meta_value) VALUES (?1, ?2, ?3)",
        )?;
        for meta in &new_entry.metadata {
            meta_stmt.execute(params![&new_entry.sha256sum, &meta.key, &meta.value])?;
        }
        for meta in &custom_metadata_to_preserve {
            meta_stmt.execute(params![&new_entry.sha256sum, &meta.key, &meta.value])?;
        }

        // 6d. 保留原始的添加时间
        if let Some(add_time) = old_add_time {
            meta_stmt.execute(params![&new_entry.sha256sum, META_FILE_ADD_TIME, add_time])?;
        }

        // 6e. 更新文件的修改时间为当前时间
        let now = crate::utils::time::now_as_rfc3339_string();
        meta_stmt.execute(params![&new_entry.sha256sum, META_FILE_UPDATE_TIME, now])?;

        let mut tag_stmt = tx.prepare("INSERT INTO tags (file_sha256sum, tag) VALUES (?1, ?2)")?;
        for tag in &old_tags {
            tag_stmt.execute(params![&new_entry.sha256sum, tag])?;
        }

        // 7. 安全删除旧文件（如有）
        if let Err(e) = vault.storage.delete(&old_entry.sha256sum) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(FixError::StorageError(e));
            }
        }

        // 8. 提交新的物理文件到存储, 必须在DB commit之前
        vault
            .storage
            .commit_write(addition_task.staging_token, &new_hash)?;
    } // -- END TRANSACTION SCOPE --

    // 9. 提交数据库事务
    tx.commit()?;

    Ok(new_hash)
}
