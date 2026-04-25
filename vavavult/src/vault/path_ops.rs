use crate::common::hash::VaultHash;
use crate::file::{PathError, VaultPath};
use crate::vault::metadata;
use crate::vault::{Vault, query};
use rusqlite::params;

/// Defines errors that can occur during path creation and copy operations.
//
// // 定义路径创建和复制操作期间可能发生的错误。
#[derive(Debug, thiserror::Error)]
pub enum PathOperationError {
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

    /// An error occurred during `VaultPath` construction.
    //
    // // `VaultPath` 构建期间发生错误。
    #[error("VaultPath error: {0}")]
    VaultPathError(#[from] PathError),

    /// The source file path was not found.
    //
    // // 未找到源文件路径。
    #[error("Source file path not found: {0}")]
    SourcePathNotFound(String),

    /// The requested file hash was not found.
    //
    // // 未找到请求的文件哈希。
    #[error("File hash not found: {0}")]
    HashNotFound(String),

    /// The target path is already occupied by a file or directory.
    //
    // // 目标路径已被文件或目录占用。
    #[error("Target path already exists: {0}")]
    TargetPathExists(String),

    /// A file-only operation received a directory path.
    //
    // // 仅限文件的操作收到了目录路径。
    #[error("Expected a file path: {0}")]
    ExpectedFilePath(String),

    /// A directory-only operation received a file path.
    //
    // // 仅限目录的操作收到了文件路径。
    #[error("Expected a directory path: {0}")]
    ExpectedDirectoryPath(String),

    /// Failed to update vault or file timestamps.
    //
    // // 更新保险库或文件时间戳失败。
    #[error("Failed to update timestamp: {0}")]
    MetadataError(#[from] metadata::MetadataError),
}

fn ensure_file_target_available(
    vault: &Vault,
    target_path: &VaultPath,
) -> Result<(), PathOperationError> {
    if !target_path.is_file() {
        return Err(PathOperationError::ExpectedFilePath(
            target_path.as_str().to_string(),
        ));
    }
    ensure_no_file_ancestor(vault, &target_path.parent()?)?;

    // 1. 文件路径不能覆盖已有文件映射。
    if query::resolve_file_entry(vault, target_path)?.is_some() {
        return Err(PathOperationError::TargetPathExists(
            target_path.as_str().to_string(),
        ));
    }

    // 2. 文件路径不能与已有目录节点冲突。
    let directory_form = VaultPath::new(format!("{}/", target_path.as_str()));
    if query::resolve_directory(vault, &directory_form)?.is_some() {
        return Err(PathOperationError::TargetPathExists(
            target_path.as_str().to_string(),
        ));
    }

    Ok(())
}

fn ensure_no_file_ancestor(
    vault: &Vault,
    directory_path: &VaultPath,
) -> Result<(), PathOperationError> {
    let mut current = String::new();
    for component in directory_path
        .as_str()
        .trim_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
    {
        current.push('/');
        current.push_str(component);
        let file_path = VaultPath::new(&current);
        if query::resolve_file_entry(vault, &file_path)?.is_some() {
            return Err(PathOperationError::TargetPathExists(current));
        }
    }

    Ok(())
}

fn directory_as_file_path(path: &VaultPath) -> Option<VaultPath> {
    if path.is_root() {
        None
    } else {
        Some(VaultPath::new(path.as_str().trim_end_matches('/')))
    }
}

fn copy_tags_between_file_entries(
    vault: &Vault,
    source_entry_id: i64,
    target_entry_id: i64,
) -> Result<(), PathOperationError> {
    let mut stmt = vault
        .database_connection
        .prepare("SELECT tag FROM tags WHERE file_entry_id = ?1 ORDER BY tag")?;
    let tags = stmt
        .query_map(params![source_entry_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;

    // 复制路径局部标签，使新路径与源路径的显示元数据一致。
    let mut insert_stmt = vault
        .database_connection
        .prepare("INSERT OR IGNORE INTO tags (file_entry_id, tag) VALUES (?1, ?2)")?;
    for tag in tags {
        insert_stmt.execute(params![target_entry_id, tag])?;
    }

    Ok(())
}

/// Creates a new file path that points to an existing file hash.
pub(crate) fn create_path_from_hash(
    vault: &Vault,
    hash: &VaultHash,
    target_path: &VaultPath,
) -> Result<(), PathOperationError> {
    ensure_file_target_available(vault, target_path)?;

    if query::check_by_hash_no_validation(vault, hash)?.is_not_found() {
        return Err(PathOperationError::HashNotFound(hash.to_string()));
    }

    // 插入新的 file_entries 映射，共享同一个加密文件实体。
    query::insert_file_entry_in_conn(&vault.database_connection, target_path, hash)?;
    metadata::touch_file_update_time(vault, hash)?;
    Ok(())
}

/// Copies one file path to another path, preserving path-local tags.
pub(crate) fn copy_file_path(
    vault: &Vault,
    source_path: &VaultPath,
    target_path: &VaultPath,
) -> Result<(), PathOperationError> {
    if !source_path.is_file() {
        return Err(PathOperationError::ExpectedFilePath(
            source_path.as_str().to_string(),
        ));
    }
    ensure_file_target_available(vault, target_path)?;

    let (source_entry_id, hash) = query::resolve_file_entry(vault, source_path)?
        .ok_or_else(|| PathOperationError::SourcePathNotFound(source_path.as_str().to_string()))?;

    // 先创建共享同一文件实体的新路径，再复制源路径的标签。
    query::insert_file_entry_in_conn(&vault.database_connection, target_path, &hash)?;
    let (target_entry_id, _) = query::resolve_file_entry(vault, target_path)?
        .ok_or_else(|| PathOperationError::SourcePathNotFound(target_path.as_str().to_string()))?;
    copy_tags_between_file_entries(vault, source_entry_id, target_entry_id)?;
    metadata::touch_file_update_time(vault, &hash)?;
    Ok(())
}

/// Creates an empty directory path in the vault tree.
pub(crate) fn create_empty_path(vault: &Vault, path: &VaultPath) -> Result<(), PathOperationError> {
    if !path.is_dir() {
        return Err(PathOperationError::ExpectedDirectoryPath(
            path.as_str().to_string(),
        ));
    }
    ensure_no_file_ancestor(vault, path)?;

    if query::resolve_directory(vault, path)?.is_some() {
        return Err(PathOperationError::TargetPathExists(
            path.as_str().to_string(),
        ));
    }
    if let Some(file_form) = directory_as_file_path(path) {
        if query::resolve_file_entry(vault, &file_form)?.is_some() {
            return Err(PathOperationError::TargetPathExists(
                path.as_str().to_string(),
            ));
        }
    }

    // 创建缺失的父级目录和最终的空目录节点。
    query::ensure_directory_in_conn(&vault.database_connection, path)?;
    Ok(())
}

trait QueryFileResultExt {
    fn is_not_found(&self) -> bool;
}

impl QueryFileResultExt for query::QueryFileResult {
    fn is_not_found(&self) -> bool {
        matches!(self, query::QueryFileResult::NotFound)
    }
}
