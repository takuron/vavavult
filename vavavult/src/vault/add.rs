use std::{fs};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};
use rusqlite::Transaction;
use crate::common::constants::{
    META_FILE_ADD_TIME, META_FILE_SIZE, META_FILE_UPDATE_TIME,
    META_SOURCE_MODIFIED_TIME, DATA_SUBDIR, TEMP_SUBDIR
};
use crate::common::hash::VaultHash;
use crate::common::metadata::MetadataEntry;
use crate::file::encrypt::{EncryptError};
use crate::file::path::VaultPath;
use crate::file::PathError;
use crate::utils::random::{generate_random_password, generate_random_string};
use crate::utils::time::now_as_rfc3339_string;
use crate::vault::{query, FileEntry, UpdateError};
use crate::vault::query::QueryResult;
pub(crate) use crate::vault::Vault;

#[derive(Debug, thiserror::Error)]
pub enum AddFileError {
    #[error("Source file not found at {0}")]
    SourceNotFound(PathBuf),

    #[error("Failed to read source file: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("The provided vault path is invalid: '{0}' (must be a file path, not a directory path)")]
    InvalidFilePath(String),

    #[error("Database query error: {0}")]
    QueryError(#[from] query::QueryError),

    #[error("A file with the same path '{0}' already exists in the vault or in this batch.")]
    DuplicateFileName(String),

    #[error("A file with the same content (encrypted SHA256: {0}) already exists in the vault.")]
    DuplicateContent(String),

    #[error("A file with the same original content (Original SHA256: {0}) already exists at path '{1}' or in this batch.")]
    DuplicateOriginalContent (String, String),

    #[error("Source file has no name and cannot be added to a directory path.")]
    SourceFileNameError,

    #[error("File encryption failed: {0}")]
    EncryptionError(#[from] EncryptError),

    #[error("Failed to update vault timestamp: {0}")]
    TimestampUpdateError(#[from] UpdateError),

    #[error("Failed to construct final path: {0}")]
    PathConstructionError(#[from] PathError),

}

/// 代表一个准备好的文件添加 (V2)。
#[derive(Debug)]
pub struct AddTransaction {
    /// 加密后内容的 Base64(unpadded) 哈希 (43 字节)
    pub encrypted_sha256sum: VaultHash,
    /// 原始文件内容的 Base64(unpadded) 哈希 (43 字节)
    pub original_sha256sum: VaultHash,
    /// 指向临时加密文件的路径 (在 `temp/` 目录下)
    pub temp_path: PathBuf,
    /// 用于此文件加密的随机密码
    pub per_file_password: String,
    /// 原始文件大小
    pub file_size: u64,
    /// 原始文件修改时间
    pub source_modified_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct EncryptedAddingFile {
    /// 最终将插入到数据库的 FileEntry 结构。
    pub file_entry: FileEntry,
    /// 指向 `temp/` 目录中临时加密文件的路径。
    pub temp_path: PathBuf,
}

/// 阶段 1: 准备一个文件添加事务 (线程安全的自由函数)
///
/// V2 中，此函数 *总是* 加密文件到 `TEMP_SUBDIR` 目录。
pub fn encrypt_file_for_add(vault: &Vault, source_path: &Path,dest_path: &VaultPath) -> Result<EncryptedAddingFile, AddFileError> {
    // 验证源文件
    if !source_path.is_file() {
        return Err(AddFileError::SourceNotFound(source_path.to_path_buf()));
    }

    // 解析最终的文件路径
    let final_dest_path = resolve_final_path(source_path, dest_path)?;

    // 在执行昂贵的加密操作 *之前* 检查无效的文件路径
    // (在 commit_add_files 中也会检查，但这里提前失败更好)
    if !final_dest_path.is_file() {
        return Err(AddFileError::InvalidFilePath(final_dest_path.as_str().to_string()));
    }

    // --- 1. 获取文件元数据 ---
    let source_metadata = fs::metadata(source_path)?;
    let file_size = source_metadata.len();
    let source_modified_time: DateTime<Utc> = source_metadata.modified()?.into();

    // --- 2. 准备临时目录和路径 ---
    let temp_dir_path = vault.root_path.join(TEMP_SUBDIR);
    fs::create_dir_all(&temp_dir_path)?;
    let temp_file_name = format!(".temp_{}", generate_random_string(24));
    let temp_path = temp_dir_path.join(&temp_file_name);

    // --- 3. 执行加密并获取两个哈希 ---
    let per_file_password = generate_random_password(16);
    let (encrypted_sha256sum, original_sha256sum) =
        crate::file::encrypt::encrypt_file(source_path, &temp_path, &per_file_password)?;

    // --- 4. 构建完整的 FileEntry ---
    let now = now_as_rfc3339_string();
    let metadata = vec![
        MetadataEntry { key: META_FILE_ADD_TIME.to_string(), value: now.clone() },
        MetadataEntry { key: META_FILE_UPDATE_TIME.to_string(), value: now },
        MetadataEntry { key: META_FILE_SIZE.to_string(), value: file_size.to_string() },
        MetadataEntry { key: META_SOURCE_MODIFIED_TIME.to_string(), value: source_modified_time.to_rfc3339() },
    ];

    let file_entry = FileEntry {
        path: final_dest_path,
        sha256sum: encrypted_sha256sum,
        original_sha256sum,
        encrypt_password: per_file_password,
        tags: Vec::new(),
        metadata,
    };

    // --- 5. 返回封装的对象 ---
    Ok(EncryptedAddingFile {
        file_entry,
        temp_path,
    })
}

/// 阶段 2: 提交一个文件添加事务 (需要独占访问的自由函数)
pub fn commit_add_files(
    vault: &mut Vault,
    files: Vec<EncryptedAddingFile>
) -> Result<(), AddFileError> {
    if files.is_empty() {
        return Ok(());
    }

    // --- 1. 预检查 (数据库读取和批内检查) ---
    let mut paths_in_batch = HashSet::new();
    let mut originals_in_batch = HashMap::new();

    for file_to_add in &files {
        let entry = &file_to_add.file_entry;

        // 检查数据库中路径是否重复
        if let QueryResult::Found(_) = query::check_by_path(vault, &entry.path)? {
            cleanup_temp_files(&files);
            return Err(AddFileError::DuplicateFileName(entry.path.to_string()));
        }
        // 检查批内路径是否重复
        if !paths_in_batch.insert(&entry.path) {
            cleanup_temp_files(&files);
            return Err(AddFileError::DuplicateFileName(entry.path.to_string()));
        }

        // 检查数据库中原始哈希是否重复
        if let QueryResult::Found(existing) = query::check_by_original_hash(vault, &entry.original_sha256sum)? {
            cleanup_temp_files(&files);
            return Err(AddFileError::DuplicateOriginalContent(entry.original_sha256sum.to_string(),existing.path.to_string()));
        }
        // 检查批内原始哈希是否重复
        if let Some(existing_path) = originals_in_batch.insert(&entry.original_sha256sum, &entry.path) {
            cleanup_temp_files(&files);
            return Err(AddFileError::DuplicateOriginalContent(entry.original_sha256sum.to_string(),existing_path.to_string()));
        }

        // 检查加密后哈希是否重复 (主键，理论上概率极低，但保险起见)
        if let QueryResult::Found(_) = query::check_by_hash(vault, &entry.sha256sum)? {
            cleanup_temp_files(&files);
            return Err(AddFileError::DuplicateContent(entry.sha256sum.to_string()));
        }
    }

    // --- 2. 提交 (数据库写入和文件移动) ---
    let data_dir_path = vault.root_path.join(DATA_SUBDIR);
    fs::create_dir_all(&data_dir_path)?;

    // (请求 4) 在单个事务中执行所有数据库写入
    let tx = vault.database_connection.transaction()?;
    {
        // 准备重用的语句
        let mut file_stmt = tx.prepare(
            "INSERT INTO files (sha256sum, path, original_sha256sum, encrypt_password) VALUES (?1, ?2, ?3, ?4)"
        )?;
        let mut meta_stmt = tx.prepare(
            "INSERT INTO metadata (file_sha256sum, meta_key, meta_value) VALUES (?1, ?2, ?3)"
        )?;

        for file_to_add in &files {
            let entry = &file_to_add.file_entry;

            // 插入 'files' 表
            file_stmt.execute((
                &entry.sha256sum,
                &entry.path,
                &entry.original_sha256sum,
                &entry.encrypt_password,
            ))?;

            // 插入 'metadata' 表
            for meta in &entry.metadata {
                meta_stmt.execute((&entry.sha256sum, &meta.key, &meta.value))?;
            }
        }

        // 仅在数据库事务准备好提交时才移动文件
        // 这样如果文件移动失败，事务可以回滚
        move_temp_files_to_data(&files, &data_dir_path, &tx)?;
    }
    tx.commit()?;

    Ok(())
}

/// 快捷函数：添加一个新文件
pub fn add_file(vault: &mut Vault, source_path: &Path, dest_path: &VaultPath) -> Result<VaultHash, AddFileError> {
    // 阶段 1: 加密 (此函数现在内部处理路径解析)
    let file_to_add = encrypt_file_for_add(vault, source_path, dest_path)?;
    let hash = file_to_add.file_entry.sha256sum.clone();

    // 阶段 2: 提交 (批量 API，但只传一个)
    commit_add_files(vault, vec![file_to_add])?;

    Ok(hash)
}

/// 辅助函数，用于在事务失败时清理所有临时文件。
fn cleanup_temp_files(files: &[EncryptedAddingFile]) {
    for file in files {
        if file.temp_path.exists() {
            let _ = fs::remove_file(&file.temp_path); // 忽略单个删除错误
        }
    }
}

/// 辅助函数：移动文件（在事务中调用）
fn move_temp_files_to_data(
    files: &[EncryptedAddingFile],
    data_dir_path: &Path,
    _tx: &Transaction, // 接收事务引用以确保它在事务中被调用
) -> Result<(), AddFileError> {
    for file_to_add in files {
        let final_path = data_dir_path.join(&file_to_add.file_entry.sha256sum.to_string());
        // 如果重命名失败，显式返回 ReadError（std::io::Error）
        // 这将导致 tx.commit() 失败并触发回滚
        fs::rename(&file_to_add.temp_path, final_path)
            .map_err(|e| AddFileError::ReadError(e))?;
    }
    Ok(())
}

/// 辅助函数：根据源路径和目标路径解析最终的文件路径。
///
/// - `source_path` = "local/file.txt"
/// - `dest_path` = "/vault/docs/" -> Ok("/vault/docs/file.txt")
/// - `dest_path` = "/vault/report.txt" -> Ok("/vault/report.txt")
fn resolve_final_path(source_path: &Path, dest_path: &VaultPath) -> Result<VaultPath, AddFileError> {
    if dest_path.is_dir() {
        // 目标是目录，附加源文件名
        let source_filename = source_path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(AddFileError::SourceFileNameError)?;

        // 使用 VaultPath::join 来创建新的文件路径
        Ok(dest_path.join(source_filename)?)
    } else {
        // 目标已经是文件，直接克隆
        Ok(dest_path.clone())
    }
}
