use std::{fs};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};
use rusqlite::Transaction;
use tempfile::NamedTempFile;
use crate::file::stream_cipher;
use crate::common::constants::{
    META_FILE_ADD_TIME, META_FILE_SIZE, META_FILE_UPDATE_TIME,
    META_SOURCE_MODIFIED_TIME, DATA_SUBDIR
};
use crate::common::hash::VaultHash;
use crate::common::metadata::MetadataEntry;
use crate::file::encrypt::{EncryptError};
use crate::file::path::VaultPath;
use crate::file::PathError;
use crate::file::stream_cipher::StreamCipherError;
use crate::utils::random::{generate_random_password};
use crate::utils::time::now_as_rfc3339_string;
use crate::vault::{query, FileEntry, UpdateError};
use crate::vault::query::QueryResult;
pub(crate) use crate::vault::Vault;

/// Defines errors that can occur during the file addition process.
//
// // 定义在文件添加过程中可能发生的错误。
#[derive(Debug, thiserror::Error)]
pub enum AddFileError {
    /// The specified source file does not exist or is not a file.
    //
    // // 指定的源文件不存在或不是一个文件。
    #[error("Source file not found at {0}")]
    SourceNotFound(PathBuf),

    /// An I/O error occurred while reading the source file or writing the encrypted file.
    //
    // // 在读取源文件或写入加密文件时发生 I/O 错误。
    #[error("Failed to read source file: {0}")]
    ReadError(#[from] std::io::Error),

    /// A database error occurred during the transaction.
    //
    // // 在事务期间发生数据库错误。
    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    /// The target `VaultPath` was a directory path, but a file path was required.
    //
    // // 目标 `VaultPath` 是一个目录路径，但需要的是文件路径。
    #[error("The provided vault path is invalid: '{0}' (must be a file path, not a directory path)")]
    InvalidFilePath(String),

    /// A database query failed during pre-checks.
    //
    // // 在预检查期间数据库查询失败。
    #[error("Database query error: {0}")]
    QueryError(#[from] query::QueryError),

    /// A file with the same target `VaultPath` already exists in the vault or batch.
    //
    // // 具有相同目标 `VaultPath` 的文件已存在于保险库或批处理中。
    #[error("A file with the same path '{0}' already exists in the vault or in this batch.")]
    DuplicateFileName(String),

    /// A file with the same *encrypted* content hash already exists.
    //
    // // 具有相同 *加密* 内容哈希的文件已存在。
    #[error("A file with the same content (encrypted SHA256: {0}) already exists in the vault.")]
    DuplicateContent(String),

    /// A file with the same *original* content hash already exists.
    //
    // // 具有相同 *原始* 内容哈希的文件已存在。
    #[error("A file with the same original content (Original SHA256: {0}) already exists at path '{1}' or in this batch.")]
    DuplicateOriginalContent (String, String),

    /// The source file path has no filename (e.g., ".") and cannot be added to a directory.
    //
    // // 源文件路径没有文件名 (例如 ".") 并且无法添加到目录中。
    #[error("Source file has no name and cannot be added to a directory path.")]
    SourceFileNameError,

    /// An error occurred during file encryption.
    //
    // // 文件加密期间发生错误。
    #[error("File encryption failed: {0}")]
    EncryptionError(#[from] EncryptError),

    /// An error occurred in the underlying stream cipher.
    //
    // // 底层流加密器发生错误。
    #[error("Stream cipher error: {0}")]
    StreamCipherError(#[from] StreamCipherError),

    /// Failed to update the vault's last-modified timestamp.
    //
    // // 更新保险库的最后修改时间戳失败。
    #[error("Failed to update vault timestamp: {0}")]
    TimestampUpdateError(#[from] UpdateError),

    /// An error occurred constructing the final `VaultPath`.
    //
    // // 构建最终 `VaultPath` 时发生错误。
    #[error("Failed to construct final path: {0}")]
    PathConstructionError(#[from] PathError),

}

/// Represents a prepared file addition (V2 - Deprecated by EncryptedAddingFile).
//
// // 代表一个准备好的文件添加 (V2 - 已被 EncryptedAddingFile 取代)。
// #[derive(Debug)]
// pub struct AddTransaction {
//     /// 加密后内容的 Base64(unpadded) 哈希 (43 字节)
//     pub encrypted_sha256sum: VaultHash,
//     /// 原始文件内容的 Base64(unpadded) 哈希 (43 字节)
//     pub original_sha256sum: VaultHash,
//     /// 指向临时加密文件的路径 (在 `temp/` 目录下)
//     pub temp_path: PathBuf,
//     /// 用于此文件加密的随机密码
//     pub per_file_password: String,
//     /// 原始文件大小
//     pub file_size: u64,
//     /// 原始文件修改时间
//     pub source_modified_time: DateTime<Utc>,
// }

/// Represents an encrypted file ready to be committed to the vault database.
/// This struct is returned by `Vault::encrypt_file_for_add` and consumed by `Vault::commit_add_files`.
//
// // 代表一个已加密、准备好提交到保险库数据库的文件。
// // 此结构由 `Vault::encrypt_file_for_add` 返回，并由 `Vault::commit_add_files` 消费。
#[derive(Debug)]
pub struct EncryptedAddingFile {
    /// 最终将插入到数据库的 FileEntry 结构。
    pub file_entry: FileEntry,
    /// 指向临时文件句柄。
    temp_file: NamedTempFile,
}

/// 这是新的独立函数 (standalone)，不依赖 Vault。
/// 它可以被 CLI 无锁调用。
pub(crate) fn encrypt_file_for_add_standalone(
    data_dir_path: &Path, // [修改] 只接收 data_dir_path
    source_path: &Path,
    dest_path: &VaultPath
) -> Result<EncryptedAddingFile, AddFileError> {

    // 1. 验证源文件
    if !source_path.is_file() {
        return Err(AddFileError::SourceNotFound(source_path.to_path_buf()));
    }
    // 2. 解析最终路径
    let final_dest_path = resolve_final_path(source_path, dest_path)?;
    if !final_dest_path.is_file() {
        return Err(AddFileError::InvalidFilePath(final_dest_path.as_str().to_string()));
    }
    // 3. 获取元数据
    let source_metadata = fs::metadata(source_path)?;
    let file_size = source_metadata.len();
    let source_modified_time: DateTime<Utc> = source_metadata.modified()?.into();

    // 4. 准备 IO 句柄
    fs::create_dir_all(data_dir_path)?;
    let mut source_file = File::open(source_path)?;
    let mut temp_file = tempfile::Builder::new()
        .prefix(".vava-add-")
        .suffix(".tmp")
        .tempfile_in(data_dir_path)?;

    // 5. 调用 stream_cipher
    let per_file_password = generate_random_password(16);
    let (encrypted_sha256sum, original_sha256sum) =
        stream_cipher::stream_encrypt_and_hash(
            &mut source_file,
            &mut temp_file,
            &per_file_password
        )?;
    // 6. 构建 FileEntry
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
    // 7. 返回
    Ok(EncryptedAddingFile {
        file_entry,
        temp_file,
    })
}

// /// 阶段 1: 准备一个文件添加事务 (线程安全的自由函数)
// pub fn encrypt_file_for_add(vault: &Vault, source_path: &Path,dest_path: &VaultPath) -> Result<EncryptedAddingFile, AddFileError> {
//     // 验证源文件
//     if !source_path.is_file() {
//         return Err(AddFileError::SourceNotFound(source_path.to_path_buf()));
//     }
//
//     // 解析最终的文件路径
//     let final_dest_path = resolve_final_path(source_path, dest_path)?;
//
//     // 在执行昂贵的加密操作 *之前* 检查无效的文件路径
//     if !final_dest_path.is_file() {
//         return Err(AddFileError::InvalidFilePath(final_dest_path.as_str().to_string()));
//     }
//
//     // --- 1. 获取文件元数据  ---
//     let source_metadata = fs::metadata(source_path)?;
//     let file_size = source_metadata.len();
//     let source_modified_time: DateTime<Utc> = source_metadata.modified()?.into();
//
//     // --- [修改] 2. 准备 IO 句柄 ---
//     let data_dir_path = vault.root_path.join(DATA_SUBDIR);
//     fs::create_dir_all(&data_dir_path)?;
//
//     // 打开源文件用于读取
//     let mut source_file = File::open(source_path)?;
//
//     // 直接在 data 目录中创建临时文件
//     let mut temp_file = tempfile::Builder::new()
//         .prefix(".vava-add-")
//         .suffix(".tmp")
//         .tempfile_in(&data_dir_path)?;
//
//     // --- [修改] 3. 直接调用 stream_cipher ---
//     let per_file_password = generate_random_password(16);
//
//     // 将 &mut source_file 和 &mut temp_file 直接传递给流式加密器
//     let (encrypted_sha256sum, original_sha256sum) =
//         stream_cipher::stream_encrypt_and_hash(
//             &mut source_file,
//             &mut temp_file, // <-- 传递可写句柄
//             &per_file_password
//         )?; // <-- 错误现在是 StreamCipherError，会被 AddFileError::from 捕获
//
//     // --- 4. 构建完整的 FileEntry (不变) ---
//     let now = now_as_rfc3339_string();
//     let metadata = vec![
//         MetadataEntry { key: META_FILE_ADD_TIME.to_string(), value: now.clone() },
//         MetadataEntry { key: META_FILE_UPDATE_TIME.to_string(), value: now },
//         MetadataEntry { key: META_FILE_SIZE.to_string(), value: file_size.to_string() },
//         MetadataEntry { key: META_SOURCE_MODIFIED_TIME.to_string(), value: source_modified_time.to_rfc3339() },
//     ];
//
//     let file_entry = FileEntry {
//         path: final_dest_path,
//         sha256sum: encrypted_sha256sum,
//         original_sha256sum,
//         encrypt_password: per_file_password,
//         tags: Vec::new(),
//         metadata,
//     };
//
//     // --- 5. 返回封装的对象 (不变) ---
//     Ok(EncryptedAddingFile {
//         file_entry,
//         temp_file,
//     })
// }

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
            return Err(AddFileError::DuplicateFileName(entry.path.to_string()));
        }
        // 检查批内路径是否重复
        if !paths_in_batch.insert(&entry.path) {
            return Err(AddFileError::DuplicateFileName(entry.path.to_string()));
        }

        // 检查数据库中原始哈希是否重复
        if let QueryResult::Found(existing) = query::check_by_original_hash(vault, &entry.original_sha256sum)? {
            return Err(AddFileError::DuplicateOriginalContent(entry.original_sha256sum.to_string(),existing.path.to_string()));
        }
        // 检查批内原始哈希是否重复
        if let Some(existing_path) = originals_in_batch.insert(&entry.original_sha256sum, &entry.path) {
            return Err(AddFileError::DuplicateOriginalContent(entry.original_sha256sum.to_string(),existing_path.to_string()));
        }

        // 检查加密后哈希是否重复 (主键，理论上概率极低，但保险起见)
        if let QueryResult::Found(_) = query::check_by_hash(vault, &entry.sha256sum)? {
            return Err(AddFileError::DuplicateContent(entry.sha256sum.to_string()));
        }
    }

    // --- 2. 提交 (数据库写入和文件移动) ---
    let data_dir_path = vault.root_path.join(DATA_SUBDIR);

    let tx = vault.database_connection.transaction()?;
    {
        let mut file_stmt = tx.prepare(
            "INSERT INTO files (sha256sum, path, original_sha256sum, encrypt_password) VALUES (?1, ?2, ?3, ?4)"
        )?;
        let mut meta_stmt = tx.prepare(
            "INSERT INTO metadata (file_sha256sum, meta_key, meta_value) VALUES (?1, ?2, ?3)"
        )?;

        for file_to_add in &files {
            let entry = &file_to_add.file_entry;

            file_stmt.execute((
                &entry.sha256sum,
                &entry.path,
                &entry.original_sha256sum,
                &entry.encrypt_password,
            ))?;

            for meta in &entry.metadata {
                meta_stmt.execute((&entry.sha256sum, &meta.key, &meta.value))?;
            }
        }

        move_temp_files_to_data(files, &data_dir_path, &tx)?;
    }
    tx.commit()?;

    Ok(())
}

/// 快捷函数：添加一个新文件
pub fn add_file(vault: &mut Vault, source_path: &Path, dest_path: &VaultPath) -> Result<VaultHash, AddFileError> {
    // 阶段 1: 加密
    let data_dir = vault.root_path.join(DATA_SUBDIR);
    let file_to_add = encrypt_file_for_add_standalone(&data_dir, source_path, dest_path)?;

    let hash = file_to_add.file_entry.sha256sum.clone();

    // 阶段 2: 提交 (批量 API，但只传一个)
    commit_add_files(vault, vec![file_to_add])?;

    Ok(hash)
}

/// 辅助函数：移动文件（在事务中调用）
fn move_temp_files_to_data(
    files: Vec<EncryptedAddingFile>, // 接收所有权
    data_dir_path: &Path,
    _tx: &Transaction,
) -> Result<(), AddFileError> {
    for file_to_add in files {
        let final_path = data_dir_path.join(&file_to_add.file_entry.sha256sum.to_string());

        file_to_add.temp_file.persist(final_path)
            .map_err(|persist_error| {
                AddFileError::ReadError(persist_error.error)
            })?;
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
