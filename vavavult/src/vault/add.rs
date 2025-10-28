use std::{fs};
use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};
use crate::common::constants::{
    META_FILE_ADD_TIME, META_FILE_SIZE, META_FILE_UPDATE_TIME,
    META_SOURCE_MODIFIED_TIME, DATA_SUBDIR, TEMP_SUBDIR
};
use crate::common::metadata::MetadataEntry;
use crate::file::encrypt::{EncryptError};
use crate::file::path::VaultPath;
use crate::utils::random::{generate_random_password, generate_random_string};
use crate::utils::time::now_as_rfc3339_string;
use crate::vault::{query, UpdateError};
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

    #[error("A file with the same path '{0}' already exists in the vault.")]
    DuplicateFileName(String),

    #[error("A file with the same content (SHA256: {0}) already exists in the vault.")]
    DuplicateContent(String),

    #[error("File encryption failed: {0}")]
    EncryptionError(#[from] EncryptError),

    #[error("Failed to update vault timestamp: {0}")]
    TimestampUpdateError(#[from] UpdateError),
}

/// 代表一个准备好的文件添加 (V2)。
#[derive(Debug)]
pub struct AddTransaction {
    /// 加密后内容的 Base64(unpadded) 哈希 (43 字节)
    pub encrypted_sha256sum: String,
    /// 原始文件内容的 Base64(unpadded) 哈希 (43 字节)
    pub original_sha256sum: String,
    /// 指向临时加密文件的路径 (在 `temp/` 目录下)
    pub temp_path: PathBuf,
    /// 用于此文件加密的随机密码
    pub per_file_password: String,
    /// 原始文件大小
    pub file_size: u64,
    /// 原始文件修改时间
    pub source_modified_time: DateTime<Utc>,
}

/// 阶段 1: 准备一个文件添加事务 (线程安全的自由函数)
///
/// V2 中，此函数 *总是* 加密文件到 `TEMP_SUBDIR` 目录。
pub fn prepare_add_transaction(vault: &Vault, source_path: &Path) -> Result<AddTransaction, AddFileError> {
    if !source_path.is_file() {
        return Err(AddFileError::SourceNotFound(source_path.to_path_buf()));
    }

    // --- 1. 获取文件元数据 ---
    let source_metadata = fs::metadata(source_path)?;
    let file_size = source_metadata.len();
    let source_modified_time: DateTime<Utc> = source_metadata.modified()?.into();

    // --- 2. (请求 1) 准备临时目录和路径 ---
    let temp_dir_path = vault.root_path.join(TEMP_SUBDIR);
    fs::create_dir_all(&temp_dir_path)?; // 确保 temp 目录存在

    let temp_file_name = format!(".temp_{}", generate_random_string(24));
    let temp_path = temp_dir_path.join(&temp_file_name);

    // --- 3. (V2 核心) 执行加密并获取两个哈希 ---
    // V2 总是加密，总是使用随机密码
    let per_file_password = generate_random_password(16);

    // 调用我们上一轮修改的 stream_cipher (通过 encrypt_file)
    // 它现在返回 (encrypted_base64_hash, original_base64_hash)
    let (encrypted_sha256sum, original_sha256sum) =
        crate::file::encrypt::encrypt_file(source_path, &temp_path, &per_file_password)?;

    // 4. 返回 V2 事务
    Ok(AddTransaction {
        encrypted_sha256sum,
        original_sha256sum,
        temp_path,
        per_file_password,
        file_size,
        source_modified_time,
    })
}

/// [V2 修改] 阶段 2: 提交一个文件添加事务 (需要独占访问的自由函数)
///
/// (请求 3) 'dest_path' 参数现在是 `&VaultPath`
pub fn commit_add_transaction_local(vault: &mut Vault, transaction: AddTransaction, dest_path: &VaultPath) -> Result<String, AddFileError> {

    // (请求 3) 验证 VaultPath 必须是一个文件路径
    if !dest_path.is_file() {
        let _ = fs::remove_file(&transaction.temp_path); // 清理
        return Err(AddFileError::InvalidFilePath(dest_path.as_str().to_string()));
    }
    let vault_path_str = dest_path.as_str();

    // --- 1. 数据库检查 ---
    // 检查路径是否重复
    if let QueryResult::Found(_) = query::check_by_name(vault, vault_path_str)? {
        let _ = fs::remove_file(&transaction.temp_path);
        return Err(AddFileError::DuplicateFileName(vault_path_str.to_string()));
    }
    // 检查加密后内容是否重复 (主键)
    if let QueryResult::Found(_) = query::check_by_hash(vault, &transaction.encrypted_sha256sum)? {
        let _ = fs::remove_file(&transaction.temp_path);
        return Err(AddFileError::DuplicateContent(transaction.encrypted_sha256sum));
    }

    // --- 2. (请求 1 & 2) 将文件从 'temp/' 移至 'data/' ---
    let data_dir_path = vault.root_path.join(DATA_SUBDIR);
    fs::create_dir_all(&data_dir_path)?; // 确保 data 目录存在

    // (请求 2) 最终文件名是 Base64 哈希
    let final_path = data_dir_path.join(&transaction.encrypted_sha256sum);
    fs::rename(&transaction.temp_path, final_path)?;

    // --- 3. 数据库插入 (V2 表结构) ---
    let tx = vault.database_connection.transaction()?;
    {
        // [修改] 插入 V2 'files' 表
        tx.execute(
            "INSERT INTO files (sha256sum, path, original_sha256sum, encrypt_password) VALUES (?1, ?2, ?3, ?4)",
            (
                &transaction.encrypted_sha256sum,
                vault_path_str,
                &transaction.original_sha256sum,
                &transaction.per_file_password,
            ),
        )?;

        // (文件元数据插入逻辑不变)
        let now = now_as_rfc3339_string();
        let metadata_to_add = vec![
            MetadataEntry { key: META_FILE_ADD_TIME.to_string(), value: now.clone() },
            MetadataEntry { key: META_FILE_UPDATE_TIME.to_string(), value: now },
            MetadataEntry { key: META_FILE_SIZE.to_string(), value: transaction.file_size.to_string() },
            MetadataEntry { key: META_SOURCE_MODIFIED_TIME.to_string(), value: transaction.source_modified_time.to_rfc3339() },
        ];

        let mut stmt = tx.prepare("INSERT INTO metadata (file_sha256sum, meta_key, meta_value) VALUES (?1, ?2, ?3)")?;
        for meta in metadata_to_add {
            // [注意] file_sha256sum 现在是加密后的 Base64 哈希
            stmt.execute((&transaction.encrypted_sha256sum, &meta.key, &meta.value))?;
        }
    }
    tx.commit()?;

    Ok(transaction.encrypted_sha256sum)
}


/// [V2 修改] 将一个新文件添加到保险库中 (V2 便捷函数)。
///
/// (请求 3) 'dest_path' 参数现在是 `&VaultPath` 且是必需的。
pub fn add_file(vault: &mut Vault, source_path: &Path, dest_path: &VaultPath) -> Result<String, AddFileError> {
    // V2 中，'dest_path' 是强制性的，不再从 'source_path' 推断
    let transaction = prepare_add_transaction(vault, source_path)?;
    commit_add_transaction_local(vault, transaction, dest_path)
}

