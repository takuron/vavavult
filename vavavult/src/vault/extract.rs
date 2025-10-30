use std::path::{Path, PathBuf};
use std::fs;
use crate::common::constants::DATA_SUBDIR;
use crate::common::hash::{HashParseError, VaultHash};
use crate::file::encrypt::EncryptError;
use crate::vault::{query, QueryResult, Vault};

/// Defines errors that can occur during the file extraction process.
//
// // 定义在文件提取过程中可能发生的错误。
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    /// A database query failed (e.g., file not found).
    //
    // // 数据库查询失败 (例如，文件未找到)。
    #[error("Database query error: {0}")]
    QueryError(#[from] query::QueryError),

    /// An I/O error occurred (e.g., cannot create destination directory).
    //
    // // 发生 I/O 错误 (例如，无法创建目标目录)。
    #[error("File system error: {0}")]
    FileSystemError(#[from] std::io::Error),

    /// The requested file (by hash) was not found in the database or `data/` directory.
    //
    // // 在数据库或 `data/` 目录中未找到所请求的文件 (按哈希)。
    #[error("File with SHA256 '{0}' not found.")]
    FileNotFound(String),

    /// File decryption failed, often due to an incorrect password (if manually supplied) or data corruption.
    //
    // // 文件解密失败，通常是由于密码错误 (如果手动提供) 或数据损坏。
    #[error("File decryption failed: {0}")]
    DecryptionError(#[from] EncryptError),

    /// The hash string provided was in an invalid format.
    //
    // // 提供的哈希字符串格式无效。
    #[error("Invalid hash format: {0}")]
    HashParseError(#[from] HashParseError),

    /// The hash of the decrypted file did not match the expected original hash.
    /// This indicates the file in the vault's `data/` directory is corrupt.
    //
    // // 解密后文件的哈希与预期的原始哈希不匹配。
    // // 这表明保险库 `data/` 目录中的文件已损坏。
    #[error("Integrity check failed for file '{path}': Expected original hash {expected}, but calculated {calculated}. The file in the vault might be corrupted.")]
    IntegrityCheckFailed {
        path: String,
        expected: String,
        calculated: String,
    }
}

/// A "ticket" containing all necessary information to perform a file extraction.
/// This is returned by `Vault::prepare_extraction_task` and is thread-safe.
//
// // 包含执行文件提取所需所有信息的“票据”。
// // 由 `Vault::prepare_extraction_task` 返回，并且是线程安全的。
#[derive(Debug, Clone)]
pub struct ExtractionTask {
    /// The path to the encrypted file within the `data/` directory.
    //
    // // `data/` 目录中加密文件的路径。
    pub internal_path: PathBuf,
    /// The password required to decrypt this specific file.
    //
    // // 解密此特定文件所需的密码。
    pub password: String,
    /// The expected hash of the *original* (decrypted) content.
    //
    // // *原始* (解密后) 内容的预期哈希值。
    pub expected_original_hash: VaultHash,
    /// The original vault path of the file (used for logging).
    //
    // // 文件的原始保险库路径 (仅用于日志记录)。
    pub original_vault_path: String,
}

/// (阶段 1) 准备一个文件用于提取。
/// 这是一个快速的、需要 `&Vault` 锁的数据库查询。
pub(crate) fn prepare_extraction_task(
    vault: &Vault,
    sha256sum: &VaultHash,
) -> Result<ExtractionTask, ExtractError> {
    // 1. 在数据库中查找文件的完整信息
    let file_entry = match query::check_by_hash(vault, sha256sum)? {
        QueryResult::Found(entry) => entry,
        QueryResult::NotFound => {
            return Err(ExtractError::FileNotFound(sha256sum.to_string()));
        }
    };

    // 2. 确定源文件路径
    let internal_path = vault.root_path.join(DATA_SUBDIR).join(sha256sum.to_string());
    if !internal_path.exists() {
        return Err(ExtractError::FileNotFound(sha256sum.to_string()));
    }

    // 3. 打包为 "工作票据"
    Ok(ExtractionTask {
        internal_path,
        password: file_entry.encrypt_password,
        expected_original_hash: file_entry.original_sha256sum,
        original_vault_path: file_entry.path.to_string(),
    })
}

/// (阶段 2) 执行一个已准备好的提取任务。
/// 这是一个缓慢的、线程安全的函数（无 `&Vault` 锁）。
pub(crate) fn execute_extraction_task_standalone(
    task: &ExtractionTask,
    destination_path: &Path,
) -> Result<(), ExtractError> {
    // 1. 确保目标目录存在
    if let Some(parent_dir) = destination_path.parent() {
        fs::create_dir_all(parent_dir)?;
    }

    // 2. 执行解密 (缓慢的操作)
    let calculated_original_hash = crate::file::encrypt::decrypt_file(
        &task.internal_path,
        destination_path,
        &task.password,
    )?;

    // 3. 比较哈希 (完整性检查)
    if calculated_original_hash != task.expected_original_hash {
        return Err(ExtractError::IntegrityCheckFailed {
            path: task.original_vault_path.clone(),
            expected: task.expected_original_hash.to_string(),
            calculated: calculated_original_hash.to_string(),
        });
    }

    Ok(())
}

/// 从保险库中提取一个文件，并在解密后验证其完整性。
pub(crate) fn extract_file(
    vault: &Vault,
    sha256sum: &VaultHash,
    destination_path: &Path,
) -> Result<(), ExtractError> {
    // 阶段 1: 准备 (快速, 有锁)
    let task = prepare_extraction_task(vault, sha256sum)?;

    // 阶段 2: 执行 (缓慢, 无锁)
    execute_extraction_task_standalone(&task, destination_path)
}