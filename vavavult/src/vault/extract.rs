use crate::common::hash::{HashParseError, VaultHash};
use crate::crypto::chunked::{ChunkedCryptoError, ChunkedReader, chunked_decrypt};
use crate::crypto::encrypt::EncryptError;
use crate::storage::{StorageBackend, StorageReader};
use crate::vault::{QueryResult, Vault, query};
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

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
    #[error(
        "Integrity check failed for file '{path}': Expected original hash {expected}, but calculated {calculated}. The file in the vault might be corrupted."
    )]
    IntegrityCheckFailed {
        path: String,
        expected: String,
        calculated: String,
    },

    /// An error occurred during the chunked decryption process.
    //
    // // 分块解密过程中发生错误。
    #[error("Chunked cipher error: {0}")]
    ChunkedCryptoError(#[from] ChunkedCryptoError),
}

/// A "ticket" containing all necessary information to perform a file extraction.
/// This is returned by `Vault::prepare_extraction_task` and is thread-safe.
//
// // 包含执行文件提取所需所有信息的“票据”。
// // 由 `Vault::prepare_extraction_task` 返回，并且是线程安全的。
#[derive(Debug, Clone)]
pub struct ExtractionTask {
    pub file_hash: VaultHash,
    pub password: String,
    pub expected_original_hash: VaultHash,
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

    // 2. 检查存储后端是否存在该文件
    if !vault.storage.exists(sha256sum)? {
        return Err(ExtractError::FileNotFound(sha256sum.to_string()));
    }

    // 3. 打包为 "工作票据"
    Ok(ExtractionTask {
        file_hash: sha256sum.clone(),
        password: file_entry.encrypt_password,
        expected_original_hash: file_entry.original_sha256sum,
        original_vault_path: file_entry.path.to_string(),
    })
}

/// Stage 1 (Extract): Prepares multiple files for extraction in a single batch.
///
/// This is a fast method that queries the database for each hash and verifies
/// that the corresponding file exists in the storage backend. Returns one
/// `ExtractionTask` per hash, in the same order.
///
/// # Arguments
/// * `vault` - The vault instance (read access).
/// * `hashes` - A slice of `VaultHash`es to prepare for extraction.
///
/// # Returns
/// A `Vec<ExtractionTask>` — one per hash, in the same order.
///
/// # Errors
/// Returns `ExtractError` if any hash is not found or a database error occurs.
//
// // 阶段 1 (提取): 在单个批次中准备多个文件用于提取。
// //
// // 这是一个快速的方法，它为每个哈希查询数据库并验证对应的文件
// // 存在于存储后端中。按相同顺序返回每个哈希对应的 `ExtractionTask`。
// //
// // # 参数
// // * `vault` - 保险库实例（读取访问）。
// // * `hashes` - 要准备提取的 `VaultHash` 切片。
// //
// // # 返回
// // `Vec<ExtractionTask>` — 每个哈希一个，顺序相同。
// //
// // # 错误
// // 如果任何哈希未找到或发生数据库错误，则返回 `ExtractError`。
pub(crate) fn prepare_extraction_tasks(
    vault: &Vault,
    hashes: &[VaultHash],
) -> Result<Vec<ExtractionTask>, ExtractError> {
    hashes
        .iter()
        .map(|hash| prepare_extraction_task(vault, hash))
        .collect()
}

/// Stage 2 (Extract): Decrypts a prepared extraction task to a writer stream.
///
/// This is a **thread-safe** function that does NOT require a `&Vault`.
/// It performs the expensive CPU/IO decryption work using only the storage backend,
/// writing the decrypted plaintext to the provided writer.
///
/// # Arguments
/// * `storage` - The storage backend to read encrypted data from.
/// * `task` - The extraction ticket from Stage 1.
/// * `writer` - An object implementing `std::io::Write` to receive the decrypted data.
///
/// # Errors
/// Returns `ExtractError` if decryption fails, IO error occurs, or integrity check fails.
//
// // 阶段 2 (提取): 将已准备好的提取任务解密到写入流。
// //
// // 这是一个 **线程安全** 的函数，不需要 `&Vault`。
// // 它仅使用存储后端执行昂贵的 CPU/IO 解密工作，
// // 将解密后的明文写入提供的写入器。
// //
// // # 参数
// // * `storage` - 用于读取加密数据的存储后端。
// // * `task` - 来自阶段 1 的提取票据。
// // * `writer` - 实现 `std::io::Write` 以接收解密数据的对象。
// //
// // # 错误
// // 如果解密失败、发生 IO 错误或完整性检查失败，则返回 `ExtractError`。
pub(crate) fn decrypt_extraction_task(
    storage: &dyn StorageBackend,
    task: &ExtractionTask,
    mut writer: impl Write,
) -> Result<(), ExtractError> {
    // 1. 从存储后端获取读取器
    let mut encrypted_reader = storage.reader(&task.file_hash)?;

    // 2. 执行分块解密，写入到调用方提供的 writer
    let calculated_original_hash =
        chunked_decrypt(&mut encrypted_reader, &mut writer, &task.password)?;

    // 3. 完整性检查
    if calculated_original_hash != task.expected_original_hash {
        return Err(ExtractError::IntegrityCheckFailed {
            path: task.original_vault_path.clone(),
            expected: task.expected_original_hash.to_string(),
            calculated: calculated_original_hash.to_string(),
        });
    }

    Ok(())
}

/// Opens a prepared extraction task as a random-access chunked reader.
///
/// This is a pull-based read API that avoids decrypting the whole file when the
/// caller only needs selected ranges.
///
/// # Arguments
/// * `storage` - The storage backend to read encrypted data from.
/// * `task` - The extraction ticket from Stage 1.
///
/// # Returns
/// An opaque plaintext stream over the encrypted backend object.
///
/// # Errors
/// Returns `ExtractError` if the backend object cannot be opened or its chunked
/// encrypted format is invalid.
//
// // 将已准备好的提取任务打开为随机访问分块读取器。
// //
// // 这是拉取式读取 API，可避免调用方只读取部分范围时解密整个文件。
// //
// // # 参数
// // * `storage` - 用于读取加密数据的存储后端。
// // * `task` - 来自阶段 1 的提取票据。
// //
// // # 返回
// // 基于后端加密对象的不透明明文流。
// //
// // # 错误
// // 如果后端对象无法打开，或其分块加密格式无效，则返回 `ExtractError`。
pub(crate) fn open_extraction_task_reader(
    storage: &dyn StorageBackend,
    task: &ExtractionTask,
) -> Result<ChunkedReader<Box<dyn StorageReader>>, ExtractError> {
    // 1. 从后端打开可寻址物理读取器。
    let encrypted_reader = storage.reader(&task.file_hash)?;

    // 2. 包装为按需解密的分块读取器。
    Ok(ChunkedReader::new(encrypted_reader, &task.password)?)
}

/// Stage 2 shortcut: Decrypts a prepared extraction task to a local file.
///
/// This wraps `decrypt_extraction_task` with atomic file writing:
/// data is first written to a temporary file in the same directory,
/// then atomically renamed to the final path on success.
///
/// # Arguments
/// * `storage` - The storage backend to read encrypted data from.
/// * `task` - The extraction ticket from Stage 1.
/// * `destination_path` - The local path to save the decrypted file.
///
/// # Errors
/// Returns `ExtractError` if decryption fails, IO error occurs, or integrity check fails.
//
// // 阶段 2 快捷方法: 将已准备好的提取任务解密到本地文件。
// //
// // 这包装了 `decrypt_extraction_task`，使用原子文件写入：
// // 数据先写入同目录下的临时文件，成功后原子重命名到最终路径。
// //
// // # 参数
// // * `storage` - 用于读取加密数据的存储后端。
// // * `task` - 来自阶段 1 的提取票据。
// // * `destination_path` - 保存解密文件的本地路径。
// //
// // # 错误
// // 如果解密失败、发生 IO 错误或完整性检查失败，则返回 `ExtractError`。
pub(crate) fn decrypt_extraction_task_to_file(
    storage: &dyn StorageBackend,
    task: &ExtractionTask,
    destination_path: &Path,
) -> Result<(), ExtractError> {
    // 1. 确保目标目录存在
    if let Some(parent_dir) = destination_path.parent() {
        fs::create_dir_all(parent_dir)?;
    }

    // 2. 准备原子写入（写入同目录下的临时文件）
    let parent_dir = destination_path.parent().unwrap_or(Path::new("."));
    let temp_file = NamedTempFile::new_in(parent_dir)?;

    // 3. 解密到临时文件
    decrypt_extraction_task(storage, task, &temp_file)?;

    // 4. 原子持久化
    temp_file
        .persist(destination_path)
        .map_err(EncryptError::TempFilePersist)?;

    Ok(())
}

/// 快捷函数：从保险库中提取一个文件到本地路径（两阶段合一）。
pub(crate) fn extract_file(
    vault: &Vault,
    sha256sum: &VaultHash,
    destination_path: &Path,
) -> Result<(), ExtractError> {
    let task = prepare_extraction_task(vault, sha256sum)?;
    decrypt_extraction_task_to_file(vault.storage.as_ref(), &task, destination_path)
}
