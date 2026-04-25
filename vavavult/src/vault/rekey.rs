//! Implements the logic for re-keying a file in the vault.
use crate::common::hash::VaultHash;
use crate::crypto::chunked::{ChunkedCryptoError, chunked_re_encrypt};
use crate::file::FileEntry;
use crate::storage::{StagingToken, StorageBackend};
use crate::utils::random::generate_random_password;
use crate::vault::query::{self, QueryError, QueryFileResult};
use crate::vault::{MetadataError, Vault};
use rusqlite::OptionalExtension;
use rusqlite::params;

/// Defines errors that can occur during the file re-keying process.
//
// // 定义在文件密钥轮换过程中可能发生的错误。
#[derive(Debug, thiserror::Error)]
pub enum RekeyError {
    /// An I/O error occurred (e.g., reading from storage or writing to a temporary file).
    //
    // // 发生 I/O 错误 (例如从存储读取或写入临时文件)。
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A database error occurred during the transaction.
    //
    // // 在事务期间发生数据库错误。
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// A database query failed.
    //
    // // 数据库查询失败。
    #[error("Database query error: {0}")]
    Query(#[from] QueryError),

    /// An error occurred in the underlying chunked cipher during encryption or decryption.
    //
    // // 在加密或解密期间，底层分块密码发生错误。
    #[error("Encryption/Decryption error: {0}")]
    ChunkedCrypto(#[from] ChunkedCryptoError),

    /// An error occurred during a metadata operation.
    //
    // // 在元数据操作期间发生错误。
    #[error("Metadata error: {0}")]
    Metadata(#[from] MetadataError),

    /// A sanity check failed: the hash of the original content changed after re-encryption,
    /// indicating a severe logic error.
    //
    // // 完整性检查失败：重加密后原始内容的哈希值发生改变，表明存在严重的逻辑错误。
    #[error("Original hash mismatch after re-encryption. Expected {expected}, got {actual}.")]
    OriginalHashMismatch {
        expected: VaultHash,
        actual: VaultHash,
    },

    /// The requested file hash does not exist in the vault database.
    //
    // // 请求的文件哈希在保险库数据库中不存在。
    #[error("File not found in vault database: {0}")]
    FileNotFound(VaultHash),
}

/// A validated rekey task ready for re-encryption — output of Stage 1, input for Stage 2.
///
/// This struct contains the database-backed `FileEntry` that will be re-encrypted.
/// It is produced while the vault database is available, then can be moved to a
/// worker thread for the database-free re-encryption stage.
///
/// # Fields
/// * `file_entry` - The validated file entry to re-encrypt.
//
// // 已验证的密钥轮换任务，准备进行重加密 — 阶段 1 的输出，阶段 2 的输入。
// //
// // 此结构体包含由数据库确认的、将被重加密的 `FileEntry`。
// // 它在可访问保险库数据库时生成，之后可移动到工作线程执行不需要数据库的重加密阶段。
// //
// // # 字段
// // * `file_entry` - 已验证、待重加密的文件条目。
#[derive(Debug, Clone)]
pub struct PendingRekeyTask {
    /// The validated file entry to re-encrypt.
    //
    // // 已验证、待重加密的文件条目。
    pub file_entry: FileEntry,
}

/// A task representing a file that has been re-encrypted into a temporary location
/// and is ready for an atomic database and filesystem commit.
//
// // 代表一个已重新加密到临时位置并准备好进行原子数据库和文件系统提交的文件任务。
#[derive(Debug)]
pub struct RekeyTask {
    /// The hash of the file *before* re-keying.
    //
    // // 密钥轮换 *前* 的文件哈希。
    pub old_hash: VaultHash,
    /// The complete file entry *after* re-keying, with a new hash and password.
    //
    // // 密钥轮换 *后* 的完整文件条目，包含新的哈希和密码。
    pub new_file_entry: FileEntry,
    /// The token representing the newly encrypted data in a temporary location.
    //
    // // 代表临时位置中新加密数据的令牌。
    pub staging_token: Box<dyn StagingToken>,
}

/// Stage 1: Validates file hashes against the vault database and prepares rekey tasks.
///
/// This stage only reads the database. It resolves each `VaultHash` into a full
/// `FileEntry` and performs no cryptographic or storage work.
///
/// # Arguments
/// * `vault` - The vault instance used for database lookup.
/// * `hashes` - The encrypted content hashes to rekey.
///
/// # Returns
/// A `Vec<PendingRekeyTask>` in the same order as the input hashes.
///
/// # Errors
/// Returns `RekeyError` if a hash is not found or the database query fails.
//
// // 阶段 1: 根据保险库数据库验证文件哈希并准备密钥轮换任务。
// //
// // 此阶段只读取数据库。它将每个 `VaultHash` 解析为完整的 `FileEntry`，
// // 不执行任何加密或存储操作。
// //
// // # 参数
// // * `vault` - 用于数据库查询的保险库实例。
// // * `hashes` - 要轮换密钥的加密内容哈希。
// //
// // # 返回
// // 与输入哈希顺序一致的 `Vec<PendingRekeyTask>`。
// //
// // # 错误
// // 如果哈希不存在或数据库查询失败，则返回 `RekeyError`。
pub(crate) fn prepare_rekey_tasks(
    vault: &Vault,
    hashes: &[VaultHash],
) -> Result<Vec<PendingRekeyTask>, RekeyError> {
    let mut tasks = Vec::with_capacity(hashes.len());

    for hash in hashes {
        // 1. 根据哈希从数据库解析完整文件条目。
        match query::check_by_hash(vault, hash)? {
            QueryFileResult::Found(file_entry) => tasks.push(PendingRekeyTask { file_entry }),
            QueryFileResult::NotFound => return Err(RekeyError::FileNotFound(hash.clone())),
        }
    }

    Ok(tasks)
}

/// Stage 2: Re-encrypts a file's content into a temporary location using a streaming pipeline.
///
/// This is a standalone, thread-safe function that performs the expensive I/O and CPU work
/// with low memory overhead. It directly pipes the decryption stream into the encryption
/// stream in memory, writing the final output to a temporary location managed by the storage backend.
pub(crate) fn rekey_task(
    storage: &dyn StorageBackend,
    pending: PendingRekeyTask,
) -> Result<RekeyTask, RekeyError> {
    let file_entry = pending.file_entry;

    // Get the input and output streams from the storage backend.
    let mut encrypted_reader = storage.reader(&file_entry.sha256sum)?;
    let (mut staging_writer, staging_token) = storage.prepare_write()?;

    // Generate a new password for the re-encrypted file.
    let new_password = generate_random_password(16);

    // Perform the in-memory streaming re-encryption.
    let (new_encrypted_hash, original_hash) = chunked_re_encrypt(
        &mut encrypted_reader,
        &mut staging_writer,
        &file_entry.encrypt_password,
        &new_password,
    )?;

    // Sanity check: the original content hash must never change.
    if original_hash != file_entry.original_sha256sum {
        return Err(RekeyError::OriginalHashMismatch {
            expected: file_entry.original_sha256sum.clone(),
            actual: original_hash,
        });
    }

    // Create the new FileEntry with updated credentials.
    let new_file_entry = FileEntry {
        sha256sum: new_encrypted_hash,
        encrypt_password: new_password,
        ..file_entry.clone()
    };

    // Create and return the rekey task, including the staging token for the new file.
    Ok(RekeyTask {
        old_hash: file_entry.sha256sum,
        new_file_entry,
        staging_token,
    })
}

/// Stage 3: Commits a batch of re-keyed files to the database and filesystem.
///
/// This function executes all changes within a single transaction. It updates the
/// database records, commits the new files from temporary storage, and deletes the old files.
/// If any step fails, the entire operation is rolled back.
pub(crate) fn commit_rekey_tasks(
    vault: &mut Vault,
    tasks: Vec<RekeyTask>,
) -> Result<(), RekeyError> {
    if tasks.is_empty() {
        return Ok(());
    }

    let tx = vault.database_connection.transaction()?;

    for task in tasks {
        // --- Database Operations ---
        // 1. Fetch existing metadata for the old hash, inside the transaction
        let old_entry = {
            let core_info: Option<(VaultHash, VaultHash, String)> = tx.query_row(
                "SELECT sha256sum, original_sha256sum, encrypt_password FROM files WHERE sha256sum = ?1",
                params![&task.old_hash],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            ).optional()?;

            if let Some((sha256sum, original_sha256sum, encrypt_password)) = core_info {
                query::fetch_full_entry(&tx, &sha256sum, &original_sha256sum, &encrypt_password)?
            } else {
                continue; // Already processed or gone, skip
            }
        };
        let old_paths = query::list_paths_by_hash_in_conn(&tx, &task.old_hash)?;
        let mut old_path_tags = Vec::new();
        for old_path in &old_paths {
            if let Some((file_entry_id, _)) = query::resolve_file_entry_in_conn(&tx, old_path)? {
                let mut tag_stmt = tx.prepare("SELECT tag FROM tags WHERE file_entry_id = ?1")?;
                let tags = tag_stmt
                    .query_map(params![file_entry_id], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                old_path_tags.push((old_path.clone(), tags));
            }
        }

        tx.execute(
            "DELETE FROM tags WHERE file_entry_id IN (SELECT id FROM file_entries WHERE file_sha256sum = ?1)",
            params![&task.old_hash],
        )?;
        tx.execute(
            "DELETE FROM metadata WHERE file_sha256sum = ?1",
            params![&task.old_hash],
        )?;
        tx.execute(
            "DELETE FROM files WHERE sha256sum = ?1",
            params![&task.old_hash],
        )?;

        tx.execute(
            "INSERT INTO files (sha256sum, original_sha256sum, encrypt_password) VALUES (?1, ?2, ?3)",
            params![
                &task.new_file_entry.sha256sum,
                &task.new_file_entry.original_sha256sum,
                &task.new_file_entry.encrypt_password,
            ],
        )?;

        for old_path in old_paths {
            query::insert_file_entry_in_conn(&tx, &old_path, &task.new_file_entry.sha256sum)?;
        }

        let mut tag_stmt = tx.prepare("INSERT INTO tags (file_entry_id, tag) VALUES (?1, ?2)")?;
        for (old_path, tags) in old_path_tags {
            if let Some((file_entry_id, _)) = query::resolve_file_entry_in_conn(&tx, &old_path)? {
                for tag in tags {
                    tag_stmt.execute(params![file_entry_id, tag])?;
                }
            }
        }
        if !old_entry.metadata.is_empty() {
            let mut meta_stmt = tx.prepare(
                "INSERT INTO metadata (file_sha256sum, meta_key, meta_value) VALUES (?1, ?2, ?3)",
            )?;
            for meta in old_entry.metadata {
                meta_stmt.execute(params![
                    &task.new_file_entry.sha256sum,
                    &meta.key,
                    &meta.value
                ])?;
            }
        }

        // --- Filesystem Operations ---
        vault
            .storage
            .commit_write(task.staging_token, &task.new_file_entry.sha256sum)?;
        vault.storage.delete(&task.old_hash)?;
    }

    tx.commit()?;
    Ok(())
}
