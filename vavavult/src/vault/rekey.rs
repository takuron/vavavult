//! Implements the logic for re-keying a file in the vault.
use crate::common::hash::VaultHash;
use crate::crypto::stream_cipher;
use crate::file::FileEntry;
use crate::storage::{StagingToken, StorageBackend};
use crate::utils::random::generate_random_password;
use crate::vault::query::{self, QueryError};
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

    /// An error occurred in the underlying stream cipher during encryption or decryption.
    //
    // // 在加密或解密期间，底层流密码发生错误。
    #[error("Encryption/Decryption error: {0}")]
    StreamCipher(#[from] stream_cipher::StreamCipherError),

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
}
/// A task representing a file that has been re-encrypted into a temporary location
/// and is ready for an atomic database and filesystem commit.
#[derive(Debug)]
pub struct RekeyTask {
    /// The hash of the file *before* re-keying.
    pub old_hash: VaultHash,
    /// The complete file entry *after* re-keying, with a new hash and password.
    pub new_file_entry: FileEntry,
    /// The token representing the newly encrypted data in a temporary location.
    pub staging_token: Box<dyn StagingToken>,
}

/// Stage 1: Re-encrypts a file's content into a temporary location using a streaming pipeline.
///
/// This is a standalone, thread-safe function that performs the expensive I/O and CPU work
/// with low memory overhead. It directly pipes the decryption stream into the encryption
/// stream in memory, writing the final output to a temporary location managed by the storage backend.
pub fn prepare_rekey_task(
    storage: &dyn StorageBackend,
    file_entry: &FileEntry,
) -> Result<RekeyTask, RekeyError> {
    // Get the input and output streams from the storage backend.
    let mut encrypted_reader = storage.reader(&file_entry.sha256sum)?;
    let (mut staging_writer, staging_token) = storage.prepare_write()?;

    // Generate a new password for the re-encrypted file.
    let new_password = generate_random_password(16);

    // Perform the in-memory streaming re-encryption.
    let (new_encrypted_hash, original_hash) = stream_cipher::stream_re_encrypt(
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
        old_hash: file_entry.sha256sum.clone(),
        new_file_entry,
        staging_token,
    })
}

/// Stage 2: Commits a batch of re-keyed files to the database and filesystem.
///
/// This function executes all changes within a single transaction. It updates the
/// database records, commits the new files from temporary storage, and deletes the old files.
/// If any step fails, the entire operation is rolled back.
pub fn execute_rekey_tasks(vault: &mut Vault, tasks: Vec<RekeyTask>) -> Result<(), RekeyError> {
    if tasks.is_empty() {
        return Ok(());
    }

    let tx = vault.database_connection.transaction()?;

    for task in tasks {
        // --- Database Operations ---
        // 1. Fetch existing tags and metadata for the old hash, inside the transaction
        let old_entry = {
            let core_info: Option<(VaultHash, crate::file::VaultPath, VaultHash, String)> = tx.query_row(
                "SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files WHERE sha256sum = ?1",
                params![&task.old_hash],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            ).optional()?;

            if let Some((sha256sum, path, original_sha256sum, encrypt_password)) = core_info {
                query::fetch_full_entry(
                    &tx,
                    &sha256sum,
                    path,
                    &original_sha256sum,
                    &encrypt_password,
                )?
            } else {
                continue; // Already processed or gone, skip
            }
        };

        tx.execute(
            "DELETE FROM tags WHERE file_sha256sum = ?1",
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
            "INSERT INTO files (sha256sum, path, original_sha256sum, encrypt_password) VALUES (?1, ?2, ?3, ?4)",
            params![
                &task.new_file_entry.sha256sum,
                &task.new_file_entry.path,
                &task.new_file_entry.original_sha256sum,
                &task.new_file_entry.encrypt_password,
            ],
        )?;

        if !old_entry.tags.is_empty() {
            let mut tag_stmt =
                tx.prepare("INSERT INTO tags (file_sha256sum, tag) VALUES (?1, ?2)")?;
            for tag in old_entry.tags {
                tag_stmt.execute(params![&task.new_file_entry.sha256sum, &tag])?;
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
