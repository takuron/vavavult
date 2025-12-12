use crate::common::hash::VaultHash;
use crate::storage::StorageBackend;
use sha2::{Digest, Sha256};
use std::io;
use thiserror::Error;

const BUFFER_LEN: usize = 8192;

/// Defines errors that can occur during the file integrity verification process.
//
// // 定义在文件完整性验证过程中可能发生的错误。
#[derive(Debug, Error)]
pub enum VerifyError {
    /// The specified file hash was not found in the vault's database.
    //
    // // 在保险库数据库中未找到指定的文件哈希。
    #[error("File not found in vault's database: {0}")]
    NotFoundInDb(String),

    /// The calculated hash of the encrypted content does not match its identifier hash.
    /// This indicates that the file's data in the storage backend is corrupted.
    //
    // // 加密内容的计算哈希与其标识符哈希不匹配。
    // // 这表明存储后端中的文件数据已损坏。
    #[error("File is corrupt: integrity check failed for hash {0}")]
    IntegrityMismatch(String),

    /// A database query failed.
    //
    // // 数据库查询失败。
    #[error("Database query error: {0}")]
    Query(#[from] crate::vault::query::QueryError),

    /// An I/O error occurred while reading the encrypted file from the storage backend.
    //
    // // 从存储后端读取加密文件时发生 I/O 错误。
    #[error("Storage I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Verifies the integrity of an encrypted file by re-calculating its SHA256 hash
/// and comparing it to the expected hash (which is also its ID).
/// This is a fast, I/O-bound operation that does not perform decryption.
//
// // 通过重新计算加密文件的 SHA256 哈希并与预期哈希（即其 ID）进行比较，来验证其完整性。
// // 这是一个快速的、受 I/O 限制的操作，不执行解密。
pub fn verify_encrypted_file_hash(
    storage: &dyn StorageBackend,
    hash: &VaultHash,
) -> Result<(), VerifyError> {
    let mut reader = storage.reader(hash)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let calculated_hash = VaultHash::new(hasher.finalize().into());

    if calculated_hash == *hash {
        Ok(())
    } else {
        Err(VerifyError::IntegrityMismatch(hash.to_string()))
    }
}
