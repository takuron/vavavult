use std::io;
use thiserror::Error;

use crate::common::hash::VaultHash;
use crate::crypto::stream_cipher::{StreamCipherError, stream_decrypt};
use crate::vault::Vault;
use crate::vault::query;

/// Defines errors that can occur during the file integrity verification process.
//
// // 定义在文件完整性验证过程中可能发生的错误。
#[derive(Debug, Error)]
pub enum VerifyError {
    /// The specified file hash was not found in the vault's database.
    //
    // // 在保险库数据库中未找到指定的文件哈希。
    #[error("File not found in vault: {0}")]
    NotFound(String),
    /// The calculated hash of the decrypted content does not match the stored original hash.
    /// This indicates that the file's data in the storage backend is corrupted.
    //
    // // 解密后内容的计算哈希与存储的原始哈希不匹配。
    // // 这表明存储后端中的文件数据已损坏。
    #[error("File is corrupt: integrity check failed for {0}")]
    IntegrityMismatch(String),
    /// A database query failed.
    //
    // // 数据库查询失败。
    #[error("Database query error: {0}")]
    Query(#[from] query::QueryError),
    /// An error occurred during the stream decryption process, often due to data corruption
    /// that prevents the cryptographic tag (GCM) from being authenticated.
    //
    // // 流式解密过程中发生错误，通常是由于数据损坏导致加密标签 (GCM) 无法通过认证。
    #[error("Stream cipher error: {0}")]
    StreamCipher(#[from] StreamCipherError),
    /// An I/O error occurred while reading the encrypted file from the storage backend.
    //
    // // 从存储后端读取加密文件时发生 I/O 错误。
    #[error("Storage I/O error: {0}")]
    Io(#[from] io::Error),
}

/// The internal implementation for verifying a file's integrity.
//
// // 用于验证文件完整性的内部实现。
pub(crate) fn verify(vault: &Vault, hash: &VaultHash) -> Result<(), VerifyError> {
    let file_entry = match query::check_by_hash(vault, hash)? {
        query::QueryResult::Found(entry) => entry,
        query::QueryResult::NotFound => return Err(VerifyError::NotFound(hash.to_string())),
    };

    let mut reader = vault.storage.reader(hash)?;

    let calculated_hash =
        stream_decrypt(&mut reader, &mut io::sink(), &file_entry.encrypt_password)?;

    let expected_hash = &file_entry.original_sha256sum;

    if &calculated_hash == expected_hash {
        Ok(())
    } else {
        Err(VerifyError::IntegrityMismatch(hash.to_string()))
    }
}
