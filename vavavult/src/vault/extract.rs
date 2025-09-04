use std::path::Path;
use std::fs;
use crate::file::encrypt::{EncryptError, EncryptionType};
use crate::vault::{query, QueryResult, Vault};

#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("Database query error: {0}")]
    QueryError(#[from] query::QueryError),

    #[error("File system error: {0}")]
    FileSystemError(#[from] std::io::Error),

    #[error("File with SHA256 '{0}' not found.")]
    FileNotFound(String),

    #[error("File decryption failed: {0}")]
    DecryptionError(#[from] EncryptError),

    #[error("Password verification failed for file '{0}'. The record may be corrupt.")]
    PasswordVerificationFailed(String),
}

/// Extracts a file from the vault to a destination path.
pub fn extract_file(
    vault: &Vault,
    sha256sum: &str,
    destination_path: &Path,
) -> Result<(), ExtractError> {
    // 1. 在数据库中查找文件的完整信息
    let file_entry = match query::check_by_hash(vault, sha256sum)? {
        QueryResult::Found(entry) => entry,
        QueryResult::NotFound => {
            return Err(ExtractError::FileNotFound(sha256sum.to_string()));
        }
    };

    // 2. 确定源文件路径
    let internal_path = vault.root_path.join(sha256sum);
    if !internal_path.exists() {
        return Err(ExtractError::FileNotFound(sha256sum.to_string()));
    }

    // 3. 确保目标目录存在
    if let Some(parent_dir) = destination_path.parent() {
        fs::create_dir_all(parent_dir)?;
    }

    // 4. 根据文件的加密类型来决定提取方式
    match file_entry.encrypt_type {
        EncryptionType::Aes256Gcm => {
            let password = &file_entry.encrypt_password;

            // [核心修改] 在解密前，先用 encrypt_check 验证密码的正确性
            if !file_entry.encrypt_check.verify(password) {
                // 如果验证失败，立即返回一个明确的错误，而不是尝试解密
                return Err(ExtractError::PasswordVerificationFailed(sha256sum.to_string()));
            }

            // 验证通过后，才执行解密操作
            crate::file::encrypt::decrypt_file(&internal_path, destination_path, password)?;
        }
        EncryptionType::None => {
            // 非加密文件直接复制
            fs::copy(&internal_path, destination_path)?;
        }
    }

    Ok(())
}