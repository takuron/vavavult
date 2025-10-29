use std::path::Path;
use std::fs;
use crate::common::constants::DATA_SUBDIR;
use crate::common::hash::{HashParseError, VaultHash};
use crate::file::encrypt::EncryptError;
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

    #[error("Wrong hash error: {0}")]
    HashPauseError(#[from] HashParseError),
}

/// 从保险库中提取一个文件到目标路径。
pub fn extract_file(
    vault: &Vault,
    sha256sum: &VaultHash, // 这是加密后内容的 Base64 哈希
    destination_path: &Path,
) -> Result<(), ExtractError> {
    // 1. 在数据库中查找文件的完整信息 (query::check_by_hash 已更新为 V2)
    let file_entry = match query::check_by_hash(vault, sha256sum)? {
        QueryResult::Found(entry) => entry,
        QueryResult::NotFound => {
            return Err(ExtractError::FileNotFound(sha256sum.to_string()));
        }
    };

    // 2. [V2 修改] 确定源文件路径 (在 data/ 子目录下，文件名是哈希)
    let internal_path = vault.root_path.join(DATA_SUBDIR).join(sha256sum.to_string());
    if !internal_path.exists() {
        // 如果数据库记录存在但物理文件丢失，这是一个错误
        return Err(ExtractError::FileNotFound(sha256sum.to_string()));
    }

    // 3. 确保目标目录存在 (保持不变)
    if let Some(parent_dir) = destination_path.parent() {
        fs::create_dir_all(parent_dir)?;
    }

    let password = &file_entry.encrypt_password;
    crate::file::encrypt::decrypt_file(&internal_path, destination_path, password)?;

    Ok(())
}