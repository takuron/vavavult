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

    #[error("Invalid hash format: {0}")]
    HashParseError(#[from] HashParseError),

    #[error("Integrity check failed for file '{path}': Expected original hash {expected}, but calculated {calculated}. The file in the vault might be corrupted.")]
    IntegrityCheckFailed {
        path: String,
        expected: String,
        calculated: String, 
    }
}

/// 从保险库中提取一个文件，并在解密后验证其完整性。
pub fn extract_file(
    vault: &Vault,
    sha256sum: &VaultHash, // 这是加密后内容的哈希
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
    let internal_path = vault.root_path.join(DATA_SUBDIR).join(sha256sum.to_string());
    if !internal_path.exists() {
        return Err(ExtractError::FileNotFound(sha256sum.to_string()));
    }

    // 3. 确保目标目录存在
    if let Some(parent_dir) = destination_path.parent() {
        fs::create_dir_all(parent_dir)?;
    }

    //  4. 执行解密并获取计算出的原始哈希 ---
    let password = &file_entry.encrypt_password;
    let calculated_original_hash = crate::file::encrypt::decrypt_file(
        &internal_path,
        destination_path, // 解密函数现在直接写入目标路径
        password
    )?; // decrypt_file 现在返回 Result<VaultHash, EncryptError>

    // --- [新增] 5. 比较哈希 ---
    if calculated_original_hash != file_entry.original_sha256sum {
        // 哈希不匹配！文件可能已损坏
        return Err(ExtractError::IntegrityCheckFailed {
            path: file_entry.path.to_string(), // 添加文件路径以便识别
            expected: file_entry.original_sha256sum.to_string(), // 转换为 String
            calculated: calculated_original_hash.to_string(), // 转换为 String
        });
    }

    // 如果哈希匹配，文件已成功解密并写入 destination_path
    Ok(())
}