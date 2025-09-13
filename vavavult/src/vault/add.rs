use std::{fs};
use std::io::Read;
use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use crate::common::constants::{META_FILE_ADD_TIME, META_FILE_SIZE, META_FILE_UPDATE_TIME, META_SOURCE_MODIFIED_TIME};
use crate::common::metadata::MetadataEntry;
use crate::file::encrypt::{EncryptError, EncryptionCheck, EncryptionType};
use crate::utils::path::normalize_path_name;
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

    #[error("Filename is not valid UTF-8")]
    InvalidFileName,

    #[error("Database query error: {0}")]
    QueryError(#[from] query::QueryError),

    #[error("A file with the same name '{0}' already exists in the vault.")]
    DuplicateFileName(String),

    #[error("A file with the same content (SHA256: {0}) already exists in the vault.")]
    DuplicateContent(String),

    #[error("File encryption failed: {0}")]
    EncryptionError(#[from] EncryptError),

    #[error("Failed to update vault timestamp: {0}")]
    TimestampUpdateError(#[from] UpdateError),
}


    /// 将一个新文件添加到保险库中。
    ///
    /// 这个过程包括：
    /// 1. 验证源文件路径。
    /// 2. 确定文件在保险库中的存储名称（使用自定义名称或源文件名）。
    /// 3. 计算文件的 SHA256 校验和。
    /// 4. 检查文件名或文件内容是否已存在。
    /// 5. 如果是新文件，则将其复制到内部存储目录。
    /// 6. 在数据库中为文件创建一个新条目。
    ///
    /// # Arguments
    /// * `source_path` - 要添加到保险库的文件的路径。
    /// * `dest_name` - 可选参数，用于在保险库中为文件指定一个自定义的存储路径/名称。
    ///   如果为 `None`，则使用源文件的原始文件名。
    ///
    /// # Returns
    /// 成功时返回文件的 SHA256 校验和 (`String`)，否则返回 `AddFileError`。
    pub fn add_file(vault: &mut Vault, source_path: &Path, dest_name: Option<&str>) -> Result<String, AddFileError> {
        // 1. 验证和确定文件名
        if !source_path.is_file() {
            return Err(AddFileError::SourceNotFound(source_path.to_path_buf()));
        }
        let raw_name = dest_name.map(|s| s.to_string()).unwrap_or_else(||
            source_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string()
        );
        if raw_name.is_empty() {
            return Err(AddFileError::InvalidFileName);
        }
        let file_name = normalize_path_name(&raw_name);

        // 2. 检查文件名是否已重复
        if let QueryResult::Found(_) = query::check_by_name(vault, &file_name)? {
            return Err(AddFileError::DuplicateFileName(file_name));
        }

        // --- 获取源文件元数据 ---
        let source_metadata = fs::metadata(source_path)?;
        let file_size = source_metadata.len();
        let source_modified_time: DateTime<Utc> = source_metadata.modified()?.into();

        // 3. 根据保险库类型处理文件
        let sha256sum: String;
        let per_file_password: String;
        let per_file_encrypt_check: EncryptionCheck;

        if vault.config.encrypt_type == EncryptionType::Aes256Gcm {
            per_file_password = generate_random_password(16);
            let temp_file_name = format!(".temp_{}", generate_random_string(24));
            let temp_file_path = vault.root_path.join(&temp_file_name);
            let _guard = ScopeGuard::new(|| {
                let _ = fs::remove_file(&temp_file_path);
            });
            sha256sum = crate::file::encrypt::encrypt_file(source_path, &temp_file_path, &per_file_password)?;
            per_file_encrypt_check = EncryptionCheck::new(&per_file_password)?;

            if let QueryResult::Found(_) = query::check_by_hash(vault, &sha256sum)? {
                return Err(AddFileError::DuplicateContent(sha256sum));
            }

            let final_path = vault.root_path.join(&sha256sum);
            fs::rename(&temp_file_path, final_path)?;
        } else {
            let mut file = fs::File::open(source_path)?;
            let mut hasher = Sha256::new();
            let mut buffer = [0; 4096];
            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
            let sha256sum_bytes = hasher.finalize();
            sha256sum = hex::encode(sha256sum_bytes);

            if let QueryResult::Found(_) = query::check_by_hash(vault, &sha256sum)? {
                return Err(AddFileError::DuplicateContent(sha256sum));
            }

            let dest_path = vault.root_path.join(&sha256sum);
            fs::copy(source_path, &dest_path)?;

            per_file_password = "".to_string();
            per_file_encrypt_check = EncryptionCheck { raw: "".to_string(), encrypted: "".to_string() };
        }

        // 4. 在数据库中插入文件记录和元数据
        let tx = vault.database_connection.transaction()?;
        {
            tx.execute(
                "INSERT INTO files (sha256sum, name, encrypt_type, encrypt_password, encrypt_check) VALUES (?1, ?2, ?3, ?4, ?5)",
                (
                    &sha256sum,
                    &file_name,
                    &vault.config.encrypt_type,
                    &per_file_password,
                    &per_file_encrypt_check,
                ),
            )?;

            let now = now_as_rfc3339_string();
            let metadata_to_add = vec![
                MetadataEntry { key: META_FILE_ADD_TIME.to_string(), value: now.clone() },
                MetadataEntry { key: META_FILE_UPDATE_TIME.to_string(), value: now },
                MetadataEntry { key: META_FILE_SIZE.to_string(), value: file_size.to_string() },
                MetadataEntry { key: META_SOURCE_MODIFIED_TIME.to_string(), value: source_modified_time.to_rfc3339() },
            ];

            let mut stmt = tx.prepare("INSERT INTO metadata (file_sha256sum, meta_key, meta_value) VALUES (?1, ?2, ?3)")?;
            for meta in metadata_to_add {
                stmt.execute((&sha256sum, &meta.key, &meta.value))?;
            }
        }

        tx.commit()?;

        Ok(sha256sum)
    }

// [新增] 一个简单的 ScopeGuard 实现，用于资源清理
// 当 guard 变量离开作用域时，它的 Drop trait 会被调用，从而执行闭包 F
struct ScopeGuard<F: FnMut()> {
    callback: F,
}

impl<F: FnMut()> ScopeGuard<F> {
    fn new(callback: F) -> Self {
        ScopeGuard { callback }
    }
}

impl<F: FnMut()> Drop for ScopeGuard<F> {
    fn drop(&mut self) {
        (self.callback)();
    }
}

