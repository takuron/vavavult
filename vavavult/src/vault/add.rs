use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use sha2::{Digest, Sha256};
use crate::file::encrypt::EncryptionCheck;
use crate::vault::common::normalize_path_name;
use crate::vault::query;
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
        // 1. 验证源文件是否存在且是一个文件
        if !source_path.is_file() {
            return Err(AddFileError::SourceNotFound(source_path.to_path_buf()));
        }

        // 2. 确定在保险库中使用的名称
        let raw_name = match dest_name {
            Some(name) => name.to_string(), // 使用提供的自定义名称
            None => source_path // 如果未提供，则使用原始文件名
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or(AddFileError::InvalidFileName)?
                .to_string(),
        };
        let file_name = normalize_path_name(&raw_name);

        // 3. 使用 query 模块检查文件名是否存在
        if let QueryResult::Found(_) = query::check_by_name(vault, &file_name)? {
            return Err(AddFileError::DuplicateFileName(file_name));
        }

        // 4. 读取文件内容并计算 SHA256 校验和
        let mut file = fs::File::open(source_path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 4096]; // 4KB 缓冲区
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        let sha256sum_bytes = hasher.finalize();
        let sha256sum = hex::encode(sha256sum_bytes);

        // 5. 使用 query 模块检查哈希是否存在
        if let QueryResult::Found(_) = query::check_by_hash(vault, &sha256sum)? {
            return Err(AddFileError::DuplicateContent(sha256sum));
        }

        // 6. 准备内部存储目录，并复制文件
        // 我们将文件存储在 vault_root/data/ 目录下，并以其校验和命名
        fs::create_dir_all(&vault.root_path)?;
        let dest_path = vault.root_path.join(&sha256sum);
        fs::copy(source_path, &dest_path)?;

        // 7. 在数据库中插入文件记录
        // 注意：目前我们假设没有加密
        vault.database_connection.execute(
            "INSERT INTO files (sha256sum, name, encrypt_type, encrypt_password, encrypt_check) VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                &sha256sum,
                &file_name, // 使用我们确定的名称
                &vault.config.encrypt_type, // 使用保险库的全局加密设置
                "", // 当前版本无密码
                EncryptionCheck{
                    raw: "".to_string(),
                    encrypted: "".to_string()
                }, // 当前版本无加密检查
            ),
        )?;

        // 8. 返回成功和文件的校验和
        Ok(sha256sum)
    }

