use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use sha2::{Digest, Sha256};
use crate::file::encrypt::EncryptionCheck;
use crate::vault::common::normalize_path_name;
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

        // 3. 检查数据库中是否已存在同名文件
        let mut name_check_stmt = vault.database_connection.prepare("SELECT 1 FROM files WHERE name = ?1")?;
        if name_check_stmt.exists([&file_name])? {
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

        // 5. 检查数据库中是否已存在该校验和 (内容重复)
        let mut content_check_stmt = vault.database_connection.prepare("SELECT 1 FROM files WHERE sha256sum = ?1")?;
        if content_check_stmt.exists([&sha256sum])? {
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

// --- 单元测试模块 ---
// 只有在 `cargo test` 时才会编译这部分代码
#[cfg(test)]
mod tests {
    use super::*; // 导入 add.rs 中的所有内容
    use crate::vault::create_vault; // 导入 create_vault 函数
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir; // 使用 tempfile 库来创建临时目录，避免弄乱文件系统

    #[test]
    fn test_add_file_successfully() {
        // 1. 准备环境
        let dir = tempdir().unwrap(); // 创建一个临时目录
        let vault_path = dir.path();
        let mut vault = create_vault(vault_path, "test_vault").unwrap();

        // 创建临时源文件
        let source_file_path1 = vault_path.join("my_test_file.txt");
        let mut source_file1 = File::create(&source_file_path1).unwrap();
        writeln!(source_file1, "Hello, Vault!").unwrap();

        let source_file_path2 = vault_path.join("my_test_file2.txt");
        let mut source_file2 = File::create(&source_file_path2).unwrap();
        writeln!(source_file2, "Hello, Vault New!").unwrap();

        // 2. 执行操作
        let result1 = add_file(&mut vault, &source_file_path1, None);
        let result2 = add_file(&mut vault, &source_file_path2, Some("/a/b/c/new_name.txt"));

        // 3. 断言结果
        assert!(result1.is_ok());
        assert!(result2.is_ok());
        let sha256sum1 = result1.unwrap();
        let sha256sum2 = result2.unwrap();

        // 4. 验证数据库
        let mut stmt = vault.database_connection.prepare("SELECT name FROM files WHERE sha256sum = ?1").unwrap();
        let file_name1: String = stmt.query_row([&sha256sum1], |row| row.get(0)).unwrap();
        let file_name2: String = stmt.query_row([&sha256sum2], |row| row.get(0)).unwrap();

        assert_eq!(file_name1, "/my_test_file.txt");
        assert_eq!(file_name2, "/a/b/c/new_name.txt");

        // 验证文件是否已复制到 data 目录
        let internal_path = vault.root_path.join(sha256sum1);
        assert!(internal_path.exists());
    }

    #[test]
    fn test_add_duplicate_file_name() {
        // 1. 准备环境
        let dir = tempdir().unwrap();
        let vault_path = dir.path();
        let mut vault = create_vault(vault_path, "test_vault").unwrap();

        // 创建第一个文件
        let source_file_path1 = vault_path.join("file1.txt");
        File::create(&source_file_path1).unwrap().write_all(b"content1").unwrap();
        add_file(&mut vault, &source_file_path1, Some("shared_name.txt")).unwrap();

        // 创建第二个内容不同的文件
        let source_file_path2 = vault_path.join("file2.txt");
        File::create(&source_file_path2).unwrap().write_all(b"content2").unwrap();

        // 2. 执行操作 (尝试用同样的名字添加第二个文件)
        let result = add_file(&mut vault, &source_file_path2, Some("shared_name.txt"));

        // 3. 断言结果
        assert!(matches!(result, Err(AddFileError::DuplicateFileName(_))));
    }
}