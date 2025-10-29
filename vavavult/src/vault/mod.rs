use rusqlite::Connection;
use std::path::{Path, PathBuf};

mod add;
mod config;
mod create;
mod extract;
mod query;
mod remove;
mod update;

use crate::common::metadata::MetadataEntry;
pub use crate::file::FileEntry;
use crate::vault::add::{add_file, commit_add_files, encrypt_file_for_add, EncryptedAddingFile};
use crate::vault::create::{create_vault, open_vault};
pub use crate::vault::extract::{ExtractError, extract_file};
use crate::vault::query::{check_by_hash, check_by_original_hash, check_by_path, find_by_keyword, find_by_tag, list_all_files, list_all_recursive, list_by_path};
use crate::vault::remove::remove_file;
use crate::vault::update::{add_tag, add_tags, clear_tags, move_file, remove_file_metadata, remove_tag, remove_vault_metadata, rename_file, rename_file_inplace, set_file_metadata, set_name, set_vault_metadata, touch_vault_update_time};
pub use add::{AddFileError, AddTransaction};
pub use config::VaultConfig;
pub use create::{CreateError, OpenError};
pub use query::ListResult;
pub use query::{QueryError, QueryResult};
pub use remove::RemoveError;
pub use update::UpdateError;
use crate::common::hash::VaultHash;
use crate::file::VaultPath;

/// Represents a vault loaded into memory.
///
/// It holds the vault's configuration and a live database connection,
/// providing the primary interface for all vault operations.
#[derive(Debug)]
pub struct Vault {
    /// The root path of the vault directory.
    pub root_path: PathBuf,
    /// The vault's configuration, loaded from `master.json`.
    pub config: VaultConfig,
    /// An open connection to the vault's database.
    pub database_connection: Connection,
}

impl Vault {
    /// Creates a new Vault at the specified path.
    ///
    /// This will create the root directory and initialize the `master.json`
    /// configuration and the `master.db` database.
    ///
    /// # Arguments
    /// * `root_path` - The path where the vault directory will be created.
    /// * `vault_name` - A name for the vault, stored in the configuration.
    /// * `password` - An optional password. If provided, the vault will be encrypted.
    ///
    /// # Errors
    /// Returns `CreateError` if the directory already exists and is not empty,
    /// or if there are I/O or database initialization errors.
    pub fn create_vault(
        root_path: &Path,
        vault_name: &str,
        password: Option<&str>,
    ) -> Result<Vault, CreateError> {
        create_vault(root_path, vault_name, password)
    }

    /// Opens an existing Vault from the specified path.
    ///
    /// # Arguments
    /// * `root_path` - The path to the existing vault directory.
    /// * `password` - An optional password. Required if the vault is encrypted.
    ///
    /// # Errors
    /// Returns `OpenError` if the path does not exist, the configuration
    /// is missing or corrupt, or if an incorrect password is provided for an
    /// encrypted vault.
    pub fn open_vault(root_path: &Path, password: Option<&str>) -> Result<Vault, OpenError> {
        open_vault(root_path, password)
    }

    // --- 查找 API (已清理) ---

    /// 按 `VaultPath` 查找文件条目。
    pub fn find_by_path(&self, path: &VaultPath) -> Result<QueryResult, QueryError> {
        check_by_path(self, path)
    }

    /// [重构] (请求 1)
    /// 按加密后内容的 `VaultHash` 查找文件条目。
    pub fn find_by_hash(&self, hash: &VaultHash) -> Result<QueryResult, QueryError> {
        check_by_hash(self, hash)
    }

    /// [新增] (请求 2)
    /// 按原始 (未加密) 内容的 `VaultHash` 查找文件条目。
    pub fn find_by_original_hash(&self, original_hash: &VaultHash) -> Result<QueryResult, QueryError> {
        check_by_original_hash(self, original_hash)
    }

    /// 查找与特定标签关联的所有文件。
    pub fn find_by_tag(&self, tag: &str) -> Result<Vec<FileEntry>, QueryError> {
        find_by_tag(self, tag)
    }

    /// 按关键字模糊搜索 (不区分大小写)。
    /// 搜索匹配 `keyword` 的文件路径或标签。
    pub fn find_by_keyword(&self, keyword: &str) -> Result<Vec<FileEntry>, QueryError> {
        find_by_keyword(self, keyword)
    }

    // --- 列表 API (根据您的新请求重构) ---

    /// 列出保险库中当前存储的所有文件 (返回完整条目)。
    pub fn list_all(&self) -> Result<Vec<FileEntry>, QueryError> {
        list_all_files(self)
    }

    /// 仅列出给定目录路径下的文件和子目录 (非递归)。
    ///
    /// 返回的 `Vec` 包含：
    /// - 文件: `VaultPath` (例如 "/docs/file.txt")
    /// - 子目录: `VaultPath` (例如 "/docs/images/")
    ///
    /// # Errors
    /// 如果 `path` 不是目录 (例如 "/a.txt")，则返回 `QueryError::NotADirectory`。
    pub fn list_by_path(&self, path: &VaultPath) -> Result<Vec<VaultPath>, QueryError> {
        list_by_path(self, path)
    }

    /// 递归列出一个目录下的所有文件，并返回它们的 `VaultHash`。
    ///
    /// # Errors
    /// 如果 `path` 不是目录 (例如 "/a.txt")，则返回 `QueryError::NotADirectory`。
    pub fn list_all_recursive(&self, path: &VaultPath) -> Result<Vec<VaultHash>, QueryError> {
        list_all_recursive(self, path)
    }

    /// [修改] 添加一个新文件到保险库 (便捷包装函数)。
    ///
    /// # Arguments
    /// * `source_path` - 本地文件系统上的文件路径。
    /// * `dest_path` - 在保险库中的目标路径。
    ///   - 如果 `dest_path` 是一个文件路径 (e.g., `/docs/report.txt`), 文件将被保存到该路径。
    ///   - 如果 `dest_path` 是一个目录路径 (e.g., `/docs/`), 源文件的名称将被自动附加 (e.g., `/docs/source_file.txt`)。
    ///
    /// # Returns
    /// 成功时返回添加文件的 SHA256 哈希。
    ///
    /// # Errors
    /// 如果源文件不存在，或者与保险库中已有的文件路径或内容重复，则返回 `AddFileError`。
    pub fn add_file(
        &mut self,
        source_path: &Path,
        dest_path: &VaultPath,
    ) -> Result<VaultHash, AddFileError> {
        let result = add_file(self, source_path, dest_path)?;

        touch_vault_update_time(self)?;
        Ok(result)
    }

    /// 阶段 1: 加密一个文件并准备用于批量提交 (线程安全)。
    ///
    /// # Arguments
    /// * `source_path` - 本地文件系统上的文件路径。
    /// * `dest_path` - 在保险库中的最终目标路径。
    ///   - 如果 `dest_path` 是一个文件路径 (e.g., `/docs/report.txt`), 文件将被加密为该路径。
    ///   - 如果 `dest_path` 是一个目录路径 (e.g., `/docs/`), 源文件的名称将被自动附加 (e.g., `/docs/source_file.txt`)。
    ///
    /// # Returns
    /// 一个 `EncryptedAddingFile` 对象，准备好传递给 `commit_add_files`。
    ///
    /// # Errors
    /// 如果源文件无法读取或最终路径无效，则返回 `AddFileError`。
    pub fn encrypt_file_for_add(
        &self,
        source_path: &Path,
        dest_path: &VaultPath,
    ) -> Result<EncryptedAddingFile, AddFileError> {
        encrypt_file_for_add(self, source_path, dest_path)
    }

    /// 阶段 2: 提交一个或多个已加密的文件到保险库 (需要独占访问)。
    /// ... (签名不变, 内部已使用 EncryptedAddingFile) ...
    pub fn commit_add_files(
        &mut self,
        files: Vec<EncryptedAddingFile>,
    ) -> Result<(), AddFileError> {
        if files.is_empty() {
            return Ok(());
        }
        commit_add_files(self, files)?;
        touch_vault_update_time(self)?;
        Ok(())
    }

    /// Moves a file within the vault to a new path.
    ///
    /// - If `target_path` is a directory (e.g., `/new/dir/`), the file is moved there, keeping its original filename.
    /// - If `target_path` is a file (e.g., `/new/dir/new_name.txt`), the file is moved and renamed.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to move (URL-safe Base64 string).
    /// * `target_path` - The target [`VaultPath`].
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found, the target path is invalid or already taken by another file.
    pub fn move_file(&mut self, hash: &VaultHash, target_path: &VaultPath) -> Result<(), UpdateError> {
        move_file(self, &hash, target_path)?;
        touch_vault_update_time(self)
    }

    /// Renames a file in its current directory.
    ///
    /// Only changes the filename part, keeping the parent directory the same.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to rename (URL-safe Base64 string).
    /// * `new_filename` - The new filename (must not contain path separators `/` or `\`).
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found, the `new_filename` is invalid, or the resulting path is already taken.
    pub fn rename_file_inplace(&mut self, hash: &VaultHash, new_filename: &str) -> Result<(), UpdateError> {
        rename_file_inplace(self, &hash, new_filename)?;
        touch_vault_update_time(self)
    }

    /// Adds a single tag to a file.
    ///
    /// If the tag already exists on the file, the operation succeeds with no change.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to tag.
    /// * `tag` - The tag to add.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    pub fn add_tag(&mut self, hash:&VaultHash, tag: &str) -> Result<(), UpdateError> {
        add_tag(self, hash, tag)?;
        touch_vault_update_time(self)
    }

    /// Adds multiple tags to a file in a single transaction.
    ///
    /// Existing tags are ignored.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to tag.
    /// * `tags` - A slice of string slices representing the tags to add.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    pub fn add_tags(&mut self, hash:&VaultHash, tags: &[&str]) -> Result<(), UpdateError> {
        add_tags(self, hash, tags)?;
        touch_vault_update_time(self)
    }

    /// Removes a single tag from a file.
    ///
    /// If the tag does not exist on the file, the operation succeeds with no change.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file.
    /// * `tag` - The tag to remove.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    pub fn remove_tag(&mut self, hash:&VaultHash, tag: &str) -> Result<(), UpdateError> {
        remove_tag(self, hash, tag)?;
        touch_vault_update_time(self)
    }

    /// Removes all tags from a file.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to clear tags from.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    pub fn clear_tags(&mut self, hash:&VaultHash) -> Result<(), UpdateError> {
        clear_tags(self, hash)?;
        touch_vault_update_time(self)
    }

    /// Sets a metadata key-value pair for a file.
    ///
    /// If the key already exists, its value will be updated. If it does not exist,
    /// a new key-value pair will be created.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to modify.
    /// * `key` - The metadata key.
    /// * `value` - The metadata value.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    pub fn set_file_metadata(
        &mut self,
        hash:&VaultHash,
        metadata: MetadataEntry,
    ) -> Result<(), UpdateError> {
        set_file_metadata(self, hash, metadata)?;
        touch_vault_update_time(self)
    }

    /// Removes a metadata key-value pair from a file.
    ///
    /// If the key does not exist, the operation succeeds with no change.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to modify.
    /// * `key` - The metadata key to remove.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    pub fn remove_file_metadata(&mut self, hash:&VaultHash, key: &str) -> Result<(), UpdateError> {
        remove_file_metadata(self, hash, key)?;
        touch_vault_update_time(self)
    }

    /// Extracts a file from the vault to a specified destination path.
    ///
    /// This copies the physical file from the vault's internal storage to a
    /// location on the external filesystem.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to extract.
    /// * `destination_path` - The full path (including filename) where the file will be saved.
    ///
    /// # Errors
    /// Returns `ExtractError` if the file is not found in the vault or if there
    /// is a filesystem error during the copy.
    pub fn extract_file(
        &self,
        hash: &VaultHash,
        destination_path: &Path,
    ) -> Result<(), ExtractError> {
        extract_file(self, hash, destination_path)
    }

    /// Removes a file from the vault.
    ///
    /// This deletes both the database record (and all associated tags/metadata
    /// via cascading delete) and the physical file from the filesystem.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to remove.
    ///
    /// # Errors
    /// Returns `RemoveError` if the file is not found or if there is a filesystem error.
    pub fn remove_file(&mut self, hash: &VaultHash) -> Result<(), RemoveError> {
        remove_file(self, hash)?;
        touch_vault_update_time(self)?;
        Ok(())
    }

    /// Sets the name of the vault.
    ///
    /// This updates the `name` property in the in-memory config and writes the
    /// change to the `master.json` file.
    ///
    /// # Arguments
    /// * `new_name` - The new name for the vault.
    ///
    /// # Errors
    /// Returns `UpdateError` if the configuration cannot be serialized or written to disk.
    pub fn set_name(&mut self, new_name: &str) -> Result<(), UpdateError> {
        set_name(self, new_name)?;
        touch_vault_update_time(self)
    }
    /// Sets a metadata key-value pair for the vault itself.
    ///
    /// This is an "upsert" operation. If the key already exists, its value is
    /// updated. If not, a new entry is created.
    ///
    /// # Arguments
    /// * `metadata` - The `MetadataEntry` to set in the vault's configuration.
    ///
    /// # Errors
    /// Returns `UpdateError` on I/O or serialization issues.
    pub fn set_vault_metadata(&mut self, metadata: MetadataEntry) -> Result<(), UpdateError> {
        set_vault_metadata(self, metadata)?;
        touch_vault_update_time(self)
    }

    /// Removes a metadata key-value pair from the vault.
    ///
    /// If the key does not exist, the operation succeeds with no change.
    ///
    /// # Arguments
    /// * `key` - The key of the metadata entry to remove.
    ///
    /// # Errors
    /// Returns `UpdateError` on I/O or serialization issues if the key is removed.
    pub fn remove_vault_metadata(&mut self, key: &str) -> Result<(), UpdateError> {
        remove_vault_metadata(self, key)?;
        touch_vault_update_time(self)
    }
}
