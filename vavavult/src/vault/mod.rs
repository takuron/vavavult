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
use crate::vault::add::{add_file, commit_add_transaction_local, prepare_add_transaction};
use crate::vault::create::{create_vault, open_vault};
use crate::vault::extract::{ExtractError, extract_file};
use crate::vault::query::{
    check_by_hash, check_by_name, find_by_name_and_tag_fuzzy, find_by_name_fuzzy,
    find_by_name_or_tag_fuzzy, find_by_tag, list_all_files, list_by_path,
};
use crate::vault::remove::remove_file;
use crate::vault::update::{
    add_tag, add_tags, clear_tags, remove_file_metadata, remove_tag, remove_vault_metadata,
    rename_file, set_file_metadata, set_name, set_vault_metadata, touch_vault_update_time,
};
pub use add::{AddFileError, AddTransaction};
pub use config::VaultConfig;
pub use create::{CreateError, OpenError};
pub use query::ListResult;
pub use query::{QueryError, QueryResult};
pub use remove::RemoveError;
pub use update::UpdateError;
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
        // [修改] 将 password 参数传递给后端的 open_vault 函数
        open_vault(root_path, password)
    }

    /// Finds a file entry by its normalized path name.
    ///
    /// # Arguments
    /// * `name` - The normalized path name of the file (e.g., "/documents/report.txt").
    ///
    /// # Returns
    /// A `QueryResult` which is `Found(FileEntry)` if the file exists,
    /// or `NotFound` otherwise.
    ///
    /// # Errors
    /// Returns `QueryError` if there is a database issue or data inconsistency.
    pub fn find_by_name(&self, name: &str) -> Result<QueryResult, QueryError> {
        check_by_name(self, name)
    }

    /// [EXPERIMENTAL] Finds a file entry using a VaultPath.
    ///
    /// This method requires the `experimental_paths` feature to be enabled.
    ///
    /// # Arguments
    /// * `path` - A [`VaultPath`] representing the normalized path of the file.
    ///
    /// # Returns
    /// A `QueryResult` which is `Found(FileEntry)` if the file exists,
    /// or `NotFound` otherwise.
    ///
    /// # Errors
    /// Returns `QueryError` if there is a database issue or data inconsistency.
    #[cfg(feature = "experimental_paths")]
    pub fn find_by_vault_path(&self, path: &VaultPath) -> Result<QueryResult, QueryError> {
        // 桥接：调用现有的 &str API
        // 注意：这依赖于 `VaultPath` 的 `as_str()` 实现
        check_by_name(self, path.as_str())
    }

    /// Finds a file entry by its SHA256 hash.
    ///
    /// # Arguments
    /// * `sha256sum` - The SHA256 hash of the file content.
    ///
    /// # Returns
    /// A `QueryResult` which is `Found(FileEntry)` if the file exists,
    /// or `NotFound` otherwise.
    ///
    /// # Errors
    /// Returns `QueryError` if there is a database issue or data inconsistency.
    pub fn find_by_hash(&self, sha256sum: &str) -> Result<QueryResult, QueryError> {
        check_by_hash(self, sha256sum)
    }

    /// Lists all files currently stored in the vault.
    ///
    /// # Returns
    /// A `Vec<FileEntry>` containing all files.
    ///
    /// # Errors
    /// Returns `QueryError` if there is a database issue.
    pub fn list_all(&self) -> Result<Vec<FileEntry>, QueryError> {
        list_all_files(self)
    }

    /// Lists files and subdirectories directly under a given path.
    ///
    /// For example, querying for `/` might return files like `/a.txt` and `/b.txt`,
    /// and subdirectories like `c`.
    ///
    /// # Arguments
    /// * `path` - The path to list (e.g., "/", "/documents/").
    ///
    /// # Returns
    /// A `ListResult` containing separate vectors for files and subdirectory names.
    ///
    /// # Errors
    /// Returns `QueryError` if there is a database issue.
    pub fn list_by_path(&self, path: &str) -> Result<ListResult, QueryError> {
        list_by_path(self, path)
    }

    /// [EXPERIMENTAL] Lists files and subdirectories directly under a given VaultPath.
    ///
    /// This method requires the `experimental_paths` feature to be enabled.
    ///
    /// # Arguments
    /// * `path` - The [`VaultPath`] to list. It must represent a directory (e.g., `/a/b/` or `/`).
    ///   If a file path is provided, the contents of its parent directory will be listed.
    ///
    /// # Returns
    /// A `ListResult` containing separate vectors for files and subdirectory names.
    ///
    /// # Errors
    /// Returns `QueryError` if there is a database issue.
    #[cfg(feature = "experimental_paths")]
    pub fn list_by_vault_path(&self, path: &VaultPath) -> Result<ListResult, QueryError> {
        // 桥接：调用现有的 &str API
        // 注意：这依赖于 `VaultPath` 的 `as_str()` 实现
        list_by_path(self, path.as_str())
    }

    /// Finds all files associated with a specific tag.
    ///
    /// # Arguments
    /// * `tag` - The tag to search for.
    ///
    /// # Returns
    /// A `Vec<FileEntry>` containing all matching files.
    ///
    /// # Errors
    /// Returns `QueryError` if there is a database issue.
    pub fn find_by_tag(&self, tag: &str) -> Result<Vec<FileEntry>, QueryError> {
        find_by_tag(self, tag)
    }

    /// Finds all files whose name contains a given pattern (case-insensitive).
    ///
    /// # Arguments
    /// * `name_pattern` - The substring to search for within file names.
    ///
    /// # Returns
    /// A `Vec<FileEntry>` containing all matching files.
    ///
    /// # Errors
    /// Returns `QueryError` if there is a database issue.
    pub fn find_by_name_fuzzy(&self, name_pattern: &str) -> Result<Vec<FileEntry>, QueryError> {
        find_by_name_fuzzy(self, name_pattern)
    }

    /// Finds all files that have a specific tag and whose name contains a given pattern.
    ///
    /// # Arguments
    /// * `name_pattern` - The substring to search for within file names.
    /// * `tag` - The tag that files must be associated with.
    ///
    /// # Returns
    /// A `Vec<FileEntry>` containing all matching files.
    ///
    /// # Errors
    /// Returns `QueryError` if there is a database issue.
    #[deprecated(since = "0.2.2", note = "Please use `find_by_name_or_tag_fuzzy` instead for combined searching")]
    pub fn find_by_name_and_tag_fuzzy(
        &self,
        name_pattern: &str,
        tag: &str,
    ) -> Result<Vec<FileEntry>, QueryError> {
        find_by_name_and_tag_fuzzy(self, name_pattern, tag)
    }

    /// Finds all files whose name or tags contain a given pattern (case-insensitive).
    ///
    /// # Arguments
    /// * `keyword` - The substring to search for within file names OR tags.
    ///
    /// # Returns
    /// A `Vec<FileEntry>` containing all matching files.
    ///
    /// # Errors
    /// Returns `QueryError` if there is a database issue.
    pub fn find_by_name_or_tag_fuzzy(&self, keyword: &str) -> Result<Vec<FileEntry>, QueryError> {
        find_by_name_or_tag_fuzzy(self, keyword)
    }

    /// Adds a new file to the vault from a source path.
    ///
    /// The file's content is copied into the vault and a new database record is created.
    ///
    /// # Arguments
    /// * `source_path` - The path to the file on the local filesystem.
    /// * `dest_name` - An optional destination name/path for the file inside the vault.
    ///   If `None`, the original filename is used.
    ///
    /// # Returns
    /// The SHA256 hash of the added file on success.
    ///
    /// # Errors
    /// Returns `AddFileError` if the source file doesn't exist, or if a file with
    /// the same name or content already exists in the vault.
    pub fn add_file(
        &mut self,
        source_path: &Path,
        dest_name: Option<&str>,
    ) -> Result<String, AddFileError> {
        // --- 桥接逻辑 ---
        // 1. 确定最终的路径字符串 (V1 行为)
        let final_path_str = dest_name.map(|s| s.to_string()).unwrap_or_else(|| {
            source_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default() // V1 add_file 内部有空检查，这里也需要
                .to_string()
        });

        // V1 add_file 在这里会检查 raw_name 是否为空，我们也加上
        if final_path_str.is_empty() {
            // V1 返回 InvalidFileName，V2 我们映射到 InvalidFilePath
            return Err(AddFileError::InvalidFilePath("".to_string()));
        }

        // 2. 将字符串转换为 VaultPath
        let dest_vault_path = VaultPath::from(final_path_str.as_str());

        // 3. 调用 V2 内部的 add_file (它现在接受 &VaultPath)
        // 注意：add::add_file 是我们在 add.rs 中定义的便捷函数
        let result = add_file(self, source_path, &dest_vault_path)?;
        // --- 桥接结束 ---

        touch_vault_update_time(self)?;
        Ok(result)
    }

    /// [EXPERIMENTAL] Adds a new file to the vault at a specific VaultPath.
    ///
    /// This method requires the `experimental_paths` feature to be enabled.
    /// `dest_path` must represent a file path (not ending in '/').
    ///
    /// # Arguments
    /// * `source_path` - The path to the file on the local filesystem.
    /// * `dest_path` - The [`VaultPath`] where the file should be stored in the vault.
    ///   Must be a file path (e.g., `/a/b.txt`).
    ///
    /// # Returns
    /// The SHA256 hash of the added file on success.
    ///
    /// # Errors
    /// Returns `AddFileError` if the source file doesn't exist, if `dest_path` is
    /// a directory path (`InvalidFilePath`), or if a file with the same name or
    /// content already exists.
    #[cfg(feature = "experimental_paths")]
    pub fn add_file_at_path(
        &mut self,
        source_path: &Path,
        dest_path: &VaultPath,
    ) -> Result<String, AddFileError> {
        // 桥接：调用现有的 &str API
        self.add_file(source_path, Some(dest_path.as_str()))
    }

    /// Stage 1: Prepares a file addition transaction (thread-safe).
    ///
    /// Performs potentially time-consuming operations like reading the source file,
    /// calculating its hash, and encrypting it (if applicable) into a temporary file.
    /// This operation does not modify the vault's state.
    ///
    /// # Arguments
    /// * `source_path` - The path to the file on the local filesystem.
    ///
    /// # Returns
    /// An [`AddTransaction`] containing the necessary information (hash, temp path, etc.)
    /// to commit the addition later using `commit_add_transaction` or `commit_add_transaction_at_path`.
    ///
    /// # Errors
    /// Returns `AddFileError` if the source file cannot be read or encryption fails.
    pub fn prepare_add_transaction(
        &self,
        source_path: &Path,
    ) -> Result<AddTransaction, AddFileError> {
        prepare_add_transaction(self, source_path)
    }

    /// Stage 2: Commits a prepared file addition transaction (requires exclusive access).
    ///
    /// Performs quick operations requiring write access: checks for duplicates in the
    /// database, renames the temporary file to its final hash-based name, and inserts
    /// the file record into the database. Enforces file name rules.
    ///
    /// # Arguments
    /// * `transaction` - The [`AddTransaction`] returned by `prepare_add_transaction`.
    /// * `dest_name` - The desired name/path for the file inside the vault. Must adhere
    ///   to file name rules. Relative names are placed under the root.
    ///
    /// # Returns
    /// The SHA256 hash of the added file on success.
    ///
    /// # Errors
    /// Returns `AddFileError` if `dest_name` violates naming rules (`InvalidFilePath`),
    /// or if a file with the same name or content already exists. Also returns errors
    /// on database or filesystem issues during the commit phase.
    pub fn commit_add_transaction(
        &mut self,
        transaction: AddTransaction,
        dest_name: &str,
    ) -> Result<String, AddFileError> {
        let dest_vault_path = VaultPath::from(dest_name);
        let result = commit_add_transaction_local(self, transaction, &dest_vault_path)?;
        touch_vault_update_time(self)?;
        Ok(result)
    }

    /// [EXPERIMENTAL] Stage 2: Commits a prepared file addition transaction using a VaultPath (requires exclusive access).
    ///
    /// This method requires the `experimental_paths` feature to be enabled.
    /// `dest_path` must represent a file path.
    ///
    /// # Arguments
    /// * `transaction` - The [`AddTransaction`] returned by `prepare_add_transaction`.
    /// * `dest_path` - The [`VaultPath`] where the file should be stored in the vault. Must be a file path.
    ///
    /// # Returns
    /// The SHA256 hash of the added file on success.
    ///
    /// # Errors
    /// Returns `AddFileError` if `dest_path` is a directory path (`InvalidFilePath`),
    /// or if a file with the same name or content already exists. Also returns errors
    /// on database or filesystem issues during the commit phase.
    #[cfg(feature = "experimental_paths")]
    pub fn commit_add_transaction_at_path(
        &mut self,
        transaction: AddTransaction,
        dest_path: &VaultPath,
    ) -> Result<String, AddFileError> {
        // 桥接：调用现有的 &str API
        self.commit_add_transaction(transaction, dest_path.as_str())
    }

    /// Renames a file identified by its SHA256 hash.
    ///
    /// This only changes the `name` property in the database. The physical file,
    /// named by its hash, is not affected.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to rename.
    /// * `new_name` - The new name for the file.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found or if the new name is already taken.
    pub fn rename_file(&mut self, sha256sum: &str, new_name: &str) -> Result<(), UpdateError> {
        rename_file(self, sha256sum, new_name)?;
        touch_vault_update_time(self)
    }

    /// [EXPERIMENTAL] Renames a file identified by its SHA256 hash to a new VaultPath.
    ///
    /// This method requires the `experimental_paths` feature to be enabled.
    /// `new_path` must represent a file path.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to rename.
    /// * `new_path` - The new [`VaultPath`] for the file. Must be a file path.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found, if `new_path` is a directory
    /// path (`InvalidNewFilePath`), or if the new name is already taken.
    #[cfg(feature = "experimental_paths")]
    pub fn rename_file_to_path(
        &mut self,
        sha256sum: &str,
        new_path: &VaultPath,
    ) -> Result<(), UpdateError> {
        // 桥接：调用现有的 &str API
        self.rename_file(sha256sum, new_path.as_str())
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
    pub fn add_tag(&mut self, sha256sum: &str, tag: &str) -> Result<(), UpdateError> {
        add_tag(self, sha256sum, tag)?;
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
    pub fn add_tags(&mut self, sha256sum: &str, tags: &[&str]) -> Result<(), UpdateError> {
        add_tags(self, sha256sum, tags)?;
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
    pub fn remove_tag(&mut self, sha256sum: &str, tag: &str) -> Result<(), UpdateError> {
        remove_tag(self, sha256sum, tag)?;
        touch_vault_update_time(self)
    }

    /// Removes all tags from a file.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to clear tags from.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    pub fn clear_tags(&mut self, sha256sum: &str) -> Result<(), UpdateError> {
        clear_tags(self, sha256sum)?;
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
        sha256sum: &str,
        metadata: MetadataEntry,
    ) -> Result<(), UpdateError> {
        set_file_metadata(self, sha256sum, metadata)?;
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
    pub fn remove_file_metadata(&mut self, sha256sum: &str, key: &str) -> Result<(), UpdateError> {
        remove_file_metadata(self, sha256sum, key)?;
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
        sha256sum: &str,
        destination_path: &Path,
    ) -> Result<(), ExtractError> {
        extract_file(self, sha256sum, destination_path)
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
    pub fn remove_file(&mut self, sha256sum: &str) -> Result<(), RemoveError> {
        remove_file(self, sha256sum)?;
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
