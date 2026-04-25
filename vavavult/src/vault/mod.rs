use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod add;
mod config;
mod create;
mod extract;
mod fix;
mod metadata;
mod open;
mod path_ops;
mod query;
mod rekey;
mod remove;
mod tags;
mod update;

use crate::common::hash::VaultHash;
use crate::common::metadata::MetadataEntry;
use crate::file::VaultPath;
pub use crate::file::{FileEntry, FilePathEntry};
use crate::storage::StorageBackend;
use crate::storage::local::LocalStorage;
use std::io::{Read, Seek};

//- Internal implementation imports
use crate::vault::add::{
    add_file, add_from_reader, commit_addition_tasks as _commit_addition_tasks,
    encrypt_addition_task as _encrypt_addition_task,
    prepare_addition_tasks as _prepare_addition_tasks,
    prepare_addition_tasks_from_files as _prepare_addition_tasks_from_files,
    resolve_file_metadata as _resolve_file_metadata,
};
use crate::vault::create::create_vault;
use crate::vault::extract::{
    decrypt_extraction_task as _decrypt_extraction_task,
    decrypt_extraction_task_to_file as _decrypt_extraction_task_to_file, extract_file,
    open_extraction_task_reader as _open_extraction_task_reader, prepare_extraction_task,
    prepare_extraction_tasks as _prepare_extraction_tasks,
};
use crate::vault::fix::fix_file as _fix_file;
use crate::vault::metadata::{
    get_vault_metadata, remove_file_metadata, remove_vault_metadata, set_file_metadata,
    set_vault_metadata, touch_vault_update_time,
};
use crate::vault::open::open_vault;
use crate::vault::path_ops::{
    copy_file_path, create_empty_path, create_path_from_hash, move_path, rename_path_inplace,
};
#[allow(unused_imports)]
use crate::vault::query::{
    check_by_hash, check_by_hash_no_validation, check_by_original_hash, check_by_path,
    check_by_path_no_validation, find_by_hashes, find_by_keyword, find_by_paths, find_by_tag,
    get_enabled_vault_features, get_storage_file_count, get_total_file_count,
    is_vault_feature_enabled, list_all_files, list_all_recursive, list_by_path, list_paths_by_hash,
};
use crate::vault::rekey::{
    commit_rekey_tasks as _commit_rekey_tasks, prepare_rekey_tasks as _prepare_rekey_tasks,
    rekey_task as _rekey_task,
};
use crate::vault::remove::{force_remove_file, remove_file, remove_file_by_path};
use crate::vault::tags::{add_tag, add_tags, clear_tags, remove_tag};
use crate::vault::update::{enable_vault_feature, set_name, update_password as _update_password};

//- Public API type re-exports
pub use add::{AddFileError, AdditionTask, PendingAdditionTask, PrepareAdditionRequest};
pub use config::VaultConfig;
pub use create::CreateError;
pub use extract::{ExtractError, ExtractionTask};
pub use fix::FixError;
pub use metadata::MetadataError;
pub use open::OpenError;
pub use path_ops::PathOperationError;
pub use query::{
    DirectoryEntry, ListPathEntry, ListResult, QueryError, QueryFileResult, QueryPathResult,
};
pub use rekey::{PendingRekeyTask, RekeyError, RekeyTask};
pub use remove::{ForceRemoveError, RemoveError};
pub use tags::TagError;
pub use update::UpdateError;
pub use update::verify_encrypted_file_hash;

/// Represents a vault loaded into memory.
///
/// It holds the vault's configuration, a live database connection, and a handle
/// to the storage backend. It provides the primary interface for all vault operations.
//
// // 代表一个加载到内存中的保险库。
// //
// // 它持有保险库的配置、一个活动的数据库连接以及存储后端的句柄。
// // 它是所有保险库操作的主要接口。
#[derive(Debug)]
pub struct Vault {
    /// The root path of the vault directory (local path).
    // // 保险库目录的根路径 (本地路径)。
    pub root_path: PathBuf,
    /// The vault's configuration, loaded from `master.json`.
    // // 保险库的配置，从 `master.json` 加载。
    pub config: VaultConfig,
    /// An open connection to the vault's SQLite database.
    // // 一个到保险库 SQLite 数据库的打开的连接。
    pub database_connection: Connection,
    /// The abstract storage backend for file content (e.g., local FS, S3).
    // // 用于文件内容的抽象存储后端 (例如本地文件系统, S3)。
    pub storage: Arc<dyn StorageBackend>,
}

impl Vault {
    /// Creates a new Vault at the specified path with a custom storage backend.
    ///
    /// This will create the root directory (if local) and initialize the `master.json`
    /// configuration and the `master.db` database.
    ///
    /// # Arguments
    /// * `root_path` - The path where the vault metadata will be stored.
    /// * `vault_name` - A name for the vault, stored in the configuration.
    /// * `password` - An optional password. If provided, the vault database will be encrypted.
    /// * `backend` - The storage backend implementation to use for file content.
    ///
    /// # Errors
    /// Returns `CreateError` if the directory already exists and is not empty,
    /// or if there are I/O or database initialization errors.
    //
    // // 在指定路径创建一个新的保险库，并使用自定义的存储后端。
    // //
    // // 这将创建根目录 (如果是本地) 并初始化 `master.json` 配置文件和 `master.db` 数据库。
    // //
    // // # 参数
    // // * `root_path` - 将存储保险库元数据的路径。
    // // * `vault_name` - 保险库的名称，存储在配置中。
    // // * `password` - 可选的密码。如果提供，保险库数据库将被加密。
    // // * `backend` - 用于文件内容的存储后端实现。
    // //
    // // # 错误
    // // 如果目录已存在且不为空，或者存在 I/O 或数据库初始化错误，则返回 `CreateError`。
    pub fn create_vault(
        root_path: &Path,
        vault_name: &str,
        password: Option<&str>,
        backend: Arc<dyn StorageBackend>,
    ) -> Result<Vault, CreateError> {
        create_vault(root_path, vault_name, password, backend)
    }

    /// Creates a new Vault using the default Local Filesystem storage backend.
    ///
    /// This is a convenience wrapper around `create_vault`.
    ///
    /// # Arguments
    /// * `root_path` - The path where the vault and its data will be created.
    /// * `vault_name` - A name for the vault.
    /// * `password` - An optional password for encryption.
    ///
    /// # Errors
    /// Returns `CreateError` if the directory already exists and is not empty,
    /// or if there are I/O or database initialization errors.
    //
    // // 使用默认的本地文件系统存储后端创建一个新的保险库。
    // //
    // // 这是 `create_vault` 的便捷包装器。
    // //
    // // # 参数
    // // * `root_path` - 将创建保险库及其数据的路径。
    // // * `vault_name` - 保险库的名称。
    // // * `password` - 用于加密的可选密码。
    // //
    // // # 错误
    // // 如果目录已存在且不为空，或者存在 I/O 或数据库初始化错误，则返回 `CreateError`。
    pub fn create_vault_local(
        root_path: &Path,
        vault_name: &str,
        password: Option<&str>,
    ) -> Result<Vault, CreateError> {
        let backend = Arc::new(LocalStorage::new(root_path));
        create_vault(root_path, vault_name, password, backend)
    }

    /// Opens an existing Vault with a custom storage backend.
    ///
    /// # Arguments
    /// * `root_path` - The path to the existing vault directory (containing `master.json`).
    /// * `password` - An optional password. Required if the vault is encrypted.
    /// * `backend` - The storage backend implementation to use.
    ///
    /// # Errors
    /// Returns `OpenError` if the path does not exist, the configuration
    /// is missing/corrupt, or if the password is incorrect.
    //
    // // 使用自定义存储后端打开一个已存在的保险库。
    // //
    // // # 参数
    // // * `root_path` - 已存在保险库目录的路径 (包含 `master.json`)。
    // // * `password` - 可选的密码。如果保险库已加密，则此项为必需。
    // // * `backend` - 要使用的存储后端实现。
    // //
    // // # 错误
    // // 如果路径不存在、配置丢失/损坏，或者密码不正确，则返回 `OpenError`。
    pub fn open_vault(
        root_path: &Path,
        password: Option<&str>,
        backend: Arc<dyn StorageBackend>,
    ) -> Result<Vault, OpenError> {
        open_vault(root_path, password, backend)
    }

    /// Opens an existing Vault using the default Local Filesystem storage backend.
    ///
    /// # Arguments
    /// * `root_path` - The path to the existing vault directory.
    /// * `password` - An optional password. Required if the vault is encrypted.
    ///
    /// # Errors
    /// Returns `OpenError` if the path does not exist, the configuration
    /// is missing/corrupt, or if the password is incorrect.
    //
    // // 使用默认的本地文件系统存储后端打开一个已存在的保险库。
    // //
    // // # 参数
    // // * `root_path` - 已存在保险库目录的路径。
    // // * `password` - 可选的密码。如果保险库已加密，则此项为必需。
    // //
    // // # 错误
    // // 如果路径不存在、配置丢失/损坏，或者密码不正确，则返回 `OpenError`。
    pub fn open_vault_local(root_path: &Path, password: Option<&str>) -> Result<Vault, OpenError> {
        let backend = Arc::new(LocalStorage::new(root_path));
        open_vault(root_path, password, backend)
    }

    /// Updates the master password for an encrypted vault.
    ///
    /// This is a static method that operates on a closed vault. It performs a "shallow"
    /// update by re-keying the database and updating the configuration file with a new
    /// password verification marker.
    ///
    /// It does **not** re-encrypt the individual files stored within the vault.
    ///
    /// # Arguments
    /// * `vault_path` - The path to the vault's root directory.
    /// * `old_password` - The current master password.
    /// * `new_password` - The new master password to set.
    ///
    /// # Returns
    /// `Ok(())` on success, or an `UpdateError` on failure.
    //
    // // 更新加密保险库的主密码。
    // //
    // // 这是一个对关闭的保险库进行操作的静态方法。它通过重新加密数据库密钥并使用
    // // 新的密码验证标记更新配置文件来执行“浅层”更新。
    // //
    // // 它 **不会** 重新加密保险库中存储的单个文件。
    // //
    // // # 参数
    // // * `vault_path` - 保险库根目录的路径。
    // // * `old_password` - 当前的主密码。
    // // * `new_password` - 要设置的新主密码。
    // //
    // // # 返回
    // // 成功时返回 `Ok(())`，失败时返回 `UpdateError`。
    pub fn update_password(
        vault_path: &Path,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), UpdateError> {
        _update_password(vault_path, old_password, new_password)
    }

    // --- Find APIs ---
    // // --- 查找 API ---

    /// Finds a file entry by the `VaultHash` of its *encrypted* content.
    /// This hash acts as the primary key/ID for the file in the vault.
    ///
    /// # Arguments
    /// * `hash` - The SHA256 hash of the encrypted file content.
    ///
    /// # Returns
    /// `QueryFileResult::Found(FileEntry)` if found, otherwise `QueryFileResult::NotFound`.
    ///
    /// # Errors
    /// Returns `QueryError` on database failures.
    //
    // // 通过其 *加密* 内容的 `VaultHash` 查找文件条目。
    // // 这个哈希充当保险库中文件的主键/ID。
    // //
    // // # 参数
    // // * `hash` - 加密文件内容的 SHA256 哈希。
    // //
    // // # 返回
    // // 如果找到，返回 `QueryFileResult::Found(FileEntry)`，否则返回 `QueryFileResult::NotFound`。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn find_by_hash(&self, hash: &VaultHash) -> Result<QueryFileResult, QueryError> {
        check_by_hash(self, hash)
    }

    /// Lists all vault paths that reference a file content hash.
    ///
    /// With the hardlink-style schema, a single file entity may be referenced by
    /// multiple paths. This method returns all paths currently linked to `hash`.
    ///
    /// # Arguments
    /// * `hash` - The SHA256 hash of the encrypted file content.
    ///
    /// # Returns
    /// A vector of `VaultPath`s that point to the file entity.
    ///
    /// # Errors
    /// Returns `QueryError` on database failures.
    //
    // // 列出引用某个文件内容哈希的所有保险库路径。
    // //
    // // 在硬链接风格 schema 中，一个文件实体可以被多个路径引用。
    // // 此方法返回当前链接到 `hash` 的所有路径。
    // //
    // // # 参数
    // // * `hash` - 加密文件内容的 SHA256 哈希。
    // //
    // // # 返回
    // // 指向该文件实体的 `VaultPath` 向量。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn list_paths_by_hash(&self, hash: &VaultHash) -> Result<Vec<VaultPath>, QueryError> {
        list_paths_by_hash(self, hash)
    }

    /// Finds multiple file entries by their `VaultHash`es in a single batch query.
    ///
    /// This is more efficient than calling `find_by_hash` in a loop.
    /// Any hashes not found in the vault are simply omitted from the result.
    ///
    /// # Arguments
    /// * `hashes` - A slice of `VaultHash`es to look up.
    ///
    /// # Returns
    /// A vector of found `FileEntry`s.
    ///
    /// # Errors
    /// Returns `QueryError` on database failures.
    //
    // // 在单个批处理查询中通过 `VaultHash` 查找多个文件条目。
    // //
    // // 这比在循环中调用 `find_by_hash` 更高效。
    // // 任何在保险库中未找到的哈希值都将从结果中省略。
    // //
    // // # 参数
    // // * `hashes` - 要查找的 `VaultHash` 切片。
    // //
    // // # 返回
    // // 找到的 `FileEntry` 向量。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn find_by_hashes(&self, hashes: &[VaultHash]) -> Result<Vec<FileEntry>, QueryError> {
        find_by_hashes(self, hashes)
    }

    /// Finds a file entry by its exact `VaultPath`.
    ///
    /// # Arguments
    /// * `path` - The normalized path within the vault (e.g., "/docs/file.txt").
    ///
    /// # Returns
    /// `QueryFileResult::Found(FileEntry)` if found, otherwise `QueryFileResult::NotFound`.
    ///
    /// # Errors
    /// Returns `QueryError` on database failures.
    //
    // // 通过精确的 `VaultPath` 查找文件条目。
    // //
    // // # 参数
    // // * `path` - 保险库内的规范化路径 (例如 "/docs/file.txt")。
    // //
    // // # 返回
    // // 如果找到，返回 `QueryFileResult::Found(FileEntry)`，否则返回 `QueryFileResult::NotFound`。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn find_by_path(&self, path: &VaultPath) -> Result<QueryPathResult, QueryError> {
        check_by_path(self, path)
    }

    /// Finds multiple file entries by their `VaultPath`s in a single batch query.
    ///
    /// Any paths not found in the vault are simply omitted from the result.
    ///
    /// # Arguments
    /// * `paths` - A slice of `VaultPath`s to look up.
    ///
    /// # Returns
    /// A vector of found `FileEntry`s.
    ///
    /// # Errors
    /// Returns `QueryError` on database failures.
    //
    // // 在单个批处理查询中通过 `VaultPath` 查找多个文件条目。
    // //
    // // 任何在保险库中未找到的路径都将从结果中省略。
    // //
    // // # 参数
    // // * `paths` - 要查找的 `VaultPath` 切片。
    // //
    // // # 返回
    // // 找到的 `FileEntry` 向量。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn find_by_paths(&self, paths: &[VaultPath]) -> Result<Vec<FilePathEntry>, QueryError> {
        find_by_paths(self, paths)
    }

    /// Finds a file entry by the `VaultHash` of its *original* (unencrypted) content.
    /// Useful for checking if a specific file content already exists (deduplication).
    ///
    /// # Arguments
    /// * `original_hash` - The SHA256 hash of the original file content.
    ///
    /// # Returns
    /// `QueryFileResult::Found(FileEntry)` if found, otherwise `QueryFileResult::NotFound`.
    ///
    /// # Errors
    /// Returns `QueryError` on database failures.
    //
    // // 通过其 *原始* (未加密) 内容的 `VaultHash` 查找文件条目。
    // // 对于检查特定文件内容是否已存在 (去重) 非常有用。
    // //
    // // # 参数
    // // * `original_hash` - 原始文件内容的 SHA256 哈希。
    // //
    // // # 返回
    // // 如果找到，返回 `QueryFileResult::Found(FileEntry)`，否则返回 `QueryFileResult::NotFound`。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn find_by_original_hash(
        &self,
        original_hash: &VaultHash,
    ) -> Result<QueryFileResult, QueryError> {
        check_by_original_hash(self, original_hash)
    }

    /// Finds all file entries associated with a specific tag.
    ///
    /// # Arguments
    /// * `tag` - The tag string to search for.
    ///
    /// # Returns
    /// A vector of `FileEntry`s that have the specified tag.
    ///
    /// # Errors
    /// Returns `QueryError` on database failures.
    //
    // // 查找与特定标签关联的所有文件条目。
    // //
    // // # 参数
    // // * `tag` - 要搜索的标签字符串。
    // //
    // // # 返回
    // // 包含指定标签的 `FileEntry` 向量。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn find_by_tag(&self, tag: &str) -> Result<Vec<FilePathEntry>, QueryError> {
        find_by_tag(self, tag)
    }

    /// Performs a case-insensitive fuzzy search by keyword.
    /// Matches the `keyword` against file paths or tags.
    ///
    /// # Arguments
    /// * `keyword` - The keyword to search for (partial match).
    ///
    /// # Returns
    /// A vector of matching `FileEntry`s.
    ///
    /// # Errors
    /// Returns `QueryError` on database failures.
    //
    // // 按关键字执行不区分大小写的模糊搜索。
    // // 将 `keyword` 与文件路径或标签进行匹配。
    // //
    // // # 参数
    // // * `keyword` - 要搜索的关键字 (部分匹配)。
    // //
    // // # 返回
    // // 匹配的 `FileEntry` 向量。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn find_by_keyword(&self, keyword: &str) -> Result<Vec<FilePathEntry>, QueryError> {
        find_by_keyword(self, keyword)
    }

    // --- List APIs ---
    // // --- 列表 API ---

    /// Lists all files currently stored in the vault, returning their full entries.
    /// WARNING: This can be slow for large vaults as it fetches all rows.
    ///
    /// # Returns
    /// A vector containing all `FileEntry`s in the vault.
    ///
    /// # Errors
    /// Returns `QueryError` on database failures.
    //
    // // 列出保险库中当前存储的所有文件，返回它们的完整条目。
    // // 警告：对于大型保险库，这可能会很慢，因为它会获取所有行。
    // //
    // // # 返回
    // // 包含保险库中所有 `FileEntry` 的向量。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn list_all(&self) -> Result<Vec<FileEntry>, QueryError> {
        list_all_files(self)
    }

    // Lists the files and subdirectories directly under a given directory path.
    // This is non-recursive.
    //
    // The returned `Vec` contains:
    // - Files: `VaultPath` (e.g., "/docs/file.txt")
    // - Subdirectories: `VaultPath` (e.g., "/docs/images/")
    //
    // # Errors
    // Returns `QueryError::NotADirectory` if `path` is a file path (e.g., "/a.txt").
    //
    // // 仅列出给定目录路径下的文件和子目录（非递归）。
    // //
    // // 返回的 `Vec` 包含：
    // // - 文件: `VaultPath` (例如 "/docs/file.txt")
    // // - 子目录: `VaultPath` (例如 "/docs/images/")
    // //
    // // # 错误
    // // 如果 `path` 是一个文件路径（例如 "/a.txt"），则返回 `QueryError::NotADirectory`。
    // pub fn list_by_path(&self, path: &VaultPath) -> Result<Vec<VaultPath>, QueryError> {
    //     list_by_path(self, path)
    // }

    /// Lists path entries directly under a given directory path.
    ///
    /// This method returns lightweight path-oriented entries:
    /// - `ListPathEntry::File(FilePathEntry)` for files, providing the path and encrypted hash.
    /// - `ListPathEntry::Directory(DirectoryEntry)` for subdirectories, providing path, parent path,
    ///   and direct child counts.
    ///
    /// This enables UI/CLI applications to display directory contents without loading
    /// full file metadata for every file.
    ///
    /// # Arguments
    /// * `path` - The directory path to list (e.g., "/docs/").
    ///
    /// # Returns
    /// A vector of `ListPathEntry` objects representing the immediate contents.
    ///
    /// # Errors
    /// Returns `QueryError::NotADirectory` if `path` is a file path.
    /// Returns `QueryError` on database failures.
    //
    // // 列出直接位于给定目录路径下的路径条目。
    // //
    // // 此方法返回轻量级、面向路径的条目：
    // // - 对于文件，返回 `ListPathEntry::File(FilePathEntry)`，提供路径和加密哈希。
    // // - 对于子目录，返回 `ListPathEntry::Directory(DirectoryEntry)`，提供路径、父目录路径和直属子项数量。
    // //
    // // 这使得 UI/CLI 应用程序能够显示目录内容，而无需为每个文件加载完整文件元数据。
    // //
    // // # 参数
    // // * `path` - 要列出的目录路径 (例如 "/docs/")。
    // //
    // // # 返回
    // // 代表直接内容的 `ListPathEntry` 对象向量。
    // //
    // // # 错误
    // // 如果 `path` 是一个文件路径，则返回 `QueryError::NotADirectory`。
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn list_by_path(&self, path: &VaultPath) -> Result<Vec<ListPathEntry>, QueryError> {
        list_by_path(self, path)
    }

    /// Recursively lists all file path mappings under a given directory path.
    ///
    /// This is optimized for bulk operations (like mass extraction or deletion).
    ///
    /// # Arguments
    /// * `path` - The root directory path to start listing from.
    ///
    /// # Returns
    /// A vector of `FilePathEntry` objects for all files found recursively.
    ///
    /// # Errors
    /// Returns `QueryError::NotADirectory` if `path` is a file path.
    /// Returns `QueryError` on database failures.
    //
    // // 递归列出一个目录下的所有文件路径映射。
    // //
    // // 这针对批量操作（如批量提取或删除）进行了优化。
    // //
    // // # 参数
    // // * `path` - 开始列出的根目录路径。
    // //
    // // # 返回
    // // 递归找到的所有文件的 `FilePathEntry` 对象向量。
    // //
    // // # 错误
    // // 如果 `path` 是一个文件路径，则返回 `QueryError::NotADirectory`。
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn list_all_recursive(&self, path: &VaultPath) -> Result<Vec<FilePathEntry>, QueryError> {
        list_all_recursive(self, path)
    }

    /// Gets the total number of file path entries in the vault.
    ///
    /// This counts the current directory tree's file mappings (`file_entries`),
    /// so hardlink-style duplicate paths are counted separately.
    ///
    /// # Returns
    /// The count of file path entries as an `i64`.
    ///
    /// # Errors
    /// Returns `QueryError` on database failures.
    //
    // // 获取保险库当前目录树中的文件路径条目总数。
    // //
    // // 这会统计当前目录树的文件映射（`file_entries`），因此硬链接式重复路径会被分别计数。
    // //
    // // # 返回
    // // 文件路径条目计数，类型为 `i64`。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn get_file_count(&self) -> Result<i64, QueryError> {
        get_total_file_count(self)
    }

    /// Gets the total number of actual stored file entities in the vault.
    ///
    /// This counts unique encrypted file records (`files`) and therefore does not
    /// count multiple path mappings to the same stored content separately.
    ///
    /// # Returns
    /// The count of actual stored file entities as an `i64`.
    ///
    /// # Errors
    /// Returns `QueryError` on database failures.
    //
    // // 获取保险库中实际存储文件实体的总数。
    // //
    // // 这会统计唯一的加密文件记录（`files`），因此多个路径映射到同一存储内容时不会重复计数。
    // //
    // // # 返回
    // // 实际存储文件实体计数，类型为 `i64`。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn get_storage_file_count(&self) -> Result<i64, QueryError> {
        get_storage_file_count(self)
    }

    // --- Add APIs ---
    // // --- 添加 API ---

    /// Adds a new file to the vault (synchronous convenience method).
    ///
    /// This handles encryption and database commit in a single call.
    /// For bulk additions, prefer using `encrypt_file_for_add` and `commit_add_files` separately.
    ///
    /// # Arguments
    /// * `source_path` - The path to the file on the local filesystem.
    /// * `dest_path` - The target `VaultPath` inside the vault.
    ///   - If `dest_path` is a directory (ends with `/`), the source filename is appended.
    ///
    /// # Returns
    /// The `VaultHash` (encrypted ID) of the added file.
    ///
    /// # Errors
    /// Returns `AddFileError` if source not found, path invalid, or duplicate content/path exists.
    //
    // // 将新文件添加到保险库 (同步便捷方法)。
    // //
    // // 这在一次调用中处理加密和数据库提交。
    // // 对于批量添加，请首选分开使用 `encrypt_file_for_add` 和 `commit_add_files`。
    // //
    // // # 参数
    // // * `source_path` - 本地文件系统上的文件路径。
    // // * `dest_path` - 保险库内部的目标 `VaultPath`。
    // //   - 如果 `dest_path` 是目录 (以 `/` 结尾)，则会追加源文件名。
    // //
    // // # 返回
    // // 添加文件的 `VaultHash` (加密 ID)。
    // //
    // // # 错误
    // // 如果源未找到、路径无效或存在重复的内容/路径，则返回 `AddFileError`。
    pub fn add_file(
        &mut self,
        source_path: &Path,
        dest_path: &VaultPath,
        allow_duplicate_files: Option<bool>,
    ) -> Result<VaultHash, AddFileError> {
        let result = add_file(self, source_path, dest_path, allow_duplicate_files)?;

        touch_vault_update_time(self)?;
        Ok(result)
    }

    // Gets the path to the internal `data` directory.
    // Used for calling `encrypt_file_for_add_standalone` without a `&Vault` lock.
    //
    // // 获取内部 `data` 目录的路径。
    // // 用于在没有 `&Vault` 锁的情况下调用 `encrypt_file_for_add_standalone`。
    // pub fn get_data_dir_path(&self) -> PathBuf {
    //     self.root_path.join(DATA_SUBDIR)
    // }

    /// Stage 1 (Add): Validates a batch of addition requests against the vault database.
    ///
    /// Checks for path validity and duplicate paths (in DB and within the batch).
    /// Does NOT perform encryption — that is deferred to Stage 2.
    ///
    /// # Arguments
    /// * `requests` - A slice of `PrepareAdditionRequest`s to validate.
    ///
    /// # Returns
    /// A `Vec<PendingAdditionTask>` — one per request, in the same order.
    ///
    /// # Errors
    /// Returns `AddFileError` if any request fails validation.
    //
    // // 阶段 1 (添加): 根据保险库数据库验证一批添加请求。
    // //
    // // 检查路径有效性和重复路径（数据库中和批次内）。
    // // 不执行加密 — 加密推迟到阶段 2。
    // //
    // // # 参数
    // // * `requests` - 要验证的 `PrepareAdditionRequest` 切片。
    // //
    // // # 返回
    // // `Vec<PendingAdditionTask>` — 每个请求一个，顺序相同。
    // //
    // // # 错误
    // // 如果任何请求验证失败，则返回 `AddFileError`。
    pub fn prepare_addition_tasks(
        &self,
        requests: &[PrepareAdditionRequest],
    ) -> Result<Vec<PendingAdditionTask>, AddFileError> {
        _prepare_addition_tasks(self, requests)
    }

    /// Stage 1 shortcut for local files: Resolves metadata and validates a batch of
    /// local file paths against the vault database in one call.
    ///
    /// This combines `resolve_file_metadata` + `prepare_addition_tasks` for the common
    /// case of adding files from the local filesystem. Each pair's destination path
    /// is resolved (e.g., if it's a directory, the source filename is appended).
    ///
    /// # Arguments
    /// * `file_pairs` - A slice of `(source_path, dest_vault_path)` pairs.
    ///
    /// # Returns
    /// A `Vec<PendingAdditionTask>` — one per pair, in the same order.
    ///
    /// # Errors
    /// Returns `AddFileError` if any source file is missing, path is invalid,
    /// or duplicates are detected.
    //
    // // 本地文件的阶段 1 快捷方法：一次调用中解析元数据并根据保险库数据库验证一批本地文件路径。
    // //
    // // 这将 `resolve_file_metadata` + `prepare_addition_tasks` 合并，
    // // 适用于从本地文件系统添加文件的常见场景。每对的目标路径会被解析
    // // （例如如果是目录，则追加源文件名）。
    // //
    // // # 参数
    // // * `file_pairs` - `(源路径, 目标保险库路径)` 对的切片。
    // //
    // // # 返回
    // // `Vec<PendingAdditionTask>` — 每对一个，顺序相同。
    // //
    // // # 错误
    // // 如果任何源文件缺失、路径无效或检测到重复，则返回 `AddFileError`。
    pub fn prepare_addition_tasks_from_files(
        &self,
        file_pairs: &[(&Path, &VaultPath)],
    ) -> Result<Vec<PendingAdditionTask>, AddFileError> {
        _prepare_addition_tasks_from_files(self, file_pairs)
    }

    /// Stage 2 (Add): Encrypts data from a reader and produces an `AdditionTask`.
    ///
    /// This is a **thread-safe** associated function that does NOT require a `&Vault`.
    /// It performs the expensive CPU/IO encryption work using only the storage backend.
    /// Callers can invoke this in parallel (e.g., via Rayon) for bulk additions.
    ///
    /// # Arguments
    /// * `storage` - The storage backend to write encrypted data to.
    /// * `pending` - A validated `PendingAdditionTask` from Stage 1.
    /// * `reader` - An object implementing `std::io::Read` to stream source data from.
    ///
    /// # Returns
    /// An `AdditionTask` containing the encrypted `FileEntry` and a `StagingToken`.
    ///
    /// # Errors
    /// Returns `AddFileError` if encryption fails or an IO error occurs.
    //
    // // 阶段 2 (添加): 从读取器加密数据并生成 `AdditionTask`。
    // //
    // // 这是一个 **线程安全** 的关联函数，不需要 `&Vault`。
    // // 它仅使用存储后端执行昂贵的 CPU/IO 加密工作。
    // // 调用方可以并行调用此函数（例如通过 Rayon）进行批量添加。
    // //
    // // # 参数
    // // * `storage` - 用于写入加密数据的存储后端。
    // // * `pending` - 来自阶段 1 的已验证 `PendingAdditionTask`。
    // // * `reader` - 实现 `std::io::Read` 以从中流入源数据的对象。
    // //
    // // # 返回
    // // 包含加密 `FileEntry` 和 `StagingToken` 的 `AdditionTask`。
    // //
    // // # 错误
    // // 如果加密失败或发生 IO 错误，则返回 `AddFileError`。
    pub fn encrypt_addition_task(
        storage: &dyn StorageBackend,
        pending: PendingAdditionTask,
        reader: impl std::io::Read,
    ) -> Result<AdditionTask, AddFileError> {
        _encrypt_addition_task(storage, pending, reader)
    }

    /// Stage 3 (Add): Commits one or more encrypted files to the vault database.
    ///
    /// This method requires exclusive `&mut self` access (locking the DB) to perform
    /// a transaction. It moves files from the staging area to permanent storage and
    /// inserts records into the database.
    ///
    /// # Arguments
    /// * `files` - A `Vec` of `AdditionTask` objects from Stage 2.
    ///
    /// # Errors
    /// Returns `AddFileError` if database transaction fails or file commit fails.
    //
    // // 阶段 3 (添加): 将一个或多个已加密的文件提交到保险库数据库。
    // //
    // // 此方法需要独占的 `&mut self` 访问权限 (锁定 DB) 来执行事务。
    // // 它将文件从暂存区移动到永久存储，并将记录插入数据库。
    // //
    // // # 参数
    // // * `files` - 来自阶段 2 的 `AdditionTask` 对象列表。
    // //
    // // # 错误
    // // 如果数据库事务失败或文件提交失败，则返回 `AddFileError`。
    /// Stage 3 (Add): Commits encrypted files with optional duplicate-content control.
    ///
    /// `allow_duplicate_files` controls whether files with the same original hash may
    /// coexist as multiple path mappings. `None` defaults to `true`, which reuses the
    /// existing file entity and only inserts new path mappings. `Some(false)` returns
    /// `AddFileError::DuplicateOriginalContent` when the same original hash already
    /// exists in the vault or earlier in the same batch.
    ///
    /// # Arguments
    /// * `files` - A `Vec` of `AdditionTask` objects from Stage 2.
    /// * `allow_duplicate_files` - Optional duplicate-content policy; defaults to `true`.
    ///
    /// # Errors
    /// Returns `AddFileError` if duplicate content is disallowed and detected, or if
    /// database transaction or storage commit fails.
    //
    // // 阶段 3 (添加): 使用可选的重复内容控制提交已加密文件。
    // //
    // // `allow_duplicate_files` 控制具有相同原始哈希的文件是否可以作为多个路径映射共存。
    // // `None` 默认等同于 `true`，即复用已有文件实体并只插入新的路径映射。
    // // `Some(false)` 会在保险库中或同一批次前面已存在相同原始哈希时返回
    // // `AddFileError::DuplicateOriginalContent`。
    // //
    // // # 参数
    // // * `files` - 来自阶段 2 的 `AdditionTask` 对象列表。
    // // * `allow_duplicate_files` - 可选的重复内容策略；默认值为 `true`。
    // //
    // // # 错误
    // // 如果禁止重复内容且检测到重复，或数据库事务、存储提交失败，则返回 `AddFileError`。
    pub fn commit_addition_tasks(
        &mut self,
        files: Vec<AdditionTask>,
        allow_duplicate_files: Option<bool>,
    ) -> Result<(), AddFileError> {
        if files.is_empty() {
            return Ok(());
        }
        _commit_addition_tasks(self, files, allow_duplicate_files)?;
        touch_vault_update_time(self)?;
        Ok(())
    }

    /// Adds a new file from a reader stream (synchronous convenience method).
    ///
    /// This handles validation, encryption, and database commit in a single call.
    /// This is the primary convenience method — for file-based additions, use `add_file`.
    ///
    /// # Arguments
    /// * `reader` - An object implementing `std::io::Read` to stream data from.
    /// * `dest_path` - The target `VaultPath` inside the vault.
    /// * `source_size` - The size of the source data in bytes.
    /// * `source_modified_time` - The modification time of the source data.
    ///
    /// # Returns
    /// The `VaultHash` (encrypted ID) of the added file.
    ///
    /// # Errors
    /// Returns `AddFileError` if path invalid, duplicate content/path exists, or encryption fails.
    //
    // // 从读取器流添加新文件（同步便捷方法）。
    // //
    // // 这在一次调用中处理验证、加密和数据库提交。
    // // 这是主要的便捷方法 — 对于基于文件的添加，请使用 `add_file`。
    // //
    // // # 参数
    // // * `reader` - 实现 `std::io::Read` 以从中流入数据的对象。
    // // * `dest_path` - 保险库内部的目标 `VaultPath`。
    // // * `source_size` - 源数据的大小（字节）。
    // // * `source_modified_time` - 源数据的修改时间。
    // //
    // // # 返回
    // // 添加文件的 `VaultHash` (加密 ID)。
    // //
    // // # 错误
    // // 如果路径无效、存在重复的内容/路径或加密失败，则返回 `AddFileError`。
    pub fn add_from_reader(
        &mut self,
        reader: impl std::io::Read,
        dest_path: &VaultPath,
        source_size: u64,
        source_modified_time: chrono::DateTime<chrono::Utc>,
        allow_duplicate_files: Option<bool>,
    ) -> Result<VaultHash, AddFileError> {
        let result = add_from_reader(
            self,
            reader,
            dest_path,
            source_size,
            source_modified_time,
            allow_duplicate_files,
        )?;
        touch_vault_update_time(self)?;
        Ok(result)
    }

    /// Safely replaces a file at a specific vault path with a new file, verifying its original hash first.
    ///
    /// This operation is for fixing an existing file. It requires the file to exist and its
    /// original (unencrypted) hash to match the `original_sha256sum` stored in the vault's database.
    ///
    /// # Arguments
    /// * `source_path` - The local filesystem path to the original, unencrypted file.
    /// * `vault_path` - The `VaultPath` of the file entry to fix.
    ///
    /// # Returns
    /// The `VaultHash` of the newly added file.
    ///
    /// # Errors
    /// Returns `FixError` if the file is not found, the hash mismatches, or the process fails.
    //
    // // 安全地替换位于特定保险库路径的文件，会先验证其原始哈希。
    // //
    // // 此操作用于修复现有文件。它要求文件存在，并且其原始（未加密）哈希
    // // 与保险库数据库中存储的 `original_sha256sum` 匹配。
    // //
    // // # 参数
    // // * `source_path` - 指向原始、未加密文件的本地文件系统路径。
    // // * `vault_path` - 要修复的文件条目的 `VaultPath`。
    // //
    // // # 返回
    // // 新添加文件的 `VaultHash`。
    // //
    // // # 错误
    // // 如果文件未找到、哈希不匹配或过程失败，则返回 `FixError`。
    pub fn fix_file(
        &mut self,
        source_path: &Path,
        vault_path: &VaultPath,
    ) -> Result<VaultHash, FixError> {
        let result = _fix_file(self, source_path, vault_path)?;
        touch_vault_update_time(self)?;
        Ok(result)
    }

    // --- Extract APIs ---
    // // --- 提取 API ---

    /// Extracts a file from the vault to a local path (synchronous convenience method).
    ///
    /// Handles preparation and decryption in a single call.
    /// For bulk extract, prefer using `prepare_extraction_tasks` and
    /// `Vault::decrypt_extraction_task` / `Vault::decrypt_extraction_task_to_file` separately.
    ///
    /// # Arguments
    /// * `hash` - The `VaultHash` of the file to extract.
    /// * `destination_path` - The full local path where the file will be saved.
    ///
    /// # Errors
    /// Returns `ExtractError` if the file is not found, decryption fails, or an I/O error occurs.
    //
    // // 从保险库中提取文件到本地路径（同步便捷方法）。
    // //
    // // 在一次调用中处理准备和解密。
    // // 对于批量提取，请首选分开使用 `prepare_extraction_tasks` 和
    // // `Vault::decrypt_extraction_task` / `Vault::decrypt_extraction_task_to_file`。
    // //
    // // # 参数
    // // * `hash` - 要提取的文件的 `VaultHash`。
    // // * `destination_path` - 文件将被保存到的完整本地路径。
    // //
    // // # 错误
    // // 如果文件未找到、解密失败或发生 IO 错误，则返回 `ExtractError`。
    pub fn extract_file(
        &self,
        hash: &VaultHash,
        destination_path: &Path,
    ) -> Result<(), ExtractError> {
        extract_file(self, hash, destination_path)
    }

    /// Stage 1 (Extract): Prepares a single file for extraction.
    ///
    /// This is a fast method that queries the database (holding a read lock)
    /// and returns an `ExtractionTask` ticket containing all information
    /// (keys, hashes, paths) needed for the slow decryption step.
    ///
    /// # Arguments
    /// * `hash` - The `VaultHash` of the file to extract.
    ///
    /// # Returns
    /// An `ExtractionTask` object.
    ///
    /// # Errors
    /// Returns `ExtractError::FileNotFound` if the hash is not in the database.
    /// Returns `ExtractError` on database failures.
    //
    // // 阶段 1 (提取): 准备一个文件用于提取。
    // //
    // // 这是一个快速的方法，它查询数据库（持有读锁）并返回一个 `ExtractionTask` 票据，
    // // 包含缓慢的解密步骤所需的所有信息（密钥、哈希、路径）。
    // //
    // // # 参数
    // // * `hash` - 要提取的文件的 `VaultHash`。
    // //
    // // # 返回
    // // 一个 `ExtractionTask` 对象。
    // //
    // // # 错误
    // // 如果在数据库中未找到该哈希，则返回 `ExtractError::FileNotFound`。
    // // 如果发生数据库故障，则返回 `ExtractError`。
    pub fn prepare_extraction_task(
        &self,
        hash: &VaultHash,
    ) -> Result<ExtractionTask, ExtractError> {
        prepare_extraction_task(self, hash)
    }

    /// Stage 1 (Extract): Prepares multiple files for extraction in a single batch.
    ///
    /// This is a fast method that queries the database for each hash and verifies
    /// that the corresponding file exists in the storage backend.
    ///
    /// # Arguments
    /// * `hashes` - A slice of `VaultHash`es to prepare for extraction.
    ///
    /// # Returns
    /// A `Vec<ExtractionTask>` — one per hash, in the same order.
    ///
    /// # Errors
    /// Returns `ExtractError` if any hash is not found or a database error occurs.
    //
    // // 阶段 1 (提取): 在单个批次中准备多个文件用于提取。
    // //
    // // 这是一个快速的方法，它为每个哈希查询数据库并验证对应的文件
    // // 存在于存储后端中。
    // //
    // // # 参数
    // // * `hashes` - 要准备提取的 `VaultHash` 切片。
    // //
    // // # 返回
    // // `Vec<ExtractionTask>` — 每个哈希一个，顺序相同。
    // //
    // // # 错误
    // // 如果任何哈希未找到或发生数据库错误，则返回 `ExtractError`。
    pub fn prepare_extraction_tasks(
        &self,
        hashes: &[VaultHash],
    ) -> Result<Vec<ExtractionTask>, ExtractError> {
        _prepare_extraction_tasks(self, hashes)
    }

    /// Stage 2 (Extract): Decrypts a prepared extraction task to a writer stream.
    ///
    /// This is a **thread-safe** associated function that does NOT require a `&Vault`.
    /// It performs the expensive CPU/IO decryption work using only the storage backend.
    /// Callers can invoke this in parallel (e.g., via Rayon) for bulk extractions.
    ///
    /// # Arguments
    /// * `storage` - The storage backend to read encrypted data from.
    /// * `task` - The extraction ticket from Stage 1.
    /// * `writer` - An object implementing `std::io::Write` to receive the decrypted data.
    ///
    /// # Errors
    /// Returns `ExtractError` if decryption fails, IO error occurs, or integrity check fails.
    //
    // // 阶段 2 (提取): 将已准备好的提取任务解密到写入流。
    // //
    // // 这是一个 **线程安全** 的关联函数，不需要 `&Vault`。
    // // 它仅使用存储后端执行昂贵的 CPU/IO 解密工作。
    // // 调用方可以并行调用此函数（例如通过 Rayon）进行批量提取。
    // //
    // // # 参数
    // // * `storage` - 用于读取加密数据的存储后端。
    // // * `task` - 来自阶段 1 的提取票据。
    // // * `writer` - 实现 `std::io::Write` 以接收解密数据的对象。
    // //
    // // # 错误
    // // 如果解密失败、发生 IO 错误或完整性检查失败，则返回 `ExtractError`。
    pub fn decrypt_extraction_task(
        storage: &dyn StorageBackend,
        task: &ExtractionTask,
        writer: impl std::io::Write,
    ) -> Result<(), ExtractError> {
        _decrypt_extraction_task(storage, task, writer)
    }

    /// Stage 2 (Extract): Opens a prepared extraction task as a random-access reader.
    ///
    /// This associated function returns a pull-based plaintext stream that decrypts
    /// and authenticates only the chunk needed by each read or seek operation.
    ///
    /// # Arguments
    /// * `storage` - The storage backend to read encrypted data from.
    /// * `task` - The extraction ticket from Stage 1.
    ///
    /// # Returns
    /// An opaque stream implementing `Read + Seek + Send` over plaintext bytes.
    ///
    /// # Errors
    /// Returns `ExtractError` if the object cannot be opened or authenticated.
    //
    // // 阶段 2 (提取): 将已准备好的提取任务打开为随机访问读取器。
    // //
    // // 此关联函数返回拉取式明文流，每次 read 或 seek 只解密并认证所需块。
    // //
    // // # 参数
    // // * `storage` - 用于读取加密数据的存储后端。
    // // * `task` - 来自阶段 1 的提取票据。
    // //
    // // # 返回
    // // 基于后端对象并实现 `Read + Seek + Send` 的不透明流。
    // //
    // // # 错误
    // // 如果对象无法打开或认证失败，则返回 `ExtractError`。
    pub fn open_extraction_task_reader(
        storage: &dyn StorageBackend,
        task: &ExtractionTask,
    ) -> Result<impl Read + Seek + Send + 'static, ExtractError> {
        _open_extraction_task_reader(storage, task)
    }

    /// Opens a vault file by hash as a random-access reader.
    ///
    /// This convenience method combines extraction preparation and pull-based
    /// chunked reader construction.
    ///
    /// # Arguments
    /// * `hash` - The `VaultHash` of the file to open.
    ///
    /// # Returns
    /// An opaque stream implementing `Read + Seek + Send` over plaintext bytes.
    ///
    /// # Errors
    /// Returns `ExtractError` if metadata lookup, storage access, or chunk
    /// authentication fails.
    //
    // // 按哈希将保险库文件打开为随机访问读取器。
    // //
    // // 此便捷方法组合了提取准备和拉取式分块读取器构建。
    // //
    // // # 参数
    // // * `hash` - 要打开的文件的 `VaultHash`。
    // //
    // // # 返回
    // // 在明文字节上实现 `Read + Seek + Send` 的不透明流。
    // //
    // // # 错误
    // // 如果元数据查询、存储访问或块认证失败，则返回 `ExtractError`。
    pub fn open_file_for_read(
        &self,
        hash: &VaultHash,
    ) -> Result<impl Read + Seek + Send + 'static, ExtractError> {
        let task = prepare_extraction_task(self, hash)?;
        _open_extraction_task_reader(self.storage.as_ref(), &task)
    }

    /// Stage 2 shortcut: Decrypts a prepared extraction task to a local file.
    ///
    /// This is a **thread-safe** associated function that wraps `decrypt_extraction_task`
    /// with atomic file writing (temp file + rename).
    ///
    /// # Arguments
    /// * `storage` - The storage backend to read encrypted data from.
    /// * `task` - The extraction ticket from Stage 1.
    /// * `destination_path` - The local path to save the decrypted file.
    ///
    /// # Errors
    /// Returns `ExtractError` if decryption fails, IO error occurs, or integrity check fails.
    //
    // // 阶段 2 快捷方法: 将已准备好的提取任务解密到本地文件。
    // //
    // // 这是一个 **线程安全** 的关联函数，包装了 `decrypt_extraction_task`，
    // // 使用原子文件写入（临时文件 + 重命名）。
    // //
    // // # 参数
    // // * `storage` - 用于读取加密数据的存储后端。
    // // * `task` - 来自阶段 1 的提取票据。
    // // * `destination_path` - 保存解密文件的本地路径。
    // //
    // // # 错误
    // // 如果解密失败、发生 IO 错误或完整性检查失败，则返回 `ExtractError`。
    pub fn decrypt_extraction_task_to_file(
        storage: &dyn StorageBackend,
        task: &ExtractionTask,
        destination_path: &Path,
    ) -> Result<(), ExtractError> {
        _decrypt_extraction_task_to_file(storage, task, destination_path)
    }

    // --- Rekey APIs ---

    /// Stage 1 (Rekey): Validates encrypted file hashes against the vault database.
    ///
    /// This stage requires database access and converts each `VaultHash` into a
    /// `PendingRekeyTask`. It performs no cryptographic or storage work.
    ///
    /// # Arguments
    /// * `hashes` - The encrypted content hashes to rekey.
    ///
    /// # Returns
    /// A `Vec<PendingRekeyTask>` — one per hash, in the same order.
    ///
    /// # Errors
    /// Returns `RekeyError` if a hash is not found or the database query fails.
    //
    // // 阶段 1 (Rekey): 根据保险库数据库验证加密文件哈希。
    // //
    // // 此阶段需要数据库访问，并将每个 `VaultHash` 转换为 `PendingRekeyTask`。
    // // 它不执行任何加密或存储操作。
    // //
    // // # 参数
    // // * `hashes` - 要轮换密钥的加密内容哈希。
    // //
    // // # 返回
    // // `Vec<PendingRekeyTask>` — 每个哈希一个，顺序相同。
    // //
    // // # 错误
    // // 如果哈希不存在或数据库查询失败，则返回 `RekeyError`。
    pub fn prepare_rekey_tasks(
        &self,
        hashes: &[VaultHash],
    ) -> Result<Vec<PendingRekeyTask>, RekeyError> {
        _prepare_rekey_tasks(self, hashes)
    }

    /// Stage 2 (Rekey): Re-encrypts a prepared file without database access.
    ///
    /// This is a **thread-safe** associated function that does NOT require a `&Vault`.
    /// It performs the expensive CPU/IO re-encryption work using only the storage backend.
    /// Callers can invoke this in parallel for bulk rekey operations.
    ///
    /// # Arguments
    /// * `storage` - The storage backend to read and write encrypted data.
    /// * `pending` - A validated `PendingRekeyTask` from Stage 1.
    ///
    /// # Returns
    /// A `RekeyTask` containing the re-encrypted `FileEntry` and a `StagingToken`.
    ///
    /// # Errors
    /// Returns `RekeyError` if I/O or re-encryption fails.
    //
    // // 阶段 2 (Rekey): 在不访问数据库的情况下重加密已准备的文件。
    // //
    // // 这是一个 **线程安全** 的关联函数，不需要 `&Vault`。
    // // 它仅使用存储后端执行昂贵的 CPU/IO 重加密工作。
    // // 调用方可以并行调用此函数进行批量密钥轮换。
    // //
    // // # 参数
    // // * `storage` - 用于读取和写入加密数据的存储后端。
    // // * `pending` - 来自阶段 1 的已验证 `PendingRekeyTask`。
    // //
    // // # 返回
    // // 包含重加密 `FileEntry` 和 `StagingToken` 的 `RekeyTask`。
    // //
    // // # 错误
    // // 如果 I/O 或重加密失败，则返回 `RekeyError`。
    pub fn rekey_task(
        storage: &dyn StorageBackend,
        pending: PendingRekeyTask,
    ) -> Result<RekeyTask, RekeyError> {
        _rekey_task(storage, pending)
    }

    /// Stage 3 (Rekey): Atomically commits a batch of re-keyed files to the vault.
    ///
    /// This method requires exclusive `&mut self` access to perform a transaction.
    /// It updates database records, moves the re-encrypted files from temporary
    /// storage to their final destination, and deletes the old files.
    ///
    /// # Arguments
    /// * `tasks` - A `Vec` of `RekeyTask` objects from Stage 2.
    ///
    /// # Errors
    /// Returns `RekeyError` if the database or filesystem commit fails.
    //
    // // 阶段 3 (Rekey): 原子化地提交一批已轮换密钥的文件到保险库。
    // //
    // // 此方法需要对 `&mut self` 的独占访问权来执行事务。
    // // 它会更新数据库记录，将被重加密的文件从临时存储移动到最终位置，并删除旧文件。
    // //
    // // # 参数
    // // * `tasks` - 一个包含来自阶段 2 的 `RekeyTask` 对象的 `Vec`。
    // //
    // // # 错误
    // // 如果数据库或文件系统提交失败，则返回 `RekeyError`。
    pub fn commit_rekey_tasks(&mut self, tasks: Vec<RekeyTask>) -> Result<(), RekeyError> {
        if tasks.is_empty() {
            return Ok(());
        }
        _commit_rekey_tasks(self, tasks)?;
        touch_vault_update_time(self)?;
        Ok(())
    }

    // --- Update APIs ---
    // // --- 更新 API ---

    /// Moves or renames a vault path to another vault path.
    ///
    /// File sources must target a file path. Directory sources must target a
    /// directory path. This single API covers moving a file to a new path,
    /// moving a directory subtree to a new path, renaming a file in place, and
    /// renaming a directory in place. File moves update only `file_entries`;
    /// directory moves update only the directory node, leaving encrypted payloads
    /// untouched.
    ///
    /// # Arguments
    /// * `source_path` - The existing vault file or directory path.
    /// * `target_path` - The final vault file or directory path.
    ///
    /// # Errors
    /// Returns `UpdateError` if the source is missing, the target exists, the
    /// path types are incompatible, or the root directory is moved.
    //
    // // 将一个保险库路径移动或重命名到另一个保险库路径。
    // //
    // // 文件源必须指向文件路径，目录源必须指向目录路径。这个单一 API 同时覆盖
    // // 文件移动到新路径、目录子树移动到新路径、文件原地重命名和目录原地重命名。
    // // 文件移动只更新 `file_entries`；目录移动只更新目录节点，加密载荷保持不变。
    // //
    // // # 参数
    // // * `source_path` - 现有的保险库文件或目录路径。
    // // * `target_path` - 最终的保险库文件或目录路径。
    // //
    // // # 错误
    // // 如果源不存在、目标已存在、路径类型不兼容或移动根目录，则返回 `PathOperationError`。
    pub fn move_path(
        &mut self,
        source_path: &VaultPath,
        target_path: &VaultPath,
    ) -> Result<(), PathOperationError> {
        move_path(self, source_path, target_path)?;
        touch_vault_update_time(self)?;
        Ok(())
    }

    /// Renames a vault file or directory path in its current parent directory.
    ///
    /// This is a convenience API over `move_path`: it accepts the existing
    /// `VaultPath` and a new leaf name, preserves whether the source is a file or
    /// directory, and moves only the path metadata without rewriting encrypted
    /// payloads.
    ///
    /// # Arguments
    /// * `source_path` - The existing vault file or directory path.
    /// * `new_name` - The new file or directory name inside the same parent.
    ///
    /// # Errors
    /// Returns `PathOperationError` if the source is missing, the target exists, the root
    /// directory is renamed, or the generated target path is invalid.
    //
    // // 在当前父目录中重命名保险库文件或目录路径。
    // //
    // // 这是 `move_path` 的便捷 API：它接受现有 `VaultPath` 和新的末级名称，
    // // 保留源路径是文件还是目录的类型，并且只移动路径元数据，不重写加密载荷。
    // //
    // // # 参数
    // // * `source_path` - 现有的保险库文件或目录路径。
    // // * `new_name` - 同一父目录中的新文件名或目录名。
    // //
    // // # 错误
    // // 如果源不存在、目标已存在、重命名根目录或生成的目标路径无效，则返回 `PathOperationError`。
    pub fn rename_path_inplace(
        &mut self,
        source_path: &VaultPath,
        new_name: &str,
    ) -> Result<(), PathOperationError> {
        rename_path_inplace(self, source_path, new_name)?;
        touch_vault_update_time(self)?;
        Ok(())
    }

    /// Creates a new file path that references the same stored file as an existing path.
    ///
    /// This is a metadata-only copy: the new path points to the same encrypted file
    /// entity, and the source path's path-local tags are copied to the new path.
    /// The encrypted payload is not rewritten.
    ///
    /// # Arguments
    /// * `source_path` - The existing vault file path to copy from.
    /// * `target_path` - The new vault file path to create.
    ///
    /// # Errors
    /// Returns `PathOperationError` if the source path is missing, either path is
    /// not a file path, the target already exists, or the database update fails.
    //
    // // 创建一个引用现有路径同一存储文件的新文件路径。
    // //
    // // 这是仅元数据复制：新路径指向同一个加密文件实体，并且源路径的路径局部标签
    // // 会复制到新路径。加密载荷不会被重写。
    // //
    // // # 参数
    // // * `source_path` - 要复制的现有保险库文件路径。
    // // * `target_path` - 要创建的新保险库文件路径。
    // //
    // // # 错误
    // // 如果源路径缺失、任一路径不是文件路径、目标已存在或数据库更新失败，
    // // 则返回 `PathOperationError`。
    pub fn copy_file_path(
        &mut self,
        source_path: &VaultPath,
        target_path: &VaultPath,
    ) -> Result<(), PathOperationError> {
        copy_file_path(self, source_path, target_path)?;
        touch_vault_update_time(self)?;
        Ok(())
    }

    /// Creates a new file path that references an existing stored file hash.
    ///
    /// This inserts a new `file_entries` mapping to the existing file entity. No
    /// path-local tags are created by this API.
    ///
    /// # Arguments
    /// * `hash` - The encrypted file hash to reference.
    /// * `target_path` - The new vault file path to create.
    ///
    /// # Errors
    /// Returns `PathOperationError` if the hash does not exist, the target path is
    /// not a file path, the target already exists, or the database update fails.
    //
    // // 创建一个引用现有存储文件哈希的新文件路径。
    // //
    // // 这会向现有文件实体插入一条新的 `file_entries` 映射。此 API 不会创建
    // // 路径局部标签。
    // //
    // // # 参数
    // // * `hash` - 要引用的加密文件哈希。
    // // * `target_path` - 要创建的新保险库文件路径。
    // //
    // // # 错误
    // // 如果哈希不存在、目标路径不是文件路径、目标已存在或数据库更新失败，
    // // 则返回 `PathOperationError`。
    pub fn create_path_from_hash(
        &mut self,
        hash: &VaultHash,
        target_path: &VaultPath,
    ) -> Result<(), PathOperationError> {
        create_path_from_hash(self, hash, target_path)?;
        touch_vault_update_time(self)?;
        Ok(())
    }

    /// Creates an empty directory path in the vault tree.
    ///
    /// Missing parent directories are created automatically. The target path must
    /// be a directory path ending with `/`; no file content is created.
    ///
    /// # Arguments
    /// * `path` - The empty directory path to create.
    ///
    /// # Errors
    /// Returns `PathOperationError` if `path` is not a directory path, the target
    /// already exists, conflicts with a file path, or the database update fails.
    //
    // // 在保险库目录树中创建一个空目录路径。
    // //
    // // 缺失的父目录会自动创建。目标路径必须是以 `/` 结尾的目录路径；
    // // 不会创建任何文件内容。
    // //
    // // # 参数
    // // * `path` - 要创建的空目录路径。
    // //
    // // # 错误
    // // 如果 `path` 不是目录路径、目标已存在、与文件路径冲突或数据库更新失败，
    // // 则返回 `PathOperationError`。
    pub fn create_empty_path(&mut self, path: &VaultPath) -> Result<(), PathOperationError> {
        create_empty_path(self, path)?;
        touch_vault_update_time(self)?;
        Ok(())
    }

    // --- Remove API ---
    // // --- 删除 API ---

    /// Removes a file entity and all of its path mappings from the vault.
    ///
    /// The hash-based API deletes every path mapping that references this
    /// entity, then removes the database record and encrypted payload.
    ///
    /// # Arguments
    /// * `hash` - The hash of the file to remove.
    ///
    /// # Errors
    /// Returns `RemoveError` if file not found or deletion fails.
    //
    // // 从保险库中移除一个文件实体及其所有路径映射。
    // //
    // // 这个基于哈希的 API 会删除引用该实体的每一条路径映射，
    // // 然后删除数据库记录和加密载荷。
    // //
    // // # 参数
    // // * `hash` - 要移除的文件的哈希。
    // //
    // // # 错误
    // // 如果文件未找到或删除失败，则返回 `RemoveError`。
    pub fn remove_file(&mut self, hash: &VaultHash) -> Result<(), RemoveError> {
        remove_file(self, hash)?;
        touch_vault_update_time(self)?;
        Ok(())
    }

    /// Removes one path mapping from the vault.
    ///
    /// If this path is the final reference to the file entity, the database
    /// record and encrypted payload are also removed.
    ///
    /// # Arguments
    /// * `path` - The vault path mapping to remove.
    ///
    /// # Errors
    /// Returns `RemoveError` if the path is not found or deletion fails.
    //
    // // 从保险库中移除一条路径映射。
    // //
    // // 如果该路径是文件实体的最后一个引用，则同时删除数据库记录和加密载荷。
    // //
    // // # 参数
    // // * `path` - 要移除的保险库路径映射。
    // //
    // // # 错误
    // // 如果路径未找到或删除失败，则返回 `RemoveError`。
    pub fn remove_file_by_path(&mut self, path: &VaultPath) -> Result<(), RemoveError> {
        remove_file_by_path(self, path)?;
        touch_vault_update_time(self)?;
        Ok(())
    }

    /// Forcefully and permanently removes a file and all path mappings from the vault.
    ///
    /// This operation is idempotent and will not fail if the file or its
    /// database record is already missing. It will attempt to delete the
    /// physical file from the storage backend, all path mappings, and the database entry.
    ///
    /// Use this for cleanup operations where the state might be inconsistent.
    ///
    /// # Arguments
    /// * `hash` - The hash of the file to remove.
    ///
    /// # Errors
    /// Returns `ForceRemoveError` only on unexpected database or filesystem errors
    /// (e.g., permission denied), but not for "not found" errors.
    //
    // // 从保险库中强制并永久地移除一个文件及其全部路径映射。
    // //
    // // 此操作是幂等的，如果文件或其数据库记录已经丢失，操作不会失败。
    // // 它会尝试删除存储后端中的物理文件、全部路径映射和数据库条目。
    // //
    // // 用于清理可能存在状态不一致的情况。
    // //
    // // # 参数
    // // * `hash` - 要移除的文件的哈希。
    // //
    // // # 错误
    // // 仅在发生意外的数据库或文件系统错误 (例如权限被拒绝) 时返回 `ForceRemoveError`，
    // // 不会因“未找到”错误而返回错误。
    pub fn force_remove_file(&mut self, hash: &VaultHash) -> Result<(), ForceRemoveError> {
        force_remove_file(self, hash)?;
        touch_vault_update_time(self)?;
        Ok(())
    }

    // --- Tag/MetaData API ---
    // // --- 元数据 API ---

    /// Adds a single tag to a file path. Idempotent.
    ///
    /// # Arguments
    /// * `path` - The vault path of the file entry to tag.
    /// * `tag` - The tag string to add.
    ///
    /// # Errors
    /// Returns `TagError` if the file is not found.
    //
    // // 为文件路径添加单个标签。幂等操作。
    // //
    // // # 参数
    // // * `path` - 要标记的文件条目的保险库路径。
    // // * `tag` - 要添加的标签字符串。
    // //
    // // # 错误
    // // 如果文件未找到，则返回 `TagError`。
    pub fn add_tag(&mut self, path: &VaultPath, tag: &str) -> Result<(), TagError> {
        add_tag(self, path, tag)?;
        touch_vault_update_time(self).map_err(|e| TagError::TimestampError(e))
    }

    /// Adds multiple tags to a file path in a transaction.
    ///
    /// # Arguments
    /// * `path` - The vault path of the file entry to tag.
    /// * `tags` - A slice of tag strings to add.
    ///
    /// # Errors
    /// Returns `TagError` if the file is not found.
    //
    // // 在事务中为文件路径添加多个标签。
    // //
    // // # 参数
    // // * `path` - 要标记的文件条目的保险库路径。
    // // * `tags` - 要添加的标签字符串切片。
    // //
    // // # 错误
    // // 如果文件未找到，则返回 `TagError`。
    pub fn add_tags(&mut self, path: &VaultPath, tags: &[&str]) -> Result<(), TagError> {
        add_tags(self, path, tags)?;
        touch_vault_update_time(self).map_err(|e| TagError::TimestampError(e))
    }

    /// Removes a single tag from a file path.
    ///
    /// # Arguments
    /// * `path` - The vault path of the file entry.
    /// * `tag` - The tag string to remove.
    ///
    /// # Errors
    /// Returns `TagError` if the file is not found.
    //
    // // 从文件路径中移除单个标签。
    // //
    // // # 参数
    // // * `path` - 文件条目的保险库路径。
    // // * `tag` - 要移除的标签字符串。
    // //
    // // # 错误
    // // 如果文件未找到，则返回 `TagError`。
    pub fn remove_tag(&mut self, path: &VaultPath, tag: &str) -> Result<(), TagError> {
        remove_tag(self, path, tag)?;
        touch_vault_update_time(self).map_err(|e| TagError::TimestampError(e))
    }

    /// Removes all tags from a file path.
    ///
    /// # Arguments
    /// * `path` - The vault path of the file entry.
    ///
    /// # Errors
    /// Returns `TagError` if the file is not found.
    //
    // // 移除文件路径的所有标签。
    // //
    // // # 参数
    // // * `path` - 文件条目的保险库路径。
    // //
    // // # 错误
    // // 如果文件未找到，则返回 `TagError`。
    pub fn clear_tags(&mut self, path: &VaultPath) -> Result<(), TagError> {
        clear_tags(self, path)?;
        touch_vault_update_time(self).map_err(|e| TagError::TimestampError(e))
    }

    /// Sets (upserts) a metadata key-value pair for a file.
    ///
    /// # Arguments
    /// * `hash` - The hash of the file.
    /// * `metadata` - The metadata key-value pair to set.
    ///
    /// # Errors
    /// Returns `MetadataError` if the file is not found.
    //
    // // 设置 (更新或插入) 文件的元数据键值对。
    // //
    // // # 参数
    // // * `hash` - 文件的哈希。
    // // * `metadata` - 要设置的元数据键值对。
    // //
    // // # 错误
    // // 如果文件未找到，则返回 `MetadataError`。
    pub fn set_file_metadata(
        &mut self,
        hash: &VaultHash,
        metadata: MetadataEntry,
    ) -> Result<(), MetadataError> {
        set_file_metadata(self, hash, metadata)?;
        // 文件元数据变更通常不触发 vault 整体更新时间，除非策略改变
        // 这里保持原样，只更新文件时间 (内部已做)
        Ok(())
    }

    /// Removes a metadata key-value pair from a file.
    ///
    /// # Arguments
    /// * `hash` - The hash of the file.
    /// * `key` - The metadata key to remove.
    ///
    /// # Errors
    /// Returns `MetadataError` if the file is not found.
    //
    // // 从文件中移除元数据键值对。
    // //
    // // # 参数
    // // * `hash` - 文件的哈希。
    // // * `key` - 要移除的元数据键。
    // //
    // // # 错误
    // // 如果文件未找到，则返回 `MetadataError`。
    pub fn remove_file_metadata(
        &mut self,
        hash: &VaultHash,
        key: &str,
    ) -> Result<(), MetadataError> {
        remove_file_metadata(self, hash, key)
    }

    // --- Vault Management APIs ---
    // // --- 保险库管理 API ---

    /// Renames the vault (updates configuration).
    ///
    /// # Arguments
    /// * `new_name` - The new name for the vault.
    ///
    /// # Errors
    /// Returns `UpdateError` on configuration write failure.
    //
    // // 重命名保险库 (更新配置)。
    // //
    // // # 参数
    // // * `new_name` - 保险库的新名称。
    // //
    // // # 错误
    // // 如果配置写入失败，则返回 `UpdateError`。
    pub fn set_name(&mut self, new_name: &str) -> Result<(), UpdateError> {
        set_name(self, new_name)?;
        Ok(())
    }

    /// Gets a vault-level metadata value.
    ///
    /// # Arguments
    /// * `key` - The metadata key to retrieve.
    ///
    /// # Returns
    /// The metadata value string.
    ///
    /// # Errors
    /// Returns `MetadataError` if key not found.
    //
    // // 获取保险库级别的元数据值。
    // //
    // // # 参数
    // // * `key` - 要检索的元数据键。
    // //
    // // # 返回
    // // 元数据值字符串。
    // //
    // // # 错误
    // // 如果键未找到，则返回 `MetadataError`。
    pub fn get_vault_metadata(&self, key: &str) -> Result<String, MetadataError> {
        get_vault_metadata(self, key)
    }

    /// Sets (upserts) a vault-level metadata key-value pair.
    ///
    /// # Arguments
    /// * `metadata` - The metadata key-value pair to set.
    ///
    /// # Errors
    /// Returns `MetadataError` on database failure.
    //
    // // 设置 (更新或插入) 保险库级别的元数据键值对。
    // //
    // // # 参数
    // // * `metadata` - 要设置的元数据键值对。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `MetadataError`。
    pub fn set_vault_metadata(&mut self, metadata: MetadataEntry) -> Result<(), MetadataError> {
        set_vault_metadata(self, metadata)?;
        touch_vault_update_time(self)?;
        Ok(())
    }

    /// Removes a vault-level metadata key-value pair.
    ///
    /// # Arguments
    /// * `key` - The metadata key to remove.
    ///
    /// # Errors
    /// Returns `MetadataError` if key not found.
    //
    // // 移除保险库级别的元数据键值对。
    // //
    // // # 参数
    // // * `key` - 要移除的元数据键。
    // //
    // // # 错误
    // // 如果键未找到，则返回 `MetadataError`。
    pub fn remove_vault_metadata(&mut self, key: &str) -> Result<(), MetadataError> {
        remove_vault_metadata(self, key)?;
        touch_vault_update_time(self)?;
        Ok(())
    }

    /// Enables a specific extension feature for this vault.
    /// Feature names must be alphanumeric and space-free.
    ///
    /// # Arguments
    /// * `feature_name` - The name of the feature to enable.
    ///
    /// # Errors
    /// Returns `UpdateError` if feature name is invalid or DB write fails.
    //
    // // 为此保险库启用特定的扩展功能。
    // // 功能名称必须是字母数字且不含空格。
    // //
    // // # 参数
    // // * `feature_name` - 要启用的功能名称。
    // //
    // // # 错误
    // // 如果功能名称无效或 DB 写入失败，则返回 `UpdateError`。
    pub fn enable_feature(&mut self, feature_name: &str) -> Result<(), UpdateError> {
        enable_vault_feature(self, feature_name)
    }

    /// Checks if a feature is enabled.
    ///
    /// # Arguments
    /// * `feature_name` - The feature name to check.
    ///
    /// # Returns
    /// `true` if enabled, `false` otherwise.
    ///
    /// # Errors
    /// Returns `QueryError` on database failures.
    //
    // // 检查功能是否已启用。
    // //
    // // # 参数
    // // * `feature_name` - 要检查的功能名称。
    // //
    // // # 返回
    // // 如果启用则返回 `true`，否则返回 `false`。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn is_feature_enabled(&self, feature_name: &str) -> Result<bool, QueryError> {
        is_vault_feature_enabled(self, feature_name)
    }

    /// Returns a list of all enabled features.
    ///
    /// # Returns
    /// A vector of enabled feature name strings.
    ///
    /// # Errors
    /// Returns `QueryError` on database failures.
    //
    // // 返回所有已启用功能的列表。
    // //
    // // # 返回
    // // 已启用功能名称字符串的向量。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn get_enabled_features(&self) -> Result<Vec<String>, QueryError> {
        get_enabled_vault_features(self)
    }

    // --- Integrity APIs ---
    // // --- 完整性 API ---

    /// Verifies the integrity of a file's *encrypted* data in the vault.
    ///
    /// This is a high-performance check that re-hashes the encrypted file from storage
    /// and compares it to its known hash ID. It does **not** decrypt the file, but it
    /// proves that the data in storage has not been altered since it was added.
    ///
    /// # Arguments
    /// * `hash` - The `VaultHash` (encrypted content hash) of the file to verify.
    ///
    /// # Returns
    /// - `Ok(())` if the file exists in the database and its stored data is intact.
    /// - `Err(UpdateError)` if the file is not found in the DB, or if the stored data is corrupt.
    //
    // // 验证保险库中文件 *加密* 数据的完整性。
    // //
    // // 这是一个高性能的检查，它会从存储中重新计算加密文件的哈希值，
    // // 并将其与已知的哈希 ID 进行比较。它 **不会** 解密文件，但能证明
    // // 存储中的数据自添加以来未经更改。
    // //
    // // # 参数
    // // * `hash` - 要验证的文件的 `VaultHash` (加密后内容的哈希)。
    // //
    // // # 返回
    // // - 如果文件存在于数据库中且其存储的数据完好无损，返回 `Ok(())`。
    // // - 如果在数据库中找不到文件，或存储的数据已损坏，返回 `Err(UpdateError)`。
    pub fn verify_file_integrity(&self, hash: &VaultHash) -> Result<(), UpdateError> {
        // 1. First, ensure the file exists in the database. This is a fast check.
        // // 1. 首先，确保文件存在于数据库中。这是一个快速检查。
        match self.find_by_hash(hash)? {
            QueryFileResult::NotFound => return Err(UpdateError::FileNotFound(hash.to_string())),
            QueryFileResult::Found(_) => {
                // File exists, proceed to hash verification.
                // // 文件存在，继续进行哈希验证。
            }
        }

        // 2. Perform the actual hashing of the stored data. This is I/O-bound.
        // // 2. 对存储的数据执行实际的哈希计算。这是 I/O 密集型操作。
        verify_encrypted_file_hash(self.storage.as_ref(), hash)
    }
}

// --- Standalone Functions for Parallelism ---
// // --- 用于并行化的独立函数 ---

/// Resolves file metadata from a local path for use with the three-stage API.
///
/// This is a utility function that extracts the resolved `VaultPath`, file size,
/// and modification time from a local file. Useful for building
/// `PrepareAdditionRequest`s in CLI parallel mode.
///
/// # Arguments
/// * `source_path` - The local source file path.
/// * `dest_path` - The target `VaultPath`.
///
/// # Returns
/// A tuple of (resolved VaultPath, file size in bytes, modification time).
///
/// # Errors
/// Returns `AddFileError` if source not found or metadata read fails.
//
// // 从本地文件路径解析元数据，用于三阶段 API。
// //
// // 这是一个实用函数，从本地文件中提取解析后的 `VaultPath`、文件大小和修改时间。
// // 适用于在 CLI 并行模式中构建 `PrepareAdditionRequest`。
// //
// // # 参数
// // * `source_path` - 本地源文件路径。
// // * `dest_path` - 目标 `VaultPath`。
// //
// // # 返回
// // (解析后的 VaultPath, 文件大小（字节）, 修改时间) 的元组。
// //
// // # 错误
// // 如果源未找到或元数据读取失败，则返回 `AddFileError`。
pub fn resolve_file_metadata(
    source_path: &Path,
    dest_path: &VaultPath,
) -> Result<(VaultPath, u64, chrono::DateTime<chrono::Utc>), AddFileError> {
    _resolve_file_metadata(source_path, dest_path)
}
