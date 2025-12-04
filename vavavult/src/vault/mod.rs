use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod add;
mod config;
mod create;
mod extract;
mod query;
mod remove;
mod update;
mod open;
mod tags;
mod metadata;

use crate::common::metadata::MetadataEntry;
pub use crate::file::FileEntry;
use crate::vault::add::{add_file, execute_addition_tasks, prepare_addition_task_standalone as _prepare_addition_task_standalone};
use crate::vault::create::{create_vault};
pub use crate::vault::extract::{ExtractError};
use crate::vault::query::{check_by_hash, check_by_original_hash, check_by_path, find_by_hashes, find_by_keyword, find_by_paths, find_by_tag, get_enabled_vault_features, get_total_file_count, is_vault_feature_enabled, list_all_files, list_all_recursive, list_by_path};
use crate::vault::remove::remove_file;
use crate::vault::update::{enable_vault_feature, move_file,  rename_file_inplace,  set_name};
pub use add::{AddFileError, AdditionTask};
pub use config::VaultConfig;
pub use create::{CreateError};
pub use open::{OpenError};
pub use query::{ListResult,DirectoryEntry};
pub use query::{QueryError, QueryResult};
pub use remove::RemoveError;
pub use update::UpdateError;
pub use metadata::MetadataError;
pub use tags::TagError;
use crate::common::hash::VaultHash;
use crate::file::VaultPath;
use crate::storage::local::LocalStorage;
use crate::storage::StorageBackend;
pub use  crate::vault::extract::ExtractionTask;
use crate::vault::extract::{extract_file, execute_extraction_task_standalone as _execute_extraction_task_standalone, prepare_extraction_task};
use crate::vault::metadata::{get_vault_metadata, remove_file_metadata, remove_vault_metadata, set_file_metadata, set_vault_metadata, touch_vault_update_time};
use crate::vault::open::{open_vault};
use crate::vault::tags::{add_tag, add_tags, clear_tags, remove_tag, };

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
    pub fn open_vault_local(
        root_path: &Path,
        password: Option<&str>,
    ) -> Result<Vault, OpenError> {
        let backend = Arc::new(LocalStorage::new(root_path));
        open_vault(root_path, password, backend)
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
    /// `QueryResult::Found(FileEntry)` if found, otherwise `QueryResult::NotFound`.
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
    // // 如果找到，返回 `QueryResult::Found(FileEntry)`，否则返回 `QueryResult::NotFound`。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn find_by_hash(&self, hash: &VaultHash) -> Result<QueryResult, QueryError> {
        check_by_hash(self, hash)
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
    /// `QueryResult::Found(FileEntry)` if found, otherwise `QueryResult::NotFound`.
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
    // // 如果找到，返回 `QueryResult::Found(FileEntry)`，否则返回 `QueryResult::NotFound`。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn find_by_path(&self, path: &VaultPath) -> Result<QueryResult, QueryError> {
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
    pub fn find_by_paths(&self, paths: &[VaultPath]) -> Result<Vec<FileEntry>, QueryError> {
        find_by_paths(self, paths)
    }

    /// Finds a file entry by the `VaultHash` of its *original* (unencrypted) content.
    /// Useful for checking if a specific file content already exists (deduplication).
    ///
    /// # Arguments
    /// * `original_hash` - The SHA256 hash of the original file content.
    ///
    /// # Returns
    /// `QueryResult::Found(FileEntry)` if found, otherwise `QueryResult::NotFound`.
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
    // // 如果找到，返回 `QueryResult::Found(FileEntry)`，否则返回 `QueryResult::NotFound`。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn find_by_original_hash(&self, original_hash: &VaultHash) -> Result<QueryResult, QueryError> {
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
    pub fn find_by_tag(&self, tag: &str) -> Result<Vec<FileEntry>, QueryError> {
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
    pub fn find_by_keyword(&self, keyword: &str) -> Result<Vec<FileEntry>, QueryError> {
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

    /// Lists entries (files or subdirectories) directly under a given directory path.
    ///
    /// Unlike `list_by_path` which might only return paths, this method returns:
    /// - `DirectoryEntry::File(FileEntry)` for files, providing full metadata (tags, size, time, etc.).
    /// - `DirectoryEntry::Directory(VaultPath)` for subdirectories.
    ///
    /// This enables UI/CLI applications to display detailed file information in a list view
    /// without performing N+1 queries.
    ///
    /// # Arguments
    /// * `path` - The directory path to list (e.g., "/docs/").
    ///
    /// # Returns
    /// A vector of `DirectoryEntry` objects representing the immediate contents.
    ///
    /// # Errors
    /// Returns `QueryError::NotADirectory` if `path` is a file path.
    /// Returns `QueryError` on database failures.
    //
    // // 列出直接位于给定目录路径下的条目（文件或子目录）。
    // //
    // // 与仅返回路径的方法不同，此方法返回：
    // // - 对于文件，返回 `DirectoryEntry::File(FileEntry)`，提供完整元数据（标签、大小、时间等）。
    // // - 对于子目录，返回 `DirectoryEntry::Directory(VaultPath)`。
    // //
    // // 这使得 UI/CLI 应用程序能够在列表视图中显示详细的文件信息，而无需执行 N+1 次查询。
    // //
    // // # 参数
    // // * `path` - 要列出的目录路径 (例如 "/docs/")。
    // //
    // // # 返回
    // // 代表直接内容的 `DirectoryEntry` 对象向量。
    // //
    // // # 错误
    // // 如果 `path` 是一个文件路径，则返回 `QueryError::NotADirectory`。
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn list_by_path(&self, path: &VaultPath) -> Result<Vec<DirectoryEntry>, QueryError> {
        list_by_path(self, path)
    }

    /// Recursively lists all files under a given directory path and returns their `VaultHash`es.
    ///
    /// This is optimized for bulk operations (like mass extraction or deletion).
    ///
    /// # Arguments
    /// * `path` - The root directory path to start listing from.
    ///
    /// # Returns
    /// A vector of `VaultHash`es for all files found recursively.
    ///
    /// # Errors
    /// Returns `QueryError::NotADirectory` if `path` is a file path.
    /// Returns `QueryError` on database failures.
    //
    // // 递归列出一个目录下的所有文件，并返回它们的 `VaultHash`。
    // //
    // // 这针对批量操作（如批量提取或删除）进行了优化。
    // //
    // // # 参数
    // // * `path` - 开始列出的根目录路径。
    // //
    // // # 返回
    // // 递归找到的所有文件的 `VaultHash` 向量。
    // //
    // // # 错误
    // // 如果 `path` 是一个文件路径，则返回 `QueryError::NotADirectory`。
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn list_all_recursive(&self, path: &VaultPath) -> Result<Vec<VaultHash>, QueryError> {
        list_all_recursive(self, path)
    }

    /// Gets the total number of files in the vault.
    ///
    /// This is a high-performance query that directly counts database rows.
    ///
    /// # Returns
    /// The count of files as an `i64`.
    ///
    /// # Errors
    /// Returns `QueryError` on database failures.
    //
    // // 获取保险库中的文件总数。
    // //
    // // 这是一个高性能查询，直接对数据库行进行计数。
    // //
    // // # 返回
    // // 文件计数，类型为 `i64`。
    // //
    // // # 错误
    // // 如果发生数据库故障，则返回 `QueryError`。
    pub fn get_file_count(&self) -> Result<i64, QueryError> {
        get_total_file_count(self)
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
    ) -> Result<VaultHash, AddFileError> {
        let result = add_file(self, source_path, dest_path)?;

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

    /// Stage 1 (Add): Encrypts a file and prepares it for a batch commit.
    ///
    /// This is a **thread-safe** method that performs the expensive CPU/IO encryption work
    /// without locking the vault database. It writes to a temporary staging area using
    /// the storage backend.
    ///
    /// # Arguments
    /// * `source_path` - The path to the local file.
    /// * `dest_path` - The final target `VaultPath`.
    ///
    /// # Returns
    /// An `EncryptedAddingFile` object ready to be passed to `commit_add_files`.
    ///
    /// # Errors
    /// Returns `AddFileError` if encryption fails, IO error occurs, or source is invalid.
    //
    // // 阶段 1 (添加): 加密文件并准备进行批量提交。
    // //
    // // 这是一个 **线程安全** 的方法，它执行昂贵的 CPU/IO 加密工作，
    // // 而无需锁定保险库数据库。它使用存储后端写入临时暂存区。
    // //
    // // # 参数
    // // * `source_path` - 本地文件的路径。
    // // * `dest_path` - 最终的目标 `VaultPath`。
    // //
    // // # 返回
    // // 一个 `EncryptedAddingFile` 对象，准备好传递给 `commit_add_files`。
    // //
    // // # 错误
    // // 如果加密失败、发生 IO 错误或源无效，则返回 `AddFileError`。
    pub fn prepare_addition_task(
        &self,
        source_path: &Path,
        dest_path: &VaultPath,
    ) -> Result<AdditionTask, AddFileError> {
        _prepare_addition_task_standalone(self.storage.as_ref(), source_path, dest_path)
    }

    /// Stage 2 (Add): Commits one or more encrypted files to the vault database.
    ///
    /// This method requires exclusive `&mut self` access (locking the DB) to perform
    /// a transaction. It moves files from the staging area to permanent storage and
    /// inserts records into the database.
    ///
    /// # Arguments
    /// * `files` - A `Vec` of `EncryptedAddingFile` objects from stage 1.
    ///
    /// # Errors
    /// Returns `AddFileError` if database transaction fails or file commit fails.
    //
    // // 阶段 2 (添加): 将一个或多个已加密的文件提交到保险库数据库。
    // //
    // // 此方法需要独占的 `&mut self` 访问权限 (锁定 DB) 来执行事务。
    // // 它将文件从暂存区移动到永久存储，并将记录插入数据库。
    // //
    // // # 参数
    // // * `files` - 来自阶段 1 的 `EncryptedAddingFile` 对象列表。
    // //
    // // # 错误
    // // 如果数据库事务失败或文件提交失败，则返回 `AddFileError`。
    pub fn execute_addition_tasks(
        &mut self,
        files: Vec<AdditionTask>,
    ) -> Result<(), AddFileError> {
        if files.is_empty() {
            return Ok(());
        }
        execute_addition_tasks(self, files)?;
        touch_vault_update_time(self)?;
        Ok(())
    }

    // --- Extract APIs ---
    // // --- 提取 API ---

    /// Extracts a file from the vault (Synchronous convenience method).
    ///
    /// Handles preparation and execution in a single call.
    /// For bulk extract, prefer using `prepare_extraction_task` and `execute_extraction_task` separately.
    ///
    /// # Arguments
    /// * `hash` - The `VaultHash` of the file to extract.
    /// * `destination_path` - The full local path where the file will be saved.
    ///
    /// # Errors
    /// Returns `ExtractError` if file not found, decryption fails, or IO error occurs.
    //
    // // 从保险库中提取文件 (同步便捷方法)。
    // //
    // // 在一次调用中处理准备和执行。
    // // 对于批量提取，请首选分开使用 `prepare_extraction_task` 和 `execute_extraction_task`。
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

    /// Stage 1 (Extract): Prepares a file for extraction.
    ///
    /// This is a fast, thread-safe method that queries the database (holding a read lock)
    /// and returns an `ExtractionTask` ticket. This ticket contains all information
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
    // // 这是一个快速、线程安全的方法，它查询数据库 (持有读锁)
    // // 并返回一个 `ExtractionTask` 票据。该票据包含缓慢的解密步骤
    // // 所需的所有信息 (密钥、哈希、路径)。
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
        hash: &VaultHash
    ) -> Result<ExtractionTask, ExtractError> {
        prepare_extraction_task(self, hash)
    }

    /// Stage 2 (Extract): Executes a prepared extraction task.
    ///
    /// This instance method wraps `execute_extraction_task_standalone`.
    /// In multithreaded contexts, consider collecting tasks and calling the standalone
    /// function in parallel to avoid contention on the Vault instance.
    ///
    /// # Arguments
    /// * `task` - The task object from `prepare_extraction_task`.
    /// * `destination_path` - The local path to save the decrypted file.
    ///
    /// # Errors
    /// Returns `ExtractError` if decryption fails, IO error occurs, or integrity check fails.
    //
    // // 阶段 2 (提取): 执行一个已准备好的提取任务。
    // //
    // // 此实例方法包装了 `execute_extraction_task_standalone`。
    // // 在多线程环境中，考虑收集任务并并行调用独立函数，
    // // 以避免对 Vault 实例的争用。
    // //
    // // # 参数
    // // * `task` - 来自 `prepare_extraction_task` 的任务对象。
    // // * `destination_path` - 保存解密文件的本地路径。
    // //
    // // # 错误
    // // 如果解密失败、发生 IO 错误或完整性检查失败，则返回 `ExtractError`。
    pub fn execute_extraction_task(
        &self, // 接收 &self 以实现 API 对称性，但内部实现不使用它
        task: &ExtractionTask,
        destination_path: &Path,
    ) -> Result<(), ExtractError> {
        _execute_extraction_task_standalone(self.storage.as_ref(), task, destination_path)
    }

    // --- Update APIs ---
    // // --- 更新 API ---

    /// Moves a file within the vault to a new path.
    ///
    /// # Arguments
    /// * `hash` - The hash of the file to move.
    /// * `target_path` - The new path.
    ///   - If directory: Moves file into directory, keeps name.
    ///   - If file: Moves and renames.
    ///
    /// # Errors
    /// Returns `UpdateError` on name collision or if file not found.
    //
    // // 在保险库中将文件移动到新路径。
    // //
    // // # 参数
    // // * `hash` - 要移动的文件的哈希。
    // // * `target_path` - 新路径。
    // //   - 如果是目录: 将文件移动到目录中，保留名称。
    // //   - 如果是文件: 移动并重命名。
    // //
    // // # 错误
    // // 如果名称冲突或文件未找到，返回 `UpdateError`。
    pub fn move_file(&mut self, hash: &VaultHash, target_path: &VaultPath) -> Result<(), UpdateError> {
        move_file(self, hash, target_path)?;
        touch_vault_update_time(self).map_err(|e| UpdateError::MetadataError(e))
    }

    /// Renames a file in its current directory (In-place).
    ///
    /// # Arguments
    /// * `hash` - The hash of the file to rename.
    /// * `new_filename` - The new filename (must NOT contain separators `/` or `\`).
    ///
    /// # Errors
    /// Returns `UpdateError` if filename is invalid, file not found, or name collision.
    //
    // // 在当前目录中重命名文件 (就地)。
    // //
    // // # 参数
    // // * `hash` - 要重命名的文件的哈希。
    // // * `new_filename` - 新文件名 (必须 **不** 包含分隔符 `/` 或 `\`)。
    // //
    // // # 错误
    // // 如果文件名无效、文件未找到或名称冲突，则返回 `UpdateError`。
    pub fn rename_file_inplace(&mut self, hash: &VaultHash, new_filename: &str) -> Result<(), UpdateError> {
        rename_file_inplace(self, hash, new_filename)?;
        touch_vault_update_time(self).map_err(|e| UpdateError::MetadataError(e))
    }

    // --- Remove API ---
    // // --- 删除 API ---

    /// Permanently removes a file from the vault.
    ///
    /// Deletes the database record (cascading to tags/metadata) and the
    /// physical encrypted file from the storage backend.
    ///
    /// # Arguments
    /// * `hash` - The hash of the file to remove.
    ///
    /// # Errors
    /// Returns `RemoveError` if file not found or deletion fails.
    //
    // // 从保险库中永久移除文件。
    // //
    // // 删除数据库记录 (级联删除标签/元数据) 以及存储后端中的物理加密文件。
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

    // --- Tag/MetaData API ---
    // // --- 元数据 API ---

    /// Adds a single tag to a file. Idempotent.
    ///
    /// # Arguments
    /// * `hash` - The hash of the file to tag.
    /// * `tag` - The tag string to add.
    ///
    /// # Errors
    /// Returns `TagError` if the file is not found.
    //
    // // 为文件添加单个标签。幂等操作。
    // //
    // // # 参数
    // // * `hash` - 要标记的文件的哈希。
    // // * `tag` - 要添加的标签字符串。
    // //
    // // # 错误
    // // 如果文件未找到，则返回 `TagError`。
    pub fn add_tag(&mut self, hash: &VaultHash, tag: &str) -> Result<(), TagError> {
        add_tag(self, hash, tag)?;
        touch_vault_update_time(self).map_err(|e| TagError::TimestampError(e))
    }

    /// Adds multiple tags to a file in a transaction.
    ///
    /// # Arguments
    /// * `hash` - The hash of the file to tag.
    /// * `tags` - A slice of tag strings to add.
    ///
    /// # Errors
    /// Returns `TagError` if the file is not found.
    //
    // // 在事务中为文件添加多个标签。
    // //
    // // # 参数
    // // * `hash` - 要标记的文件的哈希。
    // // * `tags` - 要添加的标签字符串切片。
    // //
    // // # 错误
    // // 如果文件未找到，则返回 `TagError`。
    pub fn add_tags(&mut self, hash: &VaultHash, tags: &[&str]) -> Result<(), TagError> {
        add_tags(self, hash, tags)?;
        touch_vault_update_time(self).map_err(|e| TagError::TimestampError(e))
    }

    /// Removes a single tag from a file.
    ///
    /// # Arguments
    /// * `hash` - The hash of the file.
    /// * `tag` - The tag string to remove.
    ///
    /// # Errors
    /// Returns `TagError` if the file is not found.
    //
    // // 从文件中移除单个标签。
    // //
    // // # 参数
    // // * `hash` - 文件的哈希。
    // // * `tag` - 要移除的标签字符串。
    // //
    // // # 错误
    // // 如果文件未找到，则返回 `TagError`。
    pub fn remove_tag(&mut self, hash: &VaultHash, tag: &str) -> Result<(), TagError> {
        remove_tag(self, hash, tag)?;
        touch_vault_update_time(self).map_err(|e| TagError::TimestampError(e))
    }

    /// Removes all tags from a file.
    ///
    /// # Arguments
    /// * `hash` - The hash of the file.
    ///
    /// # Errors
    /// Returns `TagError` if the file is not found.
    //
    // // 移除文件的所有标签。
    // //
    // // # 参数
    // // * `hash` - 文件的哈希。
    // //
    // // # 错误
    // // 如果文件未找到，则返回 `TagError`。
    pub fn clear_tags(&mut self, hash: &VaultHash) -> Result<(), TagError> {
        clear_tags(self, hash)?;
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
    pub fn set_file_metadata(&mut self, hash: &VaultHash, metadata: MetadataEntry) -> Result<(), MetadataError> {
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
    pub fn remove_file_metadata(&mut self, hash: &VaultHash, key: &str) -> Result<(), MetadataError> {
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
}

// --- Standalone Functions for Parallelism ---
// // --- 用于并行化的独立函数 ---

/// Encrypts a file for adding to the vault (Standalone).
///
/// This is a thread-safe, CPU-intensive function that does not require a `&Vault` lock.
/// It works directly with the `StorageBackend` to write temporary encrypted data.
///
/// # Arguments
/// * `storage` - The storage backend to use.
/// * `source_path` - The local source file path.
/// * `dest_path` - The target `VaultPath`.
///
/// # Returns
/// An `EncryptedAddingFile` struct containing encryption details and staging token.
///
/// # Errors
/// Returns `AddFileError` on encryption failure, IO error, or invalid path.
//
// // 加密一个文件用于添加到保险库 (独立函数)。
// //
// // 这是一个线程安全的、CPU 密集型的函数，不需要 `&Vault` 锁。
// // 它直接与 `StorageBackend` 协作以写入临时加密数据。
// //
// // # 参数
// // * `storage` - 要使用的存储后端。
// // * `source_path` - 本地源文件路径。
// // * `dest_path` - 目标 `VaultPath`。
// //
// // # 返回
// // 包含加密细节和暂存令牌的 `EncryptedAddingFile` 结构。
// //
// // # 错误
// // 如果加密失败、发生 IO 错误或路径无效，则返回 `AddFileError`。
pub fn prepare_addition_task_standalone(
    storage: &dyn StorageBackend,
    source_path: &Path,
    dest_path: &VaultPath,
) -> Result<AdditionTask, AddFileError> {
    _prepare_addition_task_standalone(storage, source_path, dest_path)
}

/// Executes a prepared extraction task (Standalone).
///
/// This is a thread-safe, CPU-intensive function that performs decryption.
/// Ideal for use in parallel iterators (e.g., Rayon).
///
/// # Arguments
/// * `storage` - The storage backend to read from.
/// * `task` - The extraction ticket containing keys and hashes.
/// * `destination_path` - The local path to write the decrypted file.
///
/// # Errors
/// Returns `ExtractError` on decryption failure, IO error, or integrity check failure.
//
// // 执行已准备好的提取任务 (独立函数)。
// //
// // 这是一个线程安全的、CPU 密集型的函数，用于执行解密。
// // 非常适合在并行迭代器 (如 Rayon) 中使用。
// //
// // # 参数
// // * `storage` - 要从中读取的存储后端。
// // * `task` - 包含密钥和哈希的提取票据。
// // * `destination_path` - 写入解密文件的本地路径。
// //
// // # 错误
// // 如果解密失败、发生 IO 错误或完整性检查失败，则返回 `ExtractError`。
pub fn execute_extraction_task_standalone(
    storage: &dyn StorageBackend,
    task: &ExtractionTask,
    destination_path: &Path,
) -> Result<(), ExtractError> {
    _execute_extraction_task_standalone(storage, task, destination_path)
}