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

use crate::common::metadata::MetadataEntry;
pub use crate::file::FileEntry;
use crate::vault::add::{add_file, commit_add_files, encrypt_file_for_add_standalone as _encrypt_file_for_add_standalone};
use crate::vault::create::{create_vault, open_vault};
pub use crate::vault::extract::{ExtractError};
use crate::vault::query::{check_by_hash, check_by_original_hash, check_by_path, find_by_hashes, find_by_keyword, find_by_paths, find_by_tag, get_enabled_vault_features, get_total_file_count, is_vault_feature_enabled, list_all_files, list_all_recursive, list_by_path};
use crate::vault::remove::remove_file;
use crate::vault::update::{add_tag, add_tags, clear_tags, enable_vault_feature, get_vault_metadata, move_file, remove_file_metadata, remove_tag, remove_vault_metadata, rename_file_inplace, set_file_metadata, set_name, set_vault_metadata, touch_vault_update_time};
pub use add::{AddFileError, EncryptedAddingFile};
pub use config::VaultConfig;
pub use create::{CreateError, OpenError};
pub use query::{ListResult,DirectoryEntry};
pub use query::{QueryError, QueryResult};
pub use remove::RemoveError;
pub use update::UpdateError;
use crate::common::hash::VaultHash;
use crate::file::VaultPath;
use crate::storage::local::LocalStorage;
use crate::storage::StorageBackend;
pub use  crate::vault::extract::ExtractionTask;
use crate::vault::extract::{extract_file, execute_extraction_task_standalone as _execute_extraction_task_standalone, prepare_extraction_task};

/// Represents a vault loaded into memory.
///
/// It holds the vault's configuration and a live database connection,
/// providing the primary interface for all vault operations.
//
// // 代表一个加载到内存中的保险库。
// //
// // 它持有保险库的配置和一个活动的数据库连接，
// // 提供了所有保险库操作的主要接口。
#[derive(Debug)]
pub struct Vault {
    /// The root path of the vault directory.
    // // 保险库目录的根路径。
    pub root_path: PathBuf,
    /// The vault's configuration, loaded from `master.json`.
    // // 保险库的配置，从 `master.json` 加载。
    pub config: VaultConfig,
    /// An open connection to the vault's database.
    // // 一个到保险库数据库的打开的连接。
    pub database_connection: Connection,
    /// The abstract storage backend for file content.
    // 使用 Arc<dyn ...> 实现动态分发
    pub storage: Arc<dyn StorageBackend>,
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
    //
    // // 在指定路径创建一个新的保险库。
    // //
    // // 这将创建根目录并初始化 `master.json` 配置文件和 `master.db` 数据库。
    // //
    // // # 参数
    // // * `root_path` - 将在其中创建保险库目录的路径。
    // // * `vault_name` - 保险库的名称，存储在配置中。
    // // * `password` - 可选的密码。如果提供，保险库将被加密。
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

    pub fn create_vault_local(
        root_path: &Path,
        vault_name: &str,
        password: Option<&str>,
    ) -> Result<Vault, CreateError> {
        let backend = Arc::new(LocalStorage::new(root_path));
        create_vault(root_path, vault_name, password, backend)
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
    //
    // // 从指定路径打开一个已存在的保险库。
    // //
    // // # 参数
    // // * `root_path` - 已存在的保险库目录的路径。
    // // * `password` - 可选的密码。如果保险库已加密，则此项为必需。
    // //
    // // # 错误
    // // 如果路径不存在、配置丢失或损坏，或者为加密保险库提供了错误的密码，则返回 `OpenError`。
    pub fn open_vault(
        root_path: &Path,
        password: Option<&str>,
        backend: Arc<dyn StorageBackend>,
    ) -> Result<Vault, OpenError> {
        open_vault(root_path, password, backend)
    }

    pub fn open_vault_local(
        root_path: &Path,
        password: Option<&str>,
    ) -> Result<Vault, OpenError> {
        let backend = Arc::new(LocalStorage::new(root_path));
        open_vault(root_path, password, backend)
    }

    // --- Find APIs ---
    // // --- 查找 API ---

    /// Finds a file entry by its exact `VaultPath`.
    //
    // // 通过精确的 `VaultPath` 查找文件条目。
    pub fn find_by_path(&self, path: &VaultPath) -> Result<QueryResult, QueryError> {
        check_by_path(self, path)
    }

    /// Finds a file entry by the `VaultHash` of its *encrypted* content.
    /// This hash is the file's primary key in the vault.
    //
    // // 通过其 *加密* 内容的 `VaultHash` 查找文件条目。
    // // 这个哈希是文件在保险库中的主键。
    pub fn find_by_hash(&self, hash: &VaultHash) -> Result<QueryResult, QueryError> {
        check_by_hash(self, hash)
    }

    /// Finds multiple file entries by their `VaultHash`es in a single batch query.
    ///
    /// Any hashes not found in the vault are simply omitted from the result.
    //
    // // 在单个批处理查询中通过 `VaultHash` 查找多个文件条目。
    // //
    // // 任何在保险库中未找到的哈希值都将从结果中省略。
    pub fn find_by_hashes(&self, hashes: &[VaultHash]) -> Result<Vec<FileEntry>, QueryError> {
        find_by_hashes(self, hashes)
    }

    /// Finds multiple file entries by their `VaultPath`s in a single batch query.
    ///
    /// Any paths not found in the vault are simply omitted from the result.
    //
    // // 在单个批处理查询中通过 `VaultPath` 查找多个文件条目。
    // //
    // // 任何在保险库中未找到的路径都将从结果中省略。
    pub fn find_by_paths(&self, paths: &[VaultPath]) -> Result<Vec<FileEntry>, QueryError> {
        find_by_paths(self, paths)
    }

    /// Finds a file entry by the `VaultHash` of its *original* (unencrypted) content.
    //
    // // 通过其 *原始* (未加密) 内容的 `VaultHash` 查找文件条目。
    pub fn find_by_original_hash(&self, original_hash: &VaultHash) -> Result<QueryResult, QueryError> {
        check_by_original_hash(self, original_hash)
    }

    /// Finds all file entries associated with a specific tag.
    //
    // // 查找与特定标签关联的所有文件条目。
    pub fn find_by_tag(&self, tag: &str) -> Result<Vec<FileEntry>, QueryError> {
        find_by_tag(self, tag)
    }

    /// Performs a case-insensitive fuzzy search by keyword.
    /// Searches matching the `keyword` against file paths or tags.
    //
    // // 按关键字执行不区分大小写的模糊搜索。
    // // 搜索与 `keyword` 匹配的文件路径或标签。
    pub fn find_by_keyword(&self, keyword: &str) -> Result<Vec<FileEntry>, QueryError> {
        find_by_keyword(self, keyword)
    }

    // --- List APIs ---
    // // --- 列表 API ---

    /// Lists all files currently stored in the vault, returning their full entries.
    //
    // // 列出保险库中当前存储的所有文件（返回完整条目）。
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

    /// Lists entries (files or subdirectories) under a given directory path.
    ///
    /// Unlike `list_by_path` which only returns paths, this method returns:
    /// - `DirectoryEntry::File(FileEntry)` for files, providing full metadata (tags, size, time, etc.).
    /// - `DirectoryEntry::Directory(VaultPath)` for subdirectories.
    ///
    /// This is particularly useful for UI/CLI applications that need to display detailed file information
    /// in a list view without performing N+1 queries.
    ///
    /// # Arguments
    /// * `path` - The directory path to list.
    ///
    /// # Errors
    /// Returns `QueryError::NotADirectory` if `path` is a file path.
    //
    // // 列出给定目录路径下的条目（文件或子目录）。
    // //
    // // 与仅返回路径的 `list_by_path` 不同，此方法返回：
    // // - 对于文件，返回 `DirectoryEntry::File(FileEntry)`，提供完整元数据（标签、大小、时间等）。
    // // - 对于子目录，返回 `DirectoryEntry::Directory(VaultPath)`。
    // //
    // // 这对于需要在列表视图中显示详细文件信息而又不希望执行 N+1 次查询的 UI/CLI 应用程序特别有用。
    // //
    // // # 参数
    // // * `path` - 要列出的目录路径。
    // //
    // // # 错误
    // // 如果 `path` 是一个文件路径，则返回 `QueryError::NotADirectory`。
    pub fn list_by_path(&self, path: &VaultPath) -> Result<Vec<DirectoryEntry>, QueryError> {
        list_by_path(self, path)
    }

    /// Recursively lists all files under a given directory path and returns their `VaultHash`es.
    ///
    /// # Errors
    /// Returns `QueryError::NotADirectory` if `path` is a file path (e.g., "/a.txt").
    //
    // // 递归列出一个目录下的所有文件，并返回它们的 `VaultHash`。
    // //
    // // # 错误
    // // 如果 `path` 是一个文件路径（例如 "/a.txt"），则返回 `QueryError::NotADirectory`。
    pub fn list_all_recursive(&self, path: &VaultPath) -> Result<Vec<VaultHash>, QueryError> {
        list_all_recursive(self, path)
    }

    /// Gets the total number of files in the vault.
    ///
    /// This is a high-performance query that directly counts database rows.
    //
    // // 获取保险库中的文件总数。
    // //
    // // 这是一个高性能查询，直接对数据库行进行计数。
    pub fn get_file_count(&self) -> Result<i64, QueryError> {
        get_total_file_count(self)
    }

    // --- Add APIs ---
    // // --- 添加 API ---

    /// Adds a new file to the vault.
    ///
    /// This is a high-level convenience function that handles encryption and database
    /// commit in a single call.
    ///
    /// # Arguments
    /// * `source_path` - The path to the file on the local filesystem.
    /// * `dest_path` - The target `VaultPath` inside the vault.
    ///   - If `dest_path` is a file path (e.g., `/docs/report.txt`), the file is saved to that path.
    ///   - If `dest_path` is a directory path (e.g., `/docs/`), the source filename is appended
    ///     (e.g., `/docs/source_file_name.txt`).
    ///
    /// # Returns
    /// The `VaultHash` (encrypted) of the added file on success.
    ///
    /// # Errors
    /// Returns `AddFileError` if the source file is not found, or if the
    /// `dest_path` or original content hash conflicts with an existing file.
    //
    // // 添加一个新文件到保险库。
    // //
    // // 这是一个高级便捷函数，它在一次调用中处理加密和数据库提交。
    // //
    // // # 参数
    // // * `source_path` - 本地文件系统上的文件路径。
    // // * `dest_path` - 保险库中的目标 `VaultPath`。
    // //   - 如果 `dest_path` 是一个文件路径 (例如 "/docs/report.txt")，文件将被保存到该路径。
    // //   - 如果 `dest_path` 是一个目录路径 (例如 "/docs/")，源文件名将被自动附加
    // //     (例如 "/docs/source_file_name.txt")。
    // //
    // // # 返回
    // // 成功时返回添加文件的（加密后的）`VaultHash`。
    // //
    // // # 错误
    // // 如果源文件未找到，或者 `dest_path` 或原始内容哈希与现有文件冲突，则返回 `AddFileError`。
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
    /// This is a thread-safe method that performs the expensive CPU/IO work
    /// of encryption without locking the vault database.
    ///
    /// # Arguments
    /// * `source_path` - The path to the local file.
    /// * `dest_path` - The final target `VaultPath`.
    ///
    /// # Returns
    /// An `EncryptedAddingFile` object ready to be passed to `commit_add_files`.
    ///
    /// # Errors
    /// Returns `AddFileError` if the source file cannot be read or the path is invalid.
    //
    // // 阶段 1 (添加): 加密一个文件并准备进行批量提交。
    // //
    // // 这是一个线程安全的方法，它执行昂贵的 CPU/IO 加密工作，而无需锁定保险库数据库。
    // //
    // // # 参数
    // // * `source_path` - 本地文件的路径。
    // // * `dest_path` - 最终的目标 `VaultPath`。
    // //
    // // # 返回
    // // 一个 `EncryptedAddingFile` 对象，准备好传递给 `commit_add_files`。
    // //
    // // # 错误
    // // 如果源文件无法读取或路径无效，则返回 `AddFileError`。
    pub fn encrypt_file_for_add(
        &self,
        source_path: &Path,
        dest_path: &VaultPath,
    ) -> Result<EncryptedAddingFile, AddFileError> {
        _encrypt_file_for_add_standalone(self.storage.as_ref(), source_path, dest_path)
    }

    /// Stage 2 (Add): Commits one or more encrypted files to the vault database.
    ///
    /// This method requires exclusive `&mut self` access to perform a database
    /// transaction, but it is very fast as all encryption is already complete.
    ///
    /// # Arguments
    /// * `files` - A `Vec` of `EncryptedAddingFile` objects from `encrypt_file_for_add`.
    ///
    /// # Errors
    /// Returns `AddFileError` if any file conflicts with existing vault data
    /// or if the database transaction fails.
    //
    // // 阶段 2 (添加): 将一个或多个已加密的文件提交到保险库数据库。
    // //
    // // 此方法需要独占的 `&mut self` 访问来执行数据库事务，
    // // 但由于所有加密工作都已完成，因此它非常快。
    // //
    // // # 参数
    // // * `files` - 一个 `Vec`，包含从 `encrypt_file_for_add` 获取的 `EncryptedAddingFile` 对象。
    // //
    // // # 错误
    // // 如果任何文件与现有的保险库数据冲突或数据库事务失败，则返回 `AddFileError`。
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

    // --- Extract APIs ---
    // // --- 提取 API ---

    /// Stage 1 (Extract): Prepares a file for extraction.
    ///
    /// This is a fast, thread-safe method that queries the database (with a `&self` lock)
    /// and returns an `ExtractionTask` ticket. This ticket contains all information
    /// needed for the slow, CPU-bound decryption step.
    ///
    /// # Arguments
    /// * `hash` - The `VaultHash` (encrypted) of the file to extract.
    ///
    /// # Returns
    /// An `ExtractionTask` object ready for `execute_extraction_task` or
    /// `execute_extraction_task_standalone`.
    ///
    /// # Errors
    /// Returns `ExtractError::FileNotFound` if the hash is not in the database.
    //
    // // 阶段 1 (提取): 准备一个文件用于提取。
    // //
    // // 这是一个快速、线程安全的方法，它查询数据库（使用 `&self` 锁）
    // // 并返回一个 `ExtractionTask` 票据。该票据包含缓慢的、CPU 密集的解密步骤
    // // 所需的所有信息。
    // //
    // // # 参数
    // // * `hash` - 要提取的文件的（加密后）`VaultHash`。
    // //
    // // # 返回
    // // 一个 `ExtractionTask` 对象，可用于 `execute_extraction_task` 或
    // // `execute_extraction_task_standalone`。
    // //
    // // # 错误
    // // 如果在数据库中未找到该哈希，则返回 `ExtractError::FileNotFound`。
    pub fn prepare_extraction_task(
        &self,
        hash: &VaultHash
    ) -> Result<ExtractionTask, ExtractError> {
        prepare_extraction_task(self, hash)
    }

    /// Stage 2 (Extract): Executes a prepared extraction task.
    ///
    /// This is an instance method wrapper around `execute_extraction_task_standalone`
    /// for API symmetry. It performs the slow, CPU-intensive decryption.
    ///
    /// **Note**: In multithreaded contexts (like a CLI), prefer collecting all
    /// tasks from `prepare_extraction_task` and then calling
    /// `vavavult::vault::execute_extraction_task_standalone` in parallel.
    ///
    /// # Arguments
    /// * `task` - The task object obtained from `prepare_extraction_task`.
    /// * `destination_path` - The full local filesystem path to save the decrypted file.
    //
    // // 阶段 2 (提取): 执行一个已准备好的提取任务。
    // //
    // // 这是一个实例方法，包装了 `execute_extraction_task_standalone` 以实现 API 对称性。
    // // 它执行缓慢的、CPU 密集型的解密操作。
    // //
    // // **注意**: 在多线程环境中 (如 CLI)，应优先使用 `prepare_extraction_task`
    // // 收集所有任务，然后并行调用 `vavavult::vault::execute_extraction_task_standalone`。
    // //
    // // # 参数
    // // * `task` - 从 `prepare_extraction_task` 获取的任务对象。
    // // * `destination_path` - 用于保存解密文件的完整本地文件系统路径。
    pub fn execute_extraction_task(
        &self, // 接收 &self 以实现 API 对称性，但内部实现不使用它
        task: &ExtractionTask,
        destination_path: &Path,
    ) -> Result<(), ExtractError> {
        _execute_extraction_task_standalone(self.storage.as_ref(), task, destination_path)
    }

    /// Extracts a file from the vault to a specified destination path.
    ///
    // // This is a high-level convenience function that handles preparation and
    // // execution in a single call.
    ///
    /// # Arguments
    /// * `hash` - The `VaultHash` (encrypted) of the file to extract.
    /// * `destination_path` - The full path (including filename) where the file will be saved.
    ///
    /// # Errors
    /// Returns `ExtractError` if the file is not found, decryption fails,
    /// or the integrity check (comparing original hashes) fails.
    //
    // // 从保险库中提取一个文件到指定的目标路径。
    // //
    // // 这是一个高级便捷函数，在一次调用中处理准备和执行。
    // //
    // // # 参数
    // // * `hash` - 要提取的文件的（加密后）`VaultHash`。
    // // * `destination_path` - 文件将被保存到的完整路径（包括文件名）。
    // //
    // // # 错误
    // // 如果文件未找到、解密失败或完整性检查（比较原始哈希）失败，则返回 `ExtractError`。
    pub fn extract_file(
        &self,
        hash: &VaultHash,
        destination_path: &Path,
    ) -> Result<(), ExtractError> {
        extract_file(self, hash, destination_path)
    }

    // --- Update APIs ---
    // // --- 更新 API ---

    /// Moves a file within the vault to a new path.
    ///
    /// - If `target_path` is a directory (e.g., `/new/dir/`), the file is moved there, keeping its original filename.
    /// - If `target_path` is a file (e.g., `/new/dir/new_name.txt`), the file is moved and renamed.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found, the target path is invalid or already taken by another file.
    //
    // // 在保险库中将文件移动到新路径。
    // //
    // // - 如果 `target_path` 是一个目录 (例如 "/new/dir/")，文件将被移动到那里，并保留其原始文件名。
    // // - 如果 `target_path` 是一个文件 (例如 "/new/dir/new_name.txt")，文件将被移动并重命名。
    // //
    // // # 错误
    // // 如果文件未找到，目标路径无效或已被另一个文件占用，则返回 `UpdateError`。
    pub fn move_file(&mut self, hash: &VaultHash, target_path: &VaultPath) -> Result<(), UpdateError> {
        move_file(self, &hash, target_path)?;
        touch_vault_update_time(self)
    }

    /// Renames a file in its current directory.
    ///
    /// Only changes the filename part, keeping the parent directory the same.
    ///
    /// # Arguments
    /// * `new_filename` - The new filename (must not contain path separators `/` or `\`).
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found, the `new_filename` is invalid, or the resulting path is already taken.
    //
    // // 在当前目录中重命名文件。
    // //
    // // 只改变文件名部分，保持父目录不变。
    // //
    // // # 参数
    // // * `new_filename` - 新的文件名 (不能包含路径分隔符 `/` 或 `\`)。
    // //
    // // # 错误
    // // 如果文件未找到，`new_filename` 无效，或者最终路径已被占用，则返回 `UpdateError`。
    pub fn rename_file_inplace(&mut self, hash: &VaultHash, new_filename: &str) -> Result<(), UpdateError> {
        rename_file_inplace(self, &hash, new_filename)?;
        touch_vault_update_time(self)
    }

    /// Adds a single tag to a file.
    /// If the tag already exists on the file, the operation succeeds with no change.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    //
    // // 为文件添加一个标签。
    // // 如果标签已存在于文件上，操作将成功且不产生任何更改。
    // //
    // // # 错误
    // // 如果文件未找到，则返回 `UpdateError`。
    pub fn add_tag(&mut self, hash:&VaultHash, tag: &str) -> Result<(), UpdateError> {
        add_tag(self, hash, tag)?;
        touch_vault_update_time(self)
    }

    /// Adds multiple tags to a file in a single transaction.
    /// Existing tags are ignored.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    //
    // // 在单个事务中为文件批量添加多个标签。
    // // 已存在的标签将被忽略。
    // //
    // // # 错误
    // // 如果文件未找到，则返回 `UpdateError`。
    pub fn add_tags(&mut self, hash:&VaultHash, tags: &[&str]) -> Result<(), UpdateError> {
        add_tags(self, hash, tags)?;
        touch_vault_update_time(self)
    }

    /// Removes a single tag from a file.
    /// If the tag does not exist on the file, the operation succeeds with no change.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    //
    // // 从文件中删除一个标签。
    // // 如果标签在文件上不存在，操作将成功且不产生任何更改。
    // //
    // // # 错误
    // // 如果文件未找到，则返回 `UpdateError`。
    pub fn remove_tag(&mut self, hash:&VaultHash, tag: &str) -> Result<(), UpdateError> {
        remove_tag(self, hash, tag)?;
        touch_vault_update_time(self)
    }

    /// Removes all tags from a file.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    //
    // // 删除一个文件的所有标签。
    // //
    // // # 错误
    // // 如果文件未找到，则返回 `UpdateError`。
    pub fn clear_tags(&mut self, hash:&VaultHash) -> Result<(), UpdateError> {
        clear_tags(self, hash)?;
        touch_vault_update_time(self)
    }

    /// Sets a metadata key-value pair for a file (an "upsert" operation).
    ///
    /// If the key already exists, its value will be updated.
    /// If it does not exist, a new key-value pair will be created.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    //
    // // 为文件设置一个元数据键值对（“更新或插入”操作）。
    // //
    // // 如果键已存在，其值将被更新。
    // // 如果不存在，将创建一个新的键值对。
    // //
    // // # 错误
    // // 如果文件未找到，则返回 `UpdateError`。
    pub fn set_file_metadata(
        &mut self,
        hash:&VaultHash,
        metadata: MetadataEntry,
    ) -> Result<(), UpdateError> {
        set_file_metadata(self, hash, metadata)?;
        touch_vault_update_time(self)
    }

    /// Removes a metadata key-value pair from a file.
    /// If the key does not exist, the operation succeeds with no change.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    //
    // // 从文件中删除一个元数据键值对。
    // // 如果键不存在，操作将成功且不产生任何更改。
    // //
    // // # 错误
    // // 如果文件未找到，则返回 `UpdateError`。
    pub fn remove_file_metadata(&mut self, hash:&VaultHash, key: &str) -> Result<(), UpdateError> {
        remove_file_metadata(self, hash, key)?;
        touch_vault_update_time(self)
    }

    // --- Remove API ---
    // // --- 删除 API ---

    /// Removes a file from the vault.
    ///
    /// This deletes both the database record (and all associated tags/metadata
    /// via cascading delete) and the physical encrypted file from the `data/` directory.
    ///
    /// # Arguments
    /// * `hash` - The `VaultHash` (encrypted) of the file to remove.
    ///
    /// # Errors
    /// Returns `RemoveError` if the file is not found or if there is a filesystem error.
    //
    // // 从保险库中删除一个文件。
    // //
    // // 这将同时删除数据库记录（以及所有关联的标签/元数据，通过级联删除）
    // // 和 `data/` 目录中的物理加密文件。
    // //
    // // # 参数
    // // * `hash` - 要删除的文件的（加密后）`VaultHash`。
    // //
    // // # 错误
    // // 如果文件未找到或存在文件系统错误，则返回 `RemoveError`。
    pub fn remove_file(&mut self, hash: &VaultHash) -> Result<(), RemoveError> {
        remove_file(self, hash)?;
        touch_vault_update_time(self)?;
        Ok(())
    }

    // --- Vault Management APIs ---
    // // --- 保险库管理 API ---

    /// Sets the name of the vault.
    ///
    /// This updates the `name` property in the in-memory config and writes the
    /// change to the `master.json` file.
    ///
    /// # Errors
    /// Returns `UpdateError` if the configuration cannot be serialized or written to disk.
    //
    // // 设置保险库的名称。
    // //
    // // 这将更新内存中配置的 `name` 属性，并将更改写回 `master.json` 文件。
    // //
    // // # 错误
    // // 如果配置无法序列化或写入磁盘，则返回 `UpdateError`。
    pub fn set_name(&mut self, new_name: &str) -> Result<(), UpdateError> {
        set_name(self, new_name)?;
        Ok(())
    }
    /// Gets a vault metadata value by key.
    ///
    /// # Arguments
    /// * `key` - The key of the metadata entry to retrieve.
    ///
    /// # Errors
    /// Returns `UpdateError` if the key is not found or on database issues.
    //
    // // 通过键获取保险库元数据值。
    // //
    // // # 参数
    // // * `key` - 要检索的元数据条目的键。
    // //
    // // # 错误
    // // 如果键未找到或存在数据库问题，则返回 `UpdateError`。
    pub fn get_vault_metadata(&self, key: &str) -> Result<String, UpdateError> {
        get_vault_metadata(self, key)
    }
    /// Sets a metadata key-value pair for the vault itself (an "upsert" operation).
    ///
    /// # Errors
    /// Returns `UpdateError` on database issues.
    //
    // // 为保险库本身设置一个元数据键值对（“更新或插入”操作）。
    // //
    // // # 错误
    // // 如果发生数据库问题，则返回 `UpdateError`。
    pub fn set_vault_metadata(&mut self, metadata: MetadataEntry) -> Result<(), UpdateError> {
        set_vault_metadata(self, metadata)?;
        touch_vault_update_time(self)
    }

    /// Removes a metadata key-value pair from the vault.
    ///
    /// # Errors
    /// Returns `UpdateError::MetadataKeyNotFound` if the key does not exist.
    //
    // // 从保险库中删除一个元数据键值对。
    // //
    // // # 错误
    // // 如果键不存在，则返回 `UpdateError::MetadataKeyNotFound`。
    pub fn remove_vault_metadata(&mut self, key: &str) -> Result<(), UpdateError> {
        remove_vault_metadata(self, key)?;
        touch_vault_update_time(self)
    }

    /// Enables a specific extension feature for this vault.
    ///
    /// This is used to mark the vault as using a specific capability (e.g., "compression", "deduplication_v2")
    /// that might be required by future versions of the client.
    ///
    /// The feature name is stored in the `_vavavult_feature` metadata list.
    /// Feature names must be alphanumeric and **cannot contain spaces**.
    ///
    /// # Arguments
    /// * `feature_name` - The unique identifier of the feature.
    ///
    /// # Errors
    /// Returns `UpdateError::InvalidFeatureName` if the name is invalid.
    //
    // // 为此保险库启用特定的扩展功能。
    // //
    // // 这用于将保险库标记为使用特定的能力（例如 "compression", "deduplication_v2"），
    // // 未来的客户端版本可能需要这些能力。
    // //
    // // 功能名称存储在 `_vavavult_feature` 元数据列表中。
    // // 功能名称必须是字母数字，且 **不能包含空格**。
    pub fn enable_feature(&mut self, feature_name: &str) -> Result<(), UpdateError> {
        enable_vault_feature(self, feature_name)
    }

    /// Checks if a specific extension feature is currently enabled in this vault.
    ///
    /// # Arguments
    /// * `feature_name` - The feature identifier to check.
    ///
    /// # Returns
    /// `true` if enabled, `false` otherwise.
    //
    // // 检查此保险库中目前是否启用了特定的扩展功能。
    pub fn is_feature_enabled(&self, feature_name: &str) -> Result<bool, QueryError> {
        is_vault_feature_enabled(self, feature_name)
    }

    /// Returns a list of all extension features currently enabled for this vault.
    //
    // // 返回此保险库当前启用的所有扩展功能的列表。
    pub fn get_enabled_features(&self) -> Result<Vec<String>, QueryError> {
        get_enabled_vault_features(self)
    }
}

// --- Standalone Functions for Parallelism ---
// // --- 用于并行化的独立函数 ---

/// Encrypts a file for adding to the vault.
///
/// This is a thread-safe, standalone function that does not require a `&Vault`
/// instance, making it ideal for use in `rayon` parallel iterators.
///
/// # Arguments
/// * `data_dir_path` - The path to the vault's `data` directory (from `Vault::get_data_dir_path()`).
/// * `source_path` - The path to the local source file.
/// * `dest_path` - The target `VaultPath`.
//
// // 加密一个文件用于添加到保险库。
// //
// // 这是一个线程安全的独立函数，不需要 `&Vault` 实例，
// // 使其成为在 `rayon` 并行迭代器中使用的理想选择。
// //
// // # 参数
// // * `data_dir_path` - 保险库 `data` 目录的路径 (从 `Vault::get_data_dir_path()` 获取)。
// // * `source_path` - 本地源文件的路径。
// // * `dest_path` - 目标 `VaultPath`。
pub fn encrypt_file_for_add_standalone(
    storage: &dyn StorageBackend,
    source_path: &Path,
    dest_path: &VaultPath,
) -> Result<EncryptedAddingFile, AddFileError> {
    _encrypt_file_for_add_standalone(storage, source_path, dest_path)
}

/// Executes a prepared extraction task.
///
/// This is a thread-safe, standalone function that does not require a `&Vault`
/// instance, making it ideal for use in `rayon` parallel iterators.
///
/// # Arguments
/// * `task` - The task object obtained from `Vault::prepare_extraction_task()`.
/// * `destination_path` - The full local filesystem path to save the decrypted file.
//
// // 执行一个已准备好的提取任务。
// //
// // 这是一个线程安全的独立函数，不需要 `&Vault` 实例，
// // 使其成为在 `rayon` 并行迭代器中使用的理想选择。
// //
// // # 参数
// // * `task` - 从 `Vault::prepare_extraction_task()` 获取的任务对象。
// // * `destination_path` - 用于保存解密文件的完整本地文件系统路径。
pub fn execute_extraction_task_standalone(
    storage: &dyn StorageBackend,
    task: &ExtractionTask,
    destination_path: &Path,
) -> Result<(), ExtractError> {
    _execute_extraction_task_standalone(storage, task, destination_path)
}