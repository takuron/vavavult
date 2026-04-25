use crate::common::constants::{
    META_FILE_ADD_TIME, META_FILE_SIZE, META_FILE_UPDATE_TIME, META_SOURCE_MODIFIED_TIME,
};
use crate::common::hash::VaultHash;
use crate::common::metadata::MetadataEntry;
use crate::crypto::chunked::{ChunkedCryptoError, chunked_encrypt_and_hash};
use crate::crypto::encrypt::EncryptError;
use crate::file::PathError;
use crate::file::path::VaultPath;
use crate::storage::{StagingToken, StorageBackend};
use crate::utils::random::generate_random_password;
use crate::utils::time::now_as_rfc3339_string;
pub(crate) use crate::vault::Vault;
use crate::vault::metadata::MetadataError;
use crate::vault::query::QueryResult;
use crate::vault::{FileEntry, query};
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::path::Path;
use std::path::PathBuf;

/// Defines errors that can occur during the file addition process.
//
// // 定义在文件添加过程中可能发生的错误。
#[derive(Debug, thiserror::Error)]
pub enum AddFileError {
    /// The specified source file does not exist or is not a file.
    // // 指定的源文件不存在或不是一个文件。
    #[error("Source file not found at {0}")]
    SourceNotFound(PathBuf),
    /// An I/O error occurred (reading source or storage backend IO).
    // // 发生 I/O 错误 (读取源文件或存储后端 IO)。
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    /// A database error occurred during the transaction.
    // // 在事务期间发生数据库错误。
    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),
    /// The target `VaultPath` was a directory path, but a file path was required.
    // // 目标 `VaultPath` 是一个目录路径，但需要的是文件路径。
    #[error(
        "The provided vault path is invalid: '{0}' (must be a file path, not a directory path)"
    )]
    InvalidFilePath(String),
    /// A database query failed during pre-checks.
    // // 在预检查期间数据库查询失败。
    #[error("Database query error: {0}")]
    QueryError(#[from] query::QueryError),
    /// A file with the same target `VaultPath` already exists in the vault or batch.
    // // 具有相同目标 `VaultPath` 的文件已存在于保险库或批处理中。
    #[error("A file with the same path '{0}' already exists in the vault or in this batch.")]
    DuplicateFileName(String),
    /// A file with the same *encrypted* content hash already exists.
    // // 具有相同 *加密* 内容哈希的文件已存在。
    #[error("A file with the same content (encrypted SHA256: {0}) already exists in the vault.")]
    DuplicateContent(String),
    /// A file with the same *original* content hash already exists.
    // // 具有相同 *原始* 内容哈希的文件已存在。
    #[error(
        "A file with the same original content (Original SHA256: {0}) already exists at path '{1}' or in this batch."
    )]
    DuplicateOriginalContent(String, String),
    /// The source file path has no filename (e.g., ".") and cannot be added to a directory.
    // // 源文件路径没有文件名 (例如 ".") 并且无法添加到目录中。
    #[error("Source file has no name and cannot be added to a directory path.")]
    SourceFileNameError,
    /// An error occurred during file encryption.
    // // 文件加密期间发生错误。
    #[error("File encryption failed: {0}")]
    EncryptionError(#[from] EncryptError),
    /// An error occurred in the underlying chunked cipher.
    // // 底层分块加密器发生错误。
    #[error("Chunked cipher error: {0}")]
    ChunkedCryptoError(#[from] ChunkedCryptoError),
    /// Failed to update the vault's last-modified timestamp.
    // // 更新保险库的最后修改时间戳失败。
    #[error("Failed to update vault timestamp: {0}")]
    TimestampUpdateError(#[from] MetadataError),
    /// An error occurred constructing the final `VaultPath`.
    // // 构建最终 `VaultPath` 时发生错误。
    #[error("Failed to construct final path: {0}")]
    PathConstructionError(#[from] PathError),
}

#[derive(Debug, Clone)]
enum AdditionCommitAction {
    InsertNew,
    ReuseExisting(VaultHash),
}

fn committed_hash_for_path(vault: &Vault, path: &VaultPath) -> Result<VaultHash, AddFileError> {
    match query::check_by_path(vault, path)? {
        QueryResult::Found(entry) => Ok(entry.sha256sum),
        QueryResult::NotFound => Err(AddFileError::DatabaseError(
            rusqlite::Error::QueryReturnedNoRows,
        )),
    }
}

/// A request to prepare a file addition — input for Stage 1.
///
/// The caller constructs this with the target path and source metadata.
/// Stage 1 validates the request against the vault database and returns
/// a `PendingAdditionTask` if all checks pass.
///
/// # Fields
/// * `dest_path` - The target `VaultPath` inside the vault.
/// * `source_size` - The size of the source data in bytes.
/// * `source_modified_time` - The modification time of the source data.
//
// // 准备文件添加的请求 — 阶段 1 的输入。
// //
// // 调用方使用目标路径和源元数据构建此结构。
// // 阶段 1 会根据保险库数据库验证请求，如果所有检查通过则返回 `PendingAdditionTask`。
// //
// // # 字段
// // * `dest_path` - 保险库内的目标 `VaultPath`。
// // * `source_size` - 源数据的大小（字节）。
// // * `source_modified_time` - 源数据的修改时间。
#[derive(Debug)]
pub struct PrepareAdditionRequest<'a> {
    pub dest_path: &'a VaultPath,
    pub source_size: u64,
    pub source_modified_time: DateTime<Utc>,
}

/// A validated addition task ready for encryption — output of Stage 1, input for Stage 2.
///
/// This struct proves that the vault has validated the destination path
/// (no duplicates, valid format). The caller should pair it with a `Read`
/// source and pass it to `Vault::encrypt_addition_task`.
///
/// # Fields
/// * `dest_path` - The validated target `VaultPath`.
/// * `source_size` - The size of the source data in bytes.
/// * `source_modified_time` - The modification time of the source data.
//
// // 已验证的添加任务，准备进行加密 — 阶段 1 的输出，阶段 2 的输入。
// //
// // 此结构体证明保险库已验证了目标路径（无重复、格式有效）。
// // 调用方应将其与 `Read` 源配对，传递给 `Vault::encrypt_addition_task`。
// //
// // # 字段
// // * `dest_path` - 已验证的目标 `VaultPath`。
// // * `source_size` - 源数据的大小（字节）。
// // * `source_modified_time` - 源数据的修改时间。
#[derive(Debug, Clone)]
pub struct PendingAdditionTask {
    pub dest_path: VaultPath,
    pub source_size: u64,
    pub source_modified_time: DateTime<Utc>,
}

/// Represents a task for adding a file that has passed the encryption stage.
///
/// This struct holds the encrypted file entry ready for database insertion
/// and a staging token for finalizing the storage.
//
// // 代表一个已通过加密阶段的文件添加任务。
// //
// // 此结构体持有准备插入数据库的加密文件条目，
// // 以及用于完成存储的暂存令牌。
#[derive(Debug)]
pub struct AdditionTask {
    /// The `FileEntry` struct to be inserted into the database.
    // // 将要插入数据库的 `FileEntry` 结构体。
    pub file_entry: FileEntry,
    /// The target path mapping to insert for this file entity.
    // // 要为此文件实体插入的目标路径映射。
    pub dest_path: VaultPath,
    /// The token representing the staged data in the storage backend.
    // // 代表存储后端中暂存数据的令牌。
    pub staging_token: Box<dyn StagingToken>,
}

// ---------------------------------------------------------------------------
// 阶段 1: 准备 & 校验（需要持有库）
// ---------------------------------------------------------------------------

/// Stage 1: Validates a batch of addition requests against the vault database.
///
/// Checks for path validity, duplicate paths (in DB and within the batch).
/// Does NOT perform encryption — that is deferred to Stage 2.
///
/// # Arguments
/// * `vault` - The vault instance (read access).
/// * `requests` - A slice of `PrepareAdditionRequest`s to validate.
///
/// # Returns
/// A `Vec<PendingAdditionTask>` — one per request, in the same order.
///
/// # Errors
/// Returns `AddFileError` if any request fails validation.
//
// // 阶段 1: 根据保险库数据库验证一批添加请求。
// //
// // 检查路径有效性、重复路径（数据库中和批次内）。
// // 不执行加密 — 加密推迟到阶段 2。
// //
// // # 参数
// // * `vault` - 保险库实例（读取访问）。
// // * `requests` - 要验证的 `PrepareAdditionRequest` 切片。
// //
// // # 返回
// // `Vec<PendingAdditionTask>` — 每个请求一个，顺序相同。
// //
// // # 错误
// // 如果任何请求验证失败，则返回 `AddFileError`。
pub(crate) fn prepare_addition_tasks(
    vault: &Vault,
    requests: &[PrepareAdditionRequest],
) -> Result<Vec<PendingAdditionTask>, AddFileError> {
    let mut paths_in_batch = HashSet::new();

    for req in requests {
        // 1. 验证路径是文件路径
        if !req.dest_path.is_file() {
            return Err(AddFileError::InvalidFilePath(
                req.dest_path.as_str().to_string(),
            ));
        }
        // 2. 检查数据库中路径是否重复
        if let QueryResult::Found(_) = query::check_by_path(vault, req.dest_path)? {
            return Err(AddFileError::DuplicateFileName(req.dest_path.to_string()));
        }
        // 3. 检查批内路径是否重复
        if !paths_in_batch.insert(req.dest_path) {
            return Err(AddFileError::DuplicateFileName(req.dest_path.to_string()));
        }
    }

    let tasks = requests
        .iter()
        .map(|req| PendingAdditionTask {
            dest_path: req.dest_path.clone(),
            source_size: req.source_size,
            source_modified_time: req.source_modified_time,
        })
        .collect();

    Ok(tasks)
}

// ---------------------------------------------------------------------------
// 阶段 2: 并行加密（不需要持有库）
// ---------------------------------------------------------------------------

/// Stage 2: Encrypts data from a reader and produces an `AdditionTask`.
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
// // 阶段 2: 从读取器加密数据并生成 `AdditionTask`。
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
pub(crate) fn encrypt_addition_task(
    storage: &dyn StorageBackend,
    pending: PendingAdditionTask,
    reader: impl std::io::Read,
) -> Result<AdditionTask, AddFileError> {
    // 1. 调用存储后端准备写入
    let (mut staging_writer, staging_token) =
        storage.prepare_write().map_err(AddFileError::IoError)?;

    // 2. 构建计数 Reader
    struct CountingReader<R> {
        inner: R,
        count: u64,
    }
    impl<R: std::io::Read> std::io::Read for CountingReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.count += n as u64;
            Ok(n)
        }
    }
    let mut counting_reader = CountingReader {
        inner: reader,
        count: 0,
    };

    // 3. 执行分块流式加密
    let per_file_password = generate_random_password(16);
    let (encrypted_sha256sum, original_sha256sum) = chunked_encrypt_and_hash(
        &mut counting_reader,
        &mut staging_writer,
        &per_file_password,
    )?;

    let actual_size = counting_reader.count;

    // 4. 构建 FileEntry
    let now = now_as_rfc3339_string();
    let file_size = if pending.source_size > 0 {
        pending.source_size
    } else {
        actual_size
    };

    let metadata = vec![
        MetadataEntry {
            key: META_FILE_ADD_TIME.to_string(),
            value: now.clone(),
        },
        MetadataEntry {
            key: META_FILE_UPDATE_TIME.to_string(),
            value: now,
        },
        MetadataEntry {
            key: META_FILE_SIZE.to_string(),
            value: file_size.to_string(),
        },
        MetadataEntry {
            key: META_SOURCE_MODIFIED_TIME.to_string(),
            value: pending.source_modified_time.to_rfc3339(),
        },
    ];

    let file_entry = FileEntry {
        sha256sum: encrypted_sha256sum,
        original_sha256sum,
        encrypt_password: per_file_password,
        tags: Vec::new(),
        metadata,
    };

    Ok(AdditionTask {
        file_entry,
        dest_path: pending.dest_path,
        staging_token,
    })
}

// ---------------------------------------------------------------------------
// 阶段 3: 提交（需要持有库）
// ---------------------------------------------------------------------------

/// Stage 3: Commits a batch of encrypted addition tasks to the vault database.
///
/// Performs final duplicate checks (encrypted hash, original hash, path) and then
/// executes a database transaction to insert all records and commit storage files.
///
/// # Arguments
/// * `vault` - The vault instance (exclusive write access).
/// * `files` - A `Vec` of `AdditionTask`s from Stage 2.
///
/// # Errors
/// Returns `AddFileError` if duplicate content is detected, or if the
/// database transaction or storage commit fails.
//
// // 阶段 3: 将一批已加密的添加任务提交到保险库数据库。
// //
// // 执行最终的重复检查（加密哈希、原始哈希、路径），然后执行数据库事务
// // 以插入所有记录并提交存储文件。
// //
// // # 参数
// // * `vault` - 保险库实例（独占写入访问）。
// // * `files` - 来自阶段 2 的 `AdditionTask` 列表。
// //
// // # 错误
// // 如果检测到重复内容，或数据库事务或存储提交失败，则返回 `AddFileError`。
pub(crate) fn commit_addition_tasks(
    vault: &mut Vault,
    files: Vec<AdditionTask>,
    allow_duplicate_files: Option<bool>,
) -> Result<(), AddFileError> {
    if files.is_empty() {
        return Ok(());
    }

    let allow_duplicate_files = allow_duplicate_files.unwrap_or(true);

    // --- 1. 最终重复检查 ---
    let mut paths_in_batch = HashSet::new();
    let mut originals_in_batch: HashMap<&VaultHash, VaultHash> = HashMap::new();
    let mut commit_actions = Vec::with_capacity(files.len());

    for file_to_add in &files {
        let entry = &file_to_add.file_entry;
        let dest_path = &file_to_add.dest_path;

        // 路径重复检查（防御性：阶段1已检查，但提交时可能有并发变更）
        if let QueryResult::Found(_) = query::check_by_path(vault, dest_path)? {
            return Err(AddFileError::DuplicateFileName(dest_path.to_string()));
        }
        if !paths_in_batch.insert(dest_path) {
            return Err(AddFileError::DuplicateFileName(dest_path.to_string()));
        }

        // 相同原始内容按策略处理：默认复用已有文件实体，严格模式则报错。
        let existing_hash = match query::check_by_original_hash(vault, &entry.original_sha256sum)? {
            QueryResult::Found(existing) => Some(existing.sha256sum),
            QueryResult::NotFound => originals_in_batch.get(&entry.original_sha256sum).cloned(),
        };

        if let Some(existing_hash) = existing_hash {
            if !allow_duplicate_files {
                return Err(AddFileError::DuplicateOriginalContent(
                    entry.original_sha256sum.to_string(),
                    dest_path.to_string(),
                ));
            }
            commit_actions.push(AdditionCommitAction::ReuseExisting(existing_hash));
        } else {
            originals_in_batch.insert(&entry.original_sha256sum, entry.sha256sum.clone());
            commit_actions.push(AdditionCommitAction::InsertNew);
        }
    }

    // --- 2. 提交（数据库写入和文件 Commit）---
    let tx = vault.database_connection.transaction()?;
    {
        let mut file_stmt = tx.prepare(
            "INSERT INTO files (sha256sum, original_sha256sum, encrypt_password) VALUES (?1, ?2, ?3)",
        )?;
        let mut meta_stmt = tx.prepare(
            "INSERT INTO metadata (file_sha256sum, meta_key, meta_value) VALUES (?1, ?2, ?3)",
        )?;

        for (file_to_add, action) in files.iter().zip(commit_actions.iter()) {
            let entry = &file_to_add.file_entry;
            match action {
                AdditionCommitAction::InsertNew => {
                    file_stmt.execute((
                        &entry.sha256sum,
                        &entry.original_sha256sum,
                        &entry.encrypt_password,
                    ))?;
                    query::insert_file_entry_in_conn(
                        &tx,
                        &file_to_add.dest_path,
                        &entry.sha256sum,
                    )?;
                    for meta in &entry.metadata {
                        meta_stmt.execute((&entry.sha256sum, &meta.key, &meta.value))?;
                    }
                }
                AdditionCommitAction::ReuseExisting(existing_hash) => {
                    query::insert_file_entry_in_conn(&tx, &file_to_add.dest_path, existing_hash)?;
                }
            }
        }

        commit_storage_files(files, commit_actions, vault.storage.as_ref())?;
    }
    tx.commit()?;

    Ok(())
}

// ---------------------------------------------------------------------------
// 快捷方法的内部实现
// ---------------------------------------------------------------------------

/// Stage 1 shortcut for local files: Resolves metadata and validates a batch of
/// local file paths against the vault database in one call.
///
/// This combines `resolve_file_metadata` + `prepare_addition_tasks` for the common
/// case of adding files from the local filesystem.
///
/// # Arguments
/// * `vault` - The vault instance (read access).
/// * `file_pairs` - A slice of `(source_path, dest_vault_path)` pairs.
///
/// # Returns
/// A `Vec<PendingAdditionTask>` — one per pair, in the same order.
/// Each task's `dest_path` has been resolved (e.g., directory targets get the source filename appended).
///
/// # Errors
/// Returns `AddFileError` if any source file is missing, path is invalid, or duplicates are detected.
//
// // 本地文件的阶段 1 快捷方法：一次调用中解析元数据并根据保险库数据库验证一批本地文件路径。
// //
// // 这将 `resolve_file_metadata` + `prepare_addition_tasks` 合并，
// // 适用于从本地文件系统添加文件的常见场景。
// //
// // # 参数
// // * `vault` - 保险库实例（读取访问）。
// // * `file_pairs` - `(源路径, 目标保险库路径)` 对的切片。
// //
// // # 返回
// // `Vec<PendingAdditionTask>` — 每对一个，顺序相同。
// // 每个任务的 `dest_path` 已被解析（例如目录目标会追加源文件名）。
// //
// // # 错误
// // 如果任何源文件缺失、路径无效或检测到重复，则返回 `AddFileError`。
pub(crate) fn prepare_addition_tasks_from_files(
    vault: &Vault,
    file_pairs: &[(&Path, &VaultPath)],
) -> Result<Vec<PendingAdditionTask>, AddFileError> {
    // 1. 解析所有文件的元数据
    let resolved: Vec<(VaultPath, u64, DateTime<Utc>)> = file_pairs
        .iter()
        .map(|(source_path, dest_path)| resolve_file_metadata(source_path, dest_path))
        .collect::<Result<Vec<_>, _>>()?;

    // 2. 构建请求并调用 prepare_addition_tasks 进行校验
    let requests: Vec<PrepareAdditionRequest> = resolved
        .iter()
        .map(|(dest, size, mtime)| PrepareAdditionRequest {
            dest_path: dest,
            source_size: *size,
            source_modified_time: *mtime,
        })
        .collect();

    prepare_addition_tasks(vault, &requests)
}

/// 快捷函数：从本地文件添加（三阶段合一）
pub(crate) fn add_file(
    vault: &mut Vault,
    source_path: &Path,
    dest_path: &VaultPath,
    allow_duplicate_files: Option<bool>,
) -> Result<VaultHash, AddFileError> {
    if !source_path.is_file() {
        return Err(AddFileError::SourceNotFound(source_path.to_path_buf()));
    }
    let final_dest_path = resolve_final_path(source_path, dest_path)?;
    let source_metadata = fs::metadata(source_path).map_err(AddFileError::IoError)?;
    let file_size = source_metadata.len();
    let source_modified_time: DateTime<Utc> = source_metadata
        .modified()
        .map_err(AddFileError::IoError)?
        .into();

    // 阶段 1
    let requests = [PrepareAdditionRequest {
        dest_path: &final_dest_path,
        source_size: file_size,
        source_modified_time,
    }];
    let pending_tasks = prepare_addition_tasks(vault, &requests)?;
    let pending = pending_tasks.into_iter().next().unwrap();

    // 阶段 2
    let source_file = File::open(source_path).map_err(AddFileError::IoError)?;
    let addition_task = encrypt_addition_task(vault.storage.as_ref(), pending, source_file)?;

    // 阶段 3
    commit_addition_tasks(vault, vec![addition_task], allow_duplicate_files)?;
    committed_hash_for_path(vault, &final_dest_path)
}

/// 快捷函数：从 Reader 添加（三阶段合一）
pub(crate) fn add_from_reader(
    vault: &mut Vault,
    reader: impl std::io::Read,
    dest_path: &VaultPath,
    source_size: u64,
    source_modified_time: DateTime<Utc>,
    allow_duplicate_files: Option<bool>,
) -> Result<VaultHash, AddFileError> {
    // 阶段 1
    let requests = [PrepareAdditionRequest {
        dest_path,
        source_size,
        source_modified_time,
    }];
    let pending_tasks = prepare_addition_tasks(vault, &requests)?;
    let pending = pending_tasks.into_iter().next().unwrap();

    // 阶段 2
    let addition_task = encrypt_addition_task(vault.storage.as_ref(), pending, reader)?;

    // 阶段 3
    commit_addition_tasks(vault, vec![addition_task], allow_duplicate_files)?;
    committed_hash_for_path(vault, dest_path)
}

// ---------------------------------------------------------------------------
// 辅助函数
// ---------------------------------------------------------------------------

/// 辅助函数：提交文件到存储后端
fn commit_storage_files(
    files: Vec<AdditionTask>,
    commit_actions: Vec<AdditionCommitAction>,
    storage: &dyn StorageBackend,
) -> Result<(), AddFileError> {
    for (file_to_add, action) in files.into_iter().zip(commit_actions.into_iter()) {
        match action {
            AdditionCommitAction::InsertNew => {
                storage
                    .commit_write(file_to_add.staging_token, &file_to_add.file_entry.sha256sum)
                    .map_err(AddFileError::IoError)?;
            }
            AdditionCommitAction::ReuseExisting(_) => {
                storage
                    .rollback_write(file_to_add.staging_token)
                    .map_err(AddFileError::IoError)?;
            }
        }
    }
    Ok(())
}

/// 辅助函数：根据源路径和目标路径解析最终的文件路径。
fn resolve_final_path(
    source_path: &Path,
    dest_path: &VaultPath,
) -> Result<VaultPath, AddFileError> {
    if dest_path.is_dir() {
        let source_filename = source_path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(AddFileError::SourceFileNameError)?;
        Ok(dest_path.join(source_filename)?)
    } else {
        Ok(dest_path.clone())
    }
}

/// Helper: Resolves file metadata from a local path for use with the three-stage API.
///
/// # Arguments
/// * `source_path` - The local source file path.
/// * `dest_path` - The target `VaultPath`.
///
/// # Returns
/// A tuple of (resolved VaultPath, file size, modification time).
///
/// # Errors
/// Returns `AddFileError` if source not found or metadata read fails.
//
// // 辅助函数：从本地文件路径解析元数据，用于三阶段 API。
// //
// // # 参数
// // * `source_path` - 本地源文件路径。
// // * `dest_path` - 目标 `VaultPath`。
// //
// // # 返回
// // (解析后的 VaultPath, 文件大小, 修改时间) 的元组。
// //
// // # 错误
// // 如果源未找到或元数据读取失败，则返回 `AddFileError`。
pub(crate) fn resolve_file_metadata(
    source_path: &Path,
    dest_path: &VaultPath,
) -> Result<(VaultPath, u64, DateTime<Utc>), AddFileError> {
    if !source_path.is_file() {
        return Err(AddFileError::SourceNotFound(source_path.to_path_buf()));
    }
    let final_dest_path = resolve_final_path(source_path, dest_path)?;
    if !final_dest_path.is_file() {
        return Err(AddFileError::InvalidFilePath(
            final_dest_path.as_str().to_string(),
        ));
    }
    let source_metadata = fs::metadata(source_path).map_err(AddFileError::IoError)?;
    let file_size = source_metadata.len();
    let source_modified_time: DateTime<Utc> = source_metadata
        .modified()
        .map_err(AddFileError::IoError)?
        .into();
    Ok((final_dest_path, file_size, source_modified_time))
}
