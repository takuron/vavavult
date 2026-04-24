//! Virtual filesystem layer for WebDAV access to Vavavult vaults.
//!
//! This module implements the `DavFileSystem` trait from `dav-server`, providing
//! a read-only WebDAV interface to the encrypted vault. Files are transparently
//! decrypted on demand using the vault's two-phase extraction API.
//
// // 用于 WebDAV 访问 Vavavult 保险库的虚拟文件系统层。
// //
// // 此模块实现了 `dav-server` 的 `DavFileSystem` trait，提供对加密保险库的
// // 只读 WebDAV 接口。文件使用保险库的两阶段提取 API 按需透明解密。

use std::str;
use std::sync::{Arc, Mutex};

use dav_server::davpath::DavPath;
use dav_server::fs::{
    DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsError, FsFuture, FsStream, OpenOptions,
    ReadDirMeta,
};
use vavavult::file::VaultPath;
use vavavult::vault::Vault;

mod node;
pub use node::VaultDavFile;

use std::collections::HashSet;

/// Virtual filesystem adapter that exposes a Vavavult vault via WebDAV.
///
/// This struct implements the `DavFileSystem` trait from `dav-server`, allowing
/// a vault to be mounted and accessed through standard WebDAV clients.
///
/// The VFS is read-only in this phase: write operations (PUT, DELETE, MOVE, etc.)
/// return `FsError::NotImplemented` by default. Write support will be added
/// in a later phase by overriding the corresponding `DavFileSystem` methods.
///
/// # Thread Safety
/// The vault is shared via `Arc<Mutex<Vault>>`. The mutex is held only for the
/// short duration of metadata queries and extraction task preparation. The
/// actual decryption (I/O-intensive) is performed without holding the lock,
/// using the standalone extraction API and a cloned `Arc<dyn StorageBackend>`.
//
// // 虚拟文件系统适配器，通过 WebDAV 暴露 Vavavult 保险库。
// //
// // 此结构体实现了 `dav-server` 的 `DavFileSystem` trait，允许
// // 通过标准 WebDAV 客户端挂载和访问保险库。
// //
// // 此阶段的 VFS 是只读的：写入操作（PUT、DELETE、MOVE 等）默认返回
// // `FsError::NotImplemented`。后续阶段将通过覆盖相应的 `DavFileSystem` 方法
// // 来添加写入支持。
// //
// // # 线程安全
// // 保险库通过 `Arc<Mutex<Vault>>` 共享。互斥锁仅在元数据查询和提取任务准备
// // 的短时间内持有。实际的解密（I/O 密集型）在不持有锁的情况下执行，
// // 使用独立提取 API 和克隆的 `Arc<dyn StorageBackend>`。
#[derive(Clone)]
pub struct VaultDavFs {
    /// Shared reference to the vault instance, protected by a mutex.
    // // 保险库实例的共享引用，由互斥锁保护。
    vault: Arc<Mutex<Vault>>,

    /// Whether the filesystem is read-only.
    // // 文件系统是否为只读。
    read_only: bool,

    /// Virtual directories created during this mount session.
    /// Since vault directories are implicit, we store explicitly created empty directories here.
    // // 在此挂载会话期间创建的虚拟目录。
    // // 由于保险库目录是隐式的，我们将显式创建的空目录存储在此处。
    virtual_dirs: Arc<Mutex<HashSet<VaultPath>>>,
}

impl VaultDavFs {
    /// Creates a new `VaultDavFs` instance wrapping the given vault.
    ///
    /// # Arguments
    /// * `vault` - An `Arc<Mutex<Vault>>` to the vault to be exposed via WebDAV.
    /// * `read_only` - Whether the filesystem should reject write operations.
    ///
    /// # Returns
    /// A new `VaultDavFs` instance ready to be used with a `DavHandler`.
    //
    // // 创建一个新的 `VaultDavFs` 实例，包装给定的保险库。
    // //
    // // # 参数
    // // * `vault` - 通过 WebDAV 暴露的保险库的 `Arc<Mutex<Vault>>`。
    // // * `read_only` - 文件系统是否应拒绝写入操作。
    // //
    // // # 返回
    // // 一个新的 `VaultDavFs` 实例，可用于 `DavHandler`。
    pub fn new(vault: Arc<Mutex<Vault>>, read_only: bool) -> Self {
        Self {
            vault,
            read_only,
            virtual_dirs: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

// --- Helper functions / 辅助函数 ---

/// Converts a `DavPath` to a `VaultPath`.
///
/// Extracts the raw path bytes (without prefix or URL encoding) and constructs
/// a `VaultPath`. If the bytes are not valid UTF-8, falls back to the root "/".
//
// // 将 `DavPath` 转换为 `VaultPath`。
// //
// // 提取原始路径字节（不带前缀或 URL 编码）并构造 `VaultPath`。
// // 如果字节不是有效的 UTF-8，则回退到根目录 "/"。
fn dav_path_to_vault_path(path: &DavPath) -> VaultPath {
    let bytes = path.as_bytes();
    let path_str = str::from_utf8(bytes).unwrap_or("/");
    VaultPath::new(path_str)
}

/// Extracts the original (unencrypted) file size from a `FileEntry`'s metadata.
///
/// Looks for the `_vavavult_file_size` key in the metadata entries.
/// Returns 0 if the key is not found or the value cannot be parsed as `u64`.
//
// // 从 `FileEntry` 的元数据中提取原始（未加密）文件大小。
// //
// // 在元数据条目中查找 `_vavavult_file_size` 键。
// // 如果未找到键或值无法解析为 `u64`，则返回 0。
fn extract_file_size(entry: &vavavult::file::FileEntry) -> u64 {
    entry
        .metadata
        .iter()
        .find(|m| m.key == "_vavavult_file_size")
        .and_then(|m| m.value.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Extracts the modification time from a `FileEntry`'s metadata.
///
/// Looks for the `_vavavult_create_time` key and attempts to parse it as a
/// Unix timestamp (seconds since epoch). Falls back to `SystemTime::UNIX_EPOCH`
/// if the key is missing or the value cannot be parsed.
//
// // 从 `FileEntry` 的元数据中提取修改时间。
// //
// // 查找 `_vavavult_create_time` 键并尝试将其解析为 Unix 时间戳（自 epoch 以来的秒数）。
// // 如果键缺失或值无法解析，则回退到 `SystemTime::UNIX_EPOCH`。
fn extract_modified_time(entry: &vavavult::file::FileEntry) -> std::time::SystemTime {
    entry
        .metadata
        .iter()
        .find(|m| m.key == "_vavavult_create_time")
        .and_then(|m| {
            // 尝试解析为 Unix 时间戳（秒）
            m.value
                .parse::<i64>()
                .ok()
                .map(|ts| std::time::UNIX_EPOCH + std::time::Duration::from_secs(ts as u64))
        })
        .unwrap_or(std::time::UNIX_EPOCH)
}

// --- DavFileSystem implementation / DavFileSystem 实现 ---

impl DavFileSystem for VaultDavFs {
    /// Returns metadata for the given path.
    ///
    /// - For the root directory (`/`): always succeeds with directory metadata.
    /// - For other directories: succeeds only if the directory contains entries
    ///   (vault directories are implicit — they exist only when they have children).
    /// - For files: looks up the file by path and returns its size and modification time.
    /// - If a file path is not found, falls back to checking if it's a directory
    ///   (handles clients that omit the trailing `/` on directory requests).
    //
    // // 返回给定路径的元数据。
    // //
    // // - 对于根目录 (`/`)：始终成功返回目录元数据。
    // // - 对于其他目录：仅当目录包含条目时才成功
    // //   （保险库目录是隐式的——仅当它们有子项时才存在）。
    // // - 对于文件：按路径查找文件并返回其大小和修改时间。
    // // - 如果文件路径未找到，则回退检查它是否为目录
    // //   （处理在目录请求中省略尾部 `/` 的客户端）。
    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        Box::pin(async move {
            let vault_path = dav_path_to_vault_path(path);

            // 1. 目录路径处理
            if vault_path.is_dir() {
                // 根目录始终存在
                if vault_path.is_root() {
                    return Ok(Box::new(VaultDavMetaData::dir()) as Box<dyn DavMetaData>);
                }

                // Check virtual directories first
                let virtual_dirs = self.virtual_dirs.lock().unwrap();
                if virtual_dirs.contains(&vault_path) {
                    return Ok(Box::new(VaultDavMetaData::dir()) as Box<dyn DavMetaData>);
                }
                drop(virtual_dirs);

                // 非根目录：通过 list_by_path 检查是否有子条目
                let vault = self.vault.lock().map_err(|_| FsError::GeneralFailure)?;
                match vault.list_by_path(&vault_path) {
                    Ok(entries) if !entries.is_empty() => {
                        // 目录存在（有子条目）
                        Ok(Box::new(VaultDavMetaData::dir()) as Box<dyn DavMetaData>)
                    }
                    Ok(_) => {
                        // 空目录 = 在 vault 中不存在（目录是隐式的）
                        Err(FsError::NotFound)
                    }
                    Err(_) => Err(FsError::NotFound),
                }
            } else {
                // 2. 文件路径处理
                let vault = self.vault.lock().map_err(|_| FsError::GeneralFailure)?;

                match vault.find_by_path(&vault_path) {
                    Ok(vavavult::vault::QueryResult::Found(entry)) => {
                        // 文件找到，提取元数据
                        let size = extract_file_size(&entry);
                        let modified = extract_modified_time(&entry);
                        Ok(Box::new(VaultDavMetaData::file(size, modified))
                            as Box<dyn DavMetaData>)
                    }
                    Ok(vavavult::vault::QueryResult::NotFound) => {
                        // 文件未找到，尝试作为目录查找
                        // 处理客户端省略目录路径尾部斜杠的情况
                        let dir_path_str = format!("{}/", vault_path.as_str());
                        let dir_path = VaultPath::new(dir_path_str);

                        // Check virtual directories first
                        let virtual_dirs = self.virtual_dirs.lock().unwrap();
                        if virtual_dirs.contains(&dir_path) {
                            return Ok(Box::new(VaultDavMetaData::dir()) as Box<dyn DavMetaData>);
                        }
                        drop(virtual_dirs);

                        match vault.list_by_path(&dir_path) {
                            Ok(entries) if !entries.is_empty() => {
                                Ok(Box::new(VaultDavMetaData::dir()) as Box<dyn DavMetaData>)
                            }
                            _ => Err(FsError::NotFound),
                        }
                    }
                    Err(_) => Err(FsError::GeneralFailure),
                }
            }
        })
    }

    /// Lists the entries within a directory.
    ///
    /// Calls `vault.list_by_path()` and maps each `DirectoryEntry` to a
    /// `VaultDavDirEntry`. Only the entry name (not the full path) is returned,
    /// as required by the `DavDirEntry` trait.
    //
    // // 列出目录中的条目。
    // //
    // // 调用 `vault.list_by_path()` 并将每个 `DirectoryEntry` 映射为
    // // `VaultDavDirEntry`。按照 `DavDirEntry` trait 的要求，仅返回条目名称
    // // （而非完整路径）。
    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        _meta: ReadDirMeta,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
        Box::pin(async move {
            let vault_path = dav_path_to_vault_path(path);

            // 只能列出目录
            if !vault_path.is_dir() {
                return Err(FsError::Forbidden);
            }

            let vault = self.vault.lock().map_err(|_| FsError::GeneralFailure)?;
            let entries = vault.list_by_path(&vault_path).map_err(|e| match e {
                vavavult::vault::QueryError::NotADirectory(_) => FsError::Forbidden,
                _ => FsError::GeneralFailure,
            })?;

            // 将 DirectoryEntry 转换为 DavDirEntry
            let mut items: Vec<Box<dyn DavDirEntry>> = entries
                .into_iter()
                .map(|entry| -> Box<dyn DavDirEntry> {
                    match entry {
                        vavavult::vault::DirectoryEntry::Directory(dir_path) => {
                            // 目录条目：仅提取目录名（非完整路径）
                            let name = dir_path.dir_name().unwrap_or("").to_string();
                            Box::new(VaultDavDirEntry::dir(name))
                        }
                        vavavult::vault::DirectoryEntry::File(file_entry) => {
                            // 文件条目：仅提取文件名及元数据
                            let name = vault
                                .list_paths_by_hash(&file_entry.sha256sum)
                                .ok()
                                .and_then(|paths| paths.into_iter().next())
                                .and_then(|path| path.file_name().map(str::to_string))
                                .unwrap_or_default();
                            let size = extract_file_size(&file_entry);
                            let modified = extract_modified_time(&file_entry);
                            Box::new(VaultDavDirEntry::file(name, size, modified))
                        }
                    }
                })
                .collect();

            // Add virtual directories
            let virtual_dirs = self.virtual_dirs.lock().unwrap();
            let parent_str = vault_path.as_str();
            for vdir in virtual_dirs.iter() {
                let vdir_str = vdir.as_str();
                if vdir_str.starts_with(parent_str) && vdir_str.len() > parent_str.len() {
                    let suffix = &vdir_str[parent_str.len()..];
                    // if suffix contains exactly one '/' and it's at the end, it's a direct child
                    if suffix.matches('/').count() == 1 && suffix.ends_with('/') {
                        let name = suffix.trim_end_matches('/').to_string();
                        // avoid duplicate if vault already returned it
                        let is_duplicate = items.iter().any(|item| item.name() == name.as_bytes());
                        if !is_duplicate {
                            items.push(Box::new(VaultDavDirEntry::dir(name)));
                        }
                    }
                }
            }

            Ok(Box::pin(futures::stream::iter(items.into_iter().map(Ok)))
                as FsStream<Box<dyn DavDirEntry>>)
        })
    }

    /// Opens a file for reading.
    ///
    /// Uses the vault's two-phase extraction API:
    /// 1. **Phase 1** (under lock): `find_by_path` → `prepare_extraction_task`
    /// 2. **Phase 2** (lock-free): `VaultDavFile` lazily calls
    ///    `execute_extraction_task_standalone` on first read.
    ///
    /// The vault lock is released before any I/O-intensive decryption occurs.
    //
    // // 打开文件进行读取。
    // //
    // // 使用保险库的两阶段提取 API：
    // // 1. **阶段 1**（持有锁）：`find_by_path` → `prepare_extraction_task`
    // // 2. **阶段 2**（无锁）：`VaultDavFile` 在首次读取时惰性调用
    // //    `execute_extraction_task_standalone`。
    // //
    // // 在执行任何 I/O 密集型解密之前，保险库锁已被释放。
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: OpenOptions,
    ) -> FsFuture<'a, Box<dyn DavFile>> {
        Box::pin(async move {
            let vault_path = dav_path_to_vault_path(path);

            // 不能打开目录作为文件
            if vault_path.is_dir() {
                return Err(FsError::Forbidden);
            }

            if options.write {
                if self.read_only {
                    return Err(FsError::Forbidden);
                }

                return Ok(
                    Box::new(VaultDavFile::new_write(self.vault.clone(), vault_path))
                        as Box<dyn DavFile>,
                );
            }

            let vault = self.vault.lock().map_err(|_| FsError::GeneralFailure)?;

            // 1. 查找文件条目
            let file_entry = match vault.find_by_path(&vault_path) {
                Ok(vavavult::vault::QueryResult::Found(entry)) => entry,
                Ok(vavavult::vault::QueryResult::NotFound) => return Err(FsError::NotFound),
                Err(_) => return Err(FsError::GeneralFailure),
            };

            // 2. 准备解密任务（阶段 1：快速数据库查询）
            let task = vault
                .prepare_extraction_task(&file_entry.sha256sum)
                .map_err(|_| FsError::GeneralFailure)?;

            // 3. 克隆存储后端引用（用于阶段 2 解密，无需持有 vault 锁）
            let storage = vault.storage.clone();

            // 4. 提取文件元数据（在释放锁之前）
            let file_size = extract_file_size(&file_entry);
            let modified = extract_modified_time(&file_entry);

            // 5. 释放锁
            drop(vault);

            // 6. 创建 VaultDavFile（阶段 2 解密将在首次读取时惰性执行）
            Ok(Box::new(VaultDavFile::new(task, storage, file_size, modified)) as Box<dyn DavFile>)
        })
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.read_only {
                return Err(FsError::Forbidden);
            }

            let mut path_str = dav_path_to_vault_path(path).as_str().to_string();
            if !path_str.ends_with('/') {
                path_str.push('/');
            }
            let vault_path = VaultPath::new(&path_str);

            let mut virtual_dirs = self.virtual_dirs.lock().unwrap();
            virtual_dirs.insert(vault_path);

            Ok(())
        })
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.read_only {
                return Err(FsError::Forbidden);
            }

            let vault_path = dav_path_to_vault_path(path);
            if vault_path.is_dir() {
                return Err(FsError::Forbidden);
            }

            let mut vault = self.vault.lock().map_err(|_| FsError::GeneralFailure)?;

            let file_entry = match vault.find_by_path(&vault_path) {
                Ok(vavavult::vault::QueryResult::Found(entry)) => entry,
                Ok(vavavult::vault::QueryResult::NotFound) => return Err(FsError::NotFound),
                Err(_) => return Err(FsError::GeneralFailure),
            };

            let _ = vault
                .remove_file(&file_entry.sha256sum)
                .map_err(|_| FsError::GeneralFailure)?;
            Ok(())
        })
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.read_only {
                return Err(FsError::Forbidden);
            }

            let mut path_str = dav_path_to_vault_path(path).as_str().to_string();
            if !path_str.ends_with('/') {
                path_str.push('/');
            }
            let vault_path = VaultPath::new(&path_str);

            let mut virtual_dirs = self.virtual_dirs.lock().unwrap();
            if virtual_dirs.remove(&vault_path) {
                Ok(())
            } else {
                Ok(())
            }
        })
    }

    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.read_only {
                return Err(FsError::Forbidden);
            }

            let from_path = dav_path_to_vault_path(from);
            let mut to_path = dav_path_to_vault_path(to);

            let mut vault = self.vault.lock().map_err(|_| FsError::GeneralFailure)?;

            if from_path.is_dir() {
                // 如果是目录，我们要递归移动里面的所有文件，并更新 virtual_dirs
                let mut to_path_str = to_path.as_str().to_string();
                if !to_path_str.ends_with('/') {
                    to_path_str.push('/');
                }
                to_path = vavavult::file::VaultPath::new(&to_path_str);

                // 递归获取所有文件
                let files_to_move = vault.list_all_recursive(&from_path).unwrap_or_default();
                for hash in files_to_move {
                    if let Ok(paths) = vault.list_paths_by_hash(&hash) {
                        if let Some(entry_path) = paths.into_iter().next()
                            && let Some(relative) =
                                entry_path.as_str().strip_prefix(from_path.as_str())
                        {
                            let new_path_str = format!("{}{}", to_path.as_str(), relative);
                            let new_path = vavavult::file::VaultPath::new(&new_path_str);
                            let _ = vault
                                .move_file(&hash, &new_path)
                                .map_err(|_| FsError::GeneralFailure)?;
                        }
                    }
                }

                // 更新 virtual_dirs（处理那些没有实体文件但是被记录为空目录的记录）
                let mut virtual_dirs = self.virtual_dirs.lock().unwrap();
                let mut new_virtual_dirs = std::collections::HashSet::new();
                for vd in virtual_dirs.drain() {
                    if let Some(relative) = vd.as_str().strip_prefix(from_path.as_str()) {
                        let mut new_vd_str = format!("{}{}", to_path.as_str(), relative);
                        if !new_vd_str.ends_with('/') {
                            new_vd_str.push('/');
                        }
                        new_virtual_dirs.insert(vavavult::file::VaultPath::new(&new_vd_str));
                    } else {
                        new_virtual_dirs.insert(vd);
                    }
                }
                *virtual_dirs = new_virtual_dirs;

                return Ok(());
            }

            // 单个文件重命名
            let file_entry = match vault.find_by_path(&from_path) {
                Ok(vavavult::vault::QueryResult::Found(entry)) => entry,
                Ok(vavavult::vault::QueryResult::NotFound) => return Err(FsError::NotFound),
                Err(_) => return Err(FsError::GeneralFailure),
            };

            let _ = vault
                .move_file(&file_entry.sha256sum, &to_path)
                .map_err(|_| FsError::GeneralFailure)?;
            Ok(())
        })
    }

    /// Symlink metadata delegates to regular metadata since vaults have no symlinks.
    //
    // // 符号链接元数据委托给常规元数据，因为保险库没有符号链接。
    fn symlink_metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        self.metadata(path)
    }
}

// --- Metadata type / 元数据类型 ---

/// Metadata for vault entries (both files and directories).
///
/// Implements `DavMetaData` to provide file/directory information to the
/// WebDAV server. For directories, `size` is always 0 and `modified` is
/// `UNIX_EPOCH` (vault directories are implicit and have no timestamps).
//
// // 保险库条目的元数据（文件和目录）。
// //
// // 实现了 `DavMetaData`，向 WebDAV 服务器提供文件/目录信息。
// // 对于目录，`size` 始终为 0，`modified` 为 `UNIX_EPOCH`
// // （保险库目录是隐式的，没有时间戳）。
#[derive(Debug, Clone)]
pub struct VaultDavMetaData {
    /// Size of the entry in bytes (0 for directories).
    // // 条目大小（字节），目录为 0。
    size: u64,
    /// Whether this entry is a directory.
    // // 此条目是否为目录。
    is_directory: bool,
    /// Last modification time.
    // // 最后修改时间。
    modified: std::time::SystemTime,
}

impl VaultDavMetaData {
    /// Creates metadata for a directory.
    ///
    /// Directory size is always 0 and modification time is `UNIX_EPOCH`.
    //
    // // 创建目录的元数据。
    // //
    // // 目录大小始终为 0，修改时间为 `UNIX_EPOCH`。
    pub fn dir() -> Self {
        Self {
            size: 0,
            is_directory: true,
            modified: std::time::UNIX_EPOCH,
        }
    }

    /// Creates metadata for a file.
    ///
    /// # Arguments
    /// * `size` - The file size in bytes.
    /// * `modified` - The last modification time.
    //
    // // 创建文件的元数据。
    // //
    // // # 参数
    // // * `size` - 文件大小（字节）。
    // // * `modified` - 最后修改时间。
    pub fn file(size: u64, modified: std::time::SystemTime) -> Self {
        Self {
            size,
            is_directory: false,
            modified,
        }
    }
}

impl DavMetaData for VaultDavMetaData {
    fn len(&self) -> u64 {
        self.size
    }

    fn is_dir(&self) -> bool {
        self.is_directory
    }

    fn modified(&self) -> dav_server::fs::FsResult<std::time::SystemTime> {
        Ok(self.modified)
    }
}

// --- Directory entry type / 目录条目类型 ---

/// A directory entry in the vault VFS.
///
/// Implements `DavDirEntry` to provide name and metadata information for
/// entries returned by `read_dir`. The `name` field contains only the entry
/// name (not the full path), as required by the WebDAV protocol.
//
// // 保险库 VFS 中的目录条目。
// //
// // 实现了 `DavDirEntry`，为 `read_dir` 返回的条目提供名称和元数据信息。
// // `name` 字段仅包含条目名称（而非完整路径），这是 WebDAV 协议要求的。
#[derive(Debug, Clone)]
pub struct VaultDavDirEntry {
    /// Entry name (file name or directory name, not full path).
    // // 条目名称（文件名或目录名，非完整路径）。
    name: String,
    /// Whether this entry is a directory.
    // // 此条目是否为目录。
    is_directory: bool,
    /// File size in bytes (0 for directories).
    // // 文件大小（字节），目录为 0。
    size: u64,
    /// Last modification time.
    // // 最后修改时间。
    modified: std::time::SystemTime,
}

impl VaultDavDirEntry {
    /// Creates a directory entry.
    ///
    /// # Arguments
    /// * `name` - The directory name (e.g., `"docs"`, not `"/docs/"`).
    //
    // // 创建目录条目。
    // //
    // // # 参数
    // // * `name` - 目录名称（例如 `"docs"`，而非 `"/docs/"`）。
    pub fn dir(name: String) -> Self {
        Self {
            name,
            is_directory: true,
            size: 0,
            modified: std::time::UNIX_EPOCH,
        }
    }

    /// Creates a file entry.
    ///
    /// # Arguments
    /// * `name` - The file name (e.g., `"report.txt"`, not `"/docs/report.txt"`).
    /// * `size` - The file size in bytes.
    /// * `modified` - The last modification time.
    //
    // // 创建文件条目。
    // //
    // // # 参数
    // // * `name` - 文件名称（例如 `"report.txt"`，而非 `"/docs/report.txt"`）。
    // // * `size` - 文件大小（字节）。
    // // * `modified` - 最后修改时间。
    pub fn file(name: String, size: u64, modified: std::time::SystemTime) -> Self {
        Self {
            name,
            is_directory: false,
            size,
            modified,
        }
    }
}

impl DavDirEntry for VaultDavDirEntry {
    fn name(&self) -> Vec<u8> {
        self.name.as_bytes().to_vec()
    }

    fn metadata(&self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let is_dir = self.is_directory;
        let size = self.size;
        let modified = self.modified;
        Box::pin(async move {
            if is_dir {
                Ok(Box::new(VaultDavMetaData::dir()) as Box<dyn DavMetaData>)
            } else {
                Ok(Box::new(VaultDavMetaData::file(size, modified)) as Box<dyn DavMetaData>)
            }
        })
    }

    /// Override for efficiency: avoids calling `metadata()` just to check `is_dir`.
    //
    // // 覆盖以提高效率：避免仅为了检查 `is_dir` 而调用 `metadata()`。
    fn is_dir(&self) -> FsFuture<'_, bool> {
        Box::pin(async move { Ok(self.is_directory) })
    }

    /// Override for efficiency: avoids calling `metadata()` just to check `is_file`.
    //
    // // 覆盖以提高效率：避免仅为了检查 `is_file` 而调用 `metadata()`。
    fn is_file(&self) -> FsFuture<'_, bool> {
        Box::pin(async move { Ok(!self.is_directory) })
    }
}

// --- Unit tests / 单元测试 ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;
    use vavavult::vault::Vault;

    /// Creates a temporary vault for testing.
    ///
    /// Returns `(temp_dir, Vault)` where `temp_dir` is the temporary directory
    /// containing the vault. The directory is not automatically cleaned up.
    //
    // // 创建用于测试的临时保险库。
    // //
    // // 返回 `(temp_dir, Vault)`，其中 `temp_dir` 是包含保险库的临时目录。
    // // 该目录不会自动清理。
    fn create_test_vault() -> (tempfile::TempDir, Vault) {
        let temp_dir = tempfile::tempdir().expect("无法创建临时目录");
        let password = "test_password_123";

        let vault = Vault::create_vault_local(temp_dir.path(), "test_vault", Some(password))
            .expect("无法创建测试保险库");

        (temp_dir, vault)
    }

    /// Helper: adds a small test file to the vault at the given vault path.
    //
    // // 辅助函数：向保险库添加一个小的测试文件到指定的保险库路径。
    fn add_test_file(vault: &mut Vault, vault_path: &str, content: &[u8]) {
        // 创建临时源文件
        let src_dir = tempfile::tempdir().expect("无法创建源文件临时目录");
        let src_path = src_dir.path().join("source.bin");
        std::fs::write(&src_path, content).expect("无法写入源文件");

        let dest_path = VaultPath::new(vault_path);
        vault
            .add_file(&src_path, &dest_path)
            .unwrap_or_else(|_| panic!("无法添加测试文件 {} 到保险库", vault_path));
    }

    // --- dav_path_to_vault_path tests ---

    #[test]
    fn test_dav_path_to_vault_path_root() {
        // 根路径转换
        let dav_path = DavPath::new("/").expect("无法创建 DavPath");
        let vault_path = dav_path_to_vault_path(&dav_path);
        assert!(vault_path.is_root());
        assert!(vault_path.is_dir());
    }

    #[test]
    fn test_dav_path_to_vault_path_directory() {
        // 目录路径转换
        let dav_path = DavPath::new("/docs/").expect("无法创建 DavPath");
        let vault_path = dav_path_to_vault_path(&dav_path);
        assert!(vault_path.is_dir());
        assert!(!vault_path.is_root());
    }

    #[test]
    fn test_dav_path_to_vault_path_file() {
        // 文件路径转换
        let dav_path = DavPath::new("/docs/report.txt").expect("无法创建 DavPath");
        let vault_path = dav_path_to_vault_path(&dav_path);
        assert!(vault_path.is_file());
    }

    // --- VaultDavMetaData tests ---

    #[test]
    fn test_metadata_dir() {
        let meta = VaultDavMetaData::dir();
        assert_eq!(meta.len(), 0);
        assert!(meta.is_dir());
        assert_eq!(meta.modified().unwrap(), SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn test_metadata_file_unit() {
        let now = SystemTime::now();
        let meta = VaultDavMetaData::file(1024, now);
        assert_eq!(meta.len(), 1024);
        assert!(!meta.is_dir());
        assert_eq!(meta.modified().unwrap(), now);
    }

    // --- VaultDavDirEntry tests ---

    #[test]
    fn test_dir_entry_directory() {
        let entry = VaultDavDirEntry::dir("docs".to_string());
        assert_eq!(entry.name(), b"docs");
        assert!(entry.is_directory);
    }

    #[test]
    fn test_dir_entry_file() {
        let now = SystemTime::now();
        let entry = VaultDavDirEntry::file("report.txt".to_string(), 2048, now);
        assert_eq!(entry.name(), b"report.txt");
        assert!(!entry.is_directory);
        assert_eq!(entry.size, 2048);
    }

    // --- VaultDavFs integration tests ---

    #[tokio::test]
    async fn test_metadata_root_dir() {
        // 根目录始终存在
        let (_temp_dir, vault) = create_test_vault();
        let fs = VaultDavFs::new(Arc::new(Mutex::new(vault)), true);

        let dav_path = DavPath::new("/").expect("无法创建 DavPath");
        let meta = fs.metadata(&dav_path).await.expect("根目录元数据查询失败");
        assert!(meta.is_dir());
    }

    #[tokio::test]
    async fn test_metadata_nonexistent_path() {
        // 不存在的路径应返回 NotFound
        let (_temp_dir, vault) = create_test_vault();
        let fs = VaultDavFs::new(Arc::new(Mutex::new(vault)), true);

        let dav_path = DavPath::new("/nonexistent").expect("无法创建 DavPath");
        let result = fs.metadata(&dav_path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_metadata_file() {
        // 添加文件后应能查询到元数据
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");
        let fs = VaultDavFs::new(Arc::new(Mutex::new(vault)), true);

        let dav_path = DavPath::new("/test.txt").expect("无法创建 DavPath");
        let meta = fs.metadata(&dav_path).await.expect("文件元数据查询失败");
        assert!(!meta.is_dir());
        assert_eq!(meta.len(), 11); // "hello world" = 11 bytes
    }

    #[tokio::test]
    async fn test_metadata_directory_with_files() {
        // 包含文件的目录应能查询到元数据
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/docs/report.txt", b"report content");
        let fs = VaultDavFs::new(Arc::new(Mutex::new(vault)), true);

        let dav_path = DavPath::new("/docs/").expect("无法创建 DavPath");
        let meta = fs.metadata(&dav_path).await.expect("目录元数据查询失败");
        assert!(meta.is_dir());
    }

    #[tokio::test]
    async fn test_metadata_directory_without_trailing_slash() {
        // 不带尾部斜杠的目录路径应回退为目录查找
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/docs/report.txt", b"report content");
        let fs = VaultDavFs::new(Arc::new(Mutex::new(vault)), true);

        let dav_path = DavPath::new("/docs").expect("无法创建 DavPath");
        let meta = fs.metadata(&dav_path).await.expect("目录回退查询失败");
        assert!(meta.is_dir());
    }

    #[tokio::test]
    async fn test_read_dir_root() {
        // 根目录列表
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/file1.txt", b"content1");
        add_test_file(&mut vault, "/docs/note.txt", b"content2");
        let fs = VaultDavFs::new(Arc::new(Mutex::new(vault)), true);

        let dav_path = DavPath::new("/").expect("无法创建 DavPath");
        use futures::StreamExt;
        let stream = fs
            .read_dir(&dav_path, dav_server::fs::ReadDirMeta::Data)
            .await
            .expect("读取目录失败");
        let entries: Vec<_> = stream.collect::<Vec<_>>().await;

        // 应包含 file1.txt 和 docs/ 目录
        assert!(entries.len() >= 2);
    }

    #[tokio::test]
    async fn test_read_dir_subdirectory() {
        // 子目录列表
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/docs/report.txt", b"report");
        add_test_file(&mut vault, "/docs/notes/todo.txt", b"todo");
        let fs = VaultDavFs::new(Arc::new(Mutex::new(vault)), true);

        let dav_path = DavPath::new("/docs/").expect("无法创建 DavPath");
        use futures::StreamExt;
        let stream = fs
            .read_dir(&dav_path, dav_server::fs::ReadDirMeta::Data)
            .await
            .expect("读取子目录失败");
        let entries: Vec<_> = stream.collect::<Vec<_>>().await;

        // 应包含 report.txt 和 notes/ 目录
        assert!(entries.len() >= 2);
    }

    #[tokio::test]
    async fn test_open_file() {
        // 打开文件应成功
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/hello.txt", b"hello world");
        let fs = VaultDavFs::new(Arc::new(Mutex::new(vault)), true);

        let dav_path = DavPath::new("/hello.txt").expect("无法创建 DavPath");
        let mut file = fs
            .open(
                &dav_path,
                OpenOptions {
                    read: true,
                    ..Default::default()
                },
            )
            .await
            .expect("打开文件失败");

        // 验证元数据
        let meta = file.metadata().await.expect("获取文件元数据失败");
        assert!(!meta.is_dir());
        assert_eq!(meta.len(), 11);
    }

    #[tokio::test]
    async fn test_open_nonexistent_file() {
        // 打开不存在的文件应返回 NotFound
        let (_temp_dir, vault) = create_test_vault();
        let fs = VaultDavFs::new(Arc::new(Mutex::new(vault)), true);

        let dav_path = DavPath::new("/nonexistent.txt").expect("无法创建 DavPath");
        let result = fs
            .open(
                &dav_path,
                OpenOptions {
                    read: true,
                    ..Default::default()
                },
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_open_directory_forbidden() {
        // 打开目录应返回 Forbidden
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/docs/file.txt", b"content");
        let fs = VaultDavFs::new(Arc::new(Mutex::new(vault)), true);

        let dav_path = DavPath::new("/docs/").expect("无法创建 DavPath");
        let result = fs
            .open(
                &dav_path,
                OpenOptions {
                    read: true,
                    ..Default::default()
                },
            )
            .await;
        assert!(result.is_err());
    }
}
