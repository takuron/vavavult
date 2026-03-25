use std::sync::{Arc, Mutex};
use dav_server::{DavFileSystem, DavMetaData, FsError, FsFuture};
use vavavult::vault::Vault;
use vavavult::file::VaultPath;

mod node;
pub use node::VaultDavFile;

/// Virtual filesystem adapter that exposes a Vavavult vault via WebDAV.
///
/// This struct implements the `DavFileSystem` trait from `dav-server`, allowing
/// a vault to be mounted and accessed through standard WebDAV clients.
//
// // 虚拟文件系统适配器，通过 WebDAV 暴露 Vavavult 保险库。
// //
// // 此结构体实现了 `dav-server` 的 `DavFileSystem` trait，允许
// // 通过标准 WebDAV 客户端挂载和访问保险库。
pub struct VaultDavFs {
    /// Shared reference to the vault instance.
    // // 保险库实例的共享引用。
    vault: Arc<Mutex<Vault>>,
}

impl VaultDavFs {
    /// Creates a new `VaultDavFs` instance wrapping the given vault.
    ///
    /// # Arguments
    /// * `vault` - An `Arc<Mutex<Vault>>` to the vault to be exposed.
    ///
    /// # Returns
    /// A new `VaultDavFs` instance.
    //
    // // 创建一个新的 `VaultDavFs` 实例，包装给定的保险库。
    // //
    // // # 参数
    // // * `vault` - 指向要暴露的保险库的 `Arc<Mutex<Vault>>`。
    // //
    // // # 返回
    // // 一个新的 `VaultDavFs` 实例。
    pub fn new(vault: Arc<Mutex<Vault>>) -> Self {
        Self { vault }
    }
}

impl DavFileSystem for VaultDavFs {
    fn metadata<'a>(&'a self, path: &'a dav_server::DavPath) -> FsFuture<Box<dyn DavMetaData>> {
        Box::pin(async move {
            // 1. 将 DavPath 转换为 VaultPath
            let path_str = path.as_url_string();
            let vault_path = VaultPath::new(&path_str);

            // 2. 锁定 vault 并查询元数据
            let vault = self.vault.lock().unwrap();

            // 3. 判断是目录还是文件
            if vault_path.is_dir() {
                // 目录：检查是否存在（通过 list_by_path）
                match vault.list_by_path(&vault_path) {
                    Ok(_) => {
                        // 目录存在，返回目录元数据
                        Ok(Box::new(VaultDirMetadata) as Box<dyn DavMetaData>)
                    }
                    Err(_) => Err(FsError::NotFound),
                }
            } else {
                // 文件：通过 find_by_paths 查询
                match vault.find_by_paths(&[vault_path.clone()]) {
                    Ok(results) if !results.is_empty() => {
                        let entry = &results[0];
                        // 从元数据中提取文件大小
                        let size = entry.metadata.iter()
                            .find(|m| m.key == "_vavavult_file_size")
                            .and_then(|m| m.value.parse::<u64>().ok())
                            .unwrap_or(0);

                        Ok(Box::new(VaultFileMetadata { size }) as Box<dyn DavMetaData>)
                    }
                    _ => Err(FsError::NotFound),
                }
            }
        })
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a dav_server::DavPath,
        _meta: dav_server::ReadDirMeta,
    ) -> FsFuture<dav_server::FsStream<Box<dyn DavMetaData>>> {
        Box::pin(async move {
            // 1. 转换路径
            let path_str = path.as_url_string();
            let vault_path = VaultPath::new(&path_str);

            // 2. 确保是目录路径
            if !vault_path.is_dir() {
                return Err(FsError::Forbidden);
            }

            // 3. 锁定 vault 并列出目录内容
            let vault = self.vault.lock().unwrap();
            let entries = vault.list_by_path(&vault_path)
                .map_err(|_| FsError::NotFound)?;

            // 4. 转换为 DavMetaData 流
            let items: Vec<Box<dyn DavMetaData>> = entries.into_iter()
                .map(|entry| match entry {
                    vavavult::vault::DirectoryEntry::Directory(_) => {
                        Box::new(VaultDirMetadata) as Box<dyn DavMetaData>
                    }
                    vavavult::vault::DirectoryEntry::File(file_entry) => {
                        let size = file_entry.metadata.iter()
                            .find(|m| m.key == "_vavavult_file_size")
                            .and_then(|m| m.value.parse::<u64>().ok())
                            .unwrap_or(0);
                        Box::new(VaultFileMetadata { size }) as Box<dyn DavMetaData>
                    }
                })
                .collect();

            Ok(Box::pin(futures::stream::iter(items.into_iter().map(Ok))) as dav_server::FsStream<Box<dyn DavMetaData>>)
        })
    }

    fn open<'a>(
        &'a self,
        path: &'a dav_server::DavPath,
        _options: dav_server::OpenOptions,
    ) -> FsFuture<Box<dyn dav_server::DavFile>> {
        Box::pin(async move {
            // 1. 转换路径
            let path_str = path.as_url_string();
            let vault_path = VaultPath::new(&path_str);

            // 2. 锁定 vault 并查找文件
            let vault = self.vault.lock().unwrap();
            let results = vault.find_by_paths(&[vault_path])
                .map_err(|_| FsError::NotFound)?;

            if results.is_empty() {
                return Err(FsError::NotFound);
            }

            let file_entry = results[0].clone();

            // 3. 准备解密任务
            let task = vault.prepare_extraction_task(&file_entry.sha256sum)
                .map_err(|_| FsError::GeneralFailure)?;

            // 4. 创建 VaultDavFile
            Ok(Box::new(VaultDavFile::new(task, self.vault.clone())) as Box<dyn dav_server::DavFile>)
        })
    }
}

/// Metadata for a directory in the vault.
// // 保险库中目录的元数据。
struct VaultDirMetadata;

impl DavMetaData for VaultDirMetadata {
    fn len(&self) -> u64 {
        0
    }

    fn is_dir(&self) -> bool {
        true
    }
}

/// Metadata for a file in the vault.
// // 保险库中文件的元数据。
struct VaultFileMetadata {
    size: u64,
}

impl DavMetaData for VaultFileMetadata {
    fn len(&self) -> u64 {
        self.size
    }

    fn is_dir(&self) -> bool {
        false
    }
}
