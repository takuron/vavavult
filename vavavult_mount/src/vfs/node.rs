use std::sync::{Arc, Mutex};
use std::io::Cursor;
use dav_server::{DavFile, FsError, FsFuture};
use vavavult::vault::{Vault, ExtractionTask};

/// Represents an open file handle for reading from the vault.
///
/// This struct implements the `DavFile` trait, providing streaming read access
/// to decrypted file content.
//
// // 代表从保险库读取的打开文件句柄。
// //
// // 此结构体实现了 `DavFile` trait，提供对解密文件内容的流式读取访问。
pub struct VaultDavFile {
    /// The extraction task containing decryption parameters.
    // // 包含解密参数的提取任务。
    task: ExtractionTask,
    /// Shared reference to the vault.
    // // 保险库的共享引用。
    vault: Arc<Mutex<Vault>>,
    /// Cached decrypted content.
    // // 缓存的解密内容。
    content: Option<Vec<u8>>,
}

impl VaultDavFile {
    /// Creates a new `VaultDavFile` from an extraction task.
    ///
    /// # Arguments
    /// * `task` - The extraction task prepared by the vault.
    /// * `vault` - Shared reference to the vault instance.
    ///
    /// # Returns
    /// A new `VaultDavFile` instance.
    //
    // // 从提取任务创建一个新的 `VaultDavFile`。
    // //
    // // # 参数
    // // * `task` - 由保险库准备的提取任务。
    // // * `vault` - 保险库实例的共享引用。
    // //
    // // # 返回
    // // 一个新的 `VaultDavFile` 实例。
    pub fn new(task: ExtractionTask, vault: Arc<Mutex<Vault>>) -> Self {
        Self {
            task,
            vault,
            content: None,
        }
    }

    /// Ensures the file content is decrypted and cached.
    // // 确保文件内容已解密并缓存。
    fn ensure_content(&mut self) -> Result<(), FsError> {
        if self.content.is_none() {
            // 执行解密任务
            let vault = self.vault.lock().unwrap();
            let mut buffer = Vec::new();
            Vault::execute_extraction_task_standalone(&self.task, &mut buffer)
                .map_err(|_| FsError::GeneralFailure)?;
            self.content = Some(buffer);
        }
        Ok(())
    }
}

impl DavFile for VaultDavFile {
    fn metadata<'a>(&'a mut self) -> FsFuture<Box<dyn dav_server::DavMetaData>> {
        Box::pin(async move {
            self.ensure_content()?;
            let size = self.content.as_ref().unwrap().len() as u64;
            Ok(Box::new(FileMetadata { size }) as Box<dyn dav_server::DavMetaData>)
        })
    }

    fn read_bytes<'a>(&'a mut self, count: usize) -> FsFuture<bytes::Bytes> {
        Box::pin(async move {
            self.ensure_content()?;
            let content = self.content.as_ref().unwrap();
            let bytes = if count >= content.len() {
                bytes::Bytes::copy_from_slice(content)
            } else {
                bytes::Bytes::copy_from_slice(&content[..count])
            };
            Ok(bytes)
        })
    }

    fn write_bytes<'a>(&'a mut self, _buf: bytes::Bytes) -> FsFuture<()> {
        Box::pin(async move {
            // 只读实现，拒绝写入
            Err(FsError::Forbidden)
        })
    }

    fn write_all<'a>(&'a mut self, _buf: bytes::Bytes) -> FsFuture<()> {
        Box::pin(async move {
            // 只读实现，拒绝写入
            Err(FsError::Forbidden)
        })
    }

    fn flush<'a>(&'a mut self) -> FsFuture<()> {
        Box::pin(async move { Ok(()) })
    }
}

/// Metadata for an open file.
// // 打开文件的元数据。
struct FileMetadata {
    size: u64,
}

impl dav_server::DavMetaData for FileMetadata {
    fn len(&self) -> u64 {
        self.size
    }

    fn is_dir(&self) -> bool {
        false
    }
}
