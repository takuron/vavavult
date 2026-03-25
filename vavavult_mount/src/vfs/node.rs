use std::sync::{Arc, Mutex};
use std::io::{Cursor, SeekFrom};
use dav_server::fs::{DavFile, FsError, FsFuture, DavMetaData};
use vavavult::vault::{Vault, ExtractionTask};
use bytes::Buf;

/// Represents an open file handle for reading from the vault.
///
/// This struct implements the `DavFile` trait, providing streaming read access
/// to decrypted file content.
//
// // 代表从保险库读取的打开文件句柄。
// //
// // 此结构体实现了 `DavFile` trait，提供对解密文件内容的流式读取访问。
#[derive(Debug)]
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
            let vault = self.vault.lock().unwrap();
            let temp_dir = std::env::temp_dir();
            let temp_file = temp_dir.join(format!("vavavult_{}", uuid::Uuid::new_v4()));

            vault.execute_extraction_task(&self.task, &temp_file)
                .map_err(|_| FsError::GeneralFailure)?;

            let buffer = std::fs::read(&temp_file)
                .map_err(|_| FsError::GeneralFailure)?;
            let _ = std::fs::remove_file(&temp_file);

            self.content = Some(buffer);
        }
        Ok(())
    }
}

impl DavFile for VaultDavFile {
    fn metadata<'a>(&'a mut self) -> FsFuture<Box<dyn DavMetaData>> {
        Box::pin(async move {
            self.ensure_content()?;
            let size = self.content.as_ref().unwrap().len() as u64;
            Ok(Box::new(FileMetadata { size }) as Box<dyn DavMetaData>)
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
            Err(FsError::Forbidden)
        })
    }

    fn write_buf<'a>(&'a mut self, _buf: Box<dyn Buf + Send + 'static>) -> FsFuture<()> {
        Box::pin(async move {
            Err(FsError::Forbidden)
        })
    }

    fn seek<'a>(&'a mut self, _pos: SeekFrom) -> FsFuture<u64> {
        Box::pin(async move {
            Err(FsError::NotImplemented)
        })
    }

    fn flush<'a>(&'a mut self) -> FsFuture<()> {
        Box::pin(async move { Ok(()) })
    }
}

/// Metadata for an open file.
// // 打开文件的元数据。
#[derive(Debug, Clone)]
struct FileMetadata {
    size: u64,
}

impl DavMetaData for FileMetadata {
    fn len(&self) -> u64 {
        self.size
    }

    fn is_dir(&self) -> bool {
        false
    }

    fn modified(&self) -> dav_server::fs::FsResult<std::time::SystemTime> {
        Ok(std::time::SystemTime::now())
    }
}
