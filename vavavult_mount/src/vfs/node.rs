//! Vault file handle for WebDAV read operations.
//!
//! This module implements the `DavFile` trait, providing lazy decryption and
//! file-handle-based streaming reads of vault files. Decryption is performed
//! on first read using the standalone extraction API, which does not require
//! holding the vault mutex lock.
//!
//! # Streaming Architecture
//! Unlike a `Cursor<Vec<u8>>` approach that loads the entire decrypted content
//! into memory, this implementation decrypts to a temporary file and keeps
//! only an open `File` handle. Reads and seeks operate directly on the file
//! descriptor, so memory usage is O(1) regardless of file size — only the
//! requested read buffer is allocated.
//
// // 用于 WebDAV 读取操作的保险库文件句柄。
// //
// // 此模块实现了 `DavFile` trait，提供保险库文件的惰性解密和
// // 基于文件句柄的流式读取。首次读取时使用独立提取 API 执行解密，
// // 该 API 不需要持有保险库互斥锁。
// //
// // # 流式架构
// // 与将整个解密内容加载到内存的 `Cursor<Vec<u8>>` 方法不同，
// // 此实现将内容解密到临时文件并仅保持打开的 `File` 句柄。
// // 读取和定位直接操作文件描述符，因此无论文件大小如何，
// // 内存使用均为 O(1)——仅分配请求的读取缓冲区。

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bytes::Buf;
use dav_server::fs::{DavFile, DavMetaData, FsError, FsFuture};
use vavavult::storage::StorageBackend;
use vavavult::vault::{ExtractionTask, Vault};

use super::VaultDavMetaData;

struct ReceiverReader {
    receiver: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    buffer: bytes::Bytes,
}

impl std::io::Read for ReceiverReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.buffer.is_empty() {
            match self.receiver.blocking_recv() {
                Some(bytes) => self.buffer = bytes,
                None => return Ok(0), // EOF
            }
        }

        let len = std::cmp::min(buf.len(), self.buffer.len());
        buf[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer = self.buffer.split_off(len);
        Ok(len)
    }
}

/// Represents the operation state of a `VaultDavFile`.
///
/// A WebDAV file handle can be opened for either reading (e.g., GET requests)
/// or writing (e.g., PUT requests).
//
// // 代表 `VaultDavFile` 的操作状态。
// //
// // WebDAV 文件句柄可以为了读取（例如 GET 请求）或写入（例如 PUT 请求）而打开。
pub enum VaultDavFileState {
    /// State for a file opened for reading.
    // // 为读取而打开的文件状态。
    Read {
        /// The extraction task, consumed on first read.
        // // 提取任务，在首次读取时消费。
        task: Option<ExtractionTask>,
        /// Reference to the storage backend.
        // // 对存储后端的引用。
        storage: Arc<dyn StorageBackend>,
        /// Open file handle to the decrypted temporary file.
        // // 解密临时文件的打开文件句柄。
        content: Option<File>,
        /// Path to the temporary file for cleanup.
        // // 临时文件的路径，用于清理。
        temp_path: Option<PathBuf>,
    },
    /// State for a file opened for writing.
    // // 为写入而打开的文件状态。
    Write {
        /// Channel to send incoming bytes to the background encryption task.
        // // 用于将传入字节发送到后台加密任务的通道。
        write_tx: Option<tokio::sync::mpsc::Sender<bytes::Bytes>>,
        /// Handle to await the completion of the background encryption task.
        // // 用于等待后台加密任务完成的句柄。
        write_join_handle: Option<tokio::task::JoinHandle<Result<(), FsError>>>,
    },
}

pub struct VaultDavFile {
    state: VaultDavFileState,
    file_size: u64,
    modified: std::time::SystemTime,
}

impl std::fmt::Debug for VaultDavFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultDavFile")
            .field("file_size", &self.file_size)
            .field("modified", &self.modified)
            .finish_non_exhaustive()
    }
}

impl VaultDavFile {
    pub fn new(
        task: ExtractionTask,
        storage: Arc<dyn StorageBackend>,
        file_size: u64,
        modified: std::time::SystemTime,
    ) -> Self {
        Self {
            state: VaultDavFileState::Read {
                task: Some(task),
                storage,
                content: None,
                temp_path: None,
            },
            file_size,
            modified,
        }
    }

    /// Creates a new `VaultDavFile` in write mode.
    ///
    /// This sets up a background task that streams incoming data through the
    /// encryption cipher and commits it to the vault upon completion.
    ///
    /// # Arguments
    /// * `vault` - The vault instance to write to.
    /// * `vault_path` - The target path within the vault.
    ///
    /// # Returns
    /// A new `VaultDavFile` instance ready for writing.
    //
    // // 以写入模式创建一个新的 `VaultDavFile`。
    // //
    // // 这会设置一个后台任务，通过加密密码流式传输传入数据，并在完成后将其提交到保险库。
    // //
    // // # 参数
    // // * `vault` - 要写入的保险库实例。
    // // * `vault_path` - 保险库内的目标路径。
    // //
    // // # 返回
    // // 一个准备好进行写入的新 `VaultDavFile` 实例。
    pub fn new_write(vault: Arc<Mutex<Vault>>, vault_path: vavavult::file::VaultPath) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(32);

        let join_handle = tokio::task::spawn_blocking(move || -> Result<(), FsError> {
            let mut reader = ReceiverReader {
                receiver: rx,
                buffer: bytes::Bytes::new(),
            };

            let storage = {
                let v = vault.lock().unwrap();
                v.storage.clone()
            };

            let now = chrono::Utc::now();

            // 阶段 2: 加密（无锁）
            let pending = vavavult::vault::PendingAdditionTask {
                dest_path: vault_path.clone(),
                source_size: 0,
                source_modified_time: now,
            };
            let addition_task = vavavult::vault::Vault::encrypt_addition_task(
                storage.as_ref(),
                pending,
                &mut reader,
            )
            .map_err(|e| {
                eprintln!("[vavavult_mount] 加密流失败: {:?}", e);
                FsError::GeneralFailure
            })?;

            let mut v = vault.lock().unwrap();

            // WebDAV PUT 操作通常意味着覆盖现有文件。
            // 由于 Vault 核心库会在检测到同名路径时返回 DuplicateFileName，
            // 我们需要在这里先尝试移除可能存在的旧文件。
            if let Ok(vavavult::vault::QueryResult::Found(existing_entry)) =
                v.find_by_path(&vault_path)
            {
                if let Err(e) = v.remove_file(&existing_entry.sha256sum) {
                    eprintln!("[vavavult_mount] 覆盖文件前移除旧文件失败: {:?}", e);
                    return Err(FsError::GeneralFailure);
                }
            }

            v.commit_addition_tasks(vec![addition_task]).map_err(|e| {
                eprintln!("[vavavult_mount] 提交文件失败: {:?}", e);
                FsError::GeneralFailure
            })?;

            Ok(())
        });

        Self {
            state: VaultDavFileState::Write {
                write_tx: Some(tx),
                write_join_handle: Some(join_handle),
            },
            file_size: 0,
            modified: std::time::SystemTime::UNIX_EPOCH,
        }
    }

    fn ensure_content(&mut self) -> Result<(), FsError> {
        if let VaultDavFileState::Read {
            task,
            storage,
            content,
            temp_path,
        } = &mut self.state
        {
            if content.is_none() {
                let t = task.take().ok_or_else(|| {
                    eprintln!("[vavavult_mount] 提取任务已被消费但文件句柄未就绪");
                    FsError::GeneralFailure
                })?;

                let temp_dir = std::env::temp_dir();
                let unique_id = uuid::Uuid::new_v4();
                let temp_file = temp_dir.join(format!("vavavult_mount_{}", unique_id));

                vavavult::vault::execute_extraction_task_standalone(
                    storage.as_ref(),
                    &t,
                    &temp_file,
                )
                .map_err(|e| {
                    eprintln!("[vavavult_mount] 解密失败: {:?}", e);
                    FsError::GeneralFailure
                })?;

                let file = File::open(&temp_file).map_err(|e| {
                    eprintln!("[vavavult_mount] 打开临时文件失败: {:?}", e);
                    let _ = std::fs::remove_file(&temp_file);
                    FsError::GeneralFailure
                })?;

                *content = Some(file);
                *temp_path = Some(temp_file);
            }
        } else {
            return Err(FsError::Forbidden);
        }
        Ok(())
    }
}

impl Drop for VaultDavFile {
    fn drop(&mut self) {
        if let VaultDavFileState::Read {
            content, temp_path, ..
        } = &mut self.state
        {
            *content = None;
            if let Some(path) = temp_path.take() {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

impl DavFile for VaultDavFile {
    fn metadata<'a>(&'a mut self) -> FsFuture<'a, Box<dyn DavMetaData>> {
        Box::pin(async move {
            Ok(
                Box::new(VaultDavMetaData::file(self.file_size, self.modified))
                    as Box<dyn DavMetaData>,
            )
        })
    }

    fn read_bytes<'a>(&'a mut self, count: usize) -> FsFuture<'a, bytes::Bytes> {
        Box::pin(async move {
            self.ensure_content()?;

            if let VaultDavFileState::Read {
                content: Some(file),
                ..
            } = &mut self.state
            {
                let mut buf = vec![0u8; count];
                let bytes_read = file.read(&mut buf).map_err(|e| {
                    eprintln!("[vavavult_mount] 读取文件失败: {:?}", e);
                    FsError::GeneralFailure
                })?;

                buf.truncate(bytes_read);
                Ok(bytes::Bytes::from(buf))
            } else {
                Err(FsError::GeneralFailure)
            }
        })
    }

    fn write_bytes<'a>(&'a mut self, buf: bytes::Bytes) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if let VaultDavFileState::Write { write_tx, .. } = &mut self.state {
                if let Some(tx) = write_tx {
                    tx.send(buf).await.map_err(|_| FsError::GeneralFailure)?;
                    Ok(())
                } else {
                    Err(FsError::Forbidden)
                }
            } else {
                Err(FsError::Forbidden)
            }
        })
    }

    fn write_buf<'a>(&'a mut self, mut buf: Box<dyn Buf + Send + 'static>) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if let VaultDavFileState::Write { write_tx, .. } = &mut self.state {
                if let Some(tx) = write_tx {
                    while buf.has_remaining() {
                        let chunk = buf.chunk().to_vec();
                        buf.advance(chunk.len());
                        tx.send(bytes::Bytes::from(chunk))
                            .await
                            .map_err(|_| FsError::GeneralFailure)?;
                    }
                    Ok(())
                } else {
                    Err(FsError::Forbidden)
                }
            } else {
                Err(FsError::Forbidden)
            }
        })
    }

    fn seek<'a>(&'a mut self, pos: SeekFrom) -> FsFuture<'a, u64> {
        Box::pin(async move {
            self.ensure_content()?;

            if let VaultDavFileState::Read {
                content: Some(file),
                ..
            } = &mut self.state
            {
                file.seek(pos).map_err(|e| {
                    eprintln!("[vavavult_mount] seek 失败: {:?}", e);
                    FsError::GeneralFailure
                })
            } else {
                Err(FsError::Forbidden)
            }
        })
    }

    fn flush<'a>(&'a mut self) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if let VaultDavFileState::Write {
                write_tx,
                write_join_handle,
            } = &mut self.state
            {
                if let Some(tx) = write_tx.take() {
                    drop(tx);
                }
                if let Some(handle) = write_join_handle.take() {
                    handle.await.map_err(|_| FsError::GeneralFailure)??;
                }
            }
            Ok(())
        })
    }
}

// --- Unit tests / 单元测试 ---

#[cfg(test)]
mod tests {
    use super::*;

    use vavavult::vault::Vault;

    /// Creates a temporary vault for testing.
    ///
    /// Returns `(temp_dir, Vault)` where `temp_dir` is the temporary directory
    /// containing the vault.
    //
    // // 创建用于测试的临时保险库。
    // //
    // // 返回 `(temp_dir, Vault)`，其中 `temp_dir` 是包含保险库的临时目录。
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
        let src_dir = tempfile::tempdir().expect("无法创建源文件临时目录");
        let src_path = src_dir.path().join("source.bin");
        std::fs::write(&src_path, content).expect("无法写入源文件");

        let dest_path = vavavult::file::VaultPath::new(vault_path);
        vault
            .add_file(&src_path, &dest_path)
            .unwrap_or_else(|_| panic!("无法添加测试文件 {} 到保险库", vault_path));
    }

    /// Helper: creates a VaultDavFile for the given vault path.
    ///
    /// This simulates what `VaultDavFs::open()` does: find the file,
    /// prepare extraction task, and create the file handle.
    //
    // // 辅助函数：为给定的保险库路径创建 VaultDavFile。
    // //
    // // 这模拟了 `VaultDavFs::open()` 的操作：查找文件、准备提取任务、创建文件句柄。
    fn open_vault_file(vault: &Vault, vault_path: &str) -> Option<VaultDavFile> {
        use vavavult::file::VaultPath;
        use vavavult::vault::QueryResult;

        let vp = VaultPath::new(vault_path);
        let entry = match vault.find_by_path(&vp) {
            Ok(QueryResult::Found(e)) => e,
            _ => return None,
        };

        let task = vault.prepare_extraction_task(&entry.sha256sum).ok()?;
        let storage = vault.storage.clone();

        // 提取文件大小
        let size = entry
            .metadata
            .iter()
            .find(|m| m.key == "_vavavult_file_size")
            .and_then(|m| m.value.parse::<u64>().ok())
            .unwrap_or(0);

        // 提取修改时间
        let modified = entry
            .metadata
            .iter()
            .find(|m| m.key == "_vavavult_create_time")
            .and_then(|m| {
                m.value
                    .parse::<i64>()
                    .ok()
                    .map(|ts| std::time::UNIX_EPOCH + std::time::Duration::from_secs(ts as u64))
            })
            .unwrap_or(std::time::UNIX_EPOCH);

        Some(VaultDavFile::new(task, storage, size, modified))
    }

    #[tokio::test]
    async fn test_metadata_without_decryption() {
        // 元数据应无需解密即可获取
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");

        // 需要重新打开 vault 以获取最新数据
        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");

        // 获取元数据不应触发解密
        let meta = file.metadata().await.expect("获取元数据失败");
        assert!(!meta.is_dir());
        assert_eq!(meta.len(), 11); // "hello world" = 11 bytes

        // 验证文件尚未解密（content 和 temp_path 均为 None）
        if let VaultDavFileState::Read {
            content, temp_path, ..
        } = &file.state
        {
            assert!(content.is_none());
            assert!(temp_path.is_none());
        } else {
            panic!("Expected Read state");
        }
    }

    #[tokio::test]
    async fn test_read_bytes_full_content() {
        // 读取完整内容
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");

        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");

        // 读取应触发惰性解密
        let data = file.read_bytes(1024).await.expect("读取失败");
        assert_eq!(&data[..], b"hello world");

        // 验证文件句柄已打开
        if let VaultDavFileState::Read {
            content, temp_path, ..
        } = &file.state
        {
            assert!(content.is_some());
            assert!(temp_path.is_some());
        } else {
            panic!("Expected Read state");
        }
    }

    #[tokio::test]
    async fn test_read_bytes_partial() {
        // 部分读取
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");

        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");

        // 读取前 5 字节
        let data = file.read_bytes(5).await.expect("读取失败");
        assert_eq!(&data[..], b"hello");

        // 继续读取剩余字节
        let data = file.read_bytes(1024).await.expect("读取失败");
        assert_eq!(&data[..], b" world");
    }

    #[tokio::test]
    async fn test_read_bytes_at_end() {
        // 在末尾读取应返回空
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hi");

        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");

        // 读取全部内容
        let _ = file.read_bytes(1024).await.expect("读取失败");

        // 在末尾读取
        let data = file.read_bytes(10).await.expect("读取失败");
        assert!(data.is_empty());
    }

    #[tokio::test]
    async fn test_seek_from_start() {
        // 从开头定位
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");

        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");

        // 定位到位置 6
        let pos = file.seek(SeekFrom::Start(6)).await.expect("定位失败");
        assert_eq!(pos, 6);

        // 从位置 6 读取
        let data = file.read_bytes(1024).await.expect("读取失败");
        assert_eq!(&data[..], b"world");
    }

    #[tokio::test]
    async fn test_seek_from_current() {
        // 从当前位置定位
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");

        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");

        // 先读取 5 字节
        let _ = file.read_bytes(5).await.expect("读取失败");

        // 从当前位置向前移动 1 字节
        let pos = file.seek(SeekFrom::Current(-1)).await.expect("定位失败");
        assert_eq!(pos, 4);

        // 从位置 4 读取
        let data = file.read_bytes(1024).await.expect("读取失败");
        assert_eq!(&data[..], b"o world");
    }

    #[tokio::test]
    async fn test_seek_from_end() {
        // 从末尾定位
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");

        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");

        // 从末尾向前移动 5 字节
        let pos = file.seek(SeekFrom::End(-5)).await.expect("定位失败");
        assert_eq!(pos, 6); // 11 - 5 = 6

        // 从位置 6 读取
        let data = file.read_bytes(1024).await.expect("读取失败");
        assert_eq!(&data[..], b"world");
    }

    #[tokio::test]
    async fn test_write_bytes_forbidden() {
        // 写入应被禁止
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");

        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");

        let result = file.write_bytes(bytes::Bytes::from("data")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_write_buf_forbidden() {
        // 写入缓冲区应被禁止
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");

        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");

        let buf: Box<dyn Buf + Send> = Box::new(bytes::Bytes::from("data"));
        let result = file.write_buf(buf).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_flush_noop() {
        // flush 应为无操作
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");

        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");

        let result = file.flush().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_large_file_read() {
        // 测试较大文件的读取（验证流式读取，非全量加载）
        let large_content: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/large.bin", &large_content);

        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/large.bin").expect("无法打开文件");

        // 验证元数据
        let meta = file.metadata().await.expect("获取元数据失败");
        assert_eq!(meta.len(), 1024);

        // 分段读取（每次 256 字节，模拟流式读取）
        let mut all_data = Vec::new();
        loop {
            let chunk = file.read_bytes(256).await.expect("读取失败");
            if chunk.is_empty() {
                break;
            }
            all_data.extend_from_slice(&chunk);
        }

        assert_eq!(all_data.len(), 1024);
        assert_eq!(all_data, large_content);
    }

    #[tokio::test]
    async fn test_drop_cleans_temp_file() {
        // 验证 Drop 实现清理临时文件
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");

        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");

        // 触发解密
        let _ = file.read_bytes(5).await.expect("读取失败");

        // 记录临时文件路径
        let temp_path = if let VaultDavFileState::Read { temp_path, .. } = &file.state {
            temp_path.clone().expect("应有临时文件路径")
        } else {
            panic!("Expected Read state");
        };
        assert!(temp_path.exists(), "临时文件应存在");

        // Drop 文件句柄
        drop(file);

        // 验证临时文件已被删除
        assert!(!temp_path.exists(), "临时文件应已被删除");
    }

    #[tokio::test]
    async fn test_seek_then_read_repeated() {
        // 反复 seek + read 验证文件句柄正确性
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"0123456789");

        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");

        // 第一次：seek 到 5，读取 "56789"
        file.seek(SeekFrom::Start(5)).await.expect("定位失败");
        let data = file.read_bytes(100).await.expect("读取失败");
        assert_eq!(&data[..], b"56789");

        // 第二次：seek 回 0，读取 "01234"
        file.seek(SeekFrom::Start(0)).await.expect("定位失败");
        let data = file.read_bytes(5).await.expect("读取失败");
        assert_eq!(&data[..], b"01234");

        // 第三次：seek 到末尾前 3 字节，读取 "789"
        file.seek(SeekFrom::End(-3)).await.expect("定位失败");
        let data = file.read_bytes(100).await.expect("读取失败");
        assert_eq!(&data[..], b"789");
    }
}
