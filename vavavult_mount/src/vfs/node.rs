//! Vault file handle for WebDAV read/write operations.
//!
//! This module implements the `DavFile` trait, providing lazy decryption and
//! pipe-based streaming reads of vault files. Decryption is performed in a
//! background `spawn_blocking` task using the standalone extraction API, which
//! does not require holding the vault mutex lock.
//!
//! # Streaming Architecture
//! Decryption runs in a background thread, writing 8KB chunks through an
//! `mpsc` channel. `read_bytes()` pulls from the channel on demand, so the
//! client receives data as soon as each chunk is decrypted — no need to wait
//! for the entire file. If `seek()` is called, the remaining stream is drained
//! into a temporary file and subsequent reads use random-access file I/O.
//
// // 用于 WebDAV 读写操作的保险库文件句柄。
// //
// // 此模块实现了 `DavFile` trait，提供保险库文件的惰性解密和
// // 基于管道的流式读取。解密在后台 `spawn_blocking` 任务中执行，
// // 使用独立提取 API，不需要持有保险库互斥锁。
// //
// // # 流式架构
// // 解密在后台线程中运行，通过 `mpsc` 通道写入 8KB 块。
// // `read_bytes()` 按需从通道拉取数据，因此客户端在每个块解密完成后
// // 即可收到数据——无需等待整个文件。如果调用 `seek()`，
// // 剩余流将被排空到临时文件，后续读取使用随机访问文件 I/O。

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write as IoWrite};
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Buf;
use dav_server::fs::{DavFile, DavMetaData, FsError, FsFuture};
use vavavult::storage::StorageBackend;
use vavavult::vault::ExtractionTask;

use super::VaultDavMetaData;

/// 将 `mpsc::Sender<bytes::Bytes>` 适配为 `std::io::Write`。
/// 解密线程通过此 writer 将解密后的数据块发送到通道。
struct ChannelWriter {
    sender: tokio::sync::mpsc::Sender<bytes::Bytes>,
    rt_handle: tokio::runtime::Handle,
}

impl std::io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let data = bytes::Bytes::copy_from_slice(buf);
        self.rt_handle
            .block_on(self.sender.send(data))
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "receiver dropped"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 将 `mpsc::Receiver<bytes::Bytes>` 适配为 `std::io::Read`。
/// 写入路径的后台加密任务通过此 reader 消费传入数据。
struct ReceiverReader {
    receiver: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    buffer: bytes::Bytes,
}

impl std::io::Read for ReceiverReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.buffer.is_empty() {
            match self.receiver.blocking_recv() {
                Some(bytes) => self.buffer = bytes,
                None => return Ok(0),
            }
        }

        let len = std::cmp::min(buf.len(), self.buffer.len());
        buf[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer = self.buffer.split_off(len);
        Ok(len)
    }
}

/// 读取子状态：流式管道 vs 随机访问临时文件。
pub(crate) enum ReadContent {
    /// 尚未开始解密。
    Pending {
        task: ExtractionTask,
        storage: Arc<dyn StorageBackend>,
    },
    /// 管道式流式读取：后台线程解密，通过通道传输数据。
    Streaming {
        receiver: tokio::sync::mpsc::Receiver<bytes::Bytes>,
        buffer: bytes::Bytes,
        position: u64,
        _join_handle: tokio::task::JoinHandle<Result<(), FsError>>,
    },
    /// 随机访问模式：数据已排空到临时文件，支持 seek。
    RandomAccess {
        file: File,
        temp_path: PathBuf,
    },
    /// 状态已被消费（用于 take 操作）。
    Consumed,
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
    /// State for a file opened for reading (pipe-based streaming with seek fallback).
    // // 为读取而打开的文件状态（基于管道的流式传输，支持 seek 回退）。
    Read {
        content: ReadContent,
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
                content: ReadContent::Pending { task, storage },
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
    pub fn new_write(
        vault: Arc<std::sync::Mutex<vavavult::vault::Vault>>,
        vault_path: vavavult::file::VaultPath,
    ) -> Self {
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

    /// 启动后台解密管道（从 Pending 转换到 Streaming 状态）。
    fn start_streaming(&mut self) -> Result<(), FsError> {
        if let VaultDavFileState::Read { content } = &mut self.state {
            // 仅在 Pending 状态时启动
            let old = std::mem::replace(content, ReadContent::Consumed);
            if let ReadContent::Pending { task, storage } = old {
                let (tx, rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(32);
                let rt_handle = tokio::runtime::Handle::current();

                let join_handle =
                    tokio::task::spawn_blocking(move || -> Result<(), FsError> {
                        let writer = ChannelWriter {
                            sender: tx,
                            rt_handle,
                        };
                        vavavult::vault::Vault::decrypt_extraction_task(
                            storage.as_ref(),
                            &task,
                            writer,
                        )
                        .map_err(|e| {
                            eprintln!("[vavavult_mount] 解密失败: {:?}", e);
                            FsError::GeneralFailure
                        })
                    });

                *content = ReadContent::Streaming {
                    receiver: rx,
                    buffer: bytes::Bytes::new(),
                    position: 0,
                    _join_handle: join_handle,
                };
                Ok(())
            } else {
                // 已经不是 Pending，恢复原状态
                *content = old;
                Ok(())
            }
        } else {
            Err(FsError::Forbidden)
        }
    }

    /// 将流式管道中的剩余数据排空到临时文件，切换到随机访问模式。
    fn drain_to_random_access(&mut self) -> Result<(), FsError> {
        if let VaultDavFileState::Read { content } = &mut self.state {
            let old = std::mem::replace(content, ReadContent::Consumed);
            if let ReadContent::Streaming {
                mut receiver,
                buffer,
                position,
                _join_handle,
            } = old
            {
                let temp_dir = std::env::temp_dir();
                let unique_id = uuid::Uuid::new_v4();
                let temp_path = temp_dir.join(format!("vavavult_mount_{}", unique_id));

                let mut file = File::create(&temp_path).map_err(|e| {
                    eprintln!("[vavavult_mount] 创建临时文件失败: {:?}", e);
                    FsError::GeneralFailure
                })?;

                // 先写入缓冲区中的剩余数据
                if !buffer.is_empty() {
                    file.write_all(&buffer).map_err(|e| {
                        eprintln!("[vavavult_mount] 写入临时文件失败: {:?}", e);
                        FsError::GeneralFailure
                    })?;
                }

                // 排空通道中的所有剩余数据
                while let Some(chunk) = receiver.blocking_recv() {
                    file.write_all(&chunk).map_err(|e| {
                        eprintln!("[vavavult_mount] 写入临时文件失败: {:?}", e);
                        FsError::GeneralFailure
                    })?;
                }

                file.flush().map_err(|e| {
                    eprintln!("[vavavult_mount] flush 临时文件失败: {:?}", e);
                    FsError::GeneralFailure
                })?;
                drop(file);

                // 重新打开为只读，并 seek 到当前位置
                let mut file = File::open(&temp_path).map_err(|e| {
                    eprintln!("[vavavult_mount] 打开临时文件失败: {:?}", e);
                    FsError::GeneralFailure
                })?;
                file.seek(SeekFrom::Start(position)).map_err(|e| {
                    eprintln!("[vavavult_mount] seek 临时文件失败: {:?}", e);
                    FsError::GeneralFailure
                })?;

                *content = ReadContent::RandomAccess {
                    file,
                    temp_path,
                };
                Ok(())
            } else {
                *content = old;
                Ok(())
            }
        } else {
            Err(FsError::Forbidden)
        }
    }
}

impl Drop for VaultDavFile {
    fn drop(&mut self) {
        if let VaultDavFileState::Read { content } = &mut self.state {
            if let ReadContent::RandomAccess { temp_path, .. } = content {
                let _ = std::fs::remove_file(temp_path);
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
            // 如果还在 Pending 状态，启动流式解密管道
            if matches!(
                &self.state,
                VaultDavFileState::Read {
                    content: ReadContent::Pending { .. }
                }
            ) {
                self.start_streaming()?;
            }

            if let VaultDavFileState::Read { content } = &mut self.state {
                match content {
                    ReadContent::Streaming {
                        receiver,
                        buffer,
                        position,
                        ..
                    } => {
                        // 如果缓冲区为空，从通道接收下一个块
                        if buffer.is_empty() {
                            match receiver.recv().await {
                                Some(chunk) => *buffer = chunk,
                                None => return Ok(bytes::Bytes::new()),
                            }
                        }

                        // 从缓冲区中取出请求的字节数
                        let len = std::cmp::min(count, buffer.len());
                        let result = buffer.split_to(len);
                        *position += len as u64;
                        Ok(result)
                    }
                    ReadContent::RandomAccess { file, .. } => {
                        let mut buf = vec![0u8; count];
                        let bytes_read = file.read(&mut buf).map_err(|e| {
                            eprintln!("[vavavult_mount] 读取文件失败: {:?}", e);
                            FsError::GeneralFailure
                        })?;
                        buf.truncate(bytes_read);
                        Ok(bytes::Bytes::from(buf))
                    }
                    _ => Err(FsError::GeneralFailure),
                }
            } else {
                Err(FsError::Forbidden)
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
            // 如果还在 Pending 状态，启动流式解密管道
            if matches!(
                &self.state,
                VaultDavFileState::Read {
                    content: ReadContent::Pending { .. }
                }
            ) {
                self.start_streaming()?;
            }

            // 如果在 Streaming 状态，需要排空到临时文件以支持随机访问
            if matches!(
                &self.state,
                VaultDavFileState::Read {
                    content: ReadContent::Streaming { .. }
                }
            ) {
                // drain_to_random_access 内部使用 blocking_recv，
                // 需要在 block_in_place 中执行以避免阻塞 tokio 线程
                tokio::task::block_in_place(|| self.drain_to_random_access())?;
            }

            if let VaultDavFileState::Read { content } = &mut self.state {
                if let ReadContent::RandomAccess { file, .. } = content {
                    file.seek(pos).map_err(|e| {
                        eprintln!("[vavavult_mount] seek 失败: {:?}", e);
                        FsError::GeneralFailure
                    })
                } else {
                    Err(FsError::GeneralFailure)
                }
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
    use std::io::SeekFrom;

    use vavavult::vault::Vault;

    fn create_test_vault() -> (tempfile::TempDir, Vault) {
        let temp_dir = tempfile::tempdir().expect("无法创建临时目录");
        let password = "test_password_123";
        let vault = Vault::create_vault_local(temp_dir.path(), "test_vault", Some(password))
            .expect("无法创建测试保险库");
        (temp_dir, vault)
    }

    fn add_test_file(vault: &mut Vault, vault_path: &str, content: &[u8]) {
        let src_dir = tempfile::tempdir().expect("无法创建源文件临时目录");
        let src_path = src_dir.path().join("source.bin");
        std::fs::write(&src_path, content).expect("无法写入源文件");
        let dest_path = vavavult::file::VaultPath::new(vault_path);
        vault
            .add_file(&src_path, &dest_path)
            .unwrap_or_else(|_| panic!("无法添加测试文件 {} 到保险库", vault_path));
    }

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

        let size = entry
            .metadata
            .iter()
            .find(|m| m.key == "_vavavult_file_size")
            .and_then(|m| m.value.parse::<u64>().ok())
            .unwrap_or(0);

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
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");
        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");
        let meta = file.metadata().await.expect("获取元数据失败");
        assert!(!meta.is_dir());
        assert_eq!(meta.len(), 11);

        if let VaultDavFileState::Read { content } = &file.state {
            assert!(matches!(content, ReadContent::Pending { .. }));
        } else {
            panic!("Expected Read state");
        }
    }

    #[tokio::test]
    async fn test_read_bytes_full_content() {
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");
        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");
        let data = file.read_bytes(1024).await.expect("读取失败");
        assert_eq!(&data[..], b"hello world");
    }

    #[tokio::test]
    async fn test_read_bytes_partial() {
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");
        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");
        let data = file.read_bytes(5).await.expect("读取失败");
        assert_eq!(&data[..], b"hello");

        let data = file.read_bytes(1024).await.expect("读取失败");
        assert_eq!(&data[..], b" world");
    }

    #[tokio::test]
    async fn test_read_bytes_at_end() {
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hi");
        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");
        let _ = file.read_bytes(1024).await.expect("读取失败");
        let data = file.read_bytes(10).await.expect("读取失败");
        assert!(data.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_seek_from_start() {
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");
        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");
        let pos = file.seek(SeekFrom::Start(6)).await.expect("定位失败");
        assert_eq!(pos, 6);

        let data = file.read_bytes(1024).await.expect("读取失败");
        assert_eq!(&data[..], b"world");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_seek_from_current() {
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");
        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");
        file.seek(SeekFrom::Start(5)).await.expect("定位失败");
        let pos = file.seek(SeekFrom::Current(-1)).await.expect("定位失败");
        assert_eq!(pos, 4);

        let data = file.read_bytes(1024).await.expect("读取失败");
        assert_eq!(&data[..], b"o world");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_seek_from_end() {
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");
        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");
        let pos = file.seek(SeekFrom::End(-5)).await.expect("定位失败");
        assert_eq!(pos, 6);

        let data = file.read_bytes(1024).await.expect("读取失败");
        assert_eq!(&data[..], b"world");
    }

    #[tokio::test]
    async fn test_write_bytes_forbidden() {
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");
        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");
        let result = file.write_bytes(bytes::Bytes::from("data")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_flush_noop() {
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
        let large_content: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/large.bin", &large_content);
        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/large.bin").expect("无法打开文件");
        let meta = file.metadata().await.expect("获取元数据失败");
        assert_eq!(meta.len(), 1024);

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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_seek_creates_temp_file_and_cleans_up() {
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"hello world");
        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");
        file.seek(SeekFrom::Start(0)).await.expect("定位失败");

        let temp_path = if let VaultDavFileState::Read { content } = &file.state {
            if let ReadContent::RandomAccess { temp_path, .. } = content {
                temp_path.clone()
            } else {
                panic!("Expected RandomAccess state after seek");
            }
        } else {
            panic!("Expected Read state");
        };
        assert!(temp_path.exists(), "临时文件应存在");

        drop(file);
        assert!(!temp_path.exists(), "临时文件应已被删除");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_seek_then_read_repeated() {
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/test.txt", b"0123456789");
        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/test.txt").expect("无法打开文件");

        file.seek(SeekFrom::Start(5)).await.expect("定位失败");
        let data = file.read_bytes(100).await.expect("读取失败");
        assert_eq!(&data[..], b"56789");

        file.seek(SeekFrom::Start(0)).await.expect("定位失败");
        let data = file.read_bytes(5).await.expect("读取失败");
        assert_eq!(&data[..], b"01234");

        file.seek(SeekFrom::End(-3)).await.expect("定位失败");
        let data = file.read_bytes(100).await.expect("读取失败");
        assert_eq!(&data[..], b"789");
    }
}
