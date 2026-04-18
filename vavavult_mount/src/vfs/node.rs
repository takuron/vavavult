//! Vault file handle for WebDAV read operations.
//!
//! This module implements the `DavFile` trait, providing lazy decryption and
//! cursor-based reading of vault files. Decryption is performed on first read
//! using the standalone extraction API, which does not require holding the
//! vault mutex lock.
//
// // 用于 WebDAV 读取操作的保险库文件句柄。
// //
// // 此模块实现了 `DavFile` trait，提供保险库文件的惰性解密和
// // 基于游标的读取。首次读取时使用独立提取 API 执行解密，
// // 该 API 不需要持有保险库互斥锁。

use std::io::{Cursor, Seek, SeekFrom};
use std::sync::Arc;

use bytes::Buf;
use dav_server::fs::{DavFile, DavMetaData, FsError, FsFuture};
use vavavult::storage::StorageBackend;
use vavavult::vault::ExtractionTask;

use super::VaultDavMetaData;

/// Represents an open file handle for reading from the vault.
///
/// This struct implements the `DavFile` trait, providing transparent decryption
/// and cursor-based read access to vault file content.
///
/// # Lazy Decryption
/// The file content is not decrypted until the first read operation. This
/// avoids unnecessary I/O when a client only requests metadata (e.g., HEAD
/// requests or PROPFIND without content).
///
/// # Thread Safety
/// The decryption uses `execute_extraction_task_standalone`, which only
/// requires a reference to the `StorageBackend` (not the full `Vault`).
/// This means the vault mutex is never held during the I/O-intensive
/// decryption phase.
///
/// # Seek Support
/// Full seek support is provided via an internal `Cursor`. This enables
/// HTTP Range requests, which are commonly used by WebDAV clients for
/// partial content retrieval and resumable downloads.
//
// // 代表从保险库读取的打开文件句柄。
// //
// // 此结构体实现了 `DavFile` trait，提供透明解密和基于游标的
// // 读取访问保险库文件内容。
// //
// // # 惰性解密
// // 文件内容在首次读取操作之前不会被解密。这避免了当客户端
// // 仅请求元数据时（例如 HEAD 请求或不带内容的 PROPFIND）
// // 执行不必要的 I/O。
// //
// // # 线程安全
// // 解密使用 `execute_extraction_task_standalone`，它仅需要
// // `StorageBackend` 的引用（而非完整的 `Vault`）。这意味着
// // 在 I/O 密集型解密阶段不会持有保险库互斥锁。
// //
// // # Seek 支持
// // 通过内部 `Cursor` 提供完整的 seek 支持。这启用了 HTTP Range
// // 请求，WebDAV 客户端通常使用它进行部分内容检索和可恢复下载。
#[derive(Debug)]
pub struct VaultDavFile {
    /// The extraction task containing decryption parameters.
    /// Prepared during `open()` (Phase 1), consumed during first read (Phase 2).
    // // 包含解密参数的提取任务。
    // // 在 `open()` 期间准备（阶段 1），在首次读取时消费（阶段 2）。
    task: ExtractionTask,

    /// Reference to the storage backend for standalone extraction.
    /// Cloned from `Vault::storage` during `open()`, avoiding the need
    /// to hold the vault mutex during decryption.
    // // 用于独立提取的存储后端引用。
    // // 在 `open()` 期间从 `Vault::storage` 克隆，避免在解密期间持有保险库互斥锁。
    storage: Arc<dyn StorageBackend>,

    /// Pre-computed file size (from `_vavavult_file_size` metadata).
    /// Available immediately without decryption.
    // // 预计算的文件大小（来自 `_vavavult_file_size` 元数据）。
    // // 无需解密即可立即使用。
    file_size: u64,

    /// Pre-computed modification time (from `_vavavult_create_time` metadata).
    // // 预计算的修改时间（来自 `_vavavult_create_time` 元数据）。
    modified: std::time::SystemTime,

    /// Cached decrypted content with read cursor.
    /// `None` until first read; `Some(cursor)` after lazy decryption.
    // // 缓存的解密内容和读取游标。
    // // 在首次读取之前为 `None`；惰性解密后为 `Some(cursor)`。
    content: Option<Cursor<Vec<u8>>>,
}

impl VaultDavFile {
    /// Creates a new `VaultDavFile` from an extraction task.
    ///
    /// The file content is not decrypted until the first read operation.
    /// The `storage` reference is used for standalone extraction without
    /// requiring the vault mutex.
    ///
    /// # Arguments
    /// * `task` - The extraction task prepared by the vault (Phase 1 result).
    /// * `storage` - Cloned `Arc<dyn StorageBackend>` from the vault.
    /// * `file_size` - Pre-computed file size from vault metadata.
    /// * `modified` - Pre-computed modification time from vault metadata.
    ///
    /// # Returns
    /// A new `VaultDavFile` instance ready for reading.
    //
    // // 从提取任务创建一个新的 `VaultDavFile`。
    // //
    // // 文件内容在首次读取操作之前不会被解密。
    // // `storage` 引用用于独立提取，无需保险库互斥锁。
    // //
    // // # 参数
    // // * `task` - 由保险库准备的提取任务（阶段 1 结果）。
    // // * `storage` - 从保险库克隆的 `Arc<dyn StorageBackend>`。
    // // * `file_size` - 从保险库元数据预计算的文件大小。
    // // * `modified` - 从保险库元数据预计算的修改时间。
    // //
    // // # 返回
    // // 一个新的 `VaultDavFile` 实例，准备好进行读取。
    pub fn new(
        task: ExtractionTask,
        storage: Arc<dyn StorageBackend>,
        file_size: u64,
        modified: std::time::SystemTime,
    ) -> Self {
        Self {
            task,
            storage,
            file_size,
            modified,
            content: None,
        }
    }

    /// Ensures the file content is decrypted and cached in memory.
    ///
    /// This method performs the actual decryption using
    /// `execute_extraction_task_standalone`, which does not require the
    /// vault mutex. The decrypted content is stored in an internal `Cursor`
    /// for efficient seek and read operations.
    ///
    /// # Errors
    /// Returns `FsError::GeneralFailure` if:
    /// - The temporary directory cannot be created.
    /// - The decryption fails (wrong password, data corruption).
    /// - The decrypted file cannot be read from disk.
    /// - The temporary file cannot be cleaned up.
    //
    // // 确保文件内容已解密并缓存在内存中。
    // //
    // // 此方法使用 `execute_extraction_task_standalone` 执行实际解密，
    // // 不需要保险库互斥锁。解密后的内容存储在内部 `Cursor` 中，
    // // 以实现高效的 seek 和读取操作。
    // //
    // // # 错误
    // // 在以下情况下返回 `FsError::GeneralFailure`：
    // // - 无法创建临时目录。
    // // - 解密失败（密码错误、数据损坏）。
    // // - 无法从磁盘读取解密后的文件。
    // // - 无法清理临时文件。
    fn ensure_content(&mut self) -> Result<(), FsError> {
        if self.content.is_none() {
            // 1. 创建临时文件用于解密输出
            let temp_dir = std::env::temp_dir();
            let unique_id = uuid::Uuid::new_v4();
            let temp_file = temp_dir.join(format!("vavavult_mount_{}", unique_id));

            // 2. 执行独立解密（阶段 2：I/O 密集型，不需要 vault 锁）
            vavavult::vault::execute_extraction_task_standalone(
                self.storage.as_ref(),
                &self.task,
                &temp_file,
            )
            .map_err(|e| {
                eprintln!("[vavavult_mount] 解密失败: {:?}", e);
                FsError::GeneralFailure
            })?;

            // 3. 读取解密后的内容到内存
            let buffer = std::fs::read(&temp_file).map_err(|e| {
                eprintln!("[vavavult_mount] 读取临时文件失败: {:?}", e);
                FsError::GeneralFailure
            })?;

            // 4. 清理临时文件（忽略错误，不影响主流程）
            let _ = std::fs::remove_file(&temp_file);

            // 5. 将内容包装为 Cursor 以支持 seek 操作
            self.content = Some(Cursor::new(buffer));
        }
        Ok(())
    }
}

impl DavFile for VaultDavFile {
    /// Returns metadata for this open file.
    ///
    /// Uses the pre-computed size and modification time; does not require
    /// decryption. The content is lazily decrypted only if `read_bytes`
    /// or `seek` is called.
    //
    // // 返回此打开文件的元数据。
    // //
    // // 使用预计算的大小和修改时间；不需要解密。
    // // 仅在调用 `read_bytes` 或 `seek` 时才会惰性解密内容。
    fn metadata<'a>(&'a mut self) -> FsFuture<'a, Box<dyn DavMetaData>> {
        Box::pin(async move {
            // 不需要解密即可返回元数据
            Ok(
                Box::new(VaultDavMetaData::file(self.file_size, self.modified))
                    as Box<dyn DavMetaData>,
            )
        })
    }

    /// Reads up to `count` bytes from the current cursor position.
    ///
    /// Triggers lazy decryption on first call. After reading, the cursor
    /// position advances by the number of bytes returned. If the cursor
    /// is at the end of the content, returns an empty `Bytes`.
    ///
    /// # Arguments
    /// * `count` - Maximum number of bytes to read.
    ///
    /// # Returns
    /// A `Bytes` containing the read data. May be shorter than `count`
    /// if the end of the content is reached.
    //
    // // 从当前游标位置读取最多 `count` 字节。
    // //
    // // 在首次调用时触发惰性解密。读取后，游标位置前进返回的字节数。
    // // 如果游标在内容末尾，返回空的 `Bytes`。
    // //
    // // # 参数
    // // * `count` - 要读取的最大字节数。
    // //
    // // # 返回
    // // 包含读取数据的 `Bytes`。如果到达内容末尾，可能短于 `count`。
    fn read_bytes<'a>(&'a mut self, count: usize) -> FsFuture<'a, bytes::Bytes> {
        Box::pin(async move {
            // 1. 确保内容已解密
            self.ensure_content()?;

            // 2. 从游标当前位置读取
            let cursor = self
                .content
                .as_mut()
                .expect("ensure_content 应已设置 content");
            let current_pos = cursor.position() as usize;
            let content_vec = cursor.get_ref();

            // 3. 计算可读取的字节数
            let available = if current_pos >= content_vec.len() {
                0
            } else {
                content_vec.len() - current_pos
            };
            let read_len = count.min(available);

            // 4. 提取字节切片并推进游标
            if read_len == 0 {
                return Ok(bytes::Bytes::new());
            }

            let start = current_pos;
            let end = start + read_len;
            let result = bytes::Bytes::copy_from_slice(&content_vec[start..end]);

            // 5. 推进游标位置
            cursor.set_position(end as u64);

            Ok(result)
        })
    }

    /// Write operations are not supported in read-only mode.
    ///
    /// Always returns `FsError::Forbidden`.
    //
    // // 只读模式下不支持写入操作。
    // //
    // // 始终返回 `FsError::Forbidden`。
    fn write_bytes<'a>(&'a mut self, _buf: bytes::Bytes) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Forbidden) })
    }

    /// Write operations are not supported in read-only mode.
    ///
    /// Always returns `FsError::Forbidden`.
    //
    // // 只读模式下不支持写入操作。
    // //
    // // 始终返回 `FsError::Forbidden`。
    fn write_buf<'a>(&'a mut self, _buf: Box<dyn Buf + Send + 'static>) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Forbidden) })
    }

    /// Seeks to a position within the decrypted file content.
    ///
    /// Triggers lazy decryption on first call. Supports all `SeekFrom` modes:
    /// - `SeekFrom::Start(pos)`: Absolute position from the beginning.
    /// - `SeekFrom::Current(offset)`: Relative to the current cursor position.
    /// - `SeekFrom::End(offset)`: Relative to the end of the content.
    ///
    /// # Arguments
    /// * `pos` - The seek position.
    ///
    /// # Returns
    /// The new cursor position (offset from the beginning of the content).
    ///
    /// # Errors
    /// Returns `FsError::GeneralFailure` if seeking before the beginning
    /// or to an invalid position.
    //
    // // 在解密文件内容中定位到指定位置。
    // //
    // // 在首次调用时触发惰性解密。支持所有 `SeekFrom` 模式：
    // // - `SeekFrom::Start(pos)`：从开头的绝对位置。
    // // - `SeekFrom::Current(offset)`：相对于当前游标位置。
    // // - `SeekFrom::End(offset)`：相对于内容末尾。
    // //
    // // # 参数
    // // * `pos` - 定位位置。
    // //
    // // # 返回
    // // 新的游标位置（从内容开头的偏移量）。
    // //
    // // # 错误
    // // 如果定位到开头之前或无效位置，返回 `FsError::GeneralFailure`。
    fn seek<'a>(&'a mut self, pos: SeekFrom) -> FsFuture<'a, u64> {
        Box::pin(async move {
            // 1. 确保内容已解密
            self.ensure_content()?;

            // 2. 使用 Cursor 的 seek 实现
            let cursor = self
                .content
                .as_mut()
                .expect("ensure_content 应已设置 content");
            cursor.seek(pos).map_err(|_| FsError::GeneralFailure)
        })
    }

    /// Flush is a no-op for read-only files.
    ///
    /// Always returns `Ok(())`.
    //
    // // 对于只读文件，flush 是无操作。
    // //
    // // 始终返回 `Ok(())`。
    fn flush<'a>(&'a mut self) -> FsFuture<'a, ()> {
        Box::pin(async move { Ok(()) })
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

        // 验证内容尚未解密
        assert!(file.content.is_none());
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
        // 测试较大文件的读取
        let large_content: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let (_temp_dir, mut vault) = create_test_vault();
        add_test_file(&mut vault, "/large.bin", &large_content);

        let vault = Vault::open_vault_local(_temp_dir.path(), Some("test_password_123"))
            .expect("无法重新打开保险库");

        let mut file = open_vault_file(&vault, "/large.bin").expect("无法打开文件");

        // 验证元数据
        let meta = file.metadata().await.expect("获取元数据失败");
        assert_eq!(meta.len(), 1024);

        // 分段读取
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
}
