pub mod local;

use std::any::Any;
use std::fmt::Debug;
use std::io::{self, Read, Write};
use crate::common::hash::VaultHash;

/// An opaque token holding information about a staged file operation.
///
/// It might contain a path to a temporary file (Local FS) or an upload ID (S3).
/// Must implement `Send` + `Sync` to support multi-threading.
//
// // 一个不透明的令牌，持有关于暂存文件操作的信息。
// //
// // 它可能包含临时文件的路径 (本地文件系统) 或上传 ID (S3)。
// // 必须实现 `Send` + `Sync` 以支持多线程。
pub trait StagingToken: Send + Sync + Debug {
    /// Downcasts the token to a concrete implementation (e.g., `LocalStagingToken`).
    // // 将令牌向下转型为具体的实现 (例如 `LocalStagingToken`)。
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// The storage backend trait.
///
/// Defines low-level I/O operations, decoupling business logic from physical storage.
/// Implementations handle reading, writing, and deleting encrypted file content.
//
// // 存储后端特征。
// //
// // 定义了底层的 I/O 操作，将业务逻辑与物理存储解耦。
// // 实现负责处理加密文件内容的读取、写入和删除。
pub trait StorageBackend: Send + Sync + Debug {
    // --- Read Operations / 读操作 ---

    /// Checks if an object (file) exists in the storage.
    ///
    /// # Arguments
    /// * `hash` - The VaultHash of the encrypted content (acts as the key).
    //
    // // 检查存储中是否存在对象 (文件)。
    // //
    // // # 参数
    // // * `hash` - 加密内容的 VaultHash (充当键)。
    fn exists(&self, hash: &VaultHash) -> io::Result<bool>;

    /// Gets a reader for the stored data.
    ///
    /// Used during extraction or restoration.
    //
    // // 获取存储数据的读取器。
    // //
    // // 用于提取或恢复。
    fn reader(&self, hash: &VaultHash) -> io::Result<Box<dyn Read + Send>>;

    // --- Write Operations / 写操作 (Prepare -> Write -> Commit/Rollback) ---

    /// Stage 1: Prepare for writing.
    ///
    /// Returns a `Writer` for writing data and a `StagingToken` representing this operation.
    /// Data written here is not yet permanent (e.g., written to a temp file).
    //
    // // 阶段 1: 准备写入。
    // //
    // // 返回一个用于写入数据的 `Writer` 和一个代表此操作的 `StagingToken`。
    // // 此处写入的数据尚未持久化 (例如写入了临时文件)。
    fn prepare_write(&self) -> io::Result<(Box<dyn Write + Send>, Box<dyn StagingToken>)>;

    /// Stage 2: Commit to write.
    ///
    /// Called when data is fully written, hashed, and the database transaction is successful.
    /// This step usually involves moving/renaming the staged file to permanent storage.
    //
    // // 阶段 2: 提交写入。
    // //
    // // 当数据全部写入、哈希计算完成且数据库事务成功后调用。
    // // 此步骤通常涉及将暂存文件移动/重命名为永久存储。
    fn commit_write(&self, token: Box<dyn StagingToken>, final_hash: &VaultHash) -> io::Result<()>;

    /// Exception Handling: Rollback to write.
    ///
    /// Called if encryption fails, hash collision occurs, or database write fails.
    /// Should clean up any temporary files associated with the token.
    //
    // // 异常处理：回滚写入。
    // //
    // // 如果加密失败、发生哈希冲突或数据库写入失败，调用此方法。
    // // 应清理与该令牌关联的任何临时文件。
    fn rollback_write(&self, token: Box<dyn StagingToken>) -> io::Result<()>;

    // --- Delete Operations / 删除操作 ---

    /// Deletes the data associated with the specified hash.
    //
    // // 删除与指定哈希关联的数据。
    fn delete(&self, hash: &VaultHash) -> io::Result<()>;
}