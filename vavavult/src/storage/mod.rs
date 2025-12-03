pub mod local;

use std::any::Any;
use std::fmt::Debug;
use std::io::{self, Read, Write};
use crate::common::hash::VaultHash;

/// 作为一个不透明的令牌，持有暂存文件的信息（如临时路径、S3 UploadID 等）。
/// 必须实现 Send + Sync 以支持多线程。
pub trait StagingToken: Send + Sync + Debug {
    /// 用于向下转型以获取具体的 Token 结构体 (例如 LocalStagingToken)
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// 存储后端特征
/// 定义了底层的 IO 操作，解耦了业务逻辑与物理存储。
pub trait StorageBackend: Send + Sync + Debug {
    // --- 读操作 ---

    /// 检查对象是否存在
    fn exists(&self, hash: &VaultHash) -> io::Result<bool>;

    /// 获取一个读取器，用于读取存储的数据 (对应 extract/restore)
    fn reader(&self, hash: &VaultHash) -> io::Result<Box<dyn Read + Send>>;

    // --- 写操作 (分阶段: Prepare -> Write -> Commit/Rollback) ---

    /// 第一步：准备写入。
    /// 返回一个用于写入数据的 Writer，以及一个代表这次暂存操作的 Token。
    /// 此时数据并未真正进入 Vault 的永久存储区（例如写入了临时文件）。
    fn prepare_write(&self) -> io::Result<(Box<dyn Write + Send>, Box<dyn StagingToken>)>;

    /// 第二步：提交写入。
    /// 当数据全部写入 Writer，且哈希计算完成，且数据库事务成功后调用。
    /// 这一步通常涉及 rename 操作将暂存文件变为永久文件。
    fn commit_write(&self, token: Box<dyn StagingToken>, final_hash: &VaultHash) -> io::Result<()>;

    /// 异常处理：回滚写入。
    /// 如果加密失败、哈希冲突或数据库写入失败，调用此方法清理暂存文件。
    fn rollback_write(&self, token: Box<dyn StagingToken>) -> io::Result<()>;

    // --- 删除操作 ---

    /// 删除指定哈希的数据
    fn delete(&self, hash: &VaultHash) -> io::Result<()>;
}