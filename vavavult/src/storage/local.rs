use std::any::Any;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use crate::common::constants::DATA_SUBDIR;
use crate::common::hash::VaultHash;
use super::{ StagingToken, StorageBackend};

/// 本地文件系统的暂存令牌
/// 它持有 NamedTempFile 的所有权。如果 Token 被 Drop (且未 commit)，
/// tempfile 库会自动删除磁盘上的临时文件，天然支持 Rollback。
#[derive(Debug)]
pub struct LocalStagingToken {
    pub temp_file: Option<NamedTempFile>,
}

impl StagingToken for LocalStagingToken {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// 基于本地文件系统的存储后端实现
#[derive(Debug)]
pub struct LocalStorage {
    /// 保险库根目录
    root_path: PathBuf,
}

impl LocalStorage {
    pub fn new(root_path: &Path) -> Self {
        Self {
            root_path: root_path.to_path_buf(),
        }
    }

    /// 获取数据存储目录的完整路径 (.../data)
    fn data_dir(&self) -> PathBuf {
        self.root_path.join(DATA_SUBDIR)
    }

    /// 获取特定哈希对应的最终文件路径
    fn file_path(&self, hash: &VaultHash) -> PathBuf {
        self.data_dir().join(hash.to_string())
    }
}

impl StorageBackend for LocalStorage {
    fn exists(&self, hash: &VaultHash) -> io::Result<bool> {
        Ok(self.file_path(hash).exists())
    }

    fn reader(&self, hash: &VaultHash) -> io::Result<Box<dyn Read + Send>> {
        let path = self.file_path(hash);
        let file = File::open(path)?;
        Ok(Box::new(BufReader::new(file)))
    }

    fn prepare_write(&self) -> io::Result<(Box<dyn Write + Send>, Box<dyn StagingToken>)> {
        let data_dir = self.data_dir();
        // 1. 确保存储目录存在
        fs::create_dir_all(&data_dir)?;

        // 2. 在 data 目录下创建临时文件
        // 关键点：必须在同一文件系统下创建临时文件，才能保证后续 rename 是原子操作
        let temp_file = NamedTempFile::new_in(&data_dir)?;

        // 3. 克隆文件句柄用于返回给写入者
        // NamedTempFile 底层是 File，File 实现了 try_clone
        let write_handle = temp_file.as_file().try_clone()?;

        // 4. 将 temp_file 所有权移交给 Token
        let token = LocalStagingToken {
            temp_file: Some(temp_file),
        };

        Ok((Box::new(write_handle), Box::new(token)))
    }

    fn commit_write(&self, mut token: Box<dyn StagingToken>, final_hash: &VaultHash) -> io::Result<()> {
        // 1. 向下转型，取回 LocalStagingToken
        let local_token = token.as_any_mut()
            .downcast_mut::<LocalStagingToken>()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid staging token type"))?;

        // 2. 取出 temp_file (所有权转移)
        if let Some(temp_file) = local_token.temp_file.take() {
            let target_path = self.file_path(final_hash);

            // 3. 原子重命名 (Persist)
            // 如果目标文件已存在（极其罕见的哈希冲突或幂等重试），这在 Linux 上会原子覆盖，Windows 上会报错。
            // 考虑到我们的业务逻辑会在上层检查 DB 是否存在，这里直接 persist 是安全的。
            temp_file.persist(target_path).map_err(|e| e.error)?;
        }
        Ok(())
    }

    fn rollback_write(&self, _token: Box<dyn StagingToken>) -> io::Result<()> {
        // 什么都不用做。
        // 当 token 离开作用域被 Drop 时，LocalStagingToken 内部的 NamedTempFile 也会被 Drop。
        // tempfile crate 的析构函数会自动删除物理磁盘上的临时文件。
        Ok(())
    }

    fn delete(&self, hash: &VaultHash) -> io::Result<()> {
        let path = self.file_path(hash);
        if path.exists() {
            fs::remove_file(path)?;
        }
        // 如果文件不存在，视作删除成功（幂等性）
        Ok(())
    }
}