use std::path::{Path, PathBuf};
use rusqlite::Connection;
use crate::vault::config::VaultConfig;

pub mod config;
mod create;
mod add;
mod common;

pub use create::{create_vault, CreateError};
pub use add::{AddFileError};
use crate::vault::add::add_file;

/// 代表一个加载到内存中的保险库。
/// 它持有保险库的配置和当前的文件列表状态。
pub struct Vault {
    /// 保险库的根目录路径。
    pub root_path: PathBuf,
    /// 保险库的配置 (`master.json` 的内容)。
    pub config: VaultConfig,
    /// （打开的）数据库连接。
    pub database_connection:Connection
}

impl Vault {
    pub fn add_file(&mut self, source_path: &Path, dest_name: Option<&str>) -> Result<String, AddFileError> {
        add_file(self, source_path, dest_name)
    }
}
