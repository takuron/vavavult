use std::path::{Path, PathBuf};
use rusqlite::Connection;
use crate::vault::config::VaultConfig;

pub mod config;
mod create;
mod add;
mod common;
mod query;

pub use create::{create_vault, CreateError};
pub use add::{AddFileError};
pub use query::{QueryError, QueryResult};

use crate::vault::add::add_file;
use crate::vault::query::{check_by_hash, check_by_name};

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
    pub fn find_by_name(&mut self, name: &str) -> Result<QueryResult, QueryError> {
        check_by_name(self,name)
    }
    pub fn find_by_hash(&mut self, sha256sum: &str) -> Result<QueryResult, QueryError> {
        check_by_hash(self,sha256sum)
    }
    pub fn add_file(&mut self, source_path: &Path, dest_name: Option<&str>) -> Result<String, AddFileError> {
        add_file(self, source_path, dest_name)
    }
}