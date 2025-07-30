use std::path::{Path, PathBuf};
use rusqlite::Connection;
use crate::vault::config::VaultConfig;

pub mod config;
mod create;
mod add;
mod common;
mod query;
mod update;

pub use create::{create_vault, CreateError};
pub use add::{AddFileError};
pub use query::{QueryError, QueryResult};
pub use update::{UpdateError};

use crate::vault::add::add_file;
use crate::vault::query::{check_by_hash, check_by_name};
use crate::vault::update::{add_tag, add_tags, clear_tags, remove_tag, rename_file};

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
    pub fn find_by_name(&self, name: &str) -> Result<QueryResult, QueryError> {
        check_by_name(self,name)
    }
    pub fn find_by_hash(&self, sha256sum: &str) -> Result<QueryResult, QueryError> {
        check_by_hash(self,sha256sum)
    }
    pub fn add_file(&mut self, source_path: &Path, dest_name: Option<&str>) -> Result<String, AddFileError> {
        add_file(self, source_path, dest_name)
    }
    pub fn rename_file(&self, sha256sum: &str, new_name: &str) -> Result<(), UpdateError> {
        rename_file(self,sha256sum,new_name)
    }
    pub fn add_tag(&self, sha256sum: &str, tag: &str) -> Result<(), UpdateError> {
        add_tag(self, sha256sum, tag)
    }
    pub fn add_tags(&mut self, sha256sum: &str, tags: &[&str]) -> Result<(), UpdateError> {
        add_tags(self, sha256sum, tags)
    }
    pub fn remove_tag(&self, sha256sum: &str, tag: &str) -> Result<(), UpdateError> {
        remove_tag(self,sha256sum,tag)
    }
    pub fn clear_tags(&self, sha256sum: &str)-> Result<(), UpdateError> {
        clear_tags(self,sha256sum)
    }
}