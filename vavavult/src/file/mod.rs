use crate::common::metadata::MetadataEntry;

pub mod encrypt;
mod stream_cipher;
pub mod path;
pub use path::{PathError, VaultPath};
use crate::common::hash::VaultHash;

///代表数据库中每个文件的记录
#[derive(Debug,Clone)]
pub struct FileEntry {
    /// 文件在保险库中的唯一路径 (例如 "/docs/report.txt")
    pub path: VaultPath,

    /// 加密后* 的文件内容的 SHA256 哈希值。
    /// 这是文件的主键，也是它在保险库数据目录中的存储名。
    pub sha256sum: VaultHash,

    /// 原始* (未加密) 文件内容的 SHA256 哈希值。
    pub original_sha256sum: VaultHash,

    /// 用于加密该文件的（随机生成的）密码。
    pub encrypt_password: String,

    /// 与文件关联的标签列表。
    pub tags: Vec<String>,

    /// 与文件关联的元数据键值对。
    pub metadata: Vec<MetadataEntry>,
}
