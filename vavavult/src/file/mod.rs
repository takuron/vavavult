use crate::common::metadata::MetadataEntry;
use crate::file::encrypt::{EncryptionCheck, EncryptionType};

pub mod encrypt;

///代表数据库中每个文件的记录
#[derive(Debug,Clone)]
pub struct FileEntry {
    /// 文件名，采用对象存储的方式存储。
    pub name: String,
    /// 文件的 SHA256 哈希值。
    /// 这个哈希值也是它在文件库中的存储名。
    pub sha256sum: String,
    /// 加密类型。
    pub encrypt_type: EncryptionType,
    /// 用于加密该文件内容的密码，仅在全库加密的情况下被启用。
    pub encrypt_password: String,
    /// 加密验证信息。
    pub encrypt_check: EncryptionCheck,
    /// 标签列表。
    pub tags: Vec<String>,
    /// 键值对元数据。
    pub metadata: Vec<MetadataEntry>,
}