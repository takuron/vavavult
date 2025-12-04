use crate::common::metadata::MetadataEntry;

pub mod encrypt;
pub(crate) mod stream_cipher;
pub mod path;
pub use path::{PathError, VaultPath};
use crate::common::hash::VaultHash;

/// Represents a record of a file stored in the vault database.
///
/// This struct contains all metadata associated with a file, including its
/// location, cryptographic hashes, encryption parameters, and custom tags/metadata.
//
// // 代表存储在保险库数据库中的文件记录。
// //
// // 此结构体包含与文件关联的所有元数据，包括其位置、
// // 加密哈希、加密参数以及自定义标签/元数据。
#[derive(Debug,Clone)]
pub struct FileEntry {
    /// The unique path of the file within the vault (e.g., "/docs/report.txt").
    // // 文件在保险库中的唯一路径 (例如 "/docs/report.txt")。
    pub path: VaultPath,

    /// The SHA256 hash of the *encrypted* file content.
    /// This serves as the primary key and the storage filename in the data directory.
    // // *加密后* 文件内容的 SHA256 哈希值。
    // // 这是主键，也是它在数据目录中的存储文件名。
    pub sha256sum: VaultHash,

    /// The SHA256 hash of the *original* (unencrypted) file content.
    /// Used for integrity verification and deduplication checks.
    // // *原始* (未加密) 文件内容的 SHA256 哈希值。
    // // 用于完整性验证和去重检查。
    pub original_sha256sum: VaultHash,

    /// The randomly generated password used to encrypt this specific file.
    // // 用于加密该特定文件的随机生成的密码。
    pub encrypt_password: String,

    /// A list of tags associated with the file.
    // // 与文件关联的标签列表。
    pub tags: Vec<String>,

    /// A list of key-value metadata pairs associated with the file.
    // // 与文件关联的键值对元数据列表。
    pub metadata: Vec<MetadataEntry>,
}
