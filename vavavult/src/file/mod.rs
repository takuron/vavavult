use crate::common::metadata::MetadataEntry;

pub mod path;
use crate::common::hash::VaultHash;
pub use path::{PathError, VaultPath};

/// Represents a record of a file stored in the vault database.
///
/// This struct contains all metadata associated with a file content entity,
/// including cryptographic hashes, encryption parameters, and custom metadata.
//
// // 代表存储在保险库数据库中的文件记录。
// //
// // 此结构体包含与文件内容实体关联的所有元数据，包括
// // 加密哈希、加密参数以及自定义元数据。
#[derive(Debug, Clone)]
pub struct FileEntry {
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

    /// A list of key-value metadata pairs associated with the file.
    // // 与文件关联的键值对元数据列表。
    pub metadata: Vec<MetadataEntry>,
}

/// Represents a file path mapping in the vault tree.
///
/// This struct keeps the display path, encrypted content hash, and tags that
/// belong to this specific path mapping.
//
// // 代表保险库目录树中的文件路径映射。
// //
// // 此结构体保留显示路径、加密内容哈希，以及属于此特定路径映射的标签。
#[derive(Debug, Clone)]
pub struct FilePathEntry {
    /// The absolute vault path of this file entry.
    // // 此文件条目的保险库绝对路径。
    pub path: VaultPath,

    /// The SHA256 hash of the encrypted file content.
    // // 加密后文件内容的 SHA256 哈希。
    pub sha256sum: VaultHash,

    /// A list of tags associated with this file path.
    // // 与此文件路径关联的标签列表。
    pub tags: Vec<String>,
}
