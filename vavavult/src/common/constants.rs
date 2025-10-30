/// The current version of the vault configuration file format.
pub const CURRENT_VAULT_VERSION: u32 = 2;

// --- [新增] V2 存储目录常量 ---
/// 存储加密数据文件的子目录。
pub const DATA_SUBDIR: &str = "data";

// --- 系统元数据的前缀 ---
/// The prefix for all system-generated, reserved metadata keys.
pub const META_PREFIX: &str = "_vavavult_";

// --- 文件库元数据常量 ---
/// Metadata key for the vault creation timestamp (RFC 3339 format).
pub const META_VAULT_CREATE_TIME: &str = "_vavavult_create_time";

/// Metadata key for the vault last update timestamp (RFC 3339 format).
pub const META_VAULT_UPDATE_TIME: &str = "_vavavult_update_time";

// --- 文件元数据常量 ---
/// Metadata key for the file's addition timestamp (RFC 3339 format).
pub const META_FILE_ADD_TIME: &str = "_vavavult_add_time";

/// Metadata key for the file's metadata last update timestamp (RFC 3339 format).
pub const META_FILE_UPDATE_TIME: &str = "_vavavult_update_time";

/// Metadata key for the file's size in bytes.
pub const META_FILE_SIZE: &str = "_vavavult_file_size";

/// Metadata key for the source file's last modified timestamp (RFC 3339 format).
pub const META_SOURCE_MODIFIED_TIME: &str = "_vavavult_source_modified_time";

