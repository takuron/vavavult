use serde::{Deserialize, Serialize};

/// Represents a simple key-value pair for metadata.
///
/// Used for both file-level metadata (e.g., custom attributes) and system-level
/// tracking (e.g., timestamps).
//
// // 代表一个用于元数据的简单键值对。
// //
// // 用于文件级元数据 (例如自定义属性) 和系统级跟踪 (例如时间戳)。
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetadataEntry {
    /// The metadata key (e.g., "author", "_vavavult_create_time").
    // // 元数据键 (例如 "author", "_vavavult_create_time")。
    pub key: String,
    /// The metadata value.
    // // 元数据值。
    pub value: String,
}