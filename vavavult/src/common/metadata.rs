use serde::{Deserialize, Serialize};

/// Represents a simple key-value pair for metadata.
//
// // 代表一个用于元数据的简单键值对。
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetadataEntry {
    pub key: String,
    pub value: String,
}