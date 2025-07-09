use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetadataEntry {
    pub key: String,
    pub value: String,
}