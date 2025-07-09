use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptionCheck {
    pub raw: String,
    pub encrypted: String,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EncryptionType {
    /// 0: 不加密
    None,
    // 未来可以添加其他类型，例如：
    // Aes256Gcm, // 假设它对应 1
}