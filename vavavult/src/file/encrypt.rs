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

impl Serialize for EncryptionType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // 我们将枚举成员手动映射到对应的 u32 数字。
        let value = match self {
            EncryptionType::None => 0,
            // VaultEncryptionType::Aes256Gcm => 1,
        };
        // 使用 serializer 将这个 u32 值序列化。
        serializer.serialize_u32(value)
    }
}

impl<'de> Deserialize<'de> for EncryptionType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // 首先，将 JSON 中的值反序列化为一个 u32。
        let value = u32::deserialize(deserializer)?;

        // 然后，根据这个 u32 的值，匹配回我们的枚举成员。
        match value {
            0 => Ok(EncryptionType::None),
            // 1 => Ok(VaultEncryptionType::Aes256Gcm),
            // 对于任何未知的数字，我们返回一个错误。
            // 这使得我们的解析非常健壮，不会接受无效的加密类型。
            other => Err(serde::de::Error::custom(format!(
                "unknown encryptType: {}",
                other
            ))),
        }
    }
}