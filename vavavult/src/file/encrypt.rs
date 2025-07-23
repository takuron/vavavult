use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptionCheck {
    pub raw: String,
    pub encrypted: String,
}

#[derive(Debug, PartialEq, Eq, Clone,Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub enum EncryptionType {
    /// 0: 不加密
    None,
    // 未来可以添加其他类型，例如：
    // Aes256Gcm, // 假设它对应 1
}

// --- Serde 驱动的枚举与整数转换 ---
// 现在我们使用 serde 的属性宏来定义转换，这样 JSON 和 数据库都可以复用
impl From<EncryptionType> for u32 {
    fn from(item: EncryptionType) -> Self {
        match item {
            EncryptionType::None => 0,
        }
    }
}

impl TryFrom<u32> for EncryptionType {
    type Error = String; // serde::de::Error::custom 需要一个Displayable的Error

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(EncryptionType::None),
            other => Err(format!("无效的加密类型值: {}", other)),
        }
    }
}

