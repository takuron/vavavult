use serde::{Deserialize, Serialize};
use rusqlite::{
    types::{FromSql, FromSqlResult, ToSql, ToSqlOutput, ValueRef},
    Error as RusqliteError, Result as RusqliteResult,
};
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptionCheck {
    pub raw: String,
    pub encrypted: String,
}

/// 实现 ToSql，将 EncryptionCheck 序列化为 JSON 字符串以便存入 TEXT 列
impl ToSql for EncryptionCheck {
    fn to_sql(&self) -> RusqliteResult<ToSqlOutput<'_>> {
        // 1. 使用 serde_json 将结构体序列化为 String
        let json_string = serde_json::to_string(self).map_err(|e| {
            // 2. 如果序列化失败，转换为 rusqlite 的错误类型
            RusqliteError::ToSqlConversionFailure(Box::new(e))
        })?;

        // 3. 将 String 包装在 ToSqlOutput 中
        Ok(ToSqlOutput::from(json_string))
    }
}

/// 实现 FromSql，将 TEXT 列中的 JSON 字符串反序列化为 EncryptionCheck
impl FromSql for EncryptionCheck {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        // 1. 从数据库获取 TEXT 值
        let json_str = value.as_str()?;

        // 2. 使用 serde_json 将字符串反序列化为结构体
        serde_json::from_str(json_str).map_err(|e| {
            // 3. 如果反序列化失败，转换为 rusqlite 的错误类型
            rusqlite::types::FromSqlError::Other(Box::new(e))
        })
    }
}


#[derive(Debug, PartialEq, Eq, Clone,Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub enum EncryptionType {
    None,
    Aes256Gcm,
}

// --- Serde 驱动的枚举与整数转换 ---
// 现在我们使用 serde 的属性宏来定义转换，这样 JSON 和 数据库都可以复用
impl From<EncryptionType> for u32 {
    fn from(item: EncryptionType) -> Self {
        match item {
            EncryptionType::None => 0,
            EncryptionType::Aes256Gcm => 0,
        }
    }
}

impl TryFrom<u32> for EncryptionType {
    type Error = String; // serde::de::Error::custom 需要一个Displayable的Error

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(EncryptionType::None),
            1 => Ok(EncryptionType::Aes256Gcm),
            other => Err(format!("无效的加密类型值: {}", other)),
        }
    }
}


/// 实现 ToSql trait，使得 EncryptionType 可以被写入数据库
impl ToSql for EncryptionType {
    fn to_sql(&self) -> RusqliteResult<ToSqlOutput<'_>> {
        // 复用已有的转换逻辑，将枚举转换为 u32
        // 注意这里我们克隆了self (`*self` 对于 `Copy` 类型，`self.clone()` 对于 `Clone` 类型)
        // 来调用 into()，或者直接调用 u32::from(self.clone())
        let val: u32 = self.clone().into();
        // 将 u32 转换为 rusqlite 能理解的 ToSqlOutput
        Ok(ToSqlOutput::from(val as i64)) // 推荐转为 i64，因为 SQLite 内部整数是 i64
    }
}

/// 实现 FromSql trait，使得可以从数据库读取值并转换为 EncryptionType
impl FromSql for EncryptionType {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        // 1. 先将数据库的值转换为 i64 (或者 u32)
        let val_u32 = value.as_i64()? as u32;

        // 2. 复用已有的 try_from 逻辑
        EncryptionType::try_from(val_u32).map_err(|e| {
            // 3. 如果转换失败，将其转换为 rusqlite 能理解的错误类型
            rusqlite::types::FromSqlError::Other(Box::from(e))
        })
    }
}

