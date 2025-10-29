use std::fmt;
use std::str::FromStr;
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use rusqlite::{ToSql, types::{ValueRef, FromSqlResult, FromSqlError, Value}};
use rusqlite::types::{FromSql, ToSqlOutput};

/// 一个代表 256 位哈希值 (如 SHA-256) 的类型安全包装器。
///
/// 它内部存储 32 字节的原始数据，并负责将其编码/解码为
/// 43 字节长、无填充、URL 安全的 Base64 字符串
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VaultHash([u8; 32]);

/// 解析 VaultHash 字符串时可能发生的错误。
#[derive(Debug, thiserror::Error)]
pub enum HashParseError {
    #[error("Invalid Base64 string length: expected 43, got {0}")]
    InvalidLength(usize),
    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Decoded data has invalid byte length: expected 32, got {0}")]
    InvalidByteLength(usize),
}

impl VaultHash {
    /// 原始哈希字节数组的长度 (256 位 = 32 字节)。
    pub const BYTE_LEN: usize = 32;
    /// 编码后 Base64 字符串的长度。
    pub const BASE64_LEN: usize = 43;

    /// 从原始 32 字节数组创建一个 `VaultHash`。
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 以字节切片的形式返回原始 32 字节哈希。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 将 32 字节的哈希编码为 43 字节的 Base64 字符串。
    ///
    /// 这种格式替换 `+` 为 `-`，并替换 `/` 为 `_`。
    pub fn to_nopad_base64(&self) -> String {
        // 1. 使用标准 "无填充" 引擎进行编码
        let mut s = STANDARD_NO_PAD.encode(self.0);

        // 2. 替换字符
        s = s.replace('/', "_").replace('+', "-");

        // 3. 验证 (在 debug 模式下)
        debug_assert_eq!(s.len(), Self::BASE64_LEN, "Base64 编码应为 43 字节");
        s
    }

    /// 从 43 字节的 Base64 字符串解码回 `VaultHash`。
    pub fn from_nopad_base64(s: &str) -> Result<Self, HashParseError> {
        // 1. 验证长度
        if s.len() != Self::BASE64_LEN {
            return Err(HashParseError::InvalidLength(s.len()));
        }

        // 2. 还原 Base64 字符
        let s_standard = s.replace('-', "+").replace('_', "/");

        // 3. 解码
        let bytes = STANDARD_NO_PAD.decode(s_standard.as_bytes())?;

        // 4. 转换回 [u8; 32]
        let byte_array = bytes.clone().try_into()
            .map_err(|_| HashParseError::InvalidByteLength(bytes.len()))?;

        Ok(Self(byte_array))
    }
}

// --- 核心 Trait 实现 ---

/// 允许 `VaultHash::from([0u8; 32])`
impl From<[u8; 32]> for VaultHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// 允许 `println!("{}", hash)`
impl fmt::Display for VaultHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_nopad_base64())
    }
}

/// 允许 `VaultHash::from_str("...")`
impl FromStr for VaultHash {
    type Err = HashParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_nopad_base64(s)
    }
}

// --- Serde (JSON) 序列化/反序列化 ---

/// 序列化为 43 字节的字符串
impl Serialize for VaultHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_nopad_base64())
    }
}

/// 从 43 字节的字符串反序列化
impl<'de> Deserialize<'de> for VaultHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VaultHashVisitor;

        impl<'de> serde::de::Visitor<'de> for VaultHashVisitor {
            type Value = VaultHash;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a 43-character Base64 hash string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                VaultHash::from_str(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(VaultHashVisitor)
    }
}

/// 存储到数据库时，编码为 TEXT (Base64 字符串)
impl ToSql for VaultHash {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Owned(Value::Text(self.to_nopad_base64())))
    }
}

/// 从数据库 TEXT (Base64 字符串) 读取
impl FromSql for VaultHash {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        value.as_str().and_then(|s| {
            VaultHash::from_str(s)
                .map_err(|e| FromSqlError::Other(Box::new(e)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_roundtrip_bytes_and_string() {
        // 一个 SHA256 结果 (32 字节)
        let sha256_bytes: [u8; 32] = [
            0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
            0x41, 0x41, 0x40, 0xDE, 0x5D, 0xA2, 0x22, 0x3B,
            0xA5, 0x73, 0xF2, 0x67, 0x9B, 0xF0, 0x8D, 0x4B,
            0x0C, 0x85, 0xF9, 0x6F, 0x5F, 0x6C, 0xBA, 0x31
        ];

        // 1. Bytes -> VaultHash
        let hash = VaultHash::new(sha256_bytes);
        assert_eq!(hash.as_bytes(), &sha256_bytes);

        // 2. VaultHash -> String
        // Manually verified:
        // base64(bytes) -> "ungWv48Bz+pBQUDeXaIiO6Vz8mec8I1LDIX5b19sujE="
        // no_pad -> "ungWv48Bz+pBQUDeXaIiO6Vz8mec8I1LDIX5b19sujE"
        // replace / -> -, + -> _
        let expected_string = "ungWv48Bz-pBQUDeXaIiO6Vz8meb8I1LDIX5b19sujE";
        let base64_string = hash.to_nopad_base64();
        assert_eq!(base64_string.len(), 43);
        assert_eq!(base64_string, expected_string);

        // 3. String -> VaultHash
        let parsed_hash = VaultHash::from_str(&base64_string).expect("Parsing should succeed");

        // 4. 验证往返
        assert_eq!(hash, parsed_hash);
        assert_eq!(parsed_hash.as_bytes(), &sha256_bytes);
    }

    #[test]
    fn test_serde_json_roundtrip() {
        let hash = VaultHash::new([42; 32]);
        let json_string = serde_json::to_string(&hash).expect("Serialization failed");

        // 应该序列化为一个简单的 JSON 字符串
        println!("Serialized JSON: {}", json_string);
        // "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio-"
        assert!(json_string.starts_with('"') && json_string.ends_with('"'));
        assert_eq!(json_string.len(), 43 + 2); // 43 字符 + 2 个引号

        let deserialized_hash: VaultHash = serde_json::from_str(&json_string).expect("Deserialization failed");

        assert_eq!(hash, deserialized_hash);
    }

    #[test]
    fn test_rusqlite_roundtrip() {
        let hash = VaultHash::new([123; 32]);

        // 1. ToSql
        let sql_value_output = hash.to_sql().expect("ToSql failed");

        // [修改] 先从 ToSqlOutput 中提取 Value
        let sql_value = match sql_value_output {
            ToSqlOutput::Owned(v) => v,
            // 如果您的实现使用了 Borrowed 或其他变体，也需要处理
            // ToSqlOutput::Borrowed(_) => panic!("Expected Owned variant"),
            _ => panic!("Expected Owned variant from ToSqlOutput"),
        };

        // [修改] 现在对提取出的 sql_value 进行匹配
        let text_value = match &sql_value {
            Value::Text(t) => t,
            _ => panic!("Should serialize to Text"),
        };

        println!("Stored in DB as: {}", text_value);
        assert_eq!(text_value, &hash.to_nopad_base64());

        // 2. FromSql
        let value_ref = ValueRef::Text(text_value.as_bytes());
        let recovered_hash = VaultHash::column_result(value_ref).expect("FromSql failed");

        assert_eq!(hash, recovered_hash);
    }
}