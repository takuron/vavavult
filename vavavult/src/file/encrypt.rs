use std::fs::File;
use std::io::Cursor;
use std::path::Path;
use serde::{Deserialize, Serialize};
use rusqlite::{
    types::{FromSql, FromSqlResult, ToSql, ToSqlOutput, ValueRef},
    Error as RusqliteError, Result as RusqliteResult,
};
use crate::file::stream_cipher;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use openssl::rand;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptionCheck {
    pub raw: String,
    pub encrypted: String,
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Stream cipher error: {0}")]
    StreamCipher(#[from] stream_cipher::StreamCipherError),
    #[error("String is not valid UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError), // 从 Hex 改为 Base64
    #[error("OpenSSL rand error: {0}")]
    Rand(#[from] openssl::error::ErrorStack),
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

// --- 文件加解密 (保持不变) ---

/// 加密一个文件。
pub fn encrypt_file(
    source_path: &Path,
    dest_path: &Path,
    password: &str,
) -> Result<String, EncryptError> {
    let mut source_file = File::open(source_path)?;
    let mut dest_file = File::create(dest_path)?;
    let (sha256sum, _check) = stream_cipher::stream_encrypt_and_hash(
        &mut source_file,
        &mut dest_file,
        password,
    )?;
    Ok(sha256sum)
}

/// 解密一个文件。
pub fn decrypt_file(
    source_path: &Path,
    dest_path: &Path,
    password: &str,
) -> Result<(), EncryptError> {
    let mut source_file = File::open(source_path)?;
    let mut dest_file = File::create(dest_path)?;
    stream_cipher::stream_decrypt(&mut source_file, &mut dest_file, password)?;
    Ok(())
}

// --- 更新：字符串加解密 API ---

/// 加密一个字符串，并返回 Base64 编码的密文。
pub fn encrypt_string(plaintext: &str, password: &str) -> Result<String, EncryptError> {
    let source = Cursor::new(plaintext.as_bytes());
    let mut destination_bytes = Vec::new();

    // 底层流处理函数返回加密后的原始字节
    stream_cipher::stream_encrypt_and_hash(source, &mut destination_bytes, password)?;

    // 将原始字节编码为 Base64 字符串
    let encrypted_base64 = BASE64_STANDARD.encode(&destination_bytes);
    Ok(encrypted_base64)
}

/// 解密一个 Base64 编码的字符串。
pub fn decrypt_string(ciphertext_base64: &str, password: &str) -> Result<String, EncryptError> {
    // 1. 将 Base64 字符串解码为原始加密字节
    let ciphertext_bytes = BASE64_STANDARD.decode(ciphertext_base64)?;

    // 2. 使用底层流处理函数解密字节
    let mut source = Cursor::new(ciphertext_bytes);
    let mut destination_bytes = Vec::new();
    stream_cipher::stream_decrypt(&mut source, &mut destination_bytes, password)?;

    // 3. 将解密后的字节转换为 UTF-8 字符串
    let plaintext = String::from_utf8(destination_bytes)?;
    Ok(plaintext)
}

// --- 更新：密码验证 API ---

/// 使用 EncryptionCheck 结构体验证密码是否正确。
pub fn verify_password(check: &EncryptionCheck, password: &str) -> bool {
    // 直接调用新的 decrypt_string 函数，它现在负责处理 Base64 解码
    match decrypt_string(&check.encrypted, password) {
        Ok(decrypted_raw) => {
            // 如果解密成功，比较解密出的明文是否与原始明文一致
            decrypted_raw == check.raw
        },
        Err(_) => {
            // 如果解密失败（密码错误、数据损坏或Base64格式错误），则密码无效
            false
        }
    }
}

/// 创建一个新的、基于随机字符串的 EncryptionCheck 结构体。
pub fn create_encryption_check(password: &str) -> Result<EncryptionCheck, EncryptError> {
    // 1. 生成 16 个随机字节作为原始数据
    let mut raw_bytes = [0u8; 16];
    rand::rand_bytes(&mut raw_bytes)?;

    // 2. 将随机字节编码为十六进制字符串，以确保它是有效的 UTF-8
    let raw_hex_string = hex::encode(raw_bytes);

    // 3. 使用新的 encrypt_string 函数加密这个十六进制字符串
    let encrypted_base64 = encrypt_string(&raw_hex_string, password)?;

    Ok(EncryptionCheck {
        raw: raw_hex_string,
        encrypted: encrypted_base64,
    })
}


