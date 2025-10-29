use std::fs::File;
use std::io::Cursor;
use std::path::Path;
use crate::file::stream_cipher;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use crate::common::hash::VaultHash;
use crate::utils::random::generate_random_string;

#[derive(Debug, thiserror::Error)]
pub enum EncryptError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Stream cipher error: {0}")]
    StreamCipher(#[from] stream_cipher::StreamCipherError),
    #[error("String is not valid UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("OpenSSL rand error: {0}")]
    Rand(#[from] openssl::error::ErrorStack),
}

/// V2: 创建一个新的、带随机明文的加密检查字符串 "raw:encrypted_base64"
///
/// # Arguments
/// * `password` - 用于加密的密码
///
/// # Returns
/// 成功时返回 "raw:encrypted_base64" 格式的字符串
pub fn create_v2_encrypt_check(password: &str) -> Result<String, EncryptError> {
    // [修改] 1. 生成一个 16 位的随机字母数字字符串作为 "raw"
    // (使用我们已有的 random 工具)
    let raw_check_string = generate_random_string(16);

    // [修改] 2. 加密这个随机字符串
    let encrypted_base64 = encrypt_string(&raw_check_string, password)?;

    // 3. 按格式返回
    Ok(format!("{}:{}", raw_check_string, encrypted_base64))
}

/// V2: 验证加密检查字符串 (此函数无需更改)
///
/// # Arguments
/// * `check_string` - "raw:encrypted_base64" 格式的字符串
/// * `password` - 用于解密的密码
///
/// # Returns
/// `true` 如果密码正确且解密后的字符串与 raw 匹配，否则 `false`
pub fn verify_v2_encrypt_check(check_string: &str, password: &str) -> bool {
    let parts: Vec<&str> = check_string.splitn(2, ':').collect();
    if parts.len() != 2 {
        return false; // 格式无效
    }
    let raw = parts[0];
    let encrypted_base64 = parts[1];

    match decrypt_string(encrypted_base64, password) {
        Ok(decrypted_raw) => decrypted_raw == raw, // 比较解密后的是否等于原始的
        Err(_) => false, // 解密失败
    }
}


// --- 文件加解密 (保持不变) ---

/// 加密一个文件。
/// [注意] V2 中，此函数需要更新以返回 (encrypted_sha256, original_sha256)
/// 我们将在稍后修改 'stream_cipher.rs' 时更新它。
pub fn encrypt_file(
    source_path: &Path,
    dest_path: &Path,
    password: &str,
) -> Result<(VaultHash, VaultHash), EncryptError> { // [修改] 返回值
    let mut source_file = File::open(source_path)?;
    let mut dest_file = File::create(dest_path)?;

    // [修改] stream_encrypt_and_hash 现在返回两个哈希值
    let (encrypted_sha256, original_sha256) = stream_cipher::stream_encrypt_and_hash(
        &mut source_file,
        &mut dest_file,
        password,
    )?;
    Ok((encrypted_sha256, original_sha256))
}

/// 解密一个文件，并返回解密后内容的 SHA256 哈希。
pub fn decrypt_file(
    source_path: &Path,
    dest_path: &Path,
    password: &str,
) -> Result<VaultHash, EncryptError> { // [修改] 返回值类型
    let mut source_file = File::open(source_path)?;
    let mut dest_file = File::create(dest_path)?;
    // 调用 stream_decrypt 并返回其结果 (VaultHash)
    let original_hash = stream_cipher::stream_decrypt(&mut source_file, &mut dest_file, password)?;
    Ok(original_hash)
}
// --- 字符串加解密 API (保持不变) ---

/// 加密一个字符串，并返回 Base64 编码的密文。
pub fn encrypt_string(plaintext: &str, password: &str) -> Result<String, EncryptError> {
    let source = Cursor::new(plaintext.as_bytes());
    let mut destination_bytes = Vec::new();

    // [修改] 底层函数现在返回两个哈希值，我们忽略它们
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v2_encrypt_check_logic() {
        let password = "my_strong_password_123";

        // 1. 创建一个新的 check 字符串
        let check_string = create_v2_encrypt_check(password)
            .expect("Failed to create V2 check string");

        println!("Generated V2 Check String: {}", check_string);

        // 2. 使用正确密码验证
        assert!(verify_v2_encrypt_check(&check_string, password), "Verification should succeed with correct password");

        // 3. 使用错误密码验证
        assert!(!verify_v2_encrypt_check(&check_string, "wrong_password"), "Verification should fail with incorrect password");

        // 4. 使用格式错误的字符串验证
        assert!(!verify_v2_encrypt_check("invalid_format", password), "Verification should fail with invalid format");
    }
}
