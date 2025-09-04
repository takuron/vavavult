use std::io::{Read, Seek, SeekFrom, Write};
use sha2::{Digest, Sha256};
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::rand;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::hash::MessageDigest;
use crate::file::encrypt::EncryptionCheck;

// --- 常量定义 ---
const SALT_LEN: usize = 16;
const IV_LEN: usize = 12; // AES-GCM 推荐 IV 长度
const KEY_LEN: usize = 32; // 32 字节 = 256 位
const TAG_LEN: usize = 16; // GCM 的认证标签长度
const PBKDF2_ROUNDS: usize = 10000; // 密钥派生迭代次数
const BUFFER_LEN: usize = 8192; // 8KB 缓冲区

/// 定义我们的自定义错误类型，方便统一处理
#[derive(Debug, thiserror::Error)]
pub enum StreamCipherError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("OpenSSL error stack: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),
}

/// 流式处理文件加密和计算 SHA256 哈希值。
///
/// 一次性遍历源文件，同时完成两项任务：
/// 1.  计算原始文件的 SHA256 哈希值。
/// 2.  使用 AES-256-GCM 对文件内容进行加密。
///
/// # Arguments
/// * `mut source` - 一个可读的源，比如一个文件 `std::fs::File`。
/// * `mut destination` - 一个可写的目的地，用于保存加密后的数据。
/// * `password` - 用于加密的用户密码。
///
/// # Returns
/// 成功时返回一个元组 `(String, EncryptionCheck)`:
/// * `String`: 加密文件的 SHA256 哈希值的十六进制字符串。
/// * `EncryptionCheck`: 用于未来校验密码正确性的结构体。
///
/// 失败时返回 `StreamCipherError`。
pub fn stream_encrypt_and_hash(
    mut source: impl Read,
    mut destination: impl Write,
    password: &str,
) -> Result<(String, EncryptionCheck), StreamCipherError> {
    // --- 1. 初始化 ---
    let mut hasher = Sha256::new(); // Hasher 现在要计算密文的哈希
    let mut buffer = [0u8; BUFFER_LEN];

    // --- 2. 密钥派生 (KDF) ---
    let mut salt = [0u8; SALT_LEN];
    rand::rand_bytes(&mut salt)?;
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac(
        password.as_bytes(),
        &salt,
        PBKDF2_ROUNDS,
        MessageDigest::sha256(),
        &mut key,
    )?;

    // --- 3. 初始化加密器 ---
    let mut iv = [0u8; IV_LEN];
    rand::rand_bytes(&mut iv)?;
    let cipher = Cipher::aes_256_gcm();
    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv))?;

    // --- 4. 写入头部信息，并同步更新哈希 ---
    // 写入 salt
    destination.write_all(&salt)?;
    hasher.update(&salt);

    // 写入 iv
    destination.write_all(&iv)?;
    hasher.update(&iv);

    // --- 5. 流式处理循环 ---
    loop {
        let bytes_read = source.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let original_chunk = &buffer[..bytes_read];

        // 加密数据块
        let mut encrypted_chunk_buf = vec![0; bytes_read + cipher.block_size()];
        let count = encrypter.update(original_chunk, &mut encrypted_chunk_buf)?;
        let encrypted_chunk = &encrypted_chunk_buf[..count];

        // 写入加密后的数据
        destination.write_all(encrypted_chunk)?;
        hasher.update(encrypted_chunk);
    }

    // --- 6. 完成加密 ---
    // a. 处理加密器中剩余的数据
    let mut final_chunk_buf = vec![0; cipher.block_size()];
    let count = encrypter.finalize(&mut final_chunk_buf)?;
    let final_chunk = &final_chunk_buf[..count];
    destination.write_all(final_chunk)?;
    hasher.update(final_chunk);

    // b. 获取并写入 GCM 的认证标签
    let mut tag = [0u8; TAG_LEN];
    encrypter.get_tag(&mut tag)?;
    destination.write_all(&tag)?;
    hasher.update(&tag);

    // --- 7. 完成 SHA256 计算 ---
    // 此刻，hasher 已经处理了与写入文件完全一致的字节流
    let sha256sum_bytes = hasher.finalize();
    let sha256sum = hex::encode(sha256sum_bytes);

    // --- 8. 生成加密校验 ---
    let check = EncryptionCheck {
        raw: "vavavult_check".to_string(),
        encrypted: "".to_string(),
    };

    // --- 9. 返回结果 ---
    Ok((sha256sum, check))
}

pub fn stream_decrypt(
    mut source: impl Read + Seek,
    mut destination: impl Write,
    password: &str,
) -> Result<(), StreamCipherError> {
    // --- 步骤 1-3 和之前一样：读取头部/尾部，派生密钥 ---
    let mut salt = [0u8; SALT_LEN];
    source.read_exact(&mut salt)?;
    let mut iv = [0u8; IV_LEN];
    source.read_exact(&mut iv)?;
    let mut tag = [0u8; TAG_LEN];
    source.seek(SeekFrom::End(-(TAG_LEN as i64)))?;
    source.read_exact(&mut tag)?;
    let file_size = source.seek(SeekFrom::End(0))?;
    let encrypted_content_len = file_size - (SALT_LEN as u64) - (IV_LEN as u64) - (TAG_LEN as u64);
    source.seek(SeekFrom::Start((SALT_LEN + IV_LEN) as u64))?;

    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac(
        password.as_bytes(),
        &salt,
        PBKDF2_ROUNDS,
        MessageDigest::sha256(),
        &mut key,
    )?;

    // --- 4. 初始化解密器 ---
    let cipher = Cipher::aes_256_gcm();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv))?;
    decrypter.set_tag(&tag)?;

    // --- 5. 安全的流式处理：先解密到临时缓冲区 ---
    let mut plaintext_buffer: Vec<u8> = Vec::new(); // <--- 关键改动：创建临时内部缓冲区
    let mut encrypted_stream = source.take(encrypted_content_len);
    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        let bytes_read = encrypted_stream.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let encrypted_chunk = &buffer[..bytes_read];

        let mut decrypted_chunk = vec![0; bytes_read + cipher.block_size()];
        let count = decrypter.update(encrypted_chunk, &mut decrypted_chunk)?;

        // 将解密块写入临时缓冲区，而不是最终目的地
        plaintext_buffer.write_all(&decrypted_chunk[..count])?;
    }

    // --- 6. 完成解密与验证 ---
    let mut final_chunk = vec![0; cipher.block_size()];
    // 调用 finalize() 进行最终认证
    let count = decrypter.finalize(&mut final_chunk)?; // <--- 如果失败，函数会在这里返回 Err

    // finalize 也可能产生最后一点数据，追加到临时缓冲区
    plaintext_buffer.write_all(&final_chunk[..count])?;

    // --- 7. 认证成功后，才写入最终目的地 ---
    // 只有当 finalize() 成功后，代码才会执行到这里
    destination.write_all(&plaintext_buffer)?;

    Ok(())
}

// --- 单元测试 ---
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use sha2::{Digest, Sha256};
    use tempfile::NamedTempFile;
    
    /// 一个完整的加密到解密的往返测试 (验证密文哈希)
    #[test]
    fn test_encryption_decryption_roundtrip_success() {
        // --- 1. 准备阶段 (Arrange) ---
        let original_data = b"Hello, Rust streaming world! This is a test message that is longer than one block.";
        let password = "a_very_secret_password";

        let source_stream = Cursor::new(original_data);
        let mut encrypted_data_vec: Vec<u8> = Vec::new();

        // --- 2. 执行阶段 (Act) ---

        // a. 执行加密，获取函数计算出的密文哈希
        let (hash_from_function, _check) = stream_encrypt_and_hash(
            source_stream,
            &mut encrypted_data_vec, // 传递可变借用
            password
        ).expect("Encryption failed");

        // b. 准备解密
        let mut encrypted_stream = Cursor::new(&encrypted_data_vec); // 注意：这里我们借用 vec
        let mut decrypted_data_vec: Vec<u8> = Vec::new();

        // c. 执行解密
        stream_decrypt(
            &mut encrypted_stream,
            &mut decrypted_data_vec,
            password
        ).expect("Decryption failed");

        // --- 3. 断言阶段 (Assert) ---

        // a. 手动计算整个加密后字节流的哈希值，作为期望值
        let expected_hash = hex::encode(Sha256::digest(&encrypted_data_vec));

        // b. 验证函数返回的哈希与我们手动计算的哈希是否一致
        assert_eq!(
            hash_from_function,
            expected_hash,
            "Returned ciphertext hash does not match actual ciphertext hash"
        );

        // c. 验证解密后的内容是否与原始数据完全一致
        assert_eq!(
            decrypted_data_vec,
            original_data,
            "Decrypted data does not match original data"
        );
    }

    #[test]
    fn test_decrypt_with_wrong_password_fails() {
        let original_data = b"some data to be encrypted";
        let correct_password = "correct_password";
        let wrong_password = "wrong_password";

        let source_stream = Cursor::new(original_data);
        let mut encrypted_data_vec = Vec::new();

        // 加密
        stream_encrypt_and_hash(source_stream, &mut encrypted_data_vec, correct_password)
            .unwrap();

        // 准备解密
        let mut encrypted_stream = Cursor::new(encrypted_data_vec);
        let mut decrypted_data_vec = Vec::new();

        // 尝试用错误密码解密
        let result = stream_decrypt(&mut encrypted_stream, &mut decrypted_data_vec, wrong_password);

        // 断言解密操作返回了一个错误
        assert!(result.is_err(), "Decryption should fail with wrong password");
        // 并且断言接收缓冲区是空的，没有写入任何不完整的数据
        assert!(decrypted_data_vec.is_empty(), "Decrypted buffer should be empty on failure");
    }

    /// 使用真实的临时文件进行加密解密往返测试 (验证密文哈希)
    #[test]
    fn test_file_encryption_decryption_roundtrip() {
        // --- 1. 准备阶段 (Arrange) ---
        let mut source_file = NamedTempFile::new().expect("Failed to create source temp file");
        let encrypted_file = NamedTempFile::new().expect("Failed to create encrypted temp file");
        let decrypted_file = NamedTempFile::new().expect("Failed to create decrypted temp file");
        let original_data = b"This data will be used to test ciphertext hashing.";
        source_file.write_all(original_data).expect("Failed to write to source file");
        source_file.flush().expect("Failed to flush source file");

        // --- 2. 执行阶段 (Act) ---

        // a. 执行加密，获取函数计算出的密文哈希
        let mut source_handle = source_file.reopen().expect("Failed to reopen source file");
        let mut encrypted_handle = encrypted_file.reopen().expect("Failed to reopen encrypted file for writing");
        let (hash_from_function, _) = stream_encrypt_and_hash(
            &mut source_handle,
            &mut encrypted_handle,
            "real-file-password"
        ).expect("Encryption with files failed");

        // b. 执行解密 (保持不变，用于验证解密依然可用)
        let mut encrypted_read_handle = encrypted_file.reopen().expect("Failed to reopen encrypted file for reading");
        let mut decrypted_handle = decrypted_file.reopen().expect("Failed to reopen decrypted file for writing");
        stream_decrypt(
            &mut encrypted_read_handle,
            &mut decrypted_handle,
            "real-file-password"
        ).expect("Decryption with files failed");

        // --- 3. 断言阶段 (Assert) ---

        // a. 手动计算整个加密文件的哈希值，作为期望值
        let mut encrypted_file_content = Vec::new();
        let mut encrypted_read_handle_for_hash = encrypted_file.reopen().unwrap();
        encrypted_read_handle_for_hash.read_to_end(&mut encrypted_file_content).unwrap();
        let expected_hash = hex::encode(Sha256::digest(&encrypted_file_content));

        // b. 验证函数返回的哈希与我们手动计算的哈希是否一致
        assert_eq!(hash_from_function, expected_hash, "Returned ciphertext hash does not match actual ciphertext hash");

        // c. 验证解密后的数据是否与原始数据一致
        let mut decrypted_data = Vec::new();
        let mut decrypted_read_handle = decrypted_file.reopen().unwrap();
        decrypted_read_handle.read_to_end(&mut decrypted_data).unwrap();
        assert_eq!(decrypted_data, original_data, "Decrypted file content does not match original");
    }
}