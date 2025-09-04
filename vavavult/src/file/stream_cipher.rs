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
/// * `String`: 原始文件的 SHA256 哈希值的十六进制字符串。
/// * `EncryptionCheck`: 用于未来校验密码正确性的结构体。
///
/// 失败时返回 `StreamCipherError`。
pub fn stream_encrypt_and_hash(
    mut source: impl Read,
    mut destination: impl Write,
    password: &str,
) -> Result<(String, EncryptionCheck), StreamCipherError> {
    // --- 1. 初始化 ---
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; BUFFER_LEN];

    // --- 2. 密钥派生 (KDF) ---
    // a. 生成一个随机的盐 (salt)，用于防止彩虹表攻击
    let mut salt = [0u8; SALT_LEN];
    rand::rand_bytes(&mut salt)?;

    // b. 使用 PBKDF2 从密码和盐派生出加密密钥
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac(
        password.as_bytes(),
        &salt,
        PBKDF2_ROUNDS,
        MessageDigest::sha256(),
        &mut key,
    )?;

    // --- 3. 初始化加密器 ---
    // a. 生成一个随机的初始化向量 (IV)
    let mut iv = [0u8; IV_LEN];
    rand::rand_bytes(&mut iv)?;

    // b. 创建一个 AES-256-GCM 加密器
    let cipher = Cipher::aes_256_gcm();
    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv))?;

    // --- 4. 写入头部信息 ---
    // 将 salt 和 iv 写入加密文件的开头，解密时需要它们
    destination.write_all(&salt)?;
    destination.write_all(&iv)?;

    // --- 5. 流式处理循环 ---
    loop {
        let bytes_read = source.read(&mut buffer)?;
        if bytes_read == 0 {
            break; // 文件读取完毕
        }
        let original_chunk = &buffer[..bytes_read];

        // a. 更新 SHA256 哈希值 (使用原始数据)
        hasher.update(original_chunk);

        // b. 加密数据块
        let mut encrypted_chunk = vec![0; bytes_read + cipher.block_size()];
        let count = encrypter.update(original_chunk, &mut encrypted_chunk)?;

        // c. 写入加密后的数据
        destination.write_all(&encrypted_chunk[..count])?;
    }

    // --- 6. 完成加密 ---
    // a. 处理加密器中剩余的数据
    let mut final_chunk = vec![0; cipher.block_size()];
    let count = encrypter.finalize(&mut final_chunk)?;
    destination.write_all(&final_chunk[..count])?;

    // b. 获取 GCM 的认证标签 (Tag)
    let mut tag = [0u8; TAG_LEN];
    encrypter.get_tag(&mut tag)?;

    // c. 将 Tag 写入加密文件的末尾
    destination.write_all(&tag)?;

    // --- 7. 完成 SHA256 计算 ---
    let sha256sum_bytes = hasher.finalize();
    let sha256sum = hex::encode(sha256sum_bytes);

    // --- 8. 生成加密校验 (此为示例，实际可做得更复杂) ---
    let check = EncryptionCheck {
        raw: "vavavult_check".to_string(), // 使用一段固定的明文
        encrypted: "".to_string(),        // 实际应用中需要加密 raw 字符串并存储
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

    /// 一个完整的加密到解密的往返测试
    #[test]
    fn test_encryption_decryption_roundtrip_success() {
        // --- 1. 准备阶段 (Arrange) ---
        let original_data = b"Hello, Rust streaming world! This is a test message that is longer than one block.";
        let password = "a_very_secret_password";

        // a. 源数据流 (在内存中模拟文件)
        let source_stream = Cursor::new(original_data);

        // b. 创建一个 Vec<u8> 来持有加密后的数据。测试函数拥有这个 Vec。
        let mut encrypted_data_vec: Vec<u8> = Vec::new();

        // --- 2. 执行阶段 (Act) ---

        // a. 执行加密和哈希
        // 我们将 `encrypted_data_vec` 的可变借用 `&mut` 传给函数。
        // `stream_encrypt_and_hash` 会借用它来写入数据，但所有权仍在测试函数中。
        let (calculated_hash, _check) = stream_encrypt_and_hash(
            source_stream,
            &mut encrypted_data_vec, // 传递可变借用，而不是所有权
            password
        ).expect("Encryption failed");

        // 当上一行代码执行完毕后，`encrypted_data_vec` 仍然有效，并且已经填满了加密数据。

        // b. 现在，基于加密后的数据创建一个新的、可读的流
        let mut encrypted_stream = Cursor::new(encrypted_data_vec);
        // 注意：这里我们将 `encrypted_data_vec` 的所有权转移给了新的 Cursor

        // c. 准备一个 Vec 来接收解密后的数据
        let mut decrypted_data_vec: Vec<u8> = Vec::new();

        // d. 执行解密
        stream_decrypt(
            &mut encrypted_stream, // Cursor 也需要可变借用，因为它内部的读取位置会变
            &mut decrypted_data_vec,
            password
        ).expect("Decryption failed");

        // --- 3. 断言阶段 (Assert) ---

        // a. 验证哈希值
        let mut expected_hasher = Sha256::new();
        expected_hasher.update(original_data);
        let expected_hash = hex::encode(expected_hasher.finalize());
        assert_eq!(calculated_hash, expected_hash, "SHA256 hash mismatch");

        // b. 验证解密后的内容
        assert_eq!(decrypted_data_vec, original_data, "Decrypted data does not match original data");

        println!("Roundtrip test successful!");
        println!("Original data length: {}", original_data.len());
        println!("Encrypted data length: {}", encrypted_stream.get_ref().len()); // .get_ref() 获取对内部数据的引用
        println!("Decrypted data length: {}", decrypted_data_vec.len());
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

    #[test]
    fn test_file_encryption_decryption_roundtrip() {
        // --- 1. 准备阶段 (Arrange) ---

        // a. 创建三个临时文件
        // `NamedTempFile` 创建一个在文件系统上可见的文件。
        // 当 `source_file`, `encrypted_file`, `decrypted_file` 离开作用域时，
        // 它们对应的真实文件会被自动删除。
        let mut source_file = NamedTempFile::new().expect("Failed to create source temp file");
        let encrypted_file = NamedTempFile::new().expect("Failed to create encrypted temp file");
        let decrypted_file = NamedTempFile::new().expect("Failed to create decrypted temp file");

        // b. 准备原始数据并写入源文件
        let original_data = b"This is some data that will be written to a real file on disk.";
        source_file.write_all(original_data).expect("Failed to write to source file");
        // 确保所有内容都已写入磁盘
        source_file.flush().expect("Failed to flush source file");


        // --- 2. 执行阶段 (Act) ---

        // a. 执行加密
        // 我们需要重新打开文件来获取一个独立的、可读的文件句柄。
        let mut source_handle = source_file.reopen().expect("Failed to reopen source file");
        let mut encrypted_handle = encrypted_file.reopen().expect("Failed to reopen encrypted file for writing");

        stream_encrypt_and_hash(
            &mut source_handle,
            &mut encrypted_handle,
            "real-file-password"
        ).expect("Encryption with files failed");

        // b. 执行解密
        // 准备解密所需的文件句柄
        let mut encrypted_read_handle = encrypted_file.reopen().expect("Failed to reopen encrypted file for reading");
        let mut decrypted_handle = decrypted_file.reopen().expect("Failed to reopen decrypted file for writing");

        stream_decrypt(
            &mut encrypted_read_handle,
            &mut decrypted_handle,
            "real-file-password"
        ).expect("Decryption with files failed");


        // --- 3. 断言阶段 (Assert) ---

        // a. 从最终解密的文件中读回所有内容
        let mut decrypted_data = Vec::new();
        let mut decrypted_read_handle = decrypted_file.reopen().expect("Failed to reopen decrypted file for reading result");
        decrypted_read_handle.read_to_end(&mut decrypted_data).expect("Failed to read decrypted data");

        // b. 验证解密后的数据是否与原始数据一致
        assert_eq!(decrypted_data, original_data, "Decrypted file content does not match original");
    }
}