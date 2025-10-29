use std::io::{Read, Seek, SeekFrom, Write};
use sha2::{Digest, Sha256};
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::rand;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::hash::MessageDigest;
use crate::common::hash::VaultHash;

// --- 常量定义 (保持不变) ---
const SALT_LEN: usize = 16;
const IV_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const PBKDF2_ROUNDS: usize = 10000;
const BUFFER_LEN: usize = 8192;

/// 定义我们的自定义错误类型 (保持不变)
#[derive(Debug, thiserror::Error)]
pub enum StreamCipherError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("OpenSSL error stack: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),
}

/// 流式处理文件加密并计算 *两个* SHA256 哈希值。
///
/// 一次性遍历源文件，同时完成三项任务：
/// 1.  (原始哈希) 对 *原始* (未加密) 内容计算 SHA256 哈希值。
/// 2.  (加密哈希) 对 *加密后* 的完整文件流（包括 salt, iv, 密文, tag）计算 SHA256 哈希值。
/// 3.  使用 AES-256-GCM 对文件内容进行加密。
///
/// # Arguments
/// * `mut source` - 一个可读的源。
/// * `mut destination` - 一个可写的目的地。
/// * `password` - 用于加密的用户密码。
///
/// # Returns
/// 成功时返回一个元组 `(VaultHash, VaultHash)`:
/// * `VaultHash`: (encrypted_sha256) 加密文件流的哈希值。
/// * `VaultHash`: (original_sha256) 原始文件内容的哈希值。
///
/// 失败时返回 `StreamCipherError`。
pub fn stream_encrypt_and_hash(
    mut source: impl Read,
    mut destination: impl Write,
    password: &str,
) -> Result<(VaultHash, VaultHash), StreamCipherError> { // [修改] 返回值
    // --- 1. 初始化 ---
    // [修改] 我们需要两个哈希器
    let mut encrypted_hasher = Sha256::new(); // 用于加密后的流
    let mut original_hasher = Sha256::new();  // 用于原始数据

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
    encrypted_hasher.update(&salt); 

    // 写入 iv
    destination.write_all(&iv)?;
    encrypted_hasher.update(&iv); 

    // --- 5. 流式处理循环 ---
    loop {
        let bytes_read = source.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let original_chunk = &buffer[..bytes_read];

        // 更新原始哈希
        original_hasher.update(original_chunk);

        // 加密数据块
        let mut encrypted_chunk_buf = vec![0; bytes_read + cipher.block_size()];
        let count = encrypter.update(original_chunk, &mut encrypted_chunk_buf)?;
        let encrypted_chunk = &encrypted_chunk_buf[..count];

        // 写入加密后的数据
        destination.write_all(encrypted_chunk)?;
        encrypted_hasher.update(encrypted_chunk); 
    }

    // --- 6. 完成加密 ---
    // a. 处理加密器中剩余的数据
    let mut final_chunk_buf = vec![0; cipher.block_size()];
    let count = encrypter.finalize(&mut final_chunk_buf)?;
    let final_chunk = &final_chunk_buf[..count];
    destination.write_all(final_chunk)?;
    encrypted_hasher.update(final_chunk); 

    // b. 获取并写入 GCM 的认证标签
    let mut tag = [0u8; TAG_LEN];
    encrypter.get_tag(&mut tag)?;
    destination.write_all(&tag)?;
    encrypted_hasher.update(&tag); 

    // --- 7. 完成 SHA256 计算 ---
    let encrypted_sha256_bytes: [u8; 32] = encrypted_hasher.finalize().into();
    let original_sha256_bytes: [u8; 32] = original_hasher.finalize().into();

    let encrypted_hash = VaultHash::new(<[u8; 32]>::from(encrypted_sha256_bytes));
    let original_hash = VaultHash::new(original_sha256_bytes);

    // --- 9. 返回结果 ---
    Ok((encrypted_hash, original_hash))
}


/// 解密 (V2 中此函数保持不变)
pub fn stream_decrypt(
    mut source: impl Read + Seek,
    mut destination: impl Write,
    password: &str,
) -> Result<VaultHash, StreamCipherError> {
    // ... (此函数的实现与 V1 相同，无需更改) ...
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
    let mut plaintext_buffer: Vec<u8> = Vec::new();
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

        plaintext_buffer.write_all(&decrypted_chunk[..count])?;
    }

    // --- 6. 完成解密与验证 ---
    let mut final_chunk = vec![0; cipher.block_size()];
    // [修改] finalize 会进行 GCM 认证检查，如果失败会返回 Err
    let count = decrypter.finalize(&mut final_chunk)?;
    plaintext_buffer.write_all(&final_chunk[..count])?;

    // --- [新增] 7. 计算解密后内容的哈希 ---
    // 只有在 finalize 成功后（即 GCM 认证通过）才进行哈希计算
    let original_hasher = Sha256::digest(&plaintext_buffer);
    let original_hash = VaultHash::new(original_hasher.into());

    // --- 8. 认证成功后，才写入最终目的地 ---
    destination.write_all(&plaintext_buffer)?;

    // --- [修改] 9. 返回计算出的原始哈希 ---
    Ok(original_hash)
}

// --- 单元测试 ---
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    // 导入新的编码器
    use crate::utils::hash::encode_hash_to_base64;
    use sha2::{Digest, Sha256, Sha512};
    use tempfile::NamedTempFile;

    /// 一个完整的加密到解密的往返测试 (验证两个哈希)
    #[test]
    fn test_encryption_decryption_roundtrip_success() {
        // --- 1. 准备阶段 (Arrange) ---
        let original_data = b"Hello, Rust streaming world! This is a test message that is longer than one block.";
        let password = "a_very_secret_password";

        let source_stream = Cursor::new(original_data);
        let mut encrypted_data_vec: Vec<u8> = Vec::new();

        // --- 2. 执行阶段 (Act) ---

        // a. 执行加密，获取函数计算出的两个哈希
        // [修改]
        let (encrypted_hash_from_func, original_hash_from_func) = stream_encrypt_and_hash(
            source_stream,
            &mut encrypted_data_vec, // 传递可变借用
            password
        ).expect("Encryption failed");

        // b. 准备解密
        let mut encrypted_stream = Cursor::new(&encrypted_data_vec);
        let mut decrypted_data_vec: Vec<u8> = Vec::new();

        // c. 执行解密
        stream_decrypt(
            &mut encrypted_stream,
            &mut decrypted_data_vec,
            password
        ).expect("Decryption failed");

        // --- 3. 断言阶段 (Assert) ---

        // a. 手动计算 *加密后* 字节流的哈希，作为期望值
        let expected_encrypted_hash_bytes: [u8; 32] = Sha256::digest(&encrypted_data_vec).into();
        let expected_encrypted_hash = VaultHash::new(expected_encrypted_hash_bytes);

        // b. 手动计算 *原始* 字节流的哈希，作为期望值
        let expected_original_hash_bytes: [u8; 32] = Sha256::digest(original_data).into();
        let expected_original_hash = VaultHash::new(expected_original_hash_bytes);

        // c. 验证加密哈希
        assert_eq!(
            encrypted_hash_from_func,
            expected_encrypted_hash,
            "Returned encrypted hash does not match actual encrypted hash"
        );

        // d. 验证原始哈希
        assert_eq!(
            original_hash_from_func,
            expected_original_hash,
            "Returned original hash does not match actual original hash"
        );

        // e. 验证解密后的内容是否与原始数据完全一致
        assert_eq!(
            decrypted_data_vec,
            original_data,
            "Decrypted data does not match original data"
        );
    }

    // [V2 修改] 验证错误密码
    #[test]
    fn test_decrypt_with_wrong_password_fails() {
        let original_data = b"some data to be encrypted";
        let correct_password = "correct_password";
        let wrong_password = "wrong_password";

        let source_stream = Cursor::new(original_data);
        let mut encrypted_data_vec = Vec::new();

        // 加密
        stream_encrypt_and_hash(source_stream, &mut encrypted_data_vec, correct_password)
            .unwrap(); // [修改] 忽略 V2 返回的哈希值

        // 准备解密
        let mut encrypted_stream = Cursor::new(encrypted_data_vec);
        let mut decrypted_data_vec = Vec::new();

        // 尝试用错误密码解密
        let result = stream_decrypt(&mut encrypted_stream, &mut decrypted_data_vec, wrong_password);

        // 断言解密操作返回了一个错误
        assert!(result.is_err(), "Decryption should fail with wrong password");
        // 并且断言接收缓冲区是空的
        assert!(decrypted_data_vec.is_empty(), "Decrypted buffer should be empty on failure");
    }

    // 使用真实文件的往返测试
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

        // a. 执行加密，获取函数计算出的哈希
        let mut source_handle = source_file.reopen().expect("Failed to reopen source file");
        let mut encrypted_handle = encrypted_file.reopen().expect("Failed to reopen encrypted file for writing");
        // [修改]
        let (encrypted_hash_from_func, original_hash_from_func) = stream_encrypt_and_hash(
            &mut source_handle,
            &mut encrypted_handle,
            "real-file-password"
        ).expect("Encryption with files failed");

        // b. 执行解密
        let mut encrypted_read_handle = encrypted_file.reopen().expect("Failed to reopen encrypted file for reading");
        let mut decrypted_handle = decrypted_file.reopen().expect("Failed to reopen decrypted file for writing");
        stream_decrypt(
            &mut encrypted_read_handle,
            &mut decrypted_handle,
            "real-file-password"
        ).expect("Decryption with files failed");

        // --- 3. 断言阶段 (Assert) ---

        // a. 手动计算加密文件的哈希
        let mut encrypted_file_content = Vec::new();
        let mut encrypted_read_handle_for_hash = encrypted_file.reopen().unwrap();
        encrypted_read_handle_for_hash.read_to_end(&mut encrypted_file_content).unwrap();
        let expected_encrypted_hash_bytes: [u8; 32] = Sha256::digest(&encrypted_file_content).into();
        let expected_encrypted_hash = VaultHash::new(expected_encrypted_hash_bytes);

        // b. 手动计算原始文件的哈希
        let expected_original_hash_bytes: [u8; 32] = Sha256::digest(original_data).into();
        let expected_original_hash = VaultHash::new(expected_original_hash_bytes);

        // c. 验证加密哈希
        assert_eq!(encrypted_hash_from_func, expected_encrypted_hash, "Returned encrypted hash does not match actual encrypted hash");

        // d. 验证原始哈希
        assert_eq!(original_hash_from_func, expected_original_hash, "Returned original hash does not match actual original hash");

        // e. 验证解密后的数据
        let mut decrypted_data = Vec::new();
        let mut decrypted_read_handle = decrypted_file.reopen().unwrap();
        decrypted_read_handle.read_to_end(&mut decrypted_data).unwrap();
        assert_eq!(decrypted_data, original_data, "Decrypted file content does not match original");
    }

    // 大文件测试 (此测试是黄金标准，验证 SHA512 一致性)
    #[test]
    fn test_large_media_file_cycle_consistency() {
        // ... (准备阶段不变) ...
        let password = "a-password-for-a-large-file";
        let mut source_file = NamedTempFile::new().unwrap();
        let mut buffer = [0u8; BUFFER_LEN];
        for _ in 0..(5 * 1024 * 1024 / BUFFER_LEN) {
            openssl::rand::rand_bytes(&mut buffer).unwrap();
            source_file.write_all(&buffer).unwrap();
        }
        source_file.flush().unwrap();
        let mut encrypted_file = NamedTempFile::new().unwrap();
        let mut decrypted_file = NamedTempFile::new().unwrap();

        // a. 计算原始文件的 SHA512 哈希值
        let mut original_hasher = Sha512::new();
        source_file.seek(SeekFrom::Start(0)).unwrap();
        let mut reader1 = source_file.reopen().unwrap();
        loop {
            let bytes_read = reader1.read(&mut buffer).unwrap();
            if bytes_read == 0 {
                break;
            }
            original_hasher.update(&buffer[..bytes_read]);
        }
        let original_hash = hex::encode(original_hasher.finalize()); // 使用 Hex，因为这是独立验证

        // --- 2. 执行阶段 (Act) ---

        // b. 加密
        source_file.seek(SeekFrom::Start(0)).unwrap();
        // [修改] 忽略 V2 返回的哈希值
        stream_encrypt_and_hash(
            source_file.reopen().unwrap(),
            encrypted_file.reopen().unwrap(),
            password
        ).expect("Encryption failed");

        // c. 解密
        encrypted_file.seek(SeekFrom::Start(0)).unwrap();
        stream_decrypt(
            encrypted_file.reopen().unwrap(),
            decrypted_file.reopen().unwrap(),
            password
        ).expect("Decryption failed");

        // --- 3. 断言阶段 (Assert) ---

        // d. 计算解密后文件的 SHA512 哈希值
        let mut decrypted_hasher = Sha512::new();
        decrypted_file.seek(SeekFrom::Start(0)).unwrap();
        let mut reader2 = decrypted_file.reopen().unwrap();
        loop {
            let bytes_read = reader2.read(&mut buffer).unwrap();
            if bytes_read == 0 {
                break;
            }
            decrypted_hasher.update(&buffer[..bytes_read]);
        }
        let decrypted_hash = hex::encode(decrypted_hasher.finalize());

        // e. 断言原始哈希值和解密后的哈希值必须完全相同
        assert_eq!(original_hash, decrypted_hash, "SHA512 hash of decrypted file does not match the original file's hash.");
    }
}