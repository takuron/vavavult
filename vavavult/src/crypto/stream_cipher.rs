use crate::common::hash::VaultHash;
use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::rand;
use openssl::symm::{Cipher, Crypter, Mode};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

// --- 常量定义 (保持不变) ---
const SALT_LEN: usize = 16;
const IV_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const PBKDF2_ROUNDS: usize = 10000;
const BUFFER_LEN: usize = 8192;

/// Defines errors that can occur during low-level stream cipher operations.
//
// // 定义在低级流密码操作期间可能发生的错误。
#[derive(Debug, thiserror::Error)]
pub enum StreamCipherError {
    /// An I/O error occurred during stream processing.
    //
    // // 流处理期间发生 I/O 错误。
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// An error occurred within the OpenSSL cryptographic library.
    //
    // // OpenSSL 加密库内部发生错误。
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
) -> Result<(VaultHash, VaultHash), StreamCipherError> {
    // [修改] 返回值
    // --- 1. 初始化 ---
    // [修改] 我们需要两个哈希器
    let mut encrypted_hasher = Sha256::new(); // 用于加密后的流
    let mut original_hasher = Sha256::new(); // 用于原始数据

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

/// 流式解密
///
/// 使用“滚动缓冲区”策略：
/// 我们在内存中维护一个缓冲区，始终保留读取到的最后 `TAG_LEN` 字节。
/// 只有当缓冲区数据超过 `TAG_LEN` 时，才将溢出的部分视为密文进行解密。
/// 当流结束时，缓冲区中剩余的字节即为 GCM 认证标签 (Tag)。
pub fn stream_decrypt(
    mut source: impl Read, // [修改] 不再需要 + Seek
    mut destination: impl Write,
    password: &str,
) -> Result<VaultHash, StreamCipherError> {
    // --- 1. 读取头部 (Salt + IV) ---
    // 这些位于文件开头，可以直接顺序读取
    let mut salt = [0u8; SALT_LEN];
    source.read_exact(&mut salt)?;

    let mut iv = [0u8; IV_LEN];
    source.read_exact(&mut iv)?;

    // --- 2. 派生密钥 ---
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac(
        password.as_bytes(),
        &salt,
        PBKDF2_ROUNDS,
        MessageDigest::sha256(),
        &mut key,
    )?;

    // --- 3. 初始化解密器 ---
    let cipher = Cipher::aes_256_gcm();
    // 注意：这里尚不设置 Tag，因为我们还不知道它是什么
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv))?;

    // --- 4. 滚动缓冲区处理循环 ---
    let mut original_hasher = Sha256::new();

    // 用于从 IO 读取数据的临时缓冲区
    let mut read_buffer = [0u8; BUFFER_LEN];

    // "滞后缓冲区"：用于暂存数据，直到确认它们不是 Tag
    // 容量设为 BUFFER_LEN + TAG_LEN 以避免频繁重分配
    let mut stash: Vec<u8> = Vec::with_capacity(BUFFER_LEN + TAG_LEN);

    // 解密输出缓冲区
    let mut decrypted_buffer = vec![0u8; BUFFER_LEN + cipher.block_size() + TAG_LEN];

    loop {
        let bytes_read = source.read(&mut read_buffer)?;

        if bytes_read == 0 {
            // EOF 到达
            break;
        }

        // 将新读取的数据追加到滞后缓冲区
        stash.extend_from_slice(&read_buffer[..bytes_read]);

        // 如果滞后缓冲区的数据量超过了 TAG_LEN
        // 说明超出的部分肯定是密文（因为 Tag 只有最后 16 字节）
        if stash.len() > TAG_LEN {
            let process_len = stash.len() - TAG_LEN;

            // 取出这就部分确认为密文的数据
            let chunk_to_decrypt = &stash[..process_len];

            // 解密
            let count = decrypter.update(chunk_to_decrypt, &mut decrypted_buffer)?;
            let plaintext_chunk = &decrypted_buffer[..count];

            // 写入 & 哈希
            destination.write_all(plaintext_chunk)?;
            original_hasher.update(plaintext_chunk);

            // 从 stash 中移除已处理的数据
            // drain(..n) 会移除前 n 个元素，并将剩余元素（即潜在的 Tag）移到前面
            stash.drain(..process_len);
        }
    }

    // --- 5. 验证与完成 ---

    // 此时 loop 结束，stash 中应该正好剩下 TAG_LEN 字节
    if stash.len() != TAG_LEN {
        // 如果剩余不足 16 字节，说明文件被截断或格式错误
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Stream ended prematurely: missing authentication tag",
        )
        .into());
    }

    // stash 中的这 16 字节就是 Tag
    let tag = &stash;

    // 告诉 OpenSSL 期望的 Tag 是什么
    decrypter.set_tag(tag)?;

    // Finalize 会执行 GCM 校验
    // 如果 Tag 不匹配，OpenSSL 会返回错误，这里会自动转换为 StreamCipherError
    let mut final_chunk = vec![0u8; cipher.block_size()];
    let count = decrypter.finalize(&mut final_chunk)?;

    // 处理可能剩余的最后一点明文（通常 GCM finalize 不会产生大量数据，但以防万一）
    if count > 0 {
        let final_plaintext = &final_chunk[..count];
        destination.write_all(final_plaintext)?;
        original_hasher.update(final_plaintext);
    }

    // --- 6. 返回哈希 ---
    let original_hash_bytes: [u8; 32] = original_hasher.finalize().into();
    Ok(VaultHash::new(original_hash_bytes))
}

/// Performs a true in-memory streaming re-encryption.
///
/// It reads from an encrypted source, decrypts chunk by chunk, and immediately
/// re-encrypts the plaintext chunk to a destination writer using a new password.
/// This avoids high memory usage and intermediate temporary files by combining
/// the logic of `stream_decrypt` and `stream_encrypt_and_hash` into a single,
/// pipelined operation that uses fixed-size rolling buffers.
pub fn stream_re_encrypt(
    mut source: impl Read,
    mut destination: impl Write,
    old_password: &str,
    new_password: &str,
) -> Result<(VaultHash, VaultHash), StreamCipherError> {
    // --- Part 1: Decryptor Initialization ---
    let mut old_salt = [0u8; SALT_LEN];
    source.read_exact(&mut old_salt)?;
    let mut old_iv = [0u8; IV_LEN];
    source.read_exact(&mut old_iv)?;

    let mut old_key = [0u8; KEY_LEN];
    pbkdf2_hmac(
        old_password.as_bytes(),
        &old_salt,
        PBKDF2_ROUNDS,
        MessageDigest::sha256(),
        &mut old_key,
    )?;

    let cipher = Cipher::aes_256_gcm();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, &old_key, Some(&old_iv))?;
    let mut original_hasher = Sha256::new();
    let mut read_buffer = [0u8; BUFFER_LEN];
    let mut stash: Vec<u8> = Vec::with_capacity(BUFFER_LEN + TAG_LEN);
    let mut decrypted_buffer = vec![0u8; BUFFER_LEN + cipher.block_size() + TAG_LEN];

    // --- Part 2: Encryptor Initialization ---
    let mut new_salt = [0u8; SALT_LEN];
    rand::rand_bytes(&mut new_salt)?;
    let mut new_iv = [0u8; IV_LEN];
    rand::rand_bytes(&mut new_iv)?;

    let mut new_key = [0u8; KEY_LEN];
    pbkdf2_hmac(
        new_password.as_bytes(),
        &new_salt,
        PBKDF2_ROUNDS,
        MessageDigest::sha256(),
        &mut new_key,
    )?;

    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, &new_key, Some(&new_iv))?;
    let mut new_encrypted_hasher = Sha256::new();

    destination.write_all(&new_salt)?;
    new_encrypted_hasher.update(&new_salt);
    destination.write_all(&new_iv)?;
    new_encrypted_hasher.update(&new_iv);

    // --- Part 3: The Combined Streaming Loop ---
    loop {
        let bytes_read = source.read(&mut read_buffer)?;
        if bytes_read == 0 {
            break;
        }

        stash.extend_from_slice(&read_buffer[..bytes_read]);

        if stash.len() > TAG_LEN {
            let process_len = stash.len() - TAG_LEN;
            let chunk_to_decrypt = &stash[..process_len];

            // a. Decrypt one chunk
            let count = decrypter.update(chunk_to_decrypt, &mut decrypted_buffer)?;
            let plaintext_chunk = &decrypted_buffer[..count];

            // b. Hash original plaintext
            original_hasher.update(plaintext_chunk);

            // c. Re-encrypt the plaintext chunk
            let mut encrypted_chunk_buf = vec![0; plaintext_chunk.len() + cipher.block_size()];
            let count = encrypter.update(plaintext_chunk, &mut encrypted_chunk_buf)?;
            let re_encrypted_chunk = &encrypted_chunk_buf[..count];

            // d. Write re-encrypted chunk and update its hash
            destination.write_all(re_encrypted_chunk)?;
            new_encrypted_hasher.update(re_encrypted_chunk);

            stash.drain(..process_len);
        }
    }

    // --- Part 4: Finalization ---
    // Decryptor Finalize
    if stash.len() != TAG_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Stream ended prematurely: missing authentication tag",
        )
        .into());
    }
    let old_tag = &stash;
    decrypter.set_tag(old_tag)?;
    let mut final_plaintext_buf = vec![0u8; cipher.block_size()];
    let final_plaintext_count = decrypter.finalize(&mut final_plaintext_buf)?;
    let final_plaintext_chunk = &final_plaintext_buf[..final_plaintext_count];

    // Encryptor Finalize
    original_hasher.update(final_plaintext_chunk);

    let mut final_encrypted_buf = vec![0; final_plaintext_chunk.len() + cipher.block_size()];
    let final_encrypted_count =
        encrypter.update(final_plaintext_chunk, &mut final_encrypted_buf)?;
    destination.write_all(&final_encrypted_buf[..final_encrypted_count])?;
    new_encrypted_hasher.update(&final_encrypted_buf[..final_encrypted_count]);

    let mut last_chunk_buf = vec![0; cipher.block_size()];
    let last_chunk_count = encrypter.finalize(&mut last_chunk_buf)?;
    destination.write_all(&last_chunk_buf[..last_chunk_count])?;
    new_encrypted_hasher.update(&last_chunk_buf[..last_chunk_count]);

    let mut new_tag = [0u8; TAG_LEN];
    encrypter.get_tag(&mut new_tag)?;
    destination.write_all(&new_tag)?;
    new_encrypted_hasher.update(&new_tag);

    // --- Part 5: Return Hashes ---
    let new_encrypted_hash = VaultHash::new(new_encrypted_hasher.finalize().into());
    let original_hash = VaultHash::new(original_hasher.finalize().into());

    Ok((new_encrypted_hash, original_hash))
}

// --- 单元测试 ---
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Seek, SeekFrom};
    // 导入新的编码器
    use sha2::{Digest, Sha256, Sha512};
    use tempfile::NamedTempFile;

    /// 一个完整的加密到解密的往返测试 (验证两个哈希)
    #[test]
    fn test_encryption_decryption_roundtrip_success() {
        // --- 1. 准备阶段 (Arrange) ---
        let original_data =
            b"Hello, Rust streaming world! This is a test message that is longer than one block.";
        let password = "a_very_secret_password";

        let source_stream = Cursor::new(original_data);
        let mut encrypted_data_vec: Vec<u8> = Vec::new();

        // --- 2. 执行阶段 (Act) ---

        // a. 执行加密，获取函数计算出的两个哈希
        // [修改]
        let (encrypted_hash_from_func, original_hash_from_func) = stream_encrypt_and_hash(
            source_stream,
            &mut encrypted_data_vec, // 传递可变借用
            password,
        )
        .expect("Encryption failed");

        // b. 准备解密
        let mut encrypted_stream = Cursor::new(&encrypted_data_vec);
        let mut decrypted_data_vec: Vec<u8> = Vec::new();

        // c. 执行解密
        stream_decrypt(&mut encrypted_stream, &mut decrypted_data_vec, password)
            .expect("Decryption failed");

        // --- 3. 断言阶段 (Assert) ---

        // a. 手动计算 *加密后* 字节流的哈希，作为期望值
        let expected_encrypted_hash_bytes: [u8; 32] = Sha256::digest(&encrypted_data_vec).into();
        let expected_encrypted_hash = VaultHash::new(expected_encrypted_hash_bytes);

        // b. 手动计算 *原始* 字节流的哈希，作为期望值
        let expected_original_hash_bytes: [u8; 32] = Sha256::digest(original_data).into();
        let expected_original_hash = VaultHash::new(expected_original_hash_bytes);

        // c. 验证加密哈希
        assert_eq!(
            encrypted_hash_from_func, expected_encrypted_hash,
            "Returned encrypted hash does not match actual encrypted hash"
        );

        // d. 验证原始哈希
        assert_eq!(
            original_hash_from_func, expected_original_hash,
            "Returned original hash does not match actual original hash"
        );

        // e. 验证解密后的内容是否与原始数据完全一致
        assert_eq!(
            decrypted_data_vec, original_data,
            "Decrypted data does not match original data"
        );
    }

    // 验证错误密码
    #[test]
    fn test_decrypt_with_wrong_password_fails() {
        let original_data = b"some data to be encrypted";
        let correct_password = "correct_password";
        let wrong_password = "wrong_password";

        let source_stream = Cursor::new(original_data);
        let mut encrypted_data_vec = Vec::new();

        // 加密
        stream_encrypt_and_hash(source_stream, &mut encrypted_data_vec, correct_password).unwrap(); // [修改] 忽略 V2 返回的哈希值

        // 准备解密
        let mut encrypted_stream = Cursor::new(encrypted_data_vec);
        let mut decrypted_data_vec = Vec::new();

        // 尝试用错误密码解密
        let result = stream_decrypt(
            &mut encrypted_stream,
            &mut decrypted_data_vec,
            wrong_password,
        );

        // 断言解密操作返回了一个错误
        assert!(
            result.is_err(),
            "Decryption should fail with wrong password"
        );
    }

    // 使用真实文件的往返测试
    #[test]
    fn test_file_encryption_decryption_roundtrip() {
        // --- 1. 准备阶段 (Arrange) ---
        let mut source_file = NamedTempFile::new().expect("Failed to create source temp file");
        let encrypted_file = NamedTempFile::new().expect("Failed to create encrypted temp file");
        let decrypted_file = NamedTempFile::new().expect("Failed to create decrypted temp file");
        let original_data = b"This data will be used to test ciphertext hashing.";
        source_file
            .write_all(original_data)
            .expect("Failed to write to source file");
        source_file.flush().expect("Failed to flush source file");

        // --- 2. 执行阶段 (Act) ---

        // a. 执行加密，获取函数计算出的哈希
        let mut source_handle = source_file.reopen().expect("Failed to reopen source file");
        let mut encrypted_handle = encrypted_file
            .reopen()
            .expect("Failed to reopen encrypted file for writing");
        // [修改]
        let (encrypted_hash_from_func, original_hash_from_func) = stream_encrypt_and_hash(
            &mut source_handle,
            &mut encrypted_handle,
            "real-file-password",
        )
        .expect("Encryption with files failed");

        // b. 执行解密
        let mut encrypted_read_handle = encrypted_file
            .reopen()
            .expect("Failed to reopen encrypted file for reading");
        let mut decrypted_handle = decrypted_file
            .reopen()
            .expect("Failed to reopen decrypted file for writing");
        stream_decrypt(
            &mut encrypted_read_handle,
            &mut decrypted_handle,
            "real-file-password",
        )
        .expect("Decryption with files failed");

        // --- 3. 断言阶段 (Assert) ---

        // a. 手动计算加密文件的哈希
        let mut encrypted_file_content = Vec::new();
        let mut encrypted_read_handle_for_hash = encrypted_file.reopen().unwrap();
        encrypted_read_handle_for_hash
            .read_to_end(&mut encrypted_file_content)
            .unwrap();
        let expected_encrypted_hash_bytes: [u8; 32] =
            Sha256::digest(&encrypted_file_content).into();
        let expected_encrypted_hash = VaultHash::new(expected_encrypted_hash_bytes);

        // b. 手动计算原始文件的哈希
        let expected_original_hash_bytes: [u8; 32] = Sha256::digest(original_data).into();
        let expected_original_hash = VaultHash::new(expected_original_hash_bytes);

        // c. 验证加密哈希
        assert_eq!(
            encrypted_hash_from_func, expected_encrypted_hash,
            "Returned encrypted hash does not match actual encrypted hash"
        );

        // d. 验证原始哈希
        assert_eq!(
            original_hash_from_func, expected_original_hash,
            "Returned original hash does not match actual original hash"
        );

        // e. 验证解密后的数据
        let mut decrypted_data = Vec::new();
        let mut decrypted_read_handle = decrypted_file.reopen().unwrap();
        decrypted_read_handle
            .read_to_end(&mut decrypted_data)
            .unwrap();
        assert_eq!(
            decrypted_data, original_data,
            "Decrypted file content does not match original"
        );
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
            source_file.write_all(&mut buffer).unwrap();
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
            password,
        )
        .expect("Encryption failed");

        // c. 解密
        encrypted_file.seek(SeekFrom::Start(0)).unwrap();
        stream_decrypt(
            encrypted_file.reopen().unwrap(),
            decrypted_file.reopen().unwrap(),
            password,
        )
        .expect("Decryption failed");

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
        assert_eq!(
            original_hash, decrypted_hash,
            "SHA512 hash of decrypted file does not match the original file's hash."
        );
}

    #[test]
    fn test_re_encryption_roundtrip() {
        // 1. Arrange
        let original_data =
            b"This is a re-encryption test. It needs to be longer than the tag length.";
        let old_password = "old_password_123";
        let new_password = "new_password_456";

        // 2. Act
        // a. Encrypt with old password
        let mut encrypted_data_vec = Vec::new();
        stream_encrypt_and_hash(
            Cursor::new(original_data),
            &mut encrypted_data_vec,
            old_password,
        )
        .expect("Initial encryption failed");

        // b. Re-encrypt with new password
        let mut re_encrypted_data_vec = Vec::new();
        let (new_encrypted_hash, original_hash_from_re_encrypt) = stream_re_encrypt(
            Cursor::new(&encrypted_data_vec),
            &mut re_encrypted_data_vec,
            old_password,
            new_password,
        )
        .expect("Re-encryption failed");

        // c. Decrypt the final result with new password
        let mut final_decrypted_data_vec = Vec::new();
        stream_decrypt(
            Cursor::new(&re_encrypted_data_vec),
            &mut final_decrypted_data_vec,
            new_password,
        )
        .expect("Final decryption failed");

        // 3. Assert
        // a. Final decrypted data should match original data
        assert_eq!(
            final_decrypted_data_vec, original_data,
            "Final decrypted data should match original data"
        );

        // b. The original hash returned by re_encrypt should be correct
        let expected_original_hash = VaultHash::new(Sha256::digest(original_data).into());
        assert_eq!(
            original_hash_from_re_encrypt, expected_original_hash,
            "Original hash from re-encrypt should be correct"
        );

        // c. The new encrypted hash returned by re_encrypt should be correct
        let expected_new_encrypted_hash =
            VaultHash::new(Sha256::digest(&re_encrypted_data_vec).into());
        assert_eq!(
            new_encrypted_hash, expected_new_encrypted_hash,
            "New encrypted hash from re-encrypt should be correct"
        );
    }
}
