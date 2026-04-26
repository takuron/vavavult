use crate::common::hash::VaultHash;
use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::rand;
use openssl::symm::{Cipher, Crypter, Mode};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Seek, SeekFrom, Write};

/// The plaintext size of one encrypted chunk.
///
/// Every full block stores 4 MiB of plaintext as `ciphertext + tag`.
//
// // 单个加密块的明文大小。
// //
// // 每个完整块会将 4 MiB 明文存储为 `密文 + 标签`。
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// The AES-256-GCM authentication tag length in bytes.
//
// // AES-256-GCM 认证标签的字节长度。
pub const TAG_LEN: usize = 16;

/// The chunked encrypted file header length in bytes.
///
/// The header contains `salt(16) + base_iv(12)`.
//
// // 分块加密文件头的字节长度。
// //
// // 文件头包含 `salt(16) + base_iv(12)`。
pub const HEADER_LEN: usize = SALT_LEN + IV_LEN;

const SALT_LEN: usize = 16;
const IV_LEN: usize = 12;
const KEY_LEN: usize = 32;
const PBKDF2_ROUNDS: usize = 10000;
const STREAM_BUFFER_LEN: usize = 8192;

/// Defines errors that can occur during chunked encryption or decryption.
//
// // 定义分块加密或解密过程中可能发生的错误。
#[derive(Debug, thiserror::Error)]
pub enum ChunkedCryptoError {
    /// An I/O error occurred during chunked processing.
    //
    // // 分块处理期间发生 I/O 错误。
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// An OpenSSL error occurred during cryptographic processing.
    //
    // // 加密处理期间发生 OpenSSL 错误。
    #[error("OpenSSL error stack: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),

    /// The encrypted file layout is invalid for the chunked format.
    //
    // // 加密文件布局不符合分块格式。
    #[error("Invalid chunked encrypted file format: {0}")]
    InvalidFormat(String),

    /// The chunk index exceeded the supported IV derivation range.
    //
    // // 块索引超出了支持的 IV 派生范围。
    #[error("Chunk index is too large for IV derivation: {0}")]
    ChunkIndexTooLarge(u64),
}

/// The result returned after finalizing a chunked encryption stream.
//
// // 分块加密流完成后返回的结果。
pub struct ChunkedEncryptionResult<W> {
    /// The SHA256 hash of the complete encrypted byte stream.
    // // 完整加密字节流的 SHA256 哈希。
    pub encrypted_hash: VaultHash,
    /// The SHA256 hash of the original plaintext byte stream.
    // // 原始明文字节流的 SHA256 哈希。
    pub original_hash: VaultHash,
    /// The number of plaintext bytes consumed by the encryptor.
    // // 加密器消费的明文字节数。
    pub plaintext_len: u64,
    /// The number of encrypted bytes written by the encryptor.
    // // 加密器写入的加密字节数。
    pub encrypted_len: u64,
    /// The wrapped writer returned to the caller.
    // // 返回给调用方的被包装写入器。
    pub inner: W,
}

/// A streaming AES-256-GCM chunked encryptor over a seekable writer.
///
/// The encryptor writes a fixed header, accepts plaintext through `Write`, and
/// emits independent `ciphertext + tag` chunks. Call `finish` to flush the final
/// partial block and obtain both plaintext and encrypted-stream hashes.
//
// // 基于可寻址写入器的流式 AES-256-GCM 分块加密器。
// //
// // 加密器会写入固定文件头，通过 `Write` 接收明文，并输出独立的 `密文 + 标签` 块。
// // 调用 `finish` 可刷新最后一个不完整块并取得明文与加密流哈希。
pub struct ChunkedEncryptor<W: Write + Seek> {
    writer: W,
    key: [u8; KEY_LEN],
    base_iv: [u8; IV_LEN],
    pending_plaintext: Vec<u8>,
    next_block_index: u64,
    plaintext_hasher: Sha256,
    encrypted_hasher: Sha256,
    plaintext_len: u64,
    encrypted_len: u64,
}

impl<W: Write + Seek> ChunkedEncryptor<W> {
    /// Creates a new chunked encryptor over the supplied writer.
    ///
    /// The writer is rewound to the beginning before the header is written.
    ///
    /// # Arguments
    /// * `writer` - A seekable destination for encrypted bytes.
    /// * `password` - The per-file password used to derive the encryption key.
    ///
    /// # Errors
    /// Returns `ChunkedCryptoError` if random generation, key derivation, seek,
    /// or header writing fails.
    //
    // // 在指定写入器上创建新的分块加密器。
    // //
    // // 写入器会在写入文件头之前回到开头。
    // //
    // // # 参数
    // // * `writer` - 用于写入加密字节的可寻址目标。
    // // * `password` - 用于派生加密密钥的每文件密码。
    // //
    // // # 错误
    // // 如果随机数生成、密钥派生、seek 或文件头写入失败，则返回 `ChunkedCryptoError`。
    pub fn new(mut writer: W, password: &str) -> Result<Self, ChunkedCryptoError> {
        let mut salt = [0u8; SALT_LEN];
        rand::rand_bytes(&mut salt)?;

        let mut base_iv = [0u8; IV_LEN];
        rand::rand_bytes(&mut base_iv)?;

        let key = derive_key(password, &salt)?;
        let mut encrypted_hasher = Sha256::new();

        // 1. 确保新格式从物理文件开头写入固定头部。
        writer.seek(SeekFrom::Start(0))?;
        writer.write_all(&salt)?;
        encrypted_hasher.update(salt);
        writer.write_all(&base_iv)?;
        encrypted_hasher.update(base_iv);

        Ok(Self {
            writer,
            key,
            base_iv,
            pending_plaintext: Vec::with_capacity(CHUNK_SIZE),
            next_block_index: 0,
            plaintext_hasher: Sha256::new(),
            encrypted_hasher,
            plaintext_len: 0,
            encrypted_len: HEADER_LEN as u64,
        })
    }

    /// Finalizes the encrypted stream and returns the resulting hashes.
    ///
    /// This method must be called exactly once after all plaintext has been
    /// written. It writes the final partial block, flushes the inner writer, and
    /// returns ownership of the writer to the caller.
    ///
    /// # Errors
    /// Returns `ChunkedCryptoError` if encryption or writing the final block fails.
    //
    // // 完成加密流并返回结果哈希。
    // //
    // // 所有明文写入后必须恰好调用一次。它会写入最后的不完整块，刷新底层写入器，
    // // 并将写入器所有权返还给调用方。
    // //
    // // # 错误
    // // 如果加密或写入最后一个块失败，则返回 `ChunkedCryptoError`。
    pub fn finish(mut self) -> Result<ChunkedEncryptionResult<W>, ChunkedCryptoError> {
        // 1. 空文件也写入一个 0 字节明文块，用 GCM Tag 认证文件头派生出的密钥。
        if self.plaintext_len == 0 || !self.pending_plaintext.is_empty() {
            let final_block = std::mem::take(&mut self.pending_plaintext);
            self.encrypt_and_write_block(&final_block)?;
        }

        self.writer.flush()?;

        let encrypted_hash = VaultHash::new(self.encrypted_hasher.finalize().into());
        let original_hash = VaultHash::new(self.plaintext_hasher.finalize().into());

        Ok(ChunkedEncryptionResult {
            encrypted_hash,
            original_hash,
            plaintext_len: self.plaintext_len,
            encrypted_len: self.encrypted_len,
            inner: self.writer,
        })
    }

    fn encrypt_and_write_block(&mut self, plaintext: &[u8]) -> Result<(), ChunkedCryptoError> {
        let iv = block_iv(&self.base_iv, self.next_block_index)?;
        let (ciphertext, tag) = encrypt_block(&self.key, &iv, plaintext)?;

        // 2. 每个物理块严格按 `密文 + Tag` 排列，便于 O(1) 定位。
        self.writer.write_all(&ciphertext)?;
        self.encrypted_hasher.update(&ciphertext);
        self.writer.write_all(&tag)?;
        self.encrypted_hasher.update(tag);

        self.encrypted_len += (ciphertext.len() + TAG_LEN) as u64;
        self.next_block_index += 1;
        Ok(())
    }

    fn write_plaintext(&mut self, mut buf: &[u8]) -> Result<usize, ChunkedCryptoError> {
        if buf.is_empty() {
            return Ok(0);
        }

        let written_len = buf.len();
        self.plaintext_hasher.update(buf);
        self.plaintext_len = self
            .plaintext_len
            .checked_add(written_len as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "plaintext too large"))?;

        // 3. 先填满上一次遗留的不完整块。
        if !self.pending_plaintext.is_empty() {
            let remaining_capacity = CHUNK_SIZE - self.pending_plaintext.len();
            let take_len = remaining_capacity.min(buf.len());
            self.pending_plaintext.extend_from_slice(&buf[..take_len]);
            buf = &buf[take_len..];

            if self.pending_plaintext.len() == CHUNK_SIZE {
                let full_block = std::mem::take(&mut self.pending_plaintext);
                self.pending_plaintext = Vec::with_capacity(CHUNK_SIZE);
                self.encrypt_and_write_block(&full_block)?;
            }
        }

        // 4. 对输入中的完整 4 MiB 块直接加密，避免额外复制。
        while buf.len() >= CHUNK_SIZE {
            let (full_block, rest) = buf.split_at(CHUNK_SIZE);
            self.encrypt_and_write_block(full_block)?;
            buf = rest;
        }

        // 5. 剩余尾部留待下一次写入或 finish。
        if !buf.is_empty() {
            self.pending_plaintext.extend_from_slice(buf);
        }

        Ok(written_len)
    }
}

impl<W: Write + Seek> Write for ChunkedEncryptor<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_plaintext(buf)
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// A random-access AES-256-GCM chunked reader over a seekable encrypted source.
///
/// The reader maps logical plaintext seeks to physical chunk offsets, decrypts
/// and authenticates one chunk at a time, and keeps the current plaintext chunk
/// in memory for byte-accurate reads.
//
// // 基于可寻址加密源的随机访问 AES-256-GCM 分块读取器。
// //
// // 读取器会将逻辑明文 seek 映射到物理块偏移，一次解密并认证一个块，
// // 并在内存中保留当前明文块以支持字节级精确读取。
pub(crate) struct ChunkedReader<R: Read + Seek> {
    reader: R,
    key: [u8; KEY_LEN],
    base_iv: [u8; IV_LEN],
    plaintext_len: u64,
    block_count: u64,
    position: u64,
    buffer_start: u64,
    buffer: Vec<u8>,
}

impl<R: Read + Seek> ChunkedReader<R> {
    /// Creates a new chunked reader over the supplied encrypted source.
    ///
    /// # Arguments
    /// * `reader` - A seekable encrypted byte source.
    /// * `password` - The per-file password used to derive the decryption key.
    ///
    /// # Errors
    /// Returns `ChunkedCryptoError` if the header is invalid, key derivation
    /// fails, or the encrypted layout is malformed.
    //
    // // 在指定加密源上创建新的分块读取器。
    // //
    // // # 参数
    // // * `reader` - 可寻址的加密字节源。
    // // * `password` - 用于派生解密密钥的每文件密码。
    // //
    // // # 错误
    // // 如果文件头无效、密钥派生失败或加密布局格式错误，则返回 `ChunkedCryptoError`。
    pub(crate) fn new(mut reader: R, password: &str) -> Result<Self, ChunkedCryptoError> {
        let encrypted_len = reader.seek(SeekFrom::End(0))?;
        let (plaintext_len, block_count) = parse_plaintext_layout(encrypted_len)?;

        reader.seek(SeekFrom::Start(0))?;
        let mut salt = [0u8; SALT_LEN];
        reader.read_exact(&mut salt)?;

        let mut base_iv = [0u8; IV_LEN];
        reader.read_exact(&mut base_iv)?;

        let key = derive_key(password, &salt)?;

        let mut chunked_reader = Self {
            reader,
            key,
            base_iv,
            plaintext_len,
            block_count,
            position: 0,
            buffer_start: 0,
            buffer: Vec::new(),
        };

        // 1. 空文件没有后续 read 触发块加载，因此在打开时验证唯一的空块 Tag。
        if plaintext_len == 0 {
            chunked_reader.load_block(0)?;
        }

        Ok(chunked_reader)
    }

    fn buffer_end(&self) -> u64 {
        self.buffer_start + self.buffer.len() as u64
    }

    fn buffer_contains(&self, position: u64) -> bool {
        position >= self.buffer_start && position < self.buffer_end()
    }

    fn load_block_for_position(&mut self, position: u64) -> Result<(), ChunkedCryptoError> {
        let block_index = position / CHUNK_SIZE as u64;
        self.load_block(block_index)
    }

    fn load_block(&mut self, block_index: u64) -> Result<(), ChunkedCryptoError> {
        if block_index >= self.block_count {
            return Err(ChunkedCryptoError::InvalidFormat(format!(
                "block index {block_index} exceeds block count {}",
                self.block_count
            )));
        }

        let plain_len = self.block_plaintext_len(block_index)?;
        let physical_offset = HEADER_LEN as u64
            + block_index
                .checked_mul((CHUNK_SIZE + TAG_LEN) as u64)
                .ok_or_else(|| {
                    ChunkedCryptoError::InvalidFormat("physical offset overflow".to_string())
                })?;

        self.reader.seek(SeekFrom::Start(physical_offset))?;
        let mut encrypted_block = vec![0u8; plain_len + TAG_LEN];
        self.reader.read_exact(&mut encrypted_block)?;

        let (ciphertext, tag) = encrypted_block.split_at(plain_len);
        let iv = block_iv(&self.base_iv, block_index)?;
        let plaintext = decrypt_block(&self.key, &iv, ciphertext, tag)?;

        // 2. 只在 Tag 验证成功后替换明文缓冲区，避免暴露未认证数据。
        self.buffer_start = block_index * CHUNK_SIZE as u64;
        self.buffer = plaintext;
        Ok(())
    }

    fn block_plaintext_len(&self, block_index: u64) -> Result<usize, ChunkedCryptoError> {
        if block_index + 1 < self.block_count {
            return Ok(CHUNK_SIZE);
        }

        let block_start = block_index.checked_mul(CHUNK_SIZE as u64).ok_or_else(|| {
            ChunkedCryptoError::InvalidFormat("block offset overflow".to_string())
        })?;
        let len = self.plaintext_len.checked_sub(block_start).ok_or_else(|| {
            ChunkedCryptoError::InvalidFormat("block start exceeds plaintext length".to_string())
        })?;

        usize::try_from(len).map_err(|_| {
            ChunkedCryptoError::InvalidFormat("final block length exceeds usize".to_string())
        })
    }
}

impl<R: Read + Seek> Read for ChunkedReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.position >= self.plaintext_len {
            return Ok(0);
        }

        let mut total_copied = 0;

        while total_copied < out.len() && self.position < self.plaintext_len {
            if !self.buffer_contains(self.position) {
                self.load_block_for_position(self.position)
                    .map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                    })?;
            }

            let buffer_offset = usize::try_from(self.position - self.buffer_start)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "position too large"))?;
            let available_in_buffer = self.buffer.len().saturating_sub(buffer_offset);
            if available_in_buffer == 0 {
                break;
            }

            let remaining_plaintext =
                usize::try_from(self.plaintext_len - self.position).unwrap_or(usize::MAX);
            let copy_len = available_in_buffer
                .min(out.len() - total_copied)
                .min(remaining_plaintext);

            out[total_copied..total_copied + copy_len]
                .copy_from_slice(&self.buffer[buffer_offset..buffer_offset + copy_len]);
            self.position += copy_len as u64;
            total_copied += copy_len;
        }

        Ok(total_copied)
    }
}

impl<R: Read + Seek> Seek for ChunkedReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let base = match pos {
            SeekFrom::Start(offset) => {
                return Ok({
                    self.position = offset;
                    self.position
                });
            }
            SeekFrom::End(_) => i128::from(self.plaintext_len),
            SeekFrom::Current(_) => i128::from(self.position),
        };

        let offset = match pos {
            SeekFrom::End(offset) | SeekFrom::Current(offset) => i128::from(offset),
            SeekFrom::Start(_) => unreachable!(),
        };
        let next = base + offset;

        if next < 0 || next > i128::from(u64::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid seek position",
            ));
        }

        self.position = next as u64;
        Ok(self.position)
    }
}

/// Encrypts all bytes from a reader into a chunked encrypted writer.
//
// // 将读取器中的所有字节加密写入分块加密写入器。
pub fn chunked_encrypt_and_hash(
    mut source: impl Read,
    destination: impl Write + Seek,
    password: &str,
) -> Result<(VaultHash, VaultHash), ChunkedCryptoError> {
    let mut encryptor = ChunkedEncryptor::new(destination, password)?;
    io::copy(&mut source, &mut encryptor)?;
    let result = encryptor.finish()?;
    Ok((result.encrypted_hash, result.original_hash))
}

/// Decrypts all bytes from a chunked encrypted reader into a writer.
//
// // 将分块加密读取器中的所有字节解密写入指定写入器。
pub fn chunked_decrypt(
    source: impl Read + Seek,
    mut destination: impl Write,
    password: &str,
) -> Result<VaultHash, ChunkedCryptoError> {
    let mut reader = ChunkedReader::new(source, password)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; STREAM_BUFFER_LEN];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        destination.write_all(&buffer[..bytes_read])?;
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(VaultHash::new(hasher.finalize().into()))
}

/// Re-encrypts a chunked encrypted stream with a new password.
//
// // 使用新密码重新加密一个分块加密流。
pub fn chunked_re_encrypt(
    source: impl Read + Seek,
    destination: impl Write + Seek,
    old_password: &str,
    new_password: &str,
) -> Result<(VaultHash, VaultHash), ChunkedCryptoError> {
    let mut reader = ChunkedReader::new(source, old_password)?;
    let mut encryptor = ChunkedEncryptor::new(destination, new_password)?;
    io::copy(&mut reader, &mut encryptor)?;
    let result = encryptor.finish()?;
    Ok((result.encrypted_hash, result.original_hash))
}

fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN], ChunkedCryptoError> {
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac(
        password.as_bytes(),
        salt,
        PBKDF2_ROUNDS,
        MessageDigest::sha256(),
        &mut key,
    )?;
    Ok(key)
}

fn block_iv(base_iv: &[u8; IV_LEN], block_index: u64) -> Result<[u8; IV_LEN], ChunkedCryptoError> {
    let mut iv = *base_iv;
    let index_bytes = block_index.to_be_bytes();

    // 1. 将块编号异或到 IV 的低 64 位，实现 `Base IV ^ N`。
    for (target, source) in iv[IV_LEN - index_bytes.len()..].iter_mut().zip(index_bytes) {
        *target ^= source;
    }

    Ok(iv)
}

fn encrypt_block(
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN]), ChunkedCryptoError> {
    let cipher = Cipher::aes_256_gcm();
    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;
    encrypter.pad(false);

    let mut ciphertext = vec![0u8; plaintext.len() + cipher.block_size()];
    let count = encrypter.update(plaintext, &mut ciphertext)?;
    let rest = encrypter.finalize(&mut ciphertext[count..])?;
    ciphertext.truncate(count + rest);

    let mut tag = [0u8; TAG_LEN];
    encrypter.get_tag(&mut tag)?;

    Ok((ciphertext, tag))
}

fn decrypt_block(
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, ChunkedCryptoError> {
    if tag.len() != TAG_LEN {
        return Err(ChunkedCryptoError::InvalidFormat(format!(
            "invalid tag length: {}",
            tag.len()
        )));
    }

    let cipher = Cipher::aes_256_gcm();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;
    decrypter.pad(false);

    let mut plaintext = vec![0u8; ciphertext.len() + cipher.block_size()];
    let count = decrypter.update(ciphertext, &mut plaintext)?;
    decrypter.set_tag(tag)?;
    let rest = decrypter.finalize(&mut plaintext[count..])?;
    plaintext.truncate(count + rest);

    Ok(plaintext)
}

fn parse_plaintext_layout(encrypted_len: u64) -> Result<(u64, u64), ChunkedCryptoError> {
    if encrypted_len < (HEADER_LEN + TAG_LEN) as u64 {
        return Err(ChunkedCryptoError::InvalidFormat(format!(
            "encrypted length {encrypted_len} is shorter than minimum chunked length"
        )));
    }

    let payload_len = encrypted_len - HEADER_LEN as u64;
    let block_span = (CHUNK_SIZE + TAG_LEN) as u64;
    let full_blocks = payload_len / block_span;
    let remainder = payload_len % block_span;

    if remainder == 0 {
        if full_blocks == 0 {
            return Err(ChunkedCryptoError::InvalidFormat(
                "missing encrypted chunk payload".to_string(),
            ));
        }
        let plaintext_len = full_blocks
            .checked_mul(CHUNK_SIZE as u64)
            .ok_or_else(|| ChunkedCryptoError::InvalidFormat("plaintext length overflow".into()))?;
        return Ok((plaintext_len, full_blocks));
    }

    if remainder < TAG_LEN as u64 {
        return Err(ChunkedCryptoError::InvalidFormat(format!(
            "trailing encrypted block is shorter than tag: {remainder}"
        )));
    }

    let final_plaintext_len = remainder - TAG_LEN as u64;
    let plaintext_len = full_blocks
        .checked_mul(CHUNK_SIZE as u64)
        .and_then(|value| value.checked_add(final_plaintext_len))
        .ok_or_else(|| ChunkedCryptoError::InvalidFormat("plaintext length overflow".into()))?;

    Ok((plaintext_len, full_blocks + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

    fn encrypt_to_vec(data: &[u8], password: &str) -> (Vec<u8>, VaultHash, VaultHash) {
        let mut encrypted = Cursor::new(Vec::new());
        let (encrypted_hash, original_hash) =
            chunked_encrypt_and_hash(Cursor::new(data), &mut encrypted, password).unwrap();
        (encrypted.into_inner(), encrypted_hash, original_hash)
    }

    #[test]
    fn test_chunked_roundtrip_and_hashes() {
        let original = b"hello chunked encryption";
        let password = "correct horse battery staple";
        let (encrypted, encrypted_hash, original_hash) = encrypt_to_vec(original, password);

        let expected_encrypted_hash = VaultHash::new(Sha256::digest(&encrypted).into());
        let expected_original_hash = VaultHash::new(Sha256::digest(original).into());
        assert_eq!(encrypted_hash, expected_encrypted_hash);
        assert_eq!(original_hash, expected_original_hash);

        let mut decrypted = Vec::new();
        let decrypted_hash =
            chunked_decrypt(Cursor::new(encrypted), &mut decrypted, password).unwrap();
        assert_eq!(decrypted, original);
        assert_eq!(decrypted_hash, expected_original_hash);
    }

    #[test]
    fn test_chunked_reader_seek_across_blocks() {
        let password = "seek-password";
        let original: Vec<u8> = (0..CHUNK_SIZE + 123).map(|idx| (idx % 251) as u8).collect();
        let (encrypted, _, _) = encrypt_to_vec(&original, password);

        let mut reader = ChunkedReader::new(Cursor::new(encrypted), password).unwrap();
        reader
            .seek(SeekFrom::Start((CHUNK_SIZE - 5) as u64))
            .unwrap();

        let mut slice = [0u8; 32];
        reader.read_exact(&mut slice).unwrap();
        assert_eq!(&slice, &original[CHUNK_SIZE - 5..CHUNK_SIZE - 5 + 32]);
    }

    #[test]
    fn test_chunked_reader_rejects_tampered_tag() {
        let password = "tamper-password";
        let original = b"authenticated chunk";
        let (mut encrypted, _, _) = encrypt_to_vec(original, password);
        let last = encrypted.last_mut().unwrap();
        *last ^= 0xAA;

        let mut reader = ChunkedReader::new(Cursor::new(encrypted), password).unwrap();
        let mut decrypted = Vec::new();
        let result = reader.read_to_end(&mut decrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_file_tag_is_checked_on_open() {
        let password = "empty-password";
        let (mut encrypted, _, _) = encrypt_to_vec(b"", password);
        let last = encrypted.last_mut().unwrap();
        *last ^= 0x55;

        let result = ChunkedReader::new(Cursor::new(encrypted), password);
        assert!(result.is_err());
    }

    #[test]
    fn test_chunked_encryptor_accepts_incremental_writes() {
        let password = "incremental-password";
        let mut encrypted = Cursor::new(Vec::new());
        let mut encryptor = ChunkedEncryptor::new(&mut encrypted, password).unwrap();

        encryptor.write_all(b"abc").unwrap();
        encryptor.write_all(b"def").unwrap();
        let result = encryptor.finish().unwrap();
        assert_eq!(result.plaintext_len, 6);

        let mut decrypted = Vec::new();
        chunked_decrypt(
            Cursor::new(encrypted.into_inner()),
            &mut decrypted,
            password,
        )
        .unwrap();
        assert_eq!(decrypted, b"abcdef");
    }
}
