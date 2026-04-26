use crate::common::hash::VaultHash;
use crate::crypto::chunked::{ChunkedCryptoError, ChunkedEncryptor, ChunkedReader};
use crate::storage::{StagingToken, StorageBackend, StorageWriter};
use std::io::{self, Read, Seek};
use std::sync::Arc;

/// A helper wrapper that applies chunked encryption on top of a storage backend.
///
/// The wrapper keeps the physical `StorageBackend` focused on byte storage while
/// offering convenience methods that automatically wrap backend writers with
/// `ChunkedEncryptor` and backend readers with an opaque `Read + Seek` stream.
//
// // 在存储后端之上应用分块加密的辅助包装类。
// //
// // 该包装类让物理 `StorageBackend` 继续专注于字节存储，同时提供便捷方法，
// // 自动用 `ChunkedEncryptor` 包装后端写入器，并用不透明的 `Read + Seek` 流包装后端读取器。
#[derive(Debug, Clone)]
pub struct ChunkedStorage {
    backend: Arc<dyn StorageBackend>,
}

impl ChunkedStorage {
    /// Creates a new chunked storage wrapper.
    ///
    /// # Arguments
    /// * `backend` - The underlying storage backend that stores encrypted bytes.
    ///
    /// # Returns
    /// A `ChunkedStorage` wrapper sharing ownership of the backend.
    //
    // // 创建新的分块存储包装类。
    // //
    // // # 参数
    // // * `backend` - 用于存储加密字节的底层存储后端。
    // //
    // // # 返回
    // // 共享底层后端所有权的 `ChunkedStorage` 包装类。
    pub fn new(backend: Arc<dyn StorageBackend>) -> Self {
        Self { backend }
    }

    /// Returns the wrapped storage backend.
    //
    // // 返回被包装的存储后端。
    pub fn backend(&self) -> Arc<dyn StorageBackend> {
        self.backend.clone()
    }

    /// Prepares a chunked encrypted writer for a new object.
    ///
    /// # Arguments
    /// * `password` - The per-file encryption password.
    ///
    /// # Returns
    /// A `ChunkedEncryptor` wrapping the backend staging writer, plus its staging token.
    ///
    /// # Errors
    /// Returns `io::Error` if the backend writer cannot be prepared or the chunked
    /// encryptor cannot write its header.
    //
    // // 为新对象准备分块加密写入器。
    // //
    // // # 参数
    // // * `password` - 每文件加密密码。
    // //
    // // # 返回
    // // 包装后端暂存写入器的 `ChunkedEncryptor`，以及对应的暂存令牌。
    // //
    // // # 错误
    // // 如果后端写入器无法准备，或分块加密器无法写入文件头，则返回 `io::Error`。
    pub fn prepare_write(
        &self,
        password: &str,
    ) -> io::Result<(
        ChunkedEncryptor<Box<dyn StorageWriter>>,
        Box<dyn StagingToken>,
    )> {
        let (writer, token) = self.backend.prepare_write()?;
        let encryptor = ChunkedEncryptor::new(writer, password).map_err(to_io_error)?;
        Ok((encryptor, token))
    }

    /// Opens a chunked encrypted reader for an existing object.
    ///
    /// # Arguments
    /// * `hash` - The encrypted object hash used by the backend.
    /// * `password` - The per-file decryption password.
    ///
    /// # Returns
    /// A random-access plaintext stream over the backend reader.
    ///
    /// # Errors
    /// Returns `io::Error` if the backend reader cannot be opened or the chunked
    /// encrypted stream is invalid.
    //
    // // 为既有对象打开分块加密读取器。
    // //
    // // # 参数
    // // * `hash` - 后端使用的加密对象哈希。
    // // * `password` - 每文件解密密码。
    // //
    // // # 返回
    // // 基于后端读取器的随机访问明文流。
    // //
    // // # 错误
    // // 如果后端读取器无法打开，或分块加密流无效，则返回 `io::Error`。
    pub fn reader(
        &self,
        hash: &VaultHash,
        password: &str,
    ) -> io::Result<impl Read + Seek + Send + 'static> {
        let reader = self.backend.reader(hash)?;
        ChunkedReader::new(reader, password).map_err(to_io_error)
    }
}

fn to_io_error(error: ChunkedCryptoError) -> io::Error {
    match error {
        ChunkedCryptoError::Io(error) => error,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    }
}
