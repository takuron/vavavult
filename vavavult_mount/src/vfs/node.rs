//! Vault file handle for WebDAV read/write operations.
//!
//! This module implements the `DavFile` trait, providing lazy decryption and
//! random-access reads of vault files. Decryption is performed on-demand using
//! the pull-based `ChunkedReader` from the core library, which decrypts only
//! the chunks needed for each read or seek operation.

use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use bytes::Buf;
use dav_server::fs::{DavFile, DavMetaData, FsError, FsFuture};
use vavavult::storage::StorageBackend;
use vavavult::vault::ExtractionTask;

use super::VaultDavMetaData;

/// A trait alias for a seekable, sendable plaintext reader.
///
/// This trait combines `Read`, `Seek`, and `Send` to represent a reader
/// that can be used for random-access decryption of vault files.
/// `Sync` is not required here because we wrap the reader in a `Mutex`.
pub trait PlainReader: Read + Seek + Send {}

impl<T> PlainReader for T where T: Read + Seek + Send {}

/// Adapter for `mpsc::Receiver<bytes::Bytes>` to `std::io::Read`.
/// Used by the write path to consume incoming data for the background encryption task.
struct ReceiverReader {
    receiver: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    buffer: bytes::Bytes,
}

impl std::io::Read for ReceiverReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.buffer.is_empty() {
            match self.receiver.blocking_recv() {
                Some(bytes) => self.buffer = bytes,
                None => return Ok(0),
            }
        }

        let len = std::cmp::min(buf.len(), self.buffer.len());
        buf[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer = self.buffer.split_off(len);
        Ok(len)
    }
}

/// Lazy-initialized reader state for read operations.
///
/// This enum uses a simple lazy-initialization pattern. The reader is only
/// initialized on the first read or seek operation using the core library's
/// `Read + Seek` API.
pub(crate) enum ReadContent {
    /// Reader not yet initialized.
    /// Contains the task and storage needed to initialize the reader.
    Pending {
        task: ExtractionTask,
        storage: Arc<dyn StorageBackend>,
    },
    /// Reader is initialized and ready for random-access reads.
    /// Contains a boxed seekable plaintext reader from the core library,
    /// wrapped in a `Mutex` for thread safety.
    Active {
        reader: Mutex<Box<dyn PlainReader>>,
    },
    /// State has been consumed (used for take operations).
    Consumed,
}

/// Inner state of VaultDavFile, wrapped in Arc<Mutex> for shared access.
struct VaultDavFileInner {
    /// Operation state (read or write).
    state: VaultDavFileState,
    /// Expected plaintext file size.
    file_size: u64,
    /// File modification time.
    modified: std::time::SystemTime,
}

/// Represents the operation state of a `VaultDavFile`.
///
/// A WebDAV file handle can be opened for either reading (e.g., GET requests)
/// or writing (e.g., PUT requests).
pub enum VaultDavFileState {
    /// State for a file opened for reading (lazy-initialized random-access reader).
    Read { content: ReadContent },
    /// State for a file opened for writing.
    Write {
        /// Channel to send incoming bytes to the background encryption task.
        write_tx: Option<tokio::sync::mpsc::Sender<bytes::Bytes>>,
        /// Handle to await the completion of the background encryption task.
        /// Wrapped in a `Mutex` for thread safety.
        write_join_handle: Option<Mutex<tokio::task::JoinHandle<Result<(), FsError>>>>,
    },
}

/// A file handle for WebDAV read/write operations on vault files.
///
/// This struct implements the `DavFile` trait, providing lazy decryption and
/// random-access reads using the core library's `Read + Seek` API.
///
/// # Thread Safety
/// The inner state is wrapped in `Arc<Mutex<...>>`, allowing this struct to be
/// cheaply cloned and shared across async tasks.
pub struct VaultDavFile {
    inner: Arc<Mutex<VaultDavFileInner>>,
}

impl std::fmt::Debug for VaultDavFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner_guard = self.inner.lock().unwrap();
        f.debug_struct("VaultDavFile")
            .field("file_size", &inner_guard.file_size)
            .field("modified", &inner_guard.modified)
            .finish_non_exhaustive()
    }
}

impl Clone for VaultDavFile {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl VaultDavFile {
    /// Creates a new `VaultDavFile` in read mode with lazy initialization.
    ///
    /// The reader is not initialized until the first read or seek operation.
    ///
    /// # Arguments
    /// * `task` - The extraction task containing decryption keys and metadata.
    /// * `storage` - The storage backend to read encrypted data from.
    /// * `file_size` - The expected plaintext file size.
    /// * `modified` - The file modification time.
    ///
    /// # Returns
    /// A new `VaultDavFile` instance in `Read` state with `Pending` content.
    pub fn new(
        task: ExtractionTask,
        storage: Arc<dyn StorageBackend>,
        file_size: u64,
        modified: std::time::SystemTime,
    ) -> Self {
        let inner = VaultDavFileInner {
            state: VaultDavFileState::Read {
                content: ReadContent::Pending { task, storage },
            },
            file_size,
            modified,
        };

        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// Creates a new `VaultDavFile` in write mode.
    ///
    /// This sets up a background task that streams incoming data through the
    /// encryption cipher and commits it to the vault upon completion.
    ///
    /// # Arguments
    /// * `vault` - The vault instance to write to.
    /// * `vault_path` - The target path within the vault.
    ///
    /// # Returns
    /// A new `VaultDavFile` instance ready for writing.
    pub fn new_write(
        vault: Arc<std::sync::Mutex<vavavult::vault::Vault>>,
        vault_path: vavavult::file::VaultPath,
    ) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(32);

        let join_handle = tokio::task::spawn_blocking(move || -> Result<(), FsError> {
            let mut reader = ReceiverReader {
                receiver: rx,
                buffer: bytes::Bytes::new(),
            };

            let storage = {
                let v = vault.lock().unwrap();
                v.storage.clone()
            };

            let now = chrono::Utc::now();

            let pending = vavavult::vault::PendingAdditionTask {
                dest_path: vault_path.clone(),
                source_size: 0,
                source_modified_time: now,
            };
            let addition_task = vavavult::vault::Vault::encrypt_addition_task(
                storage.as_ref(),
                pending,
                &mut reader,
            )
            .map_err(|e| {
                log::error!("[vavavult_mount] encryption stream failed: {:?}", e);
                FsError::GeneralFailure
            })?;

            let mut v = vault.lock().unwrap();

            if matches!(
                v.find_by_path(&vault_path),
                Ok(vavavult::vault::QueryPathResult::Found(_))
            ) {
                if let Err(e) = v.remove_file_by_path(&vault_path) {
                    log::error!("[vavavult_mount] failed to remove old file before overwrite: {:?}", e);
                    return Err(FsError::GeneralFailure);
                }
            }

            v.commit_addition_tasks(vec![addition_task], None)
                .map_err(|e| {
                    log::error!("[vavavult_mount] failed to commit file: {:?}", e);
                    FsError::GeneralFailure
                })?;

            Ok(())
        });

        let inner = VaultDavFileInner {
            state: VaultDavFileState::Write {
                write_tx: Some(tx),
                write_join_handle: Some(Mutex::new(join_handle)),
            },
            file_size: 0,
            modified: std::time::SystemTime::UNIX_EPOCH,
        };

        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// Synchronously initializes the reader if it's in Pending state.
    ///
    /// This function properly handles error recovery: if initialization fails,
    /// the Pending state is restored so the operation can be retried.
    ///
    /// Must be called while holding the inner lock.
    fn sync_ensure_reader_initialized(content: &mut ReadContent) -> Result<(), FsError> {
        match content {
            ReadContent::Pending { .. } => {
                let old = std::mem::replace(content, ReadContent::Consumed);
                if let ReadContent::Pending { task, storage } = old {
                    let result = vavavult::vault::Vault::open_extraction_task_reader(
                        storage.as_ref(),
                        &task,
                    );

                    match result {
                        Ok(reader) => {
                            *content = ReadContent::Active {
                                reader: Mutex::new(Box::new(reader)),
                            };
                            Ok(())
                        }
                        Err(e) => {
                            log::error!("[vavavult_mount] failed to open reader: {:?}", e);
                            *content = ReadContent::Pending { task, storage };
                            Err(FsError::GeneralFailure)
                        }
                    }
                } else {
                    unreachable!()
                }
            }
            ReadContent::Active { .. } => Ok(()),
            ReadContent::Consumed => Err(FsError::GeneralFailure),
        }
    }

    /// Synchronously performs a read operation.
    ///
    /// Must be called from within a blocking context (e.g., spawn_blocking).
    pub fn sync_read(&self, count: usize) -> Result<bytes::Bytes, FsError> {
        let mut inner_guard = self.inner.lock().map_err(|_| FsError::GeneralFailure)?;

        match &mut inner_guard.state {
            VaultDavFileState::Read { content } => {
                Self::sync_ensure_reader_initialized(content)?;

                match content {
                    ReadContent::Active { reader } => {
                        let mut reader_guard = reader.lock().map_err(|_| FsError::GeneralFailure)?;
                        let mut buffer = vec![0u8; count];
                        let bytes_read = reader_guard.read(&mut buffer).map_err(|e| {
                            log::error!("[vavavult_mount] read failed: {:?}", e);
                            FsError::GeneralFailure
                        })?;
                        buffer.truncate(bytes_read);
                        Ok(bytes::Bytes::from(buffer))
                    }
                    _ => unreachable!(),
                }
            }
            _ => Err(FsError::Forbidden),
        }
    }

    /// Synchronously performs a seek operation.
    ///
    /// Must be called from within a blocking context (e.g., spawn_blocking).
    pub fn sync_seek(&self, pos: SeekFrom) -> Result<u64, FsError> {
        let mut inner_guard = self.inner.lock().map_err(|_| FsError::GeneralFailure)?;

        match &mut inner_guard.state {
            VaultDavFileState::Read { content } => {
                Self::sync_ensure_reader_initialized(content)?;

                match content {
                    ReadContent::Active { reader } => {
                        let mut reader_guard = reader.lock().map_err(|_| FsError::GeneralFailure)?;
                        let new_pos = reader_guard.seek(pos).map_err(|e| {
                            log::error!("[vavavult_mount] seek failed: {:?}", e);
                            FsError::GeneralFailure
                        })?;
                        Ok(new_pos)
                    }
                    _ => unreachable!(),
                }
            }
            _ => Err(FsError::Forbidden),
        }
    }
}

impl DavFile for VaultDavFile {
    fn metadata(&mut self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let inner_guard = self.inner.lock().unwrap();
        let file_size = inner_guard.file_size;
        let modified = inner_guard.modified;
        drop(inner_guard);

        Box::pin(async move {
            Ok(Box::new(VaultDavMetaData::file(file_size, modified)) as Box<dyn DavMetaData>)
        })
    }

    fn read_bytes(&mut self, count: usize) -> FsFuture<'_, bytes::Bytes> {
        let self_clone = self.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || self_clone.sync_read(count))
                .await
                .map_err(|e| {
                    log::error!("[vavavult_mount] read task panicked: {:?}", e);
                    FsError::GeneralFailure
                })?
        })
    }

    fn write_bytes(&mut self, buf: bytes::Bytes) -> FsFuture<'_, ()> {
        let self_clone = self.clone();
        Box::pin(async move {
            let tx = {
                let inner_guard = self_clone.inner.lock().map_err(|_| FsError::GeneralFailure)?;
                match &inner_guard.state {
                    VaultDavFileState::Write { write_tx, .. } => {
                        write_tx.clone().ok_or(FsError::Forbidden)?
                    }
                    _ => return Err(FsError::Forbidden),
                }
            };

            tx.send(buf).await.map_err(|e| {
                log::error!("[vavavult_mount] write channel closed: {:?}", e);
                FsError::GeneralFailure
            })?;

            Ok(())
        })
    }

    fn write_buf(&mut self, mut buf: Box<dyn Buf + Send>) -> FsFuture<'_, ()> {
        Box::pin(async move {
            let bytes = buf.copy_to_bytes(buf.remaining());
            self.write_bytes(bytes).await
        })
    }

    fn seek(&mut self, pos: SeekFrom) -> FsFuture<'_, u64> {
        let self_clone = self.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || self_clone.sync_seek(pos))
                .await
                .map_err(|e| {
                    log::error!("[vavavult_mount] seek task panicked: {:?}", e);
                    FsError::GeneralFailure
                })?
        })
    }

    fn flush(&mut self) -> FsFuture<'_, ()> {
        Box::pin(async move {
            let join_handle = {
                let mut inner_guard = self.inner.lock().map_err(|_| FsError::GeneralFailure)?;

                match &mut inner_guard.state {
                    VaultDavFileState::Write {
                        write_tx,
                        write_join_handle,
                    } => {
                        drop(write_tx.take());

                        if let Some(join_handle_mutex) = write_join_handle.take() {
                            join_handle_mutex
                                .into_inner()
                                .map_err(|_| FsError::GeneralFailure)?
                        } else {
                            return Ok(());
                        }
                    }
                    _ => return Ok(()),
                }
            };

            join_handle
                .await
                .map_err(|e| {
                    log::error!("[vavavult_mount] background task panicked: {:?}", e);
                    FsError::GeneralFailure
                })?
                .map_err(|e| {
                    log::error!("[vavavult_mount] background task failed: {:?}", e);
                    e
                })?;

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_reader_trait() {
        use std::io::Cursor;
        let data = b"test data";
        let cursor = Cursor::new(data);
        let _reader: Box<dyn PlainReader> = Box::new(cursor);
    }

    #[test]
    fn test_vault_dav_file_debug() {
        use std::sync::Mutex;

        let inner = VaultDavFileInner {
            state: VaultDavFileState::Read {
                content: ReadContent::Consumed,
            },
            file_size: 100,
            modified: std::time::SystemTime::UNIX_EPOCH,
        };

        let file = VaultDavFile {
            inner: Arc::new(Mutex::new(inner)),
        };

        let debug_str = format!("{:?}", file);
        assert!(debug_str.contains("VaultDavFile"));
        assert!(debug_str.contains("100"));
    }

    #[test]
    fn test_vault_dav_file_clone() {
        use vavavult::storage::local::LocalStorage;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(LocalStorage::new(temp_dir.path()));

        let task = ExtractionTask {
            file_hash: vavavult::common::hash::VaultHash::new([0u8; 32]),
            password: "test".to_string(),
            expected_original_hash: vavavult::common::hash::VaultHash::new([0u8; 32]),
            original_vault_path: "/test.txt".to_string(),
        };

        let file = VaultDavFile::new(
            task,
            storage,
            100,
            std::time::SystemTime::UNIX_EPOCH,
        );

        let cloned = file.clone();
        let debug_str = format!("{:?}", cloned);
        assert!(debug_str.contains("VaultDavFile"));
    }
}
