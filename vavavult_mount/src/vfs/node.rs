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

pub struct VaultDavFile {
    state: Mutex<VaultDavFileState>,
    file_size: u64,
    modified: std::time::SystemTime,
}

impl std::fmt::Debug for VaultDavFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultDavFile")
            .field("file_size", &self.file_size)
            .field("modified", &self.modified)
            .finish_non_exhaustive()
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
        Self {
            state: Mutex::new(VaultDavFileState::Read {
                content: ReadContent::Pending { task, storage },
            }),
            file_size,
            modified,
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

        Self {
            state: Mutex::new(VaultDavFileState::Write {
                write_tx: Some(tx),
                write_join_handle: Some(Mutex::new(join_handle)),
            }),
            file_size: 0,
            modified: std::time::SystemTime::UNIX_EPOCH,
        }
    }

    /// Ensures the reader is initialized and performs a read operation.
    ///
    /// This is a synchronous helper that must be called within a lock.
    fn ensure_and_read(
        &self,
        count: usize,
    ) -> Result<bytes::Bytes, FsError> {
        let mut state_guard = self.state.lock().map_err(|_| FsError::GeneralFailure)?;

        match &mut *state_guard {
            VaultDavFileState::Read { content } => {
                Self::ensure_reader_initialized(content)?;

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

    /// Ensures the reader is initialized and performs a seek operation.
    ///
    /// This is a synchronous helper that must be called within a lock.
    fn ensure_and_seek(
        &self,
        pos: SeekFrom,
    ) -> Result<u64, FsError> {
        let mut state_guard = self.state.lock().map_err(|_| FsError::GeneralFailure)?;

        match &mut *state_guard {
            VaultDavFileState::Read { content } => {
                Self::ensure_reader_initialized(content)?;

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

    /// Helper to initialize the reader if it's in Pending state.
    ///
    /// This must be called while holding the state lock.
    fn ensure_reader_initialized(content: &mut ReadContent) -> Result<(), FsError> {
        match content {
            ReadContent::Pending { .. } => {
                let old = std::mem::replace(content, ReadContent::Consumed);
                if let ReadContent::Pending { task, storage } = old {
                    let reader = vavavult::vault::Vault::open_extraction_task_reader(
                        storage.as_ref(),
                        &task,
                    )
                    .map_err(|e| {
                        log::error!("[vavavult_mount] failed to open reader: {:?}", e);
                        FsError::GeneralFailure
                    })?;

                    *content = ReadContent::Active {
                        reader: Mutex::new(Box::new(reader)),
                    };
                } else {
                    unreachable!()
                }
            }
            ReadContent::Active { .. } => {}
            ReadContent::Consumed => return Err(FsError::GeneralFailure),
        }
        Ok(())
    }
}

impl DavFile for VaultDavFile {
    fn metadata(&mut self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let file_size = self.file_size;
        let modified = self.modified;
        Box::pin(async move {
            Ok(Box::new(VaultDavMetaData::file(file_size, modified)) as Box<dyn DavMetaData>)
        })
    }

    fn read_bytes(&mut self, count: usize) -> FsFuture<'_, bytes::Bytes> {
        Box::pin(async move {
            self.ensure_and_read(count)
        })
    }

    fn write_bytes(&mut self, buf: bytes::Bytes) -> FsFuture<'_, ()> {
        Box::pin(async move {
            let tx = {
                let state_guard = self.state.lock().map_err(|_| FsError::GeneralFailure)?;
                match &*state_guard {
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
        Box::pin(async move {
            self.ensure_and_seek(pos)
        })
    }

    fn flush(&mut self) -> FsFuture<'_, ()> {
        Box::pin(async move {
            let join_handle = {
                let mut state_guard = self.state.lock().map_err(|_| FsError::GeneralFailure)?;

                match &mut *state_guard {
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
        use vavavult::storage::StorageBackend;
        use vavavult::vault::ExtractionTask;

        let state = Mutex::new(VaultDavFileState::Read {
            content: ReadContent::Consumed,
        });

        let file = VaultDavFile {
            state,
            file_size: 100,
            modified: std::time::SystemTime::UNIX_EPOCH,
        };

        let debug_str = format!("{:?}", file);
        assert!(debug_str.contains("VaultDavFile"));
        assert!(debug_str.contains("100"));
    }
}
