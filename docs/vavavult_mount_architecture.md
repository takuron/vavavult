# Vavavult Mount Architecture (English)

## 3.5. `vavavult_mount` - WebDAV Mount Extension

A WebDAV server extension that allows mounting a Vavavult vault as a read-only (or optionally read-write) virtual filesystem, accessible via standard WebDAV clients.

### 3.5.1. Architecture Overview

The crate implements the `DavFileSystem` trait from the `dav-server` crate, providing a virtual filesystem layer (VFS) that transparently decrypts vault files on demand. The architecture follows a two-phase approach for file reads to minimize lock contention:

1. **Phase 1 (under vault mutex lock):** Query metadata and prepare an `ExtractionTask`.
2. **Phase 2 (lock-free):** Open a pull-based plaintext reader using `Vault::open_extraction_task_reader` with a cloned `Arc<dyn StorageBackend>`.

### Seekable Reader Architecture

`VaultDavFile` uses a **pull-based seekable reader** approach:

- **Lazy open:** The file handle stores an `ExtractionTask` and cloned `Arc<dyn StorageBackend>`. The core `Read + Seek` plaintext reader is opened only on the first `read_bytes()` or `seek()` call.
- **Random access:** `seek()` delegates to the core chunked reader, which maps plaintext offsets to encrypted chunk offsets and decrypts only the chunk needed by the next read.
- **Blocking isolation:** Synchronous `Read` and `Seek` operations run through `spawn_blocking`, keeping Tokio worker threads responsive while storage and crypto work execute on the blocking pool.
- **State machine:** Read handles transition from `Pending` to `Active`; failed initialization restores `Pending` so the operation can be retried.

### rclone Performance Parameters

When mounting via rclone, the following cache/performance parameters are applied:
- `--vfs-cache-mode=writes` or the default cache mode is sufficient for read-only random access because WebDAV `seek()` is supported by the backend. `--vfs-cache-mode=full` remains a compatibility option for clients that perform unusual concurrent reads on the same handle.
- `--dir-cache-time=30m` / `--attr-timeout=30m`: Reduce PROPFIND and attribute query frequency.

### 3.5.2. Key Modules and Their Functions

*   **`vavavult_mount::vfs`**
    *   **Path:** `vavavult_mount/src/vfs/`
    *   **Description:** The virtual filesystem layer implementing `DavFileSystem`.
    *   `mod.rs`: Defines `VaultDavFs` (the main `DavFileSystem` implementation), `VaultDavMetaData`, and `VaultDavDirEntry`. Provides `metadata()`, `read_dir()`, and `open()` methods.
    *   `node.rs`: Defines `VaultDavFile` (the `DavFile` implementation), providing lazy pull-based decryption through the core `Read + Seek` plaintext reader. `read_bytes()` and `seek()` run blocking storage/crypto work on Tokio's blocking pool and support random access without full-file prefetching.

*   **`vavavult_mount::sys_mount`**
    *   **Path:** `vavavult_mount/src/sys_mount.rs`
    *   **Description:** System-level utility class for mounting WebDAV as a local network drive across different platforms (Windows, macOS, Linux). Allows the use of third-party support (e.g., `rclone` with `winfsp`) on systems where the native method is problematic.

*   **`vavavult_mount::config`**
    *   **Path:** `vavavult_mount/src/config.rs`
    *   **Description:** Defines `MountConfig` (bind address, port, read-only flag, prefix) and `AuthConfig` (HTTP Basic Auth credentials).

*   **`vavavult_mount::error`**
    *   **Path:** `vavavult_mount/src/error.rs`
    *   **Description:** Defines `MountError`, the unified error type for vault operations, I/O, server, authentication, and configuration errors.

*   **`vavavult_mount::auth`**
    *   **Path:** `vavavult_mount/src/auth.rs`
    *   **Description:** Provides `check_basic_auth()`, a stateless function that validates an HTTP `Authorization: Basic ...` header against an `AuthConfig`. Decodes Base64, splits on the first colon, and compares username/password. Handles passwords containing colons correctly.

*   **`vavavult_mount::server`**
    *   **Path:** `vavavult_mount/src/server.rs`
    *   **Description:** WebDAV server startup and lifecycle management. Provides `start_webdav_server(vault, config)` which binds a TCP listener, builds a `DavHandler` backed by `VaultDavFs`, and spawns a background tokio task that accepts connections via `hyper` HTTP/1.1. Returns a `ServerHandle` for graceful shutdown. If `config.auth` is set, every request is gated by `check_basic_auth()`; unauthenticated requests receive a `401 Unauthorized` with a `WWW-Authenticate: Basic realm="vavavult"` header.

### 3.5.3. Key Public Types

*   **`VaultDavFs`**: The main `DavFileSystem` implementation. Wraps `Arc<Mutex<Vault>>` and translates WebDAV paths to `VaultPath` queries.
*   **`VaultDavFile`**: A `DavFile` implementation with lazy decryption. Stores an `ExtractionTask` and `Arc<dyn StorageBackend>` while pending; on first read or seek, opens the core `Read + Seek` plaintext reader with `Vault::open_extraction_task_reader`. Reads and seeks are dispatched via `spawn_blocking`, and random access is handled directly by the chunked decryptor.
*   **`VaultDavMetaData`**: Metadata for vault entries (files and directories). Carries size, directory flag, and modification time.
*   **`VaultDavDirEntry`**: Directory entry for `read_dir()` results. Contains only the entry name (not full path), as required by WebDAV.
*   **`MountConfig`**: Server configuration (bind address, port, read-only mode, auth, prefix).
*   **`AuthConfig`**: HTTP Basic Auth credentials (username, password). Used by `check_basic_auth()` and `start_webdav_server()`.
*   **`MountError`**: Unified error enum for the mount crate.
*   **`MountHandle`**: Represents a mount handle. The mount will be automatically unmounted when the handle is dropped.
*   **`SystemMounter`**: Utility struct that provides a cross-platform `mount` method for attaching a WebDAV URL as a local network drive.
*   **`ServerHandle`**: Handle to a running WebDAV server. Exposes `bound_addr: SocketAddr` (useful for port-0 tests) and `shutdown() -> impl Future` for graceful teardown.

### 3.5.4. Testing

*   **Path:** `vavavult_mount/src/vfs/mod.rs` (tests module), `vavavult_mount/src/vfs/node.rs` (tests module)
*   **Description:** Unit and integration tests for the VFS layer. Tests cover:
    - Path conversion (`DavPath` → `VaultPath`)
    - Metadata for root directories, files, and non-existent paths
    - Directory listing (root and subdirectories)
    - File opening (success, not found, forbidden for directories)
    - Lazy decryption (metadata without opening the plaintext reader)
    - Seekable reads (`SeekFrom::Start`, `SeekFrom::Current`, and `SeekFrom::End`)
    - Write prohibition in read-only mode
    - Large file reading through pull-based chunked decryption
