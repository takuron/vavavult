# Vavavult Mount Architecture (English)

## 3.5. `vavavult_mount` - WebDAV Mount Extension

A WebDAV server extension that allows mounting a Vavavult vault as a read-only (or optionally read-write) virtual filesystem, accessible via standard WebDAV clients.

### 3.5.1. Architecture Overview

The crate implements the `DavFileSystem` trait from the `dav-server` crate, providing a virtual filesystem layer (VFS) that transparently decrypts vault files on demand. The architecture follows a two-phase approach for file reads to minimize lock contention:

1. **Phase 1 (under vault mutex lock):** Query metadata and prepare an `ExtractionTask`.
2. **Phase 2 (lock-free):** Execute decryption using `execute_extraction_task_standalone` with a cloned `Arc<dyn StorageBackend>`.

### Streaming Architecture

`VaultDavFile` uses a **pipe-based streaming** approach:

- **Streaming mode:** Decryption runs in a background `spawn_blocking` task, writing 8KB chunks through an `mpsc` channel. `read_bytes()` pulls from the channel on demand, so the client receives data as soon as each chunk is decrypted — no need to wait for the entire file. Memory usage is O(chunk_size).
- **No seek support:** `seek()` always returns `FsError::NotImplemented`. Random access and concurrency are handled by rclone's `--vfs-cache-mode=full` at the VFS layer.
- The state machine transitions: `Pending` → `Streaming`.

### rclone Performance Parameters

When mounting via rclone, the following cache/performance parameters are applied:
- `--vfs-cache-mode=full`: Full VFS caching; rclone downloads files sequentially via the streaming pipe, then handles random access and concurrent reads locally.
- `--dir-cache-time=30m` / `--attr-timeout=30m`: Reduce PROPFIND and attribute query frequency.

### 3.5.2. Key Modules and Their Functions

*   **`vavavult_mount::vfs`**
    *   **Path:** `vavavult_mount/src/vfs/`
    *   **Description:** The virtual filesystem layer implementing `DavFileSystem`.
    *   `mod.rs`: Defines `VaultDavFs` (the main `DavFileSystem` implementation), `VaultDavMetaData`, and `VaultDavDirEntry`. Provides `metadata()`, `read_dir()`, and `open()` methods.
    *   `node.rs`: Defines `VaultDavFile` (the `DavFile` implementation), providing lazy decryption via a background `spawn_blocking` task and pipe-based streaming reads through `mpsc` channel. Seek is not supported (`FsError::NotImplemented`); rclone `--vfs-cache-mode=full` handles random access at the VFS layer.

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
*   **`VaultDavFile`**: A `DavFile` implementation with lazy decryption. Stores an `ExtractionTask` and `Arc<dyn StorageBackend>`; on first read, starts a background `spawn_blocking` decryption task that streams 8KB chunks through an `mpsc` channel. Reads pull from the channel on demand (pipe-based streaming). `seek()` returns `FsError::NotImplemented`; random access is delegated to rclone `--vfs-cache-mode=full`.
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
    - Lazy decryption (metadata without decryption, pipe-based streaming reads)
    - Seek returns `FsError::NotImplemented`
    - Write prohibition in read-only mode
    - Large file reading (streaming via mpsc channel)
