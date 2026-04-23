# Vavavult Technical Overview for LLM

!!! IMPORTANT: YOU MUST FOLLOW THE CODING SPECIFICATIONS IN SECTION 5 FOR EVERY RESPONSE. !!!

## 1. Windows Build Setup

### Prerequisites
- Install via scoop: `vcpkg`, `strawberryperl`
- Run: `vcpkg install openssl:x64-windows`
- Run: `perl -MCPAN -e "install Locale::Maketext::Simple"`

### Environment Variables
```
OPENSSL_DIR=C:\Users\<Username>\scoop\apps\vcpkg\current\installed\x64-windows
OPENSSL_NO_VENDOR=1
PATH += C:\Strawberry\perl\bin
```

Restart terminal, then `cargo build` should work.

## 2. Project Structure

Vavavult is a Rust workspace composed of three crates: a core library (`vavavult`), a command-line interface (`vavavult_cli`), and a WebDAV mount extension (`vavavult_mount`).

## 2. `vavavult` - Core Library

Provides the core logic for managing encrypted file vaults.

### 2.1. Main Public Interface: `vavavult::vault::Vault`
*   **Path:** `vavavult/src/vault/mod.rs`
*   **Description:** The primary struct for all vault operations. It encapsulates the vault's configuration, a live connection to the encrypted SQLite database, and a handle to the storage backend. All high-level operations (add, extract, query, etc.) are methods on this struct.

### 2.2. Key Modules and Their Functions

*   **`vavavult::vault`**
    *   **Path:** `vavavult/src/vault/`
    *   **Description:** Contains the core logic for vault operations, broken down into submodules for each action (e.g., `add.rs`, `extract.rs`, `query.rs`). It defines the main `Vault` struct and its comprehensive API. The API supports three-phase operations (prepare/encrypt/commit) for performance-critical additions, allowing CPU-intensive encryption to be parallelized without holding the vault lock. The three phases are:
    *     1. **Prepare** (`prepare_addition_tasks`): Validates requests against the vault DB (requires `&self`).
    *     2. **Encrypt** (`Vault::encrypt_addition_task`): Encrypts data from a `Read` stream (associated function, no `&self` needed — parallelizable).
    *     3. **Commit** (`commit_addition_tasks`): Commits encrypted files to DB (requires `&mut self`).

*     The extraction API follows a similar two-phase pattern:
    *     1. **Prepare** (`prepare_extraction_task` / `prepare_extraction_tasks`): Queries DB for decryption keys (requires `&self`).
    *     2. **Decrypt** (`Vault::decrypt_extraction_task`): Decrypts to a `Write` stream (associated function, no `&self` — parallelizable). A file shortcut `Vault::decrypt_extraction_task_to_file` is also provided.

*   **`vavavult::storage`**
    *   **Path:** `vavavult/src/storage/`
    *   **Description:** Implements the storage backend abstraction.
    *   `mod.rs`: Defines the `StorageBackend` trait, which abstracts file storage operations (read, write, delete, etc.).
    *   `local.rs`: Provides `LocalStorage`, the default implementation of `StorageBackend` that stores encrypted file data on the local filesystem within the vault's `data` directory.

*   **`vavavult::crypto`**
    *   **Path:** `vavavult/src/crypto/`
    *   **Description:** Handles all cryptographic operations.
    *   `encrypt.rs`: Contains functions for encrypting and decrypting data using `openssl`.
    *   `stream_cipher.rs`: Implements stream-based encryption and decryption, suitable for large files.
    *   The metadata database is encrypted using SQLCipher, configured via `rusqlite` with the `bundled-sqlcipher` feature.

*   **`vavavult::file`**
    *   **Path:** `vavavult/src/file/`
    *   **Description:** Provides utilities for handling file paths and entries within the vault.
    *   `path.rs`: Defines the `VaultPath` struct, a normalized, slash-separated path representation used internally.
    *   `mod.rs`: Defines the `FileEntry` struct, which represents a file's metadata within the vault.

*   **`vavavult::common`**
    *   **Path:** `vavavult/src/common/`
    *   **Description:** Contains shared data structures, constants, and utility functions used across the library.
    *   `constants.rs`: Defines project-wide constants.
    *   `hash.rs`: Defines the `VaultHash` type, a wrapper around a SHA256 hash.
    *   `metadata.rs`: Defines the `MetadataEntry` struct for key-value metadata.

## 3. `vavavult_cli` - Command-Line Interface

A user-facing CLI application for interacting with `vavavult` vaults.

### 3.1. Entry Point: `main.rs`
*   **Path:** `vavavult_cli/src/main.rs`
*   **Description:** Parses top-level commands (`create`, `open`) using `clap`. Upon success, it initializes an `AppState` and enters an interactive REPL (Read-Eval-Print Loop).

### 3.2. Key Modules and Their Functions

*   **`vavavult_cli::repl`**
    *   **Path:** `vavavult_cli/src/repl/`
    *   **Description:** Implements the interactive shell.
    *   `mod.rs`: Contains the main `run_repl` loop which uses `rustyline` to read user input.
    *   `dispatcher.rs`: Takes the parsed command and delegates it to the appropriate handler in the `handlers` module.
    *   `state.rs`: Defines `AppState`, which holds the active `Vault` instance wrapped in an `Arc<Mutex>`.

*   **`vavavult_cli::handlers`**
    *   **Path:** `vavavult_cli/src/handlers/`
    *   **Description:** Contains the implementation for each REPL command (e.g., `add.rs`, `extract.rs`, `list.rs`, `search.rs`). Each handler function receives the current `AppState` and the command arguments, calls the corresponding `vavavult` library functions, and uses the `ui` module to print the results.

*   **`vavavult_cli::ui`**
    *   **Path:** `vavavult_cli/src/ui/`
    *   **Description:** Responsible for all console output.
    *   `printer.rs`: Contains functions for printing tables, lists, and other formatted output.
    *   `formatter.rs`: Provides helper functions to format data for display (e.g., file sizes, timestamps).
    *   `prompt.rs`: Handles user prompts and confirmation dialogs.

*   **`vavavult_cli::cli`**
    *   **Path:** `vavavult_cli/src/cli.rs`
    *   **Description:** Defines the command-line interface structure using `clap`. It specifies all available commands, subcommands, and their arguments.

### 3.3. Testing
*   **Path:** `vavavult_cli/tests/`
*   **Description:** Integration tests for the CLI are built using the `assert_cmd` and `predicates` crates, providing a robust way to test command execution and output.
*   **Framework:**
    *   `tests/common/mod.rs`: A shared helper module that provides utilities to simplify testing.
    *   `TestContext`: A key struct within the common module that creates a fully isolated environment for each test. `TestContext::new()` handles the creation of a temporary directory and a new vault inside it, ready for testing.
*   **Usage:** To write a new test, you typically start by creating a `TestContext`, then use `assert_cmd::Command` to run `vavavult` commands (either top-level or REPL commands via stdin), and finally use `predicates` to assert that the `stdout` or `stderr` contains the expected output.

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

## 4. LLM Coding Specification

To ensure consistency and maintainability when using an LLM for development, the following rules must be strictly followed.

### 4.1. Documentation Synchronicity
*   **Rule:** Any change that modifies the project's structure, adds or removes a module, or alters the core public API **must** be accompanied by a corresponding update to this document (`llm_readme.txt`).
*   **Goal:** This document must always serve as a reliable and up-to-date source of truth for the project's architecture.

### 4.2. Changelog Maintenance
*   **Rule:** After every coding task (e.g., adding a feature, fixing a bug), a concise summary of the changes must be logged by executing the `llm_log.py` script.
*   **Format:** The command should be `python llm_log.py "Your concise log message."`. The script will automatically handle timestamping and appending to `llm_log.txt`.
*   **Goal:** To maintain a persistent, append-only log of all modifications made by the LLM, with a standardized format.

### 4.3. Internal Code Commenting
*   **Rule:** Internal implementation logic should be commented in Chinese, focusing on the sequence and purpose of operations.
*   **Style:** Comments should be brief and precede the code block they describe.
*   **Example:**
    ```rust
    // 1. 首先，确保文件存在于数据库中。这是一个快速检查。
    match self.find_by_hash(hash)? {
        QueryResult::NotFound => return Err(UpdateError::FileNotFound(hash.to_string())),
        QueryResult::Found(_) => {
            // 文件存在，继续进行哈希验证。
        }
    }

    // 2. 对存储的数据执行实际的哈希计算。这是 I/O 密集型操作。
    verify_encrypted_file_hash(self.storage.as_ref(), hash)
    ```

### 4.4. Public API Documentation
*   **Rule:** All public APIs (structs, functions, and fields) must be documented using a dual-language (English and Chinese) format.
*   **Format:**
    1.  **English:** Use standard Rustdoc (`///`) comments. The comment should include a summary, a detailed description, and sections for `# Arguments`, `# Returns`, and `# Errors` where applicable.
    2.  **Chinese:** Immediately following the English comment, provide a direct translation, with each line prefixed by `// //`.
*   **Example:**
    ```rust
    /// Creates a new Vault at the specified path.
    ///
    /// This will create the root directory and initialize the `master.json`
    /// configuration and the `master.db` database.
    ///
    /// # Arguments
    /// * `root_path` - The path where the vault metadata will be stored.
    ///
    /// # Errors
    /// Returns `CreateError` if the directory already exists and is not empty.
    //
    // // 在指定路径创建一个新的保险库。
    // //
    // // 这将创建根目录并初始化 `master.json` 配置文件和 `master.db` 数据库。
    // //
    // // # 参数
    // // * `root_path` - 将存储保险库元数据的路径。
    // //
    // // # 错误
    // // 如果目录已存在且不为空，则返回 `CreateError`。
    pub fn create_vault(...) -> Result<Vault, CreateError> { ... }
    ```
