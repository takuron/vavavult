# Vavavult Technical Overview for LLM

!!! IMPORTANT: YOU MUST FOLLOW THE CODING SPECIFICATIONS IN SECTION 4 FOR EVERY RESPONSE. !!!

## 1. Project Structure

Vavavult is a Rust workspace composed of two main crates: a core library (`vavavult`) and a command-line interface (`vavavult_cli`).

## 2. `vavavult` - Core Library

Provides the core logic for managing encrypted file vaults.

### 2.1. Main Public Interface: `vavavult::vault::Vault`
*   **Path:** `vavavult/src/vault/mod.rs`
*   **Description:** The primary struct for all vault operations. It encapsulates the vault's configuration, a live connection to the encrypted SQLite database, and a handle to the storage backend. All high-level operations (add, extract, query, etc.) are methods on this struct.

### 2.2. Key Modules and Their Functions

*   **`vavavult::vault`**
    *   **Path:** `vavavult/src/vault/`
    *   **Description:** Contains the core logic for vault operations, broken down into submodules for each action (e.g., `add.rs`, `extract.rs`, `query.rs`). It defines the main `Vault` struct and its comprehensive API. The API supports two-phase operations (prepare/execute) for performance-critical tasks, allowing CPU-intensive work to be parallelized.

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

## 4. LLM Coding Specification

To ensure consistency and maintainability when using an LLM for development, the following rules must be strictly followed.

### 4.1. Documentation Synchronicity
*   **Rule:** Any change that modifies the project's structure, adds or removes a module, or alters the core public API **must** be accompanied by a corresponding update to this document (`llm_readme.txt`).
*   **Goal:** This document must always serve as a reliable and up-to-date source of truth for the project's architecture.

### 4.2. Changelog Maintenance
*   **Rule:** After every coding task (e.g., adding a feature, fixing a bug), a concise summary of the changes must be appended to `llm_log.txt`.
*   **Format:** The log entry should be a single line summarizing the change.
*   **Goal:** To maintain a persistent, append-only log of all modifications made by the LLM.

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
