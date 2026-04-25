# Vavavult Core Library Architecture

## 1. Overview

`vavavult` is the core library of the Vavavult workspace. It provides the foundational logic for managing encrypted file vaults, abstracting away the complexities of cryptography, database management, and physical storage.

The primary entry point is **`vavavult::vault::Vault`** (`vavavult/src/vault/mod.rs`), which encapsulates:
- The vault's configuration.
- A live connection to the encrypted SQLite database (SQLCipher).
- A handle to the storage backend abstraction.

All high-level operations (adding files, extracting, querying metadata) are executed as methods on the `Vault` struct.

---

## 2. Database Schema & Hardlink Mapping

Starting with recent architectural overhauls, the vault uses a **DB-first, many-to-one hardlink-style mapping** system. This separates physical file payloads from their virtual paths within the vault.

### Core Tables
*   **`files`**: Stores the encrypted file content identities and decryption keys. It no longer stores path strings.
*   **`directories`**: Stores the virtual directory tree structure, starting from a root record (`id = 1`).
*   **`file_entries`**: Maps filenames within a directory to a specific `files` record. This allows multiple paths to point to the exact same physical payload without duplicating data.
*   **`tags`**: References `file_entries.id`. This means the same underlying file content can have completely different tags when accessed via different vault paths.

### Invariants & DB-First Logic
*   **DB-First Metadata:** Metadata operations (find, list, tag search/mutation, move/copy, path removal) trust the SQLite path/content records and **do not fail** simply because the encrypted payload in the storage directory (`data/`) is missing. 
*   **Content Boundary:** Content-level operations (`extract`, stage-2 `rekey`, `verify_file_integrity`, `fix`) are strictly responsible for checking physical file existence and detecting corruption.
*   **Path Enforcement:** Shared creation helpers ensure invariants are kept—e.g., the database cannot simultaneously contain `/a` as a file mapping and `/a/` as a directory node.
*   **Foreign Keys:** Reopened SQLite connections always enable `PRAGMA foreign_keys = ON` so cascades (like deleting `file_entries` automatically deleting associated `tags`) remain active.

---

## 3. Data Structures & Entities

Because paths and physical files are decoupled, the API exposes distinct entities:

*   **`FileEntry`**: Represents core file content metadata (size, hashes). It no longer stores a path or tags.
*   **`FilePathEntry` (`vavavult::file`)**: Contains the resolved vault path, the encrypted hash, and the path-local tags. 
*   **`DirectoryEntry`**: Represents a directory node (directory path, parent path, direct child counts).
*   **`ListPathEntry`**: An enum wrapping either a `DirectoryEntry` or a `FilePathEntry`, typically returned by `Vault::list_by_path()`.

### Query API Returns
*   **Path-Oriented Queries:** Methods like `find_by_path`, `find_by_paths`, `find_by_tag`, and `find_by_keyword` return path-specific types like `QueryPathResult` or `FilePathEntry`.
*   **Hash/Content Queries:** Return `QueryFileResult`.
*   **Counters:** `Vault::get_file_count()` counts the current directory file mappings (`file_entries`), whereas `Vault::get_storage_file_count()` counts the actual stored, deduplicated file entities (`files`).

---

## 4. Multi-Phase Operations (CPU Paralleling)

To prevent the `Vault` mutex lock from becoming a bottleneck during CPU-intensive operations (like AES encryption/decryption), the library heavily employs a **three-phase pattern**:

### Addition API
1.  **Prepare (`prepare_addition_tasks`)**: Validates the request against the database schema. Requires `&self`.
2.  **Encrypt (`Vault::encrypt_addition_task`)**: Encrypts data from a `Read` stream into blocks. This is an associated function (no `&self` required) and can be fully parallelized.
3.  **Commit (`commit_addition_tasks`)**: Atomically commits the encrypted files to the database, creating any missing parent `directories` and inserting `file_entries` mappings. Requires `&mut self`.
    *   *Deduplication Policy:* Accepts an `Option<bool>` to handle duplicate hashes. `None`/`Some(true)` merges duplicates as new path mappings referencing the existing file entity. `Some(false)` rejects duplicates with an error.

### Extraction API
1.  **Prepare (`prepare_extraction_tasks`)**: Queries the database for the required decryption keys. Requires `&self`.
2.  **Decrypt (`Vault::decrypt_extraction_task`)**: Streams decrypted data to a `Write` destination. Requires no `&self` and can be parallelized.

### Rekey API
1.  **Prepare (`prepare_rekey_tasks`)**: Resolves requested hashes into `PendingRekeyTask` objects via the database. Requires `&self`.
2.  **Re-encrypt (`Vault::rekey_task`)**: Reads, decrypts, and re-encrypts the physical file payload via the `StorageBackend`. Requires no `&self`.
3.  **Commit (`commit_rekey_tasks`)**: Atomically updates the database rows, commits the newly staged encrypted payloads, and drops the old payloads. Requires `&mut self`.

---

## 5. Path Operations (`vavavult::vault::path_ops`)

Since files and paths are separate, manipulating them uses specialized logic:

*   **Removal:**
    *   `remove_file`: A hash-based operation that deletes the core file entity and **all** of its associated path mappings.
    *   `remove_file_by_path`: Unlinks only the specific path. The physical payload is only deleted when its final path mapping is removed.
*   **Moving / Renaming:**
    *   `Vault::move_path(source, target)`: Unified moving logic using `VaultPath`s.
    *   `Vault::rename_path_inplace(source, new_name)`: Works for both files and directories.
    *   *Optimization:* Moving or renaming a directory simply updates the directory node's parent or name, instantly moving the entire subtree without any I/O overhead on the encrypted payloads.
*   **Copying & Linking:**
    *   `Vault::copy_file_path(source, target)`: Creates a new path mapping referencing the identical underlying file entity. It copies the source path's local tags.
    *   `Vault::create_path_from_hash(hash, target)`: Creates a new path from a raw content hash, starting with empty tags.
*   **Directory Creation:**
    *   `Vault::create_empty_path(path)`: Creates an empty directory and ensures all missing parent directories are created.

---

## 6. Storage Backend Abstraction (`vavavult::storage`)

The library decouples cryptographic storage from the underlying file system via the `StorageBackend` trait.

*   **`StorageBackend` Trait**: Defines primitives for I/O (read, write, delete, exists). To support chunked encryption, backends must vend `StorageReader` (`Read + Seek + Send`) and `StorageWriter` (`Write + Seek + Send`) trait objects.
*   **`LocalStorage`**: The default implementation storing encrypted payloads in the `data/` subdirectory of the vault root.
*   **`ChunkedStorage`**: A wrapper implementation that automatically wraps underlying backend streams into `ChunkedEncryptor` and `ChunkedReader` streams.

---

## 7. Cryptography (`vavavult::crypto`)

*   **Chunked Encryption (`chunked.rs`)**: Vavavult mandates a chunked AES-256-GCM format.
    *   `ChunkedEncryptor<W: Write + Seek>` writes data as `Header + N * (ciphertext + tag)` blocks.
    *   `ChunkedReader<R: Read + Seek>` provides authenticated, random-access (seekable) plaintext reads over the underlying chunked ciphertext.
*   **OpenSSL (`encrypt.rs`)**: Houses the low-level bindings and helper functions for invoking the OpenSSL AES-256-GCM routines.
*   **SQLCipher**: The metadata database is encrypted transparently via the `rusqlite` crate compiled with the `bundled-sqlcipher` feature.

---

## 8. Common Utilities (`vavavult::common`)

*   **`constants.rs`**: Project-wide magic strings, numerical limits, and keys.
*   **`hash.rs`**: Defines `VaultHash`, a robust wrapper for manipulating SHA-256 hashes used as file identities.
*   **`metadata.rs`**: Defines `MetadataEntry` structures for arbitrary key-value attachments on vault entities.